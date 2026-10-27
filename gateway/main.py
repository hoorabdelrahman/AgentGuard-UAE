"""AgentGuard UAE gateway (FastAPI).

Pipeline for every agent action (POST /call):
  task-token check -> policy engine -> ML anomaly detector (only if policy allowed)
  -> execute | deny/hold -> corrective LLM (only on deny/hold) -> quarantine if repeated
  -> hash-chained audit log
Run:  uvicorn gateway.main:app --port 8000
"""
import json
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import config
import db
import pii
import runtime
import seed
from gateway import anomaly, audit, corrector, identity, llm, policy, quarantine, report, tasks, tools


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_schema()
    anomaly.load()
    yield


app = FastAPI(title="AgentGuard UAE Gateway", version="1.0", lifespan=lifespan)


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        return ""
    return authorization.split(" ", 1)[1].strip()


def _admin(key: str | None):
    if key != config.ADMIN_KEY:
        raise HTTPException(403, "admin key required")


def _approved_hosts():
    return tuple(policy.rules()["approved_destinations"])


# ------------------------------------------------------------------ health / info
@app.get("/health")
def health():
    b = anomaly.load()
    return {"status": "ok", "ml_model_loaded": b is not None, "llm_enabled": llm.enabled(),
            "llm_provider": config.LLM_PROVIDER, "runtime": runtime.STATE}


@app.get("/agents")
def list_agents():
    with db.session() as conn:
        return [dict(r) for r in conn.execute("SELECT agent_id,name,role,owner_entity,platform,status FROM agents")]


# ------------------------------------------------------------------ identity
class AuthBody(BaseModel):
    agent_id: str
    nonce: str
    signature: str


@app.get("/auth/nonce")
def get_nonce(agent_id: str):
    with db.WRITE_LOCK, db.session() as conn:
        return {"nonce": identity.new_nonce(conn, agent_id), "expires_in": config.NONCE_TTL}


@app.post("/auth/token")
def auth_token(body: AuthBody):
    with db.WRITE_LOCK, db.session() as conn:
        token, err, agent = identity.authenticate(conn, body.agent_id, body.nonce, body.signature)
        if err:
            audit.append(conn, "AUTH_FAILED", agent_id=body.agent_id, policy_code=err, final_decision="rejected")
            return JSONResponse({"ok": False, "code": err}, status_code=401)
        audit.append(conn, "AUTH_OK", agent_id=body.agent_id, agent_role=agent["role"], platform=agent["platform"])
        return {"ok": True, "token": token, "expires_in": config.IDENTITY_TTL}


# ------------------------------------------------------------------ task tokens
class TaskBody(BaseModel):
    task_type: str
    case_id: str


@app.post("/tasks")
def create_task(body: TaskBody, authorization: str | None = Header(None)):
    with db.WRITE_LOCK, db.session() as conn:
        res = tasks.issue(conn, _bearer(authorization), body.task_type, body.case_id)
    if not res["ok"]:
        return JSONResponse({"ok": False, "code": res["code"]}, status_code=res["status"])
    return res


# ------------------------------------------------------------------ the main pipeline
class CallBody(BaseModel):
    tool: str
    args: dict = Field(default_factory=dict)
    parent_event_id: str | None = None
    correction_attempt: int = 0


@app.post("/call")
def call(body: CallBody, authorization: str | None = Header(None)):
    t0 = time.perf_counter()
    token, args = _bearer(authorization), body.args or {}

    # ---------------- phase 1: decide + execute (under the write lock)
    with db.WRITE_LOCK, db.session() as conn:
        claims, task, agent, rej = tasks.validate(conn, token)
        if rej:
            ev = audit.append(conn, "ACTION", agent_id=rej["agent_id"], jti=rej["jti"], tool_name=body.tool,
                              final_decision="rejected", policy_code=rej["code"], execution_status="not_executed",
                              parent_event_id=body.parent_event_id, correction_attempt=body.correction_attempt)
            status = 403 if rej["code"] in ("AGENT_QUARANTINED", "TOKEN_REVOKED") else 401
            return JSONResponse({"decision": "rejected", "code": rej["code"], "event_id": ev["event_id"]}, status_code=status)

        verdict = policy.evaluate(claims, task, body.tool, args)
        ml_decision, ml_score = "skipped", None
        if verdict.allow:
            ml_decision, ml_score = anomaly.score(conn, claims, task, body.tool, args)

        code = reason = None
        if not verdict.allow:
            final, code, reason = "denied", verdict.code, verdict.reason
        elif ml_decision == "deny":
            final, code, reason = "denied", "ML_ANOMALY", f"Behavioural anomaly score {ml_score} (deny threshold)."
        elif ml_decision == "hold":
            final, code, reason = "held", "ML_HOLD", f"Behavioural anomaly score {ml_score} (hold threshold)."
        else:
            final = "allowed"

        result, n_rec, exec_status = None, 0, "not_executed"
        if final == "allowed":
            try:
                result, n_rec = tools.run(conn, body.tool, args, claims["agent_id"], "guard", _approved_hosts())
                exec_status = "executed"
            except (tools.ToolError, ValueError, TypeError) as ex:
                final, code, reason, exec_status = "error", "TOOL_ERROR", str(ex), "failed"

        conn.execute("INSERT INTO calls (jti,ts,tool,requested,records,outcome) VALUES (?,?,?,?,?,?)",
                     (claims["jti"], time.time(), body.tool,
                      __import__("gateway.features", fromlist=["x"]).requested_records(body.tool, args), n_rec, final))
        violations = task["violations"]
        conn.execute("UPDATE task_tokens SET calls_used = calls_used + 1 WHERE jti=?", (claims["jti"],))
        if final in ("denied", "held"):
            violations += 1
            conn.execute("UPDATE task_tokens SET violations=? WHERE jti=?", (violations, claims["jti"]))
        quarantine_now = final in ("denied", "held") and violations >= config.MAX_VIOLATIONS_PER_TASK
        latency_ms = (time.perf_counter() - t0) * 1000

    # ---------------- phase 2: corrective LLM (no lock held; only on deny/hold)
    corr = None
    if final in ("denied", "held") and not quarantine_now and runtime.STATE["corrector_enabled"]:
        corr = corrector.suggest(claims, body.tool, args, code, reason)

    # ---------------- phase 3: audit log (+ queue / quarantine)
    with db.WRITE_LOCK, db.session() as conn:
        ev = audit.append(
            conn, "ACTION", agent_id=claims["agent_id"], agent_role=agent["role"], platform=agent["platform"],
            jti=claims["jti"], case_id=claims["case_id"], task_type=claims["task_type"],
            tool_name=body.tool, action=json.dumps(pii.sanitize(args), default=str)[:300],
            policy_decision="allowed" if verdict.allow else "denied", policy_code=code,
            policy_reason=reason, ml_decision=ml_decision, ml_score=ml_score,
            correction_attempt=body.correction_attempt, parent_event_id=body.parent_event_id,
            correction_recommendation=(corr or {}).get("explanation"),
            correction_source=(corr or {}).get("source"),
            revised_action=json.dumps((corr or {}).get("suggestion"), default=str)[:300] if corr and corr.get("suggestion") else None,
            final_decision=final, execution_status=exec_status, latency_ms=round(latency_ms, 2),
            corrector_ms=(corr or {}).get("ms"),
            sensitive_hits_attempted=pii.count_sensitive(args) if final in ("denied", "held") else None)
        if final == "held":
            conn.execute("INSERT INTO human_queue (kind,jti,agent_id,case_id,task_type,reason,held_action,status,ts) "
                         "VALUES ('held_action',?,?,?,?,?,?, 'pending', ?)",
                         (claims["jti"], claims["agent_id"], claims["case_id"], claims["task_type"], code,
                          json.dumps({"tool": body.tool, "args": args}, default=str), time.time()))
        if quarantine_now:
            quarantine.run(conn, claims, f"{violations} violations in one task (last: {code})", ev["event_id"])

    resp = {"decision": "quarantined" if quarantine_now else final, "event_id": ev["event_id"],
            "latency_ms": round(latency_ms, 2)}
    if final == "allowed":
        resp["result"] = result
    elif quarantine_now:
        resp.update(code=code, hint="Agent quarantined. The task was reassigned to a human reviewer.")
    elif final in ("denied", "held", "error"):
        resp.update(code=code, retries_left=max(0, config.MAX_VIOLATIONS_PER_TASK - violations))
        if corr:  # the agent only ever sees a one-line hint + a suggested (re-validated) action
            resp.update(hint=corr["hint"], suggestion=corr["suggestion"])
    return resp


# ------------------------------------------------------------------ the "classic" baseline (no protection)
class BaselineBody(BaseModel):
    claimed_agent: str = "unknown"
    tool: str
    args: dict = Field(default_factory=dict)


@app.post("/baseline/call")
def baseline_call(body: BaselineBody, x_api_key: str | None = Header(None)):
    """How most agents run today: one shared static API key, self-declared identity, no scoping."""
    if x_api_key != config.BASELINE_API_KEY:
        raise HTTPException(401, "bad api key")
    with db.WRITE_LOCK, db.session() as conn:
        conn.execute("INSERT INTO baseline_calls (ts,claimed_agent,tool) VALUES (?,?,?)",
                     (time.time(), body.claimed_agent, body.tool))
        try:
            result, _ = tools.run(conn, body.tool, body.args, body.claimed_agent, "baseline", _approved_hosts())
        except (tools.ToolError, ValueError, TypeError) as ex:
            return JSONResponse({"decision": "error", "code": "TOOL_ERROR", "detail": str(ex)}, status_code=400)
    return {"decision": "allowed", "result": result, "event_id": None}


# ------------------------------------------------------------------ audit + AI report
@app.get("/audit/verify")
def audit_verify():
    with db.session() as conn:
        ok, broken, n = audit.verify_chain(conn)
    return {"chain_ok": ok, "first_broken_row": broken, "rows_checked": n}


@app.get("/audit/events")
def audit_events(limit: int = 200):
    with db.session() as conn:
        return audit.events(conn, limit=min(limit, 5000))


@app.get("/report/questions")
def report_questions():
    return report.QUESTIONS


@app.get("/report/ask")
def report_ask(q: str = "full_summary"):
    with db.session() as conn:
        return report.answer(conn, q)


# ------------------------------------------------------------------ admin (demo operations)
@app.post("/admin/reset")
def admin_reset(x_admin_key: str | None = Header(None)):
    _admin(x_admin_key)
    if not config.DEMO_MODE:
        raise HTTPException(403, "reset disabled (DEMO_MODE=false)")
    with db.WRITE_LOCK, db.session() as conn:
        db.reset_runtime(conn)
        seed.seed_cases(conn)
    runtime.STATE.update(ml_enabled=True, corrector_enabled=True)
    return {"ok": True}


class ConfigBody(BaseModel):
    ml_enabled: bool | None = None
    corrector_enabled: bool | None = None


@app.post("/admin/config")
def admin_config(body: ConfigBody, x_admin_key: str | None = Header(None)):
    _admin(x_admin_key)
    for k, v in body.model_dump().items():
        if v is not None:
            runtime.STATE[k] = v
    return runtime.STATE


@app.post("/admin/release/{agent_id}")
def admin_release(agent_id: str, x_admin_key: str | None = Header(None)):
    """A human reviewer lifts a quarantine."""
    _admin(x_admin_key)
    with db.WRITE_LOCK, db.session() as conn:
        conn.execute("UPDATE agents SET status='active' WHERE agent_id=?", (agent_id,))
        audit.append(conn, "AGENT_RELEASED", agent_id=agent_id, reason="released by human reviewer")
    return {"ok": True}


class DecisionBody(BaseModel):
    decision: str  # approve | reject | complete
    by: str = "human_reviewer"


@app.post("/admin/human_queue/{qid}/decision")
def human_decision(qid: int, body: DecisionBody, x_admin_key: str | None = Header(None)):
    _admin(x_admin_key)
    with db.WRITE_LOCK, db.session() as conn:
        row = conn.execute("SELECT * FROM human_queue WHERE id=?", (qid,)).fetchone()
        if not row:
            raise HTTPException(404, "no such queue item")
        if row["status"] != "pending":
            raise HTTPException(409, "already resolved")
        outcome = {"approve": "approved", "reject": "rejected", "complete": "completed"}.get(body.decision)
        if not outcome:
            raise HTTPException(400, "decision must be approve|reject|complete")
        detail = None
        if outcome == "approved" and row["kind"] == "held_action":
            act = json.loads(row["held_action"])
            _, _ = tools.run(conn, act["tool"], act["args"], row["agent_id"], "guard", _approved_hosts())
            detail = f"executed held action {act['tool']}"
        conn.execute("UPDATE human_queue SET status=?, resolved_by=?, resolved_ts=? WHERE id=?",
                     (outcome, body.by, time.time(), qid))
        audit.append(conn, "HUMAN_REVIEW", queue_id=qid, queue_kind=row["kind"], agent_id=row["agent_id"],
                     case_id=row["case_id"], decision=outcome, reviewer=body.by, detail=detail)
    return {"ok": True, "status": outcome}
