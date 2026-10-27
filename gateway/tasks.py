"""Task tokens: short-lived, single-task, single-case, tool-limited credentials issued by the gateway."""
import json
import time
import uuid
from functools import lru_cache

import jwt
import yaml

import config
from gateway import audit, identity


@lru_cache(maxsize=1)
def task_catalog() -> dict:
    return yaml.safe_load(config.TASKS_FILE.read_text())


def issue(conn, identity_token: str, task_type: str, case_id: str) -> dict:
    """Validate the request and mint a task token. Logs every outcome to the audit chain."""
    def fail(code, agent_id=None, status=403):
        audit.append(conn, "TASK_DENIED", agent_id=agent_id or "unknown", task_type=task_type,
                     case_id=case_id, final_decision="denied", policy_code=code)
        return {"ok": False, "code": code, "status": status}

    claims, err, hint = identity.decode(identity_token, "identity")
    if err:
        return fail("IDENTITY_" + err, hint, 401)
    agent_id = claims["sub"]
    agent = conn.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
    if not agent or agent["status"] != "active":
        return fail("AGENT_NOT_ACTIVE", agent_id)
    task = task_catalog().get(task_type)
    if not task:
        return fail("UNKNOWN_TASK", agent_id, 400)
    if agent["role"] not in task["allowed_roles"]:
        return fail("ROLE_NOT_ALLOWED", agent_id)
    if not conn.execute("SELECT 1 FROM cases WHERE case_id=?", (case_id,)).fetchone():
        return fail("UNKNOWN_CASE", agent_id, 404)
    if not conn.execute("SELECT 1 FROM case_assignments WHERE agent_id=? AND case_id=?", (agent_id, case_id)).fetchone():
        return fail("CASE_NOT_ASSIGNED", agent_id)

    now = int(time.time())
    jti = uuid.uuid4().hex
    exp = now + int(task["ttl_seconds"])
    token_claims = {"typ": "task", "jti": jti, "sub": agent_id, "agent_id": agent_id, "task_type": task_type,
                    "case_id": case_id, "tools": task["tools"], "max_calls": task["max_calls"],
                    "iat": now, "exp": exp}
    token = jwt.encode(token_claims, config.GATEWAY_SECRET, algorithm="HS256")
    conn.execute("INSERT INTO task_tokens (jti,agent_id,task_type,case_id,tools,max_calls,status,issued_at,expires_at) "
                 "VALUES (?,?,?,?,?,?, 'active', ?, ?)",
                 (jti, agent_id, task_type, case_id, json.dumps(task["tools"]), task["max_calls"], time.time(), exp))
    audit.append(conn, "TASK_ISSUED", agent_id=agent_id, agent_role=agent["role"], task_type=task_type,
                 case_id=case_id, jti=jti, tools=task["tools"], ttl_seconds=task["ttl_seconds"])
    return {"ok": True, "token": token, "jti": jti, "expires_in": task["ttl_seconds"], "tools": task["tools"]}


def validate(conn, token: str):
    """Check a task token on every call. Returns (claims, task_row, agent_row, None) or (..., rejection)."""
    claims, err, hint = identity.decode(token, "task")
    if err:
        return None, None, None, {"code": err, "agent_id": hint or "unknown", "jti": None}
    task = conn.execute("SELECT * FROM task_tokens WHERE jti=?", (claims["jti"],)).fetchone()
    agent = conn.execute("SELECT * FROM agents WHERE agent_id=?", (claims["agent_id"],)).fetchone()
    if not task or not agent:
        return None, None, None, {"code": "TOKEN_UNKNOWN", "agent_id": claims.get("agent_id"), "jti": claims.get("jti")}
    if agent["status"] != "active":
        return None, None, None, {"code": "AGENT_QUARANTINED", "agent_id": agent["agent_id"], "jti": claims["jti"]}
    if task["status"] != "active":
        return None, None, None, {"code": "TOKEN_REVOKED", "agent_id": agent["agent_id"], "jti": claims["jti"]}
    return claims, task, agent, None
