"""AgentGuard UAE dashboard (Streamlit).  Run:  streamlit run dashboard/app.py"""
import json
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402
import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

import config  # noqa: E402
from gateway import audit, report  # noqa: E402

st.set_page_config(page_title="AgentGuard UAE", page_icon="🛡️", layout="wide")
GW = config.GATEWAY_URL
ADMIN = {"X-Admin-Key": config.ADMIN_KEY}
BACKUP = config.DATA_DIR / "tamper_backup.json"


# ---------------------------------------------------------------- data helpers
def conn():
    if not config.DB_PATH.exists():
        return None
    c = sqlite3.connect(f"file:{config.DB_PATH}?mode=ro", uri=True, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def gw_get(path, **kw):
    try:
        return httpx.get(GW + path, timeout=15, **kw).json()
    except Exception:
        return None


def gw_post(path, body=None):
    try:
        return httpx.post(GW + path, json=body, headers=ADMIN, timeout=60).json()
    except Exception as e:
        return {"error": str(e)}


def load_events(limit=2000):
    c = conn()
    if not c:
        return pd.DataFrame()
    evs = audit.events(c, limit=limit)
    c.close()
    return pd.DataFrame(evs)


def chips(e):
    """Compact pipeline strip, e.g.  Identity ✓ → Task ✓ → Policy ✗ → Corrected ✓"""
    if e.get("final_decision") == "rejected":
        return f"Credential ✗ ({e.get('policy_code')})"
    s = "Identity ✓ → Task ✓ → "
    s += "Policy ✓" if e.get("policy_decision") == "allowed" else f"Policy ✗ ({e.get('policy_code')})"
    ml = e.get("ml_decision")
    if e.get("policy_decision") == "allowed":
        s += " → ML ✓" if ml in ("normal", "disabled", "unavailable") else f" → ML ✗ ({ml})"
    fd = e.get("final_decision")
    if e.get("parent_event_id") and fd == "allowed":
        s += " → Revalidated ✓ → Executed"
    elif fd == "allowed":
        s += " → Executed"
    elif fd in ("denied", "held"):
        s += " → " + ("Held for review" if fd == "held" else "Blocked") + " → Correction suggested"
    return s


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.title("🛡️ AgentGuard UAE")
    health = gw_get("/health")
    if health:
        st.success("Gateway online")
        st.caption(f"ML model: {'loaded' if health['ml_model_loaded'] else 'MISSING'} · LLM: "
                   f"{health['llm_provider'] if health['llm_enabled'] else 'off (rule fallback)'}")
    else:
        st.error(f"Gateway not reachable at {GW}")
    st.divider()
    st.subheader("Demo controls")
    scen = st.selectbox("Scenario", ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10"], index=5,
                        format_func=lambda x: {"S1": "S1 normal work", "S2": "S2 forged identity", "S3": "S3 credential abuse",
                                               "S4": "S4 prohibited tool", "S5": "S5 wrong case", "S6": "S6 injection → corrected",
                                               "S7": "S7 stubborn → quarantine", "S8": "S8 data harvesting (ML)",
                                               "S9": "S9 PII in report", "S10": "S10 audit tampering"}[x])
    if st.button("▶ Run scenario"):
        with st.spinner(f"Running {scen} ..."):
            p = subprocess.run([sys.executable, "-m", "scenarios.run_all", "--only", scen, "--no-reset"],
                               cwd=ROOT, capture_output=True, text=True, timeout=300)
        st.session_state["last_run"] = (p.stdout + p.stderr)[-3000:]
    if st.button("⟲ Reset demo state", help="Clears the audit log, tokens and queues."):
        st.session_state["reset"] = gw_post("/admin/reset")
    if "reset" in st.session_state:
        st.caption(f"reset: {st.session_state['reset']}")
    if "last_run" in st.session_state:
        with st.expander("Scenario output", expanded=True):
            st.code(st.session_state["last_run"])


# ---------------------------------------------------------------- header + live KPIs
st.title("AgentGuard UAE — security gateway for government AI agents")
st.caption("Prevent · Correct · Prove.  All data on this screen is simulated.")


@st.fragment(run_every=3)
def live():
    c = conn()
    if not c:
        st.warning("No database yet. Run: python -m scripts.init_db")
        return
    stats = report.compute_stats(c)
    agents = pd.DataFrame([dict(r) for r in c.execute("SELECT agent_id,name,role,platform,status FROM agents")])
    exf = c.execute("SELECT COUNT(*) n, COALESCE(SUM(records),0) r FROM exfil_log WHERE mode='guard'").fetchone()
    pend = c.execute("SELECT COUNT(*) FROM human_queue WHERE status='pending'").fetchone()[0]
    c.close()
    ver = gw_get("/audit/verify") or {}
    quar = int((agents["status"] == "quarantined").sum()) if len(agents) else 0

    k = st.columns(6)
    k[0].metric("Agents active / quarantined", f"{len(agents) - quar} / {quar}")
    k[1].metric("Actions allowed / blocked", f"{stats['allowed']} / {stats['denied'] + stats['held']}")
    k[2].metric("Self-corrected", f"{stats['chains_recovered_by_correction']} of {stats['violation_chains']}")
    k[3].metric("Mean time to quarantine", "-" if stats["mean_time_to_quarantine_s"] is None else f"{stats['mean_time_to_quarantine_s']} s")
    k[4].metric("Latency p50 / p95", "-" if stats["latency_ms_p50"] is None else f"{stats['latency_ms_p50']} / {stats['latency_ms_p95']} ms")
    k[5].metric("Records exfiltrated", int(exf["r"]), help="Records that left to non-approved destinations while protected by the gateway.")
    b = st.columns([1, 1, 3])
    b[0].markdown("✅ **Audit chain verified**" if ver.get("chain_ok") else ("❌ **CHAIN BROKEN at row %s**" % ver.get("first_broken_row") if ver else "—"))
    b[1].caption(f"{ver.get('rows_checked', 0)} events · {pend} pending human review")

    left, right = st.columns([1, 2])
    with left:
        st.subheader("Agent registry")
        if len(agents):
            agents["status"] = agents["status"].map(lambda s: "🟥 quarantined" if s == "quarantined" else "🟩 verified / active")
            st.dataframe(agents, hide_index=True)
    with right:
        st.subheader("Live action feed")
        df = load_events(300)
        if len(df):
            rows = []
            for e in df[df["event_type"].isin(["ACTION", "QUARANTINE", "HUMAN_REVIEW", "AGENT_RELEASED"])].head(25).to_dict("records"):
                e = {k: (None if (isinstance(v, float) and pd.isna(v)) else v) for k, v in e.items()}
                if e["event_type"] == "ACTION":
                    rows.append({"time": e["ts"][11:23], "agent": e.get("agent_id"), "tool": e.get("tool_name"),
                                 "pipeline": chips(e), "result": e.get("final_decision"), "retry": e.get("correction_attempt")})
                else:
                    rows.append({"time": e["ts"][11:23], "agent": e.get("agent_id"), "tool": "—",
                                 "pipeline": f"{e['event_type']}: {e.get('reason') or e.get('decision') or ''}", "result": "", "retry": None})
            st.dataframe(pd.DataFrame(rows), hide_index=True, height=420)


live()

tab_inc, tab_q, tab_audit, tab_cmp = st.tabs(["🔎 Incident detail", "🧑‍⚖️ Human queue", "📜 Audit & AI report", "📊 Compare vs baseline"])

# ---------------------------------------------------------------- incident detail
with tab_inc:
    df = load_events(3000)
    if df.empty or "final_decision" not in df:
        st.info("No incidents yet. Run scenario S6 from the sidebar.")
    else:
        acts = df[df["event_type"] == "ACTION"]
        roots = acts[(acts["parent_event_id"].isna()) & (acts["final_decision"].isin(["denied", "held"]))]
        if roots.empty:
            st.info("No blocked actions yet.")
        else:
            opts = {f"{r.ts[11:23]} · {r.agent_id} · {r.tool_name} · {r.policy_code}": r.event_id for r in roots.itertuples()}
            pick = st.selectbox("Pick an incident", list(opts))
            root = acts[acts["event_id"] == opts[pick]].iloc[0]
            kids = acts[acts["parent_event_id"] == opts[pick]].sort_values("correction_attempt")
            st.markdown(f"**1 · Original action** — `{root.tool_name}` by **{root.agent_id}** on `{root.case_id}`")
            st.code(root.action or "")
            st.markdown(f"**2 · Policy decision** — `{root.policy_decision}` · code `{root.policy_code}`")
            st.caption(f"Internal reason (audit only, never shown to the agent): {root.policy_reason}")
            if isinstance(root.ml_decision, str) and root.ml_decision != "skipped":
                st.markdown(f"**3 · ML detector** — `{root.ml_decision}` (score {root.ml_score})")
            else:
                st.markdown("**3 · ML detector** — not run (policy already denied)")
            if isinstance(root.correction_recommendation, str):
                st.markdown(f"**4 · Corrective LLM** ({root.correction_source}) — {root.correction_recommendation}")
                st.caption(f"Proposed safer action: {root.revised_action}")
            for k in kids.itertuples():
                icon = "✅" if k.final_decision == "allowed" else "⛔"
                st.markdown(f"**Retry {k.correction_attempt}** {icon} `{k.tool_name}` → **{k.final_decision}** "
                            f"({k.policy_code or 'passed policy + ML'})")
            ok = (kids["final_decision"] == "allowed").any() if len(kids) else False
            q = df[(df["event_type"] == "QUARANTINE") & (df["jti"] == root.jti)]
            if ok:
                st.success("Outcome: the unsafe action was never executed; the corrected action passed revalidation.")
            elif len(q):
                st.error(f"Outcome: agent quarantined — {q.iloc[0].reason}")
            else:
                st.warning("Outcome: blocked, no safe alternative executed yet.")

# ---------------------------------------------------------------- human queue
with tab_q:
    c = conn()
    rows = [dict(r) for r in c.execute("SELECT * FROM human_queue ORDER BY id DESC LIMIT 50")] if c else []
    if not rows:
        st.info("Queue is empty. Scenarios S7 and S8 create items (reassigned tasks and held actions).")
    for r in rows:
        with st.container(border=True):
            st.markdown(f"**#{r['id']} · {r['kind']}** · agent `{r['agent_id']}` · case `{r['case_id']}` · reason `{r['reason']}` · status **{r['status']}**")
            if r["status"] == "pending":
                a, b2, _ = st.columns([1, 1, 4])
                if r["kind"] == "held_action":
                    if a.button("Approve & execute", key=f"ap{r['id']}"):
                        st.write(gw_post(f"/admin/human_queue/{r['id']}/decision", {"decision": "approve", "by": "dashboard"}))
                        st.rerun()
                    if b2.button("Reject", key=f"rj{r['id']}"):
                        st.write(gw_post(f"/admin/human_queue/{r['id']}/decision", {"decision": "reject", "by": "dashboard"}))
                        st.rerun()
                else:
                    if a.button("Mark task completed", key=f"cp{r['id']}"):
                        st.write(gw_post(f"/admin/human_queue/{r['id']}/decision", {"decision": "complete", "by": "dashboard"}))
                        st.rerun()
                    if b2.button("Release agent", key=f"rl{r['id']}"):
                        st.write(gw_post(f"/admin/release/{r['agent_id']}"))
                        st.rerun()

# ---------------------------------------------------------------- audit + AI report
with tab_audit:
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Tamper-evidence")
        if st.button("Verify audit chain"):
            st.json(gw_get("/audit/verify"))
        c = conn()
        n = c.execute("SELECT COUNT(*) FROM audit").fetchone()[0] if c else 0
        row = st.number_input("Audit row to tamper with (demo)", min_value=1, max_value=max(1, n), value=min(4, max(1, n)))
        t1, t2 = st.columns(2)
        if t1.button("😈 Tamper with this row"):
            import db
            with db.session() as w:
                body = w.execute("SELECT body FROM audit WHERE id=?", (int(row),)).fetchone()["body"]
                BACKUP.write_text(json.dumps({"id": int(row), "body": body}))
                w.execute("UPDATE audit SET body=? WHERE id=?", (body.replace("agent_", "agent_X", 1) if "agent_" in body else body + " ", int(row)))
            st.warning("Row modified directly in the database. Now click 'Verify audit chain'.")
        if t2.button("↩ Undo tamper") and BACKUP.exists():
            import db
            b = json.loads(BACKUP.read_text())
            with db.session() as w:
                w.execute("UPDATE audit SET body=? WHERE id=?", (b["body"], b["id"]))
            st.success("Restored.")
    with c2:
        st.subheader("Audit LLM (retrospective)")
        qs = gw_get("/report/questions") or {}
        qid = st.selectbox("Question", list(qs), format_func=lambda k: qs[k]) if qs else None
        if qid and st.button("Ask"):
            with st.spinner("Analysing audit records ..."):
                ans = gw_get(f"/report/ask?q={qid}")
            if ans:
                st.write(ans["answer"])
                st.caption(f"written by: {ans['source']} (facts are computed from the log, not by the LLM)")
                with st.expander("Facts used"):
                    st.json(ans["facts"])
    st.subheader("Export")
    df = load_events(5000)
    if len(df):
        st.download_button("⬇ Audit log as CSV (opens in Excel)", df.to_csv(index=False).encode(), "audit_log.csv", "text/csv")
        st.download_button("⬇ Audit log as JSON Lines", "\n".join(json.dumps({k: v for k, v in r.items() if not (isinstance(v, float) and pd.isna(v))}, default=str) for r in df.to_dict("records")).encode(), "audit_log.jsonl")

# ---------------------------------------------------------------- compare
with tab_cmp:
    f = config.DATA_DIR / "eval_results.json"
    if st.button("Run evaluation now (about 2 minutes; RESETS the audit log)"):
        with st.spinner("Running baseline vs AgentGuard evaluation ..."):
            subprocess.run([sys.executable, "-m", "evaluation.run_eval", "--benign", "30", "--reps", "4"],
                           cwd=ROOT, capture_output=True, text=True, timeout=900)
    if not f.exists():
        st.info("No results yet. Run:  python -m evaluation.run_eval")
    else:
        r = json.loads(f.read_text())
        b, g = r["baseline"], r["guard"]
        st.caption(f"Measured {r['generated_at']} on SIMULATED agents and attacks · {r['benign_tasks']} benign tasks · {r['reps_per_attack']} runs per attack")
        st.subheader("Identity and task tokens")
        st.table(pd.DataFrame([
            ["Credential-abuse attempts accepted (of 5)", b["credential_abuse_accepted"], g["credential_abuse_accepted"]],
            ["Actions tied to a cryptographically verified agent", f"{b['actions_tied_to_verified_agent_pct']}%", f"{g['actions_tied_to_verified_agent_pct']}%"],
            ["Tools one session can execute (of 6)", b["tools_executable_in_one_session"], g["tools_executable_in_one_session"]],
            ["Records reachable by one hijacked session", b["per_attack"]["harvesting"]["records_exposed_mean"], g["per_attack"]["harvesting"]["records_exposed_mean"]],
            ["Privilege window", r["privilege_window"]["baseline"], r["privilege_window"]["guard"]],
        ], columns=["Metric", "Baseline (shared key)", "AgentGuard"]).astype(str).set_index("Metric"))
        st.subheader("Security and continuity")
        lat = r["latency"]
        st.table(pd.DataFrame([
            ["Overall attack success rate", b["overall_attack_success_rate"], g["overall_attack_success_rate"]],
            ["Benign task completion", b["benign"]["task_completion_rate"], g["benign"]["task_completion_rate"]],
            ["False-positive rate (benign actions blocked)", "n/a", g["benign"]["false_positive_rate_actions"]],
            ["Round trip p50 / p95 per allowed action (ms)", f"{lat['baseline_p50_ms']} / {lat['baseline_p95_ms']}", f"{lat['guard_p50_ms']} / {lat['guard_p95_ms']}"],
            ["Mean time to first block (ms)", "never blocked", g["per_attack"]["prohibited_tool"]["t_first_block_ms"]],
            ["Mean time to quarantine, persistent attacker (s)", "never", g["per_attack"]["injection_stubborn"]["t_quarantine_s"]],
        ], columns=["Metric", "Baseline", "AgentGuard"]).astype(str).set_index("Metric"))
        pa = pd.DataFrame({"baseline": {k: v["attack_success_rate"] for k, v in b["per_attack"].items()},
                           "AgentGuard": {k: v["attack_success_rate"] for k, v in g["per_attack"].items()}})
        st.subheader("Attack success rate by attack type")
        st.bar_chart(pa)
        if "ablation" in r:
            st.subheader("What each layer adds (ablation)")
            ab = pd.DataFrame(r["ablation"]).T
            ab.columns = ["Harvesting attack success", "Records harvested", "PII-report safe completion", "Wrong-case safe completion"]
            st.table(ab)
            st.caption("Policy alone cannot see a harvesting pattern made of individually permitted calls (the ML layer can). "
                       "Without the corrective loop, blocked agents cannot finish their legitimate work.")
        if "ml_offline" in r:
            st.caption(f"ML offline check — hold-out false positives {r['ml_offline']['holdout_fp_rate']:.2%}; "
                       f"synthetic harvesting flagged {r['ml_offline']['synthetic_anomaly_recall']:.0%} "
                       "(synthetic anomalies are blatant; real-world recall is unknown).")
