"""Quarantine: freeze the agent, revoke its tokens, hand the task to a human / backup agent."""
import time

from gateway import audit


def run(conn, claims: dict, reason: str, trigger_event_id: str | None = None):
    agent_id, jti = claims["agent_id"], claims["jti"]
    conn.execute("UPDATE agents SET status='quarantined' WHERE agent_id=?", (agent_id,))
    conn.execute("UPDATE task_tokens SET status='revoked' WHERE agent_id=? AND status='active'", (agent_id,))
    conn.execute("INSERT INTO quarantine_events (agent_id, jti, reason, ts) VALUES (?,?,?,?)",
                 (agent_id, jti, reason, time.time()))
    conn.execute("INSERT INTO human_queue (kind,jti,agent_id,case_id,task_type,reason,status,ts) "
                 "VALUES ('reassigned',?,?,?,?,?,'pending',?)",
                 (jti, agent_id, claims["case_id"], claims["task_type"], reason, time.time()))
    audit.append(conn, "QUARANTINE", agent_id=agent_id, jti=jti, case_id=claims["case_id"],
                 reason=reason, trigger_event_id=trigger_event_id,
                 action_taken="agent frozen; all tokens revoked; task reassigned to human queue / backup agent")
