"""Audit LLM (retrospective). Facts are computed with plain Python/SQL over the audit log;
the LLM only PHRASES them. It cannot change records or add events."""
import json
from collections import Counter, defaultdict

import numpy as np

from gateway import audit, llm

VIOLATION = ("denied", "held")


def compute_stats(conn) -> dict:
    evs = audit.events(conn, limit=100000, newest_first=False)
    actions = [e for e in evs if e.get("event_type") == "ACTION"]
    by_agent, codes = Counter(), Counter()
    sens_blocked = 0
    for e in actions:
        if e.get("final_decision") in VIOLATION:
            by_agent[e.get("agent_id")] += 1
            codes[e.get("policy_code")] += 1
            sens_blocked += int(e.get("sensitive_hits_attempted", 0) or 0)

    roots = [e for e in actions if not e.get("parent_event_id") and e.get("final_decision") in VIOLATION]
    children = defaultdict(list)
    for e in actions:
        if e.get("parent_event_id"):
            children[e["parent_event_id"]].append(e)
    recovered, retries_needed = 0, []
    for r in roots:
        kids = sorted(children.get(r["event_id"], []), key=lambda k: k.get("correction_attempt", 0))
        win = next((k for k in kids if k.get("final_decision") == "allowed"), None)
        if win:
            recovered += 1
            retries_needed.append(win.get("correction_attempt", 1))
    stubborn = Counter()
    for r in roots:
        kids = children.get(r["event_id"], [])
        if sum(1 for k in kids if k.get("final_decision") in VIOLATION) >= 2:
            stubborn[r.get("agent_id")] += 1

    quars = [e for e in evs if e.get("event_type") == "QUARANTINE"]
    first_viol = {}
    for e in actions:
        if e.get("final_decision") in VIOLATION and e.get("jti") not in first_viol:
            first_viol[e["jti"]] = e["t"]
    ttc = [q["t"] - first_viol[q["jti"]] for q in quars if q.get("jti") in first_viol]
    lat = [e["latency_ms"] for e in actions if e.get("final_decision") == "allowed" and "latency_ms" in e]

    return {
        "events_total": len(evs),
        "actions_total": len(actions),
        "allowed": sum(e.get("final_decision") == "allowed" for e in actions),
        "denied": sum(e.get("final_decision") == "denied" for e in actions),
        "held": sum(e.get("final_decision") == "held" for e in actions),
        "rejected": sum(e.get("final_decision") == "rejected" for e in actions),
        "auth_failures": sum(e.get("event_type") == "AUTH_FAILED" for e in evs),
        "violations_by_agent": dict(by_agent.most_common()),
        "violation_codes": dict(codes.most_common()),
        "sensitive_identifiers_blocked": sens_blocked,
        "violation_chains": len(roots),
        "chains_recovered_by_correction": recovered,
        "correction_success_rate": round(recovered / len(roots), 3) if roots else None,
        "avg_retries_to_recover": round(float(np.mean(retries_needed)), 2) if retries_needed else None,
        "agents_repeating_after_correction": dict(stubborn),
        "quarantines": len(quars),
        "mean_time_to_quarantine_s": round(float(np.mean(ttc)), 3) if ttc else None,
        "latency_ms_p50": round(float(np.percentile(lat, 50)), 2) if lat else None,
        "latency_ms_p95": round(float(np.percentile(lat, 95)), 2) if lat else None,
    }


def _fmt(v):
    return "n/a" if v is None else v


def template_summary(s: dict) -> str:
    worst = next(iter(s["violations_by_agent"].items()), None)
    top_code = next(iter(s["violation_codes"].items()), None)
    lines = [
        f"The gateway processed {s['actions_total']} agent actions: {s['allowed']} allowed, {s['denied']} denied, "
        f"{s['held']} held for review and {s['rejected']} rejected at the credential check; "
        f"{s['auth_failures']} identity proofs failed.",
    ]
    if worst:
        lines.append(f"Most violations came from {worst[0]} ({worst[1]}); the most common violation was {top_code[0]} ({top_code[1]}).")
    lines.append(f"Self-correction recovered {s['chains_recovered_by_correction']} of {s['violation_chains']} blocked actions "
                 f"(success rate {_fmt(s['correction_success_rate'])}, average retries {_fmt(s['avg_retries_to_recover'])}).")
    lines.append(f"{s['quarantines']} agent(s) were quarantined; mean time from first violation to quarantine: "
                 f"{_fmt(s['mean_time_to_quarantine_s'])} s. {s['sensitive_identifiers_blocked']} personal identifiers were stopped from leaving.")
    lines.append(f"Gateway processing latency for allowed actions: p50 {_fmt(s['latency_ms_p50'])} ms, p95 {_fmt(s['latency_ms_p95'])} ms.")
    return " ".join(lines)


QUESTIONS = {
    "full_summary": "Summarize all incidents",
    "worst_agents": "Which agents have the most policy violations?",
    "common_violations": "Which unsafe behaviors recur most often?",
    "correction_success": "How often does self-correction succeed?",
    "repeat_offenders": "Which agents keep attempting prohibited actions after correction?",
    "recovery_effort": "How many retries and how much time does safe recovery need?",
}

SYSTEM = ("You are the audit analyst for a government AI-agent security gateway. Using ONLY the JSON facts given, "
          "answer in at most 6 plain sentences. Never invent events, agents or numbers. If a value is null, say it is unavailable.")


def answer(conn, qid: str) -> dict:
    s = compute_stats(conn)
    facts = {
        "full_summary": s,
        "worst_agents": {"violations_by_agent": s["violations_by_agent"]},
        "common_violations": {"violation_codes": s["violation_codes"]},
        "correction_success": {k: s[k] for k in ("violation_chains", "chains_recovered_by_correction", "correction_success_rate")},
        "repeat_offenders": {"agents_repeating_after_correction": s["agents_repeating_after_correction"], "quarantines": s["quarantines"]},
        "recovery_effort": {k: s[k] for k in ("avg_retries_to_recover", "mean_time_to_quarantine_s", "chains_recovered_by_correction")},
    }.get(qid, s)
    text = llm.chat(SYSTEM, f"Question: {QUESTIONS.get(qid, qid)}\nFacts: {json.dumps(facts)}") if llm.enabled() else None
    source = "llm" if text else "template"
    if not text:
        text = template_summary(s) if qid == "full_summary" else f"{QUESTIONS.get(qid, qid)} -> {json.dumps(facts)}"
    return {"question": QUESTIONS.get(qid, qid), "answer": text.strip(), "source": source, "facts": facts}
