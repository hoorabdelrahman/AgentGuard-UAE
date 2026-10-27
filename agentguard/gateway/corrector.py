"""Corrective LLM: after a denial/hold, explain the problem and propose a safer alternative.

SAFETY DESIGN
* The LLM's output is an UNTRUSTED suggestion. Arguments are always rebuilt by deterministic code
  (build_action), so the LLM can never smuggle a new destination, case id or personal data through.
* The agent gets a one-line hint only. The longer explanation goes to the audit log.
* If the LLM is off/slow/invalid, a rule table produces the same kind of answer instantly.
"""
import hashlib
import json
import time

import config
import pii
import runtime
from gateway import llm

HINTS = {
    "EXTERNAL_DESTINATION": "Case data may only be stored in the approved evidence store. Retry there, without unnecessary personal data.",
    "SENSITIVE_DATA": "Remove personal identifiers from the payload and retry.",
    "WRONG_CASE": "This task is limited to its assigned case.",
    "PROHIBITED_TOOL": "That action is not permitted. Use a permitted tool for this task.",
    "OUT_OF_SCOPE_TOOL": "That tool is not part of this task. Use a permitted tool.",
    "VOLUME_LIMIT": "Request fewer records per call.",
    "ML_ANOMALY": "Unusual activity pattern detected. Narrow the request and retry.",
    "ML_HOLD": "Action held for review because of an unusual pattern. Narrow the request and retry.",
    "BUDGET": "The call budget for this task is used up. A human will take over.",
}


def build_action(target_tool: str, orig_args: dict, claims: dict) -> dict | None:
    """Deterministically build SAFE arguments for the target tool."""
    case = claims["case_id"]
    if target_tool == "create_report":
        content = pii.redact_text(str(orig_args.get("content") or f"Sanitized summary prepared for {case}."))
        return {"tool": "create_report", "args": {"case_id": case, "content": content[:600]}}
    if target_tool == "upload_evidence":
        # A compact evidence package: identifiers and free text are NOT forwarded, only a digest of what was attempted.
        orig = orig_args.get("data") if isinstance(orig_args.get("data"), dict) else {}
        digest = hashlib.sha1(json.dumps(orig, sort_keys=True, default=str).encode()).hexdigest()[:12]
        data = {"case_id": case, "status": str(orig.get("status", "unknown")), "evidence_digest": digest,
                "summary": "Sanitized evidence package; personal identifiers and free text removed."}
        return {"tool": "upload_evidence", "args": {"url": config.APPROVED_EVIDENCE_URL, "data": data}}
    if target_tool == "read_case":
        return {"tool": "read_case", "args": {"case_id": case}}
    if target_tool == "search_evidence":
        return {"tool": "search_evidence", "args": {"query": str(orig_args.get("query", ""))[:40], "max_results": 3}}
    return None


def _rule_target(code: str, tool: str, allowed: list) -> str | None:
    if code == "EXTERNAL_DESTINATION":
        return "upload_evidence"
    if code == "SENSITIVE_DATA":
        return tool if tool in ("create_report", "upload_evidence") else "create_report"
    if code == "WRONG_CASE":
        return tool if tool in ("read_case", "create_report") else "read_case"
    if code in ("PROHIBITED_TOOL", "OUT_OF_SCOPE_TOOL"):
        return "create_report" if "create_report" in allowed else None
    if code in ("VOLUME_LIMIT", "ML_ANOMALY", "ML_HOLD"):
        return "search_evidence" if tool == "search_evidence" else None
    return None  # BUDGET etc: nothing safe to try -> escalate to a human


SYSTEM = ("You are a security assistant inside a government AI-agent gateway. An agent action was blocked. "
          "Reply with JSON only: {\"explanation\": \"<=2 sentences for the audit log, no personal data\", "
          "\"safe_tool\": \"<one tool name from allowed_tools that achieves the task safely, or null>\"}.")


def suggest(claims: dict, tool: str, args: dict, code: str, reason: str) -> dict:
    t0 = time.perf_counter()
    allowed = list(claims["tools"])
    target = _rule_target(code, tool, allowed)
    hint = HINTS.get(code, "Action blocked. Use a permitted alternative.")
    explanation, source = reason, "rules"

    if runtime.STATE["corrector_enabled"] and llm.enabled():
        prompt = (f"violation_code: {code}\ntool_attempted: {tool}\nallowed_tools: {allowed}\n"
                  f"task: {claims['task_type']}\naction (redacted): {str(pii.sanitize(args))[:300]}")
        out = llm.chat_json(SYSTEM, prompt)
        if out:
            exp = str(out.get("explanation", ""))[:300]
            st = out.get("safe_tool")
            if exp and not pii.count_sensitive(exp):
                explanation, source = exp, "llm"
            if st in allowed and st not in ("export_all", "delete_case") and st != target:
                target = st  # accepted only because it is on the task's allowed list

    suggestion = build_action(target, args, claims) if target else None
    if suggestion and suggestion["tool"] not in allowed:
        suggestion = None
    return {"hint": hint, "suggestion": suggestion, "explanation": explanation, "source": source,
            "ms": round((time.perf_counter() - t0) * 1000, 1)}
