"""Deterministic policy engine. Runs FIRST on every action; a deny here is final."""
import json
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlparse

import yaml

import config
import pii


@dataclass
class Verdict:
    allow: bool
    code: str | None = None
    reason: str | None = None  # full internal reason -> audit log only, never sent to the agent


@lru_cache(maxsize=1)
def rules() -> dict:
    return yaml.safe_load(config.POLICIES_FILE.read_text())


def evaluate(claims: dict, task, tool: str, args: dict) -> Verdict:
    r = rules()
    if tool in r["prohibited_tools"]:
        return Verdict(False, "PROHIBITED_TOOL", f"Tool '{tool}' is prohibited for all agents.")
    if tool not in claims["tools"]:
        return Verdict(False, "OUT_OF_SCOPE_TOOL",
                       f"Tool '{tool}' is not part of task '{claims['task_type']}'.")
    if task["calls_used"] >= task["max_calls"]:
        return Verdict(False, "BUDGET", f"Call budget of {task['max_calls']} exhausted for this task.")
    if "case_id" in args and args["case_id"] != claims["case_id"]:
        return Verdict(False, "WRONG_CASE",
                       f"Task is scoped to {claims['case_id']} but the action targets {args['case_id']}.")
    if tool == "upload_evidence":
        host = urlparse(str(args.get("url", ""))).hostname or ""
        if host not in r["approved_destinations"]:
            return Verdict(False, "EXTERNAL_DESTINATION",
                           f"Unauthorized transfer of case data to non-approved destination '{host or 'unknown'}'.")
    if tool in r["sensitive_scan_tools"]:
        hits = pii.count_sensitive(json.dumps(args, default=str))
        if hits:
            return Verdict(False, "SENSITIVE_DATA",
                           f"Action payload contains {hits} personal identifier(s) (Emirates ID / phone).")
    if tool == "search_evidence" and int(args.get("max_results", 5)) > r["max_records_per_call"]:
        return Verdict(False, "VOLUME_LIMIT",
                       f"Requested more than {r['max_records_per_call']} records in one call.")
    return Verdict(True)
