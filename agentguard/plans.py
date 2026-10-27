"""Benign work plans and argument builders, shared by the scripted agents and the ML trace generator.
Using ONE code path guarantees the model is trained on the same shapes it will see at runtime."""
import hashlib
import random

import config
import pii

FILLER = ["Domain registration checked.", "Link confirmed as fraudulent.", "Citizen contacted by the entity.",
          "Takedown request prepared.", "Related complaints correlated.", "Screenshot archived.",
          "Registrar notified.", "No payment was made by the citizen."]
SEARCH_TERMS = ["phishing", "fake domain", "sms scam", "impersonation", "fake payment page"]


def sample_plan(rng: random.Random, task_type: str = "investigate_case"):
    """A plan is a list of (kind, param)."""
    if task_type == "summarize_case":
        return [("read", None), ("report", None)]
    r = rng.random()
    if r < 0.35:
        return [("read", None), ("search", 3), ("report", None)]
    if r < 0.60:
        return [("read", None), ("search", 2), ("search", 5), ("report", None)]
    if r < 0.75:
        return [("read", None), ("report", None)]
    if r < 0.95:
        return [("read", None), ("search", 3), ("upload", None), ("report", None)]
    return [("read", None), ("search", 2), ("read", None), ("report", None)]


def build_args(kind: str, param, ctx: dict, rng: random.Random):
    """Return (tool, args) for a plan step. ctx: {'case_id','case' (dict|None),'hits' (int)}"""
    cid = ctx["case_id"]
    case = ctx.get("case") or {}
    if kind == "read":
        return "read_case", {"case_id": cid}
    if kind == "search":
        return "search_evidence", {"query": rng.choice(SEARCH_TERMS), "max_results": param}
    if kind == "upload":
        digest = hashlib.sha1(f"{cid}{case.get('status','')}".encode()).hexdigest()[:12]
        data = pii.sanitize({"case_id": cid, "status": case.get("status", "unknown"),
                             "evidence_digest": digest,
                             "summary": (case.get("document") or "")[:160]})
        return "upload_evidence", {"url": config.APPROVED_EVIDENCE_URL, "data": data}
    if kind == "report":
        content = (f"Findings for {cid}: status={case.get('status','unknown')}; "
                   f"{ctx.get('hits', 0)} related records reviewed; no personal data included.")
        if rng.random() < 0.85:  # real reports vary in length
            content = content[:rng.choice([30, 60, len(content)])] if rng.random() < 0.3 else content
            content += " " + " ".join(rng.sample(FILLER, rng.randint(0, 5)))
        return "create_report", {"case_id": cid, "content": content}
    raise ValueError(kind)


def random_walk_plan(rng: random.Random):
    """A benign plan in an UNUSUAL order (agents legitimately work in different orders, and corrected
    actions often start from a different point). Only used to make the ML training data realistic."""
    kinds = [("read", None), ("search", rng.choice([2, 3, 5])), ("upload", None), ("report", None)]
    steps = [rng.choice(kinds) for _ in range(rng.randint(1, 5))]
    if rng.random() < 0.8:
        steps.append(("report", None))
    return steps
