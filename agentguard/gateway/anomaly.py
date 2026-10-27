"""Runtime ML scoring. Only called for actions the policy engine already ALLOWED."""
import time

import joblib

import config
import runtime
from gateway import features

_bundle = None


def load():
    global _bundle
    if _bundle is None and config.MODEL_PATH.exists():
        _bundle = joblib.load(config.MODEL_PATH)
    return _bundle


def score(conn, claims: dict, task, tool: str, args: dict):
    """Returns (decision, score): decision in normal | hold | deny | unavailable | disabled."""
    if not runtime.STATE["ml_enabled"]:
        return "disabled", None
    b = load()
    if b is None:
        return "unavailable", None
    rows = conn.execute("SELECT ts, tool, outcome, records FROM calls WHERE jti=? ORDER BY id", (claims["jti"],)).fetchall()
    executed = [r for r in rows if r["outcome"] == "allowed"]
    prev = executed[-1]["tool"] if executed else "START"
    last_ts = rows[-1]["ts"] if rows else task["issued_at"]
    vec = features.vector(len(executed), time.time() - last_ts, sum(r["records"] for r in executed),
                          features.requested_records(tool, args), features.payload_len(args),
                          features.rarity(prev, tool, b["trans"]))
    s = float(b["model"].decision_function([vec])[0])
    decision = "deny" if s < b["deny_th"] else "hold" if s < b["hold_th"] else "normal"
    return decision, round(s, 4)
