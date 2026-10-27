"""Tamper-evident audit log: every row stores sha256(prev_hash + canonical_json(event))."""
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone

GENESIS = "GENESIS"


def new_event_id() -> str:
    return uuid.uuid4().hex[:12]


def canonical(event: dict) -> str:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def append(conn, event_type: str, **fields) -> dict:
    """Append one event. MUST be called while holding db.WRITE_LOCK."""
    now = time.time()
    event = {"event_id": fields.pop("event_id", None) or new_event_id(),
             "event_type": event_type, "t": round(now, 4),
             "ts": datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="milliseconds")}
    event.update({k: v for k, v in fields.items() if v is not None})
    row = conn.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev = row["hash"] if row else GENESIS
    body = canonical(event)
    digest = hashlib.sha256((prev + body).encode()).hexdigest()
    conn.execute("INSERT INTO audit (body, prev_hash, hash) VALUES (?,?,?)", (body, prev, digest))
    return event


def verify_chain(conn):
    """Walk the chain. Returns (ok, first_broken_row_id | None, rows_checked)."""
    prev = GENESIS
    n = 0
    for r in conn.execute("SELECT id, body, prev_hash, hash FROM audit ORDER BY id"):
        n += 1
        expected = hashlib.sha256((r["prev_hash"] + r["body"]).encode()).hexdigest()
        if r["prev_hash"] != prev or expected != r["hash"]:
            return False, r["id"], n
        prev = r["hash"]
    return True, None, n


def events(conn, limit: int = 500, newest_first: bool = True):
    order = "DESC" if newest_first else "ASC"
    rows = conn.execute(f"SELECT id, body FROM audit ORDER BY id {order} LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        try:
            e = json.loads(r["body"])
        except Exception:
            e = {"event_type": "CORRUPTED"}
        e["_row"] = r["id"]
        out.append(e)
    return out
