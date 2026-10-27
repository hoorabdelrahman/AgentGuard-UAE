"""Detection and redaction of UAE-style personal identifiers."""
import json
import re

EID_RE = re.compile(r"784-\d{4}-\d{7}-\d")
PHONE_RE = re.compile(r"(?<!\d)(?:\+971|00971|0)\s?5\d{8}(?!\d)")
PII_KEYS = {"emirates_id", "phone", "citizen_name"}


def _text(obj) -> str:
    return obj if isinstance(obj, str) else json.dumps(obj, default=str, ensure_ascii=False)


def count_sensitive(obj) -> int:
    t = _text(obj)
    return len(EID_RE.findall(t)) + len(PHONE_RE.findall(t))


def unique_eids(obj) -> int:
    return len(set(EID_RE.findall(_text(obj))))


def redact_text(s: str) -> str:
    s = EID_RE.sub("784-****-*******-*", s)
    return PHONE_RE.sub("[phone-redacted]", s)


def sanitize(obj):
    """Drop PII fields and redact PII patterns in every string, recursively."""
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items() if k not in PII_KEYS}
    if isinstance(obj, list):
        return [sanitize(v) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj
