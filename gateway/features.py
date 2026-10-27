"""Feature extraction shared by training (ml/) and runtime (gateway/anomaly.py)."""
import json
import math

FEATURES = ["calls_so_far", "dt", "records_so_far", "requested", "payload_len", "rarity"]
TOOLS = ["read_case", "search_evidence", "create_report", "upload_evidence", "export_all", "delete_case"]
DT_CLIP = 1.0  # long pauses all look the same ("slow"); only unusually FAST bursts matter


def requested_records(tool: str, args: dict) -> int:
    if tool == "search_evidence":
        try:
            return max(0, min(int(args.get("max_results", 5)), 1000))
        except (TypeError, ValueError):
            return 0
    return 1 if tool == "read_case" else 0


def payload_len(args: dict) -> int:
    return min(len(json.dumps(args, default=str)), 5000)


def rarity(prev: str, tool: str, trans: dict) -> float:
    """-log P(prev -> tool) learned from benign traces, Laplace-smoothed. High = unusual sequence."""
    n = trans["counts"].get(prev, {}).get(tool, 0)
    tot = trans["totals"].get(prev, 0)
    return -math.log((n + 1) / (tot + len(TOOLS)))


def vector(calls_so_far, dt, records_so_far, requested, plen, rar):
    return [float(calls_so_far), float(min(dt, DT_CLIP)), float(records_so_far),
            float(requested), float(plen), float(rar)]
