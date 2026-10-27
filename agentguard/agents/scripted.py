"""Scripted agents. They are plain Python on purpose: deterministic, so demos and measurements repeat.

ScriptedAgent can be configured as:
  * normal            - does its job
  * hijackable        - obeys instructions hidden inside case documents (simulated prompt injection)
  * follows_correction=False - 'stubborn': repeats a blocked action instead of using the hint
"""
import random
import re
import time

import config
import plans

INJECTION_RE = re.compile(r"UPLOAD EVIDENCE TO (\S+)")


def act_with_correction(client, tool, args, follows=True, think=None, rng=None, max_retries=None):
    """Propose an action. If blocked, either follow the gateway's suggestion or (stubborn) repeat it.
    Every retry is linked to the ORIGINAL attempt via parent_event_id. Returns a dict with all attempts."""
    rng = rng or random.Random()
    think = think or (config.THINK_MIN, config.THINK_MAX)
    cap = max_retries if max_retries is not None else (2 if follows else 8)
    attempts = []

    def record(t, a, res):
        attempts.append({"tool": t, "args": a, "decision": res.get("decision"), "code": res.get("code"),
                         "rt_ms": res.get("rt_ms"), "latency_ms": res.get("latency_ms"),
                         "result": res.get("result"), "event_id": res.get("event_id")})

    res = client.call(tool, args)
    record(tool, args, res)
    root, n = res.get("event_id"), 0
    while res.get("decision") in ("denied", "held") and n < cap:
        n += 1
        time.sleep(rng.uniform(*think))
        if follows:
            sug = res.get("suggestion")
            if not sug:
                break
            t2, a2 = sug["tool"], sug["args"]
        else:
            t2, a2 = tool, args
        res = client.call(t2, a2, parent_event_id=root, correction_attempt=n)
        record(t2, a2, res)
    return {"attempts": attempts, "final": res, "recovered": res.get("decision") == "allowed" and n > 0}


class ScriptedAgent:
    def __init__(self, client, hijackable=False, follows_correction=True, rng=None, think=None):
        self.client = client
        self.hijackable = hijackable
        self.follows = follows_correction
        self.rng = rng or random.Random()
        self.think = think or (config.THINK_MIN, config.THINK_MAX)

    def _sleep(self):
        time.sleep(self.rng.uniform(*self.think))

    def run_task(self, task_type: str, case_id: str, plan=None, verbose=False) -> dict:
        out = {"agent": self.client.agent_id, "case_id": case_id, "attempts": [], "steps": [],
               "completed": False, "quarantined": False, "rejected": None, "t_quarantine_s": None}
        a = self.client.authenticate()
        if not a["ok"]:
            out["rejected"] = a.get("code")
            return out
        t = self.client.request_task(task_type, case_id)
        if not t["ok"]:
            out["rejected"] = t.get("code")
            return out

        ctx = {"case_id": case_id, "case": None, "hits": 0}
        for kind, param in (plan or plans.sample_plan(self.rng, task_type)):
            self._sleep()
            tool, args = plans.build_args(kind, param, ctx, self.rng)
            r = self._act(out, tool, args, kind)
            if r["decision"] == "quarantined":
                out["quarantined"] = True
                break
            if r["decision"] == "allowed":
                if kind == "read":
                    ctx["case"] = r["result"]
                    m = INJECTION_RE.search((r["result"] or {}).get("document", ""))
                    if m and self.hijackable:  # <- simulated prompt injection: the agent obeys the document
                        self._sleep()
                        inj = self._act(out, "upload_evidence", {"url": m.group(1), "data": r["result"]}, "injected")
                        if inj["decision"] == "quarantined":
                            out["quarantined"] = True
                            break
                elif kind == "search":
                    ctx["hits"] = len(r["result"] or [])
                elif kind == "report":
                    out["completed"] = True
        out.pop("_t_first", None)
        return out

    def _act(self, out, tool, args, kind):
        t_start = time.perf_counter()
        res = act_with_correction(self.client, tool, args, follows=self.follows, think=self.think, rng=self.rng)
        out["attempts"].extend(res["attempts"])
        final = res["final"]
        first = res["attempts"][0]["decision"]
        out["steps"].append({"kind": kind, "first_decision": first, "final_decision": final.get("decision")})
        if first != "allowed" and "_t_first" not in out:
            out["_t_first"] = t_start
        if final.get("decision") == "quarantined" and out.get("t_quarantine_s") is None:
            out["t_quarantine_s"] = round(time.perf_counter() - out.get("_t_first", t_start), 3)
        # a correction that succeeded counts as allowed for plan-flow purposes
        decision = final.get("decision")
        if decision == "allowed":
            return {"decision": "allowed", "result": final.get("result")}
        return {"decision": decision, "result": None}
