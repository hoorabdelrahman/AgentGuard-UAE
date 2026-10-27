"""Baseline vs AgentGuard evaluation on SIMULATED traces. Produces the numbers for the pitch.

  python -m evaluation.run_eval                      # default: 40 benign tasks, 5 reps per attack
  python -m evaluation.run_eval --benign 20 --reps 3 # faster
Output: data/eval_results.json and data/eval_results.csv  (the dashboard 'Compare' tab reads the JSON)
WARNING: resets the demo database (audit log included) first. Run `python -m scenarios.run_all` afterwards
         if you want a fresh, clean log for the live demo.
"""
import argparse
import csv
import json
import random
import time

import httpx
import joblib
import numpy as np

import config
from agents.client import admin
from gateway import features  # noqa: F401
from scenarios import attacks

ATTACKS = [("injection_corrected", lambda m, r: attacks.injection(m, follows=True, rng=r)),
           ("injection_stubborn", lambda m, r: attacks.injection(m, agent_id="agent_03", case="CASE-0045", follows=False, rng=r)),
           ("wrong_case", lambda m, r: attacks.wrong_case(m, rng=r)),
           ("prohibited_tool", lambda m, r: attacks.prohibited_tool(m, rng=r)),
           ("pii_in_report", lambda m, r: attacks.pii_report(m, rng=r)),
           ("harvesting", lambda m, r: attacks.harvest(m, rng=r))]
BENIGN_AGENTS = [("agent_01", "investigate_case"), ("agent_02", "summarize_case"),
                 ("agent_03", "investigate_case"), ("agent_04", "investigate_case")]


def pct(xs, p):
    return round(float(np.percentile(xs, p)), 2) if xs else None


def mean(xs):
    xs = [x for x in xs if x is not None]
    return round(float(np.mean(xs)), 3) if xs else None


def release_all():
    for a in ("agent_01", "agent_02", "agent_03", "agent_04"):
        admin(f"/admin/release/{a}")


def run_benign(mode, n, seed):
    rng = random.Random(seed)
    rts, fp_tasks, fp_actions, total_actions, completed, quarantined = [], 0, 0, 0, 0, 0
    for _ in range(n):
        agent, ttype = rng.choice(BENIGN_AGENTS)
        case = rng.choice([i for i in range(1, 101) if i not in (7, 45)])
        out = attacks.benign(mode, agent, ttype, f"CASE-{case:04d}", rng=rng)
        steps = out["steps"]
        total_actions += len(steps)
        bad = [s for s in steps if s["first_decision"] != "allowed"]
        fp_actions += len(bad)
        fp_tasks += 1 if bad or out["rejected"] else 0
        completed += 1 if out["completed"] else 0
        if out["quarantined"]:
            quarantined += 1
            release_all()
        rts += [a["rt_ms"] for a in out["attempts"] if a["decision"] == "allowed"]
    return {"tasks": n, "task_completion_rate": round(completed / n, 3),
            "false_positive_rate_tasks": round(fp_tasks / n, 3),
            "false_positive_rate_actions": round(fp_actions / max(1, total_actions), 4),
            "agents_wrongly_quarantined": quarantined,
            "roundtrip_ms_p50": pct(rts, 50), "roundtrip_ms_p95": pct(rts, 95)}


def run_attacks(mode, reps, seed):
    rng = random.Random(seed)
    per = {}
    for name, fn in ATTACKS:
        runs = []
        for _ in range(reps):
            runs.append(fn(mode, rng))
            if mode == "guard":
                release_all()
        per[name] = {
            "runs": reps,
            "attack_success_rate": mean([1.0 if r["harm"] else 0.0 for r in runs]),
            "records_exposed_mean": mean([r["records_exposed"] for r in runs]),
            "blocked_rate": mean([1.0 if r["blocked"] else 0.0 for r in runs]),
            "quarantine_rate": mean([1.0 if r["quarantined"] else 0.0 for r in runs]),
            "safe_completion_rate": mean([1.0 if (r["completed"] and not r["harm"]) else 0.0 for r in runs]),
            "t_first_block_ms": mean([r["t_first_block_ms"] for r in runs]),
            "t_quarantine_s": mean([r["t_quarantine_s"] for r in runs]),
        }
    overall = mean([v["attack_success_rate"] for v in per.values()])
    return {"per_attack": per, "overall_attack_success_rate": overall}


def run_ablation(reps, seed):
    cfgs = [("policy_only", False, False), ("policy_plus_ml", True, False), ("full_agentguard", True, True)]
    out = {}
    for name, ml, corr in cfgs:
        admin("/admin/config", json={"ml_enabled": ml, "corrector_enabled": corr})
        rng = random.Random(seed)
        h = [attacks.harvest("guard", rng=rng) for _ in range(reps) if not release_all()]
        p = [attacks.pii_report("guard", rng=rng) for _ in range(reps)]
        w = [attacks.wrong_case("guard", rng=rng) for _ in range(reps)]
        release_all()
        out[name] = {"harvesting_attack_success_rate": mean([1.0 if r["harm"] else 0.0 for r in h]),
                     "harvest_records_exposed_mean": mean([r["records_exposed"] for r in h]),
                     "pii_report_safe_completion_rate": mean([1.0 if (r["completed"] and not r["harm"]) else 0.0 for r in p]),
                     "wrong_case_safe_completion_rate": mean([1.0 if (r["completed"] and not r["harm"]) else 0.0 for r in w])}
    admin("/admin/config", json={"ml_enabled": True, "corrector_enabled": True})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", type=int, default=40)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--skip-ablation", action="store_true")
    a = ap.parse_args()
    httpx.get(config.GATEWAY_URL + "/health", timeout=5)
    admin("/admin/reset")
    t_start = time.time()
    res = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "benign_tasks": a.benign, "reps_per_attack": a.reps,
           "note": "All results measured on SIMULATED agents, cases and attacks (scripted, deterministic)."}

    print("1/5 baseline (shared static key) ...")
    res["baseline"] = {"benign": run_benign("baseline", a.benign, a.seed), **run_attacks("baseline", a.reps, a.seed)}
    res["baseline"]["credential_abuse_accepted"] = sum(c["accepted"] for c in attacks.credential_attacks("baseline"))
    ok, n = attacks.tools_reachable("baseline")
    res["baseline"]["tools_executable_in_one_session"] = f"{ok}/{n}"
    admin("/admin/reset")

    print("2/5 AgentGuard ...")
    res["guard"] = {"benign": run_benign("guard", a.benign, a.seed), **run_attacks("guard", a.reps, a.seed)}
    cred = attacks.credential_attacks("guard")
    res["guard"]["credential_abuse_accepted"] = sum(c["accepted"] for c in cred)
    res["credential_tests"] = [c["name"] for c in cred]
    release_all()
    ok, n = attacks.tools_reachable("guard")
    res["guard"]["tools_executable_in_one_session"] = f"{ok}/{n}"
    release_all()

    ev = httpx.get(config.GATEWAY_URL + "/audit/events?limit=5000").json()
    acts = [e for e in ev if e.get("event_type") == "ACTION" and e.get("final_decision") != "rejected"]
    res["guard"]["actions_tied_to_verified_agent_pct"] = round(100 * sum(1 for e in acts if e.get("agent_id") not in (None, "unknown")) / max(1, len(acts)), 1)
    res["baseline"]["actions_tied_to_verified_agent_pct"] = 0.0
    res["guard"]["audit_chain"] = httpx.get(config.GATEWAY_URL + "/audit/verify").json()
    res["guard"]["server_report"] = httpx.get(config.GATEWAY_URL + "/report/ask?q=full_summary").json()["facts"]

    b, g = res["baseline"]["benign"], res["guard"]["benign"]
    res["latency"] = {"baseline_p50_ms": b["roundtrip_ms_p50"], "guard_p50_ms": g["roundtrip_ms_p50"],
                      "added_p50_ms": round(g["roundtrip_ms_p50"] - b["roundtrip_ms_p50"], 2),
                      "baseline_p95_ms": b["roundtrip_ms_p95"], "guard_p95_ms": g["roundtrip_ms_p95"],
                      "added_p95_ms": round(g["roundtrip_ms_p95"] - b["roundtrip_ms_p95"], 2),
                      "note": "client-side round trip per allowed action, localhost, includes audit write"}

    if not a.skip_ablation:
        print("3/5 ablation (policy only -> +ML -> +corrective LLM loop) ...")
        res["ablation"] = run_ablation(max(3, a.reps // 2 + 1), a.seed)
    try:
        res["ml_offline"] = joblib.load(config.MODEL_PATH)["report"]
    except Exception:
        pass
    res["privilege_window"] = {"baseline": "until the shared key is rotated (no expiry)",
                               "guard": "task token: 600-900 s, one task, one case"}
    res["runtime_s"] = round(time.time() - t_start, 1)

    (config.DATA_DIR / "eval_results.json").write_text(json.dumps(res, indent=2))
    with open(config.DATA_DIR / "eval_results.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["attack", "mode", "attack_success_rate", "records_exposed_mean", "safe_completion_rate",
                    "blocked_rate", "quarantine_rate", "t_first_block_ms", "t_quarantine_s"])
        for mode in ("baseline", "guard"):
            for name, v in res[mode]["per_attack"].items():
                w.writerow([name, mode, v["attack_success_rate"], v["records_exposed_mean"], v["safe_completion_rate"],
                            v["blocked_rate"], v["quarantine_rate"], v["t_first_block_ms"], v["t_quarantine_s"]])
    print_summary(res)


def print_summary(r):
    b, g = r["baseline"], r["guard"]
    print("\n================ RESULTS (simulated traces) ================")
    print(f"{'metric':<52}{'baseline':>12}{'AgentGuard':>14}")
    rows = [("credential-abuse attempts accepted (of 5)", b["credential_abuse_accepted"], g["credential_abuse_accepted"]),
            ("tools one session can execute (of 6)", b["tools_executable_in_one_session"], g["tools_executable_in_one_session"]),
            ("actions tied to a verified agent (%)", b["actions_tied_to_verified_agent_pct"], g["actions_tied_to_verified_agent_pct"]),
            ("overall attack success rate", b["overall_attack_success_rate"], g["overall_attack_success_rate"]),
            ("benign task completion rate", b["benign"]["task_completion_rate"], g["benign"]["task_completion_rate"]),
            ("false-positive rate (benign actions blocked)", "n/a", g["benign"]["false_positive_rate_actions"]),
            ("added latency p50 / p95 (ms)", "-", f"{r['latency']['added_p50_ms']} / {r['latency']['added_p95_ms']}")]
    for m, x, y in rows:
        print(f"{m:<52}{str(x):>12}{str(y):>14}")
    print("\nper attack (success rate | records exposed | safe completion):")
    for name in b["per_attack"]:
        bb, gg = b["per_attack"][name], g["per_attack"][name]
        print(f"  {name:<22} baseline {bb['attack_success_rate']:.2f} | {bb['records_exposed_mean']:>6} | {bb['safe_completion_rate']:.2f}"
              f"    guard {gg['attack_success_rate']:.2f} | {gg['records_exposed_mean']:>6} | {gg['safe_completion_rate']:.2f}"
              f"   t_block={gg['t_first_block_ms']} ms  t_quarantine={gg['t_quarantine_s']} s")
    if "ablation" in r:
        print("\nablation:", json.dumps(r["ablation"], indent=1))
    print(f"\nsaved data/eval_results.json (+csv). runtime {r['runtime_s']} s")


if __name__ == "__main__":
    main()
