"""Generate SYNTHETIC benign traces (no public dataset matches our tool/action format).

Each row = one tool call from a simulated benign task. Uses the SAME plan sampler and argument
builders as the real scripted agents, so the training data has the same shape as live traffic.
Run:  python -m ml.make_traces
"""
import random

import pandas as pd
from faker import Faker

import config
import plans
import seed
from gateway import features

N_TASKS = 2500


def _dt(rng: random.Random) -> float:
    r = rng.random()
    if r < 0.82:   # normal agent "thinking time" + network overhead
        return rng.uniform(config.THINK_MIN, config.THINK_MAX) + rng.uniform(0.005, 0.05)
    if r < 0.95:   # a bit slower (e.g. retries after a corrective LLM call)
        return rng.uniform(0.4, 1.0)
    return 1.0     # long pause (clipped)


def generate(n_tasks: int = N_TASKS, seed_value: int = 7) -> pd.DataFrame:
    rng = random.Random(seed_value)
    Faker.seed(seed_value)
    fake = Faker("en_US")
    rows = []
    for _ in range(n_tasks):
        cid = rng.randint(1, 100)
        task_type = "summarize_case" if rng.random() < 0.2 else "investigate_case"
        ctx = {"case_id": seed.case_id(cid), "case": seed.make_case(cid, rng, fake), "hits": 0}
        prev, calls, recs = "START", 0, 0
        plan = (plans.random_walk_plan(rng) if (task_type == "investigate_case" and rng.random() < 0.4)
                else plans.sample_plan(rng, task_type))
        for kind, param in plan:
            tool, args = plans.build_args(kind, param, ctx, rng)
            req = features.requested_records(tool, args)
            rows.append({"tool": tool, "prev_tool": prev, "calls_so_far": calls, "dt": min(_dt(rng), features.DT_CLIP),
                         "records_so_far": recs, "requested": req, "payload_len": features.payload_len(args)})
            if tool == "search_evidence":
                ctx["hits"] = req
            prev, calls, recs = tool, calls + 1, recs + req
    return pd.DataFrame(rows)


if __name__ == "__main__":
    df = generate()
    config.DATA_DIR.mkdir(exist_ok=True)
    df.to_csv(config.TRACES_PATH, index=False)
    print(f"wrote {len(df)} benign call rows from {N_TASKS} simulated tasks -> {config.TRACES_PATH}")
