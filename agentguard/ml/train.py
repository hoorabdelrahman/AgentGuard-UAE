"""Train the anomaly detector on BENIGN traces only (unsupervised) and pick thresholds.

Model: kNN-distance detector (ml/detector.py). We first tried Isolation Forest and Local Outlier Factor;
Isolation Forest scored harvesting like rare-but-benign behaviour and LOF was numerically unstable on
duplicate rows (see README, "Design notes").
Run:  python -m ml.train
"""
import random

import joblib
import numpy as np
import pandas as pd

import config
from gateway import features
from ml import make_traces
from ml.detector import KnnDetector


def build_transitions(df: pd.DataFrame) -> dict:
    counts, totals = {}, {}
    for prev, tool in zip(df["prev_tool"], df["tool"]):
        counts.setdefault(prev, {}).setdefault(tool, 0)
        counts[prev][tool] += 1
        totals[prev] = totals.get(prev, 0) + 1
    return {"counts": counts, "totals": totals}


def to_matrix(df: pd.DataFrame, trans: dict) -> np.ndarray:
    rows = [features.vector(r.calls_so_far, r.dt, r.records_so_far, r.requested, r.payload_len,
                            features.rarity(r.prev_tool, r.tool, trans)) for r in df.itertuples()]
    return np.array(rows)


def synthetic_anomalies(trans: dict, n: int = 400, seed_value: int = 3) -> np.ndarray:
    """Synthetic 'slow data harvesting' calls: big, fast, repeated searches. Used ONLY for evaluation."""
    rng = random.Random(seed_value)
    rows = []
    for _ in range(n):
        calls = rng.randint(0, 10)
        rows.append(features.vector(calls, rng.uniform(0.0, 0.08), calls * 20, rng.choice([20, 25]),
                                    rng.randint(40, 90), features.rarity("search_evidence", "search_evidence", trans)))
    return np.array(rows)


def main():
    if not config.TRACES_PATH.exists():
        df = make_traces.generate()
        config.DATA_DIR.mkdir(exist_ok=True)
        df.to_csv(config.TRACES_PATH, index=False)
    df = pd.read_csv(config.TRACES_PATH)
    trans = build_transitions(df)
    X = to_matrix(df, trans)

    rng = np.random.RandomState(0)
    idx = rng.permutation(len(X))
    cut = int(len(X) * 0.8)
    X_train, X_hold = X[idx[:cut]], X[idx[cut:]]

    model = KnnDetector(k=10).fit(X_train)
    hold_scores = model.decision_function(X_hold)           # calibrate on UNSEEN benign rows (unbiased)
    hold_th = float(np.percentile(hold_scores, 0.5))        # below this -> HOLD for human review
    deny_th = hold_th * 5 if hold_th < 0 else hold_th - 1.0  # far below -> DENY outright

    def decide(s):
        return "deny" if s < deny_th else "hold" if s < hold_th else "normal"

    fp = np.mean([decide(s) != "normal" for s in hold_scores])
    A = synthetic_anomalies(trans)
    a_scores = model.decision_function(A)
    tp = np.mean([decide(s) != "normal" for s in a_scores])
    print(f"benign rows: {len(df)} | hold-out false-positive rate: {fp:.2%}")
    print(f"synthetic harvesting anomalies flagged (hold or deny): {tp:.2%}")
    print(f"thresholds: hold < {hold_th:.3f}, deny < {deny_th:.3f}")

    joblib.dump({"model": model, "trans": trans, "hold_th": hold_th, "deny_th": deny_th,
                 "features": features.FEATURES,
                 "report": {"holdout_fp_rate": float(fp), "synthetic_anomaly_recall": float(tp),
                            "train_rows": int(cut), "holdout_rows": int(len(X_hold))}}, config.MODEL_PATH)
    print(f"saved model -> {config.MODEL_PATH}")


if __name__ == "__main__":
    main()
