"""One-time setup: create tables, seed fake cases, create agent keys + registry, train the ML model.
Run:  python -m scripts.init_db            (add --reset to wipe and rebuild everything)
"""
import argparse

import config
import db
import seed
from ml import make_traces, train


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reset", action="store_true", help="delete the existing database first")
    ap.add_argument("--retrain", action="store_true", help="regenerate traces and retrain the ML model")
    a = ap.parse_args()

    if a.reset and config.DB_PATH.exists():
        for suffix in ("", "-wal", "-shm"):
            p = config.DB_PATH.with_name(config.DB_PATH.name + suffix)
            p.unlink(missing_ok=True)
        print("old database removed")

    db.init_schema()
    with db.session() as conn:
        seed.seed_cases(conn)
        seed.register_agents(conn)
    print(f"database ready at {config.DB_PATH}")
    print(f"agents registered; private keys are in {config.KEYS_DIR}/ (public keys are in the registry)")

    if a.retrain or not config.MODEL_PATH.exists():
        df = make_traces.generate()
        config.DATA_DIR.mkdir(exist_ok=True)
        df.to_csv(config.TRACES_PATH, index=False)
        print(f"generated {len(df)} synthetic benign call rows")
        train.main()
    else:
        print("ML model already exists (use --retrain to rebuild)")
    print("\nSetup complete. Next: uvicorn gateway.main:app --port 8000")


if __name__ == "__main__":
    main()
