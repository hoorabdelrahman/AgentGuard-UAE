# AgentGuard UAE

A security gateway for government AI agents. It **verifies who each agent is, limits each agent to one task and one case,
blocks unsafe actions, helps the agent correct itself so the service keeps running, quarantines repeat offenders, and records
everything in a tamper-evident audit log** that an AI can summarise.

Everything here is a **hackathon proof of concept running on simulated agents and fake data**. All services used are free.

```
agent ──► /auth (Ed25519 challenge) ──► identity token
      ──► /tasks (task, case)       ──► task token (tools, case, budget, 15 min)
      ──► /call  ──► token check ─► POLICY ENGINE ─► ML ANOMALY DETECTOR ─► execute
                                        │ deny              │ hold/deny
                                        └──────────┬────────┘
                                         CORRECTIVE LLM (rules fallback)
                                                   │ safer action → agent retries → re-validated from the start
                                         repeated violations → QUARANTINE → human queue / backup agent
      every step ──► hash-chained AUDIT LOG ──► AUDIT LLM (summaries; facts computed in code)
```

## 1. Requirements
* Python **3.10 or newer** (check: `python --version`), any OS
* ~500 MB disk for packages. No GPU, no paid account, no internet needed after install (unless you enable a hosted free LLM).

## 2. Install (once)
```bash
cd agentguard
python -m venv venv
# macOS / Linux:        source venv/bin/activate
# Windows PowerShell:   venv\Scripts\Activate.ps1      (cmd.exe: venv\Scripts\activate.bat)
pip install -r requirements.txt

cp .env.example .env            # Windows: copy .env.example .env
# open .env and set GATEWAY_SECRET and ADMIN_KEY (see section 4)

python -m scripts.init_db       # creates the DB, fake cases, agent keys + registry, trains the ML model
```

## 3. Run (three terminals, each with the venv activated, all inside the `agentguard` folder)
| Terminal | Command | What it is |
|---|---|---|
| 1 | `uvicorn gateway.main:app --port 8000` | the gateway |
| 2 | `streamlit run dashboard/app.py` | dashboard (opens at http://localhost:8501) |
| 3 | `python -m scenarios.run_all` | runs scenarios S1–S10, prints PASS/FAIL |

Useful variations:
* `python -m scenarios.run_all --only S6` runs the main demo only.
* `python -m scenarios.run_all --mode baseline` runs the same attacks against the unprotected baseline.
* `python -m evaluation.run_eval` produces the numbers for your slides (about 2 minutes). **It resets the audit log**, so run `python -m scenarios.run_all` again afterwards to leave a clean log for the live demo.

## 4. Keys and free services
**Nothing is required for the project to work.** Without an LLM, the corrective and audit steps use deterministic rule fallbacks.
An LLM only makes the explanations and the summary read more naturally. Pick ONE (or none):

| Option | Cost | Get the key | `.env` |
|---|---|---|---|
| **None** (default) | free | no key | `LLM_PROVIDER=none` |
| **Ollama** (local, no rate limit, no key) | free | install from ollama.com, then `ollama pull llama3.2:3b` | `LLM_PROVIDER=ollama` |
| **Groq** (hosted, fast) | free tier | console.groq.com → API Keys | `LLM_PROVIDER=groq` + `LLM_API_KEY=...` |
| **Google AI Studio (Gemini)** | free tier | aistudio.google.com/apikey | `LLM_PROVIDER=gemini` + `LLM_API_KEY=...` |
| **OpenRouter** (`:free` models) | free tier | openrouter.ai/keys | `LLM_PROVIDER=openrouter` + `LLM_API_KEY=...` + `LLM_MODEL=<a model id ending in :free>` |

Free tiers have rate limits and **model names change**. If a call fails or times out (`LLM_TIMEOUT`, default 8 s), the gateway
silently uses the rule fallback, so the demo never depends on the LLM. Check the provider's page for current model names and
limits, and override with `LLM_MODEL=`. Ollama is the safest choice for a live demo (no network, no limit).

**Secrets you set yourself (no sign-up needed):**
* `GATEWAY_SECRET` signs tokens. Generate: `python -c "import secrets; print(secrets.token_hex(32))"`
* `ADMIN_KEY` is any long random string; the dashboard reads it from `.env` too.
* `BASELINE_API_KEY` is only for the baseline comparison; leave it as is.

Never commit `.env` or `keys/`. Agents' **private** keys live in `keys/`; the gateway registry holds only **public** keys.

## 5. What each piece does
| File | Role |
|---|---|
| `gateway/identity.py` | nonce + Ed25519 signature check, then an identity JWT |
| `gateway/tasks.py`, `policies/tasks.yaml` | task tokens: tools, one case, call budget, expiry; case-assignment check |
| `gateway/policy.py`, `policies/policies.yaml` | deterministic rules: prohibited tools, scope, case scope, destination allow-list, personal data, volume, budget |
| `gateway/anomaly.py`, `ml/` | kNN-distance detector trained on synthetic benign traces; only sees policy-approved actions |
| `gateway/corrector.py`, `gateway/llm.py` | corrective LLM, treated as untrusted: arguments are rebuilt by code and LLM output is validated |
| `gateway/quarantine.py` | freezes the agent, revokes tokens, queues the task for a human or backup agent |
| `gateway/audit.py` | hash-chained log (`sha256(prev_hash + event)`) and verification |
| `gateway/report.py` | audit LLM: statistics are computed in Python; the LLM only phrases them |
| `gateway/main.py` | FastAPI app and the `/call` pipeline; also `/baseline/call` (the unprotected comparison) |
| `agents/` | scripted agents (normal / hijackable / stubborn) and the gateway clients |
| `scenarios/` | S1–S10 demo scenarios and the shared attack functions |
| `evaluation/run_eval.py` | baseline vs AgentGuard measurements and ablation; writes `data/eval_results.json` and `.csv` |
| `dashboard/app.py` | Streamlit dashboard: incident timeline, human queue, tamper demo, compare tab |

## 6. Storage
One SQLite file, `data/agentguard.db`, holds the agent registry, tokens, the `audit` table (a JSON event per row plus `prev_hash`
and `hash`), quarantine events and the human queue. Exports from the dashboard: CSV (opens in Excel) and JSON Lines. The audit
LLM's summary is generated *from* the log and is never a substitute for it.

## 7. Live demo script (about 4 minutes)
1. Dashboard open, click *Reset demo state*, run **S1**: normal work, everything green.
2. Run **S6**, then open *Incident detail*: original external upload, policy denial, corrective suggestion, revised action allowed, task completed.
3. Run **S7**: a stubborn agent is quarantined in under a second, and *Human queue* shows the reassigned task.
4. Run **S8**: every call is within policy, yet the ML layer stops the harvesting.
5. *Audit & AI report* tab: *Tamper with this row*, then *Verify audit chain* fails, then *Undo*. Ask the audit LLM a question.
6. *Compare* tab: baseline vs AgentGuard.

## 8. Honest limits (say these in the pitch)
* Agents, cases and attacks are **simulated**. The "hijackable" agent obeys an injected instruction deterministically; it stands in for a vulnerable LLM agent.
* The evaluation is **in-distribution**: the rules were written for these attack types and the ML thresholds were tuned on synthetic data, so "0% attack success" describes this test set, not a guarantee. Adaptive attackers are future work.
* The anomaly detector's recall is measured on synthetic anomalies that are clearly unlike benign behaviour. Real-world recall is unknown.
* Prototype crypto: HS256 gateway tokens and a file-based key store. Production would use mTLS/SPIFFE, HSM-backed signing, OPA/Cedar, a redundant gateway, and the audit head hash anchored externally (someone with write access to the database could rewrite the whole chain, though not a single row undetected).
* `/admin/reset` wipes the audit log and exists only for demos (`DEMO_MODE=true`). Change `ADMIN_KEY`.

## 9. Design notes
* **Detector choice.** Isolation Forest scored harvesting almost like rare-but-benign behaviour (0% flagged at a safe threshold). Local Outlier Factor was numerically unstable on duplicate rows. A kNN-distance detector gave 100% recall on synthetic harvesting at about 0.5% false positives and is easy to explain.
* **Early false positives.** During development the ML blocked legitimate corrected actions because the benign training data lacked variation (different step orders, short reports). The fix was to train on more varied benign behaviour, not to loosen the threshold.
* **Policy first, ML second, never reversed.** The ML cannot override a policy denial. Uncertain anomalies are *held* for a human instead of blocked.

## 10. Troubleshooting
* `Gateway not reachable`: start terminal 1 first and check `GATEWAY_URL` in `.env`.
* `ModuleNotFoundError`: run commands from inside the `agentguard` folder with the venv active, using `python -m ...` as shown.
* Scenarios behave oddly after many runs: click *Reset demo state*, or run `python -m scenarios.run_all` (it resets first).
* Windows: if PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process Bypass` first.
* Re-train the model: `python -m scripts.init_db --retrain`. Full rebuild (new keys, new DB): `python -m scripts.init_db --reset --retrain`.
