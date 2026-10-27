"""Central configuration. Values come from environment variables or a .env file."""
import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


# ---------- paths ----------
DATA_DIR = ROOT / "data"
DB_PATH = Path(os.getenv("DB_PATH", str(DATA_DIR / "agentguard.db")))
MODEL_PATH = DATA_DIR / "anomaly_model.joblib"
TRACES_PATH = DATA_DIR / "benign_traces.csv"
KEYS_DIR = ROOT / "keys"
POLICIES_FILE = ROOT / "policies" / "policies.yaml"
TASKS_FILE = ROOT / "policies" / "tasks.yaml"

# ---------- gateway ----------
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:8000")
GATEWAY_SECRET = os.getenv("GATEWAY_SECRET", "dev-only-secret-change-me-please-32-bytes-min")
ADMIN_KEY = os.getenv("ADMIN_KEY", "admin-demo-key")
BASELINE_API_KEY = os.getenv("BASELINE_API_KEY", "shared-static-key-123")  # the "classic" shared key
DEMO_MODE = _bool("DEMO_MODE", True)  # enables /admin/reset (wipes the audit log!)

IDENTITY_TTL = 3600       # seconds an identity token lives
NONCE_TTL = 30            # seconds a nonce lives
MAX_VIOLATIONS_PER_TASK = int(os.getenv("MAX_VIOLATIONS_PER_TASK", "3"))  # original + 2 retries
APPROVED_EVIDENCE_URL = "https://evidence-store.internal/upload"

# ---------- simulated agent "thinking time" (seconds) ----------
THINK_MIN = float(os.getenv("THINK_MIN", "0.10"))
THINK_MAX = float(os.getenv("THINK_MAX", "0.40"))

# ---------- LLM (corrective + audit LLM) ----------
# LLM_PROVIDER: none | ollama | groq | gemini | openrouter
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "none").strip().lower()
_LLM_DEFAULTS = {
    "ollama": ("http://localhost:11434", "llama3.2:3b"),
    "groq": ("https://api.groq.com/openai/v1", "llama-3.1-8b-instant"),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai", "gemini-2.5-flash"),
    "openrouter": ("https://openrouter.ai/api/v1", "meta-llama/llama-3.3-70b-instruct:free"),
}
_base, _model = _LLM_DEFAULTS.get(LLM_PROVIDER, ("", ""))
LLM_BASE_URL = os.getenv("LLM_BASE_URL", _base).rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", _model)
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "8"))
