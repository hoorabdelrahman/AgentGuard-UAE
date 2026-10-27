"""Gateway clients. Guard mode = identity + task tokens. Baseline = one shared static key (classic)."""
import time

import httpx
from cryptography.hazmat.primitives import serialization

import config
import seed


class GuardClient:
    def __init__(self, agent_id: str, base_url: str | None = None, key_agent: str | None = None):
        """key_agent: use ANOTHER agent's private key (to simulate a forged identity in tests)."""
        self.agent_id = agent_id
        self.http = httpx.Client(base_url=base_url or config.GATEWAY_URL, timeout=60)
        pem = seed.key_path(key_agent or agent_id).read_bytes()
        self.priv = serialization.load_pem_private_key(pem, password=None)
        self.identity_token = None
        self.task_token = None

    def authenticate(self) -> dict:
        nonce = self.http.get("/auth/nonce", params={"agent_id": self.agent_id}).json()["nonce"]
        sig = self.priv.sign(nonce.encode()).hex()           # proof of possession of the private key
        r = self.http.post("/auth/token", json={"agent_id": self.agent_id, "nonce": nonce, "signature": sig})
        if r.status_code == 200:
            self.identity_token = r.json()["token"]
            return {"ok": True}
        return {"ok": False, "code": r.json().get("code")}

    def request_task(self, task_type: str, case_id: str) -> dict:
        r = self.http.post("/tasks", json={"task_type": task_type, "case_id": case_id},
                           headers={"Authorization": f"Bearer {self.identity_token}"})
        j = r.json()
        if r.status_code == 200 and j.get("ok"):
            self.task_token = j["token"]
            return {"ok": True, "tools": j["tools"]}
        return {"ok": False, "code": j.get("code")}

    def call(self, tool: str, args: dict, parent_event_id=None, correction_attempt=0, token=None) -> dict:
        t0 = time.perf_counter()
        r = self.http.post("/call", json={"tool": tool, "args": args, "parent_event_id": parent_event_id,
                                          "correction_attempt": correction_attempt},
                           headers={"Authorization": f"Bearer {token or self.task_token}"})
        out = r.json()
        out["rt_ms"] = (time.perf_counter() - t0) * 1000
        return out


class BaselineClient:
    """The classic setup: every agent shares ONE static API key and just *claims* who it is."""

    def __init__(self, agent_id: str, base_url: str | None = None, api_key: str | None = None):
        self.agent_id = agent_id
        self.http = httpx.Client(base_url=base_url or config.GATEWAY_URL, timeout=60)
        self.api_key = api_key or config.BASELINE_API_KEY

    def authenticate(self) -> dict:
        return {"ok": True}

    def request_task(self, task_type: str, case_id: str) -> dict:
        return {"ok": True}

    def call(self, tool: str, args: dict, parent_event_id=None, correction_attempt=0) -> dict:
        t0 = time.perf_counter()
        r = self.http.post("/baseline/call", json={"claimed_agent": self.agent_id, "tool": tool, "args": args},
                           headers={"x-api-key": self.api_key})
        out = r.json() if r.status_code != 401 else {"decision": "rejected", "code": "BAD_API_KEY"}
        out["rt_ms"] = (time.perf_counter() - t0) * 1000
        return out


def make_client(mode: str, agent_id: str, **kw):
    return GuardClient(agent_id, **kw) if mode == "guard" else BaselineClient(agent_id)


def admin(path: str, method: str = "POST", json=None, base_url: str | None = None):
    r = httpx.request(method, (base_url or config.GATEWAY_URL) + path, json=json,
                      headers={"X-Admin-Key": config.ADMIN_KEY}, timeout=60)
    return r.json()
