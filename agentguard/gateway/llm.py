"""Tiny provider-agnostic LLM client. Every call is optional and has a timeout:
if the LLM is off, slow or returns junk, callers fall back to deterministic rules."""
import json
import re

import httpx

import config


def enabled() -> bool:
    if config.LLM_PROVIDER in ("", "none"):
        return False
    if config.LLM_PROVIDER != "ollama" and not config.LLM_API_KEY:
        return False
    return True


def chat(system: str, user: str, max_tokens: int = 350) -> str | None:
    if not enabled():
        return None
    try:
        if config.LLM_PROVIDER == "ollama":
            r = httpx.post(f"{config.LLM_BASE_URL}/api/chat", timeout=config.LLM_TIMEOUT, json={
                "model": config.LLM_MODEL, "stream": False,
                "options": {"temperature": 0.1, "num_predict": max_tokens},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
            r.raise_for_status()
            return r.json()["message"]["content"]
        r = httpx.post(f"{config.LLM_BASE_URL}/chat/completions", timeout=config.LLM_TIMEOUT,
                       headers={"Authorization": f"Bearer {config.LLM_API_KEY}"},
                       json={"model": config.LLM_MODEL, "temperature": 0.1, "max_tokens": max_tokens,
                             "messages": [{"role": "system", "content": system},
                                          {"role": "user", "content": user}]})
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    except Exception:
        return None


def chat_json(system: str, user: str) -> dict | None:
    text = chat(system, user)
    if not text:
        return None
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
