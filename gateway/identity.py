"""Agent identity: Ed25519 challenge-response -> short-lived identity JWT."""
import secrets
import time

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import config


def new_nonce(conn, agent_id: str) -> str:
    nonce = secrets.token_hex(16)
    conn.execute("INSERT INTO nonces (nonce, agent_id, expires_at, used) VALUES (?,?,?,0)",
                 (nonce, agent_id, time.time() + config.NONCE_TTL))
    return nonce


def _verify(pub_hex: str, nonce: str, sig_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(bytes.fromhex(sig_hex), nonce.encode())
        return True
    except (InvalidSignature, ValueError):
        return False


def authenticate(conn, agent_id: str, nonce: str, signature_hex: str):
    """Returns (token | None, error_code | None, agent_row | None)."""
    row = conn.execute("SELECT * FROM nonces WHERE nonce=?", (nonce,)).fetchone()
    if (not row or row["agent_id"] != agent_id or row["used"] or row["expires_at"] < time.time()):
        return None, "BAD_NONCE", None
    conn.execute("UPDATE nonces SET used=1 WHERE nonce=?", (nonce,))  # single use, even if the proof fails
    agent = conn.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
    if not agent:
        return None, "UNKNOWN_AGENT", None
    if agent["status"] != "active":
        return None, "AGENT_NOT_ACTIVE", agent
    if not _verify(agent["public_key"], nonce, signature_hex):
        return None, "BAD_SIGNATURE", agent
    now = int(time.time())
    token = jwt.encode({"typ": "identity", "sub": agent_id, "role": agent["role"],
                        "iat": now, "exp": now + config.IDENTITY_TTL},
                       config.GATEWAY_SECRET, algorithm="HS256")
    return token, None, agent


def decode(token: str, typ: str):
    """Returns (claims | None, error_code | None, agent_id_hint | None)."""
    try:
        claims = jwt.decode(token, config.GATEWAY_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        try:
            hint = jwt.decode(token, config.GATEWAY_SECRET, algorithms=["HS256"],
                              options={"verify_exp": False}).get("sub")
        except jwt.InvalidTokenError:
            hint = None
        return None, "TOKEN_EXPIRED", hint
    except jwt.InvalidTokenError:
        return None, "TOKEN_INVALID", None
    if claims.get("typ") != typ:
        return None, "WRONG_TOKEN_TYPE", claims.get("sub")
    return claims, None, claims.get("sub")
