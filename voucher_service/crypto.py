"""
Keys, thumbprints and compact JWS.

Two signatures matter here:

- the operator's, on vouchers (``Signer``), which the registry verifies;
- the agent's, on proofs it sends this service (``verify_agent_proof``), which
  is how only the agent that asked for a voucher can collect it.
"""
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)

#: How far an agent proof's iat may drift from this service's clock.
PROOF_SKEW_SECONDS = 300


class ProofError(Exception):
    """An agent proof is missing, malformed, or doesn't verify."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def now() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def public_jwk(public_key: Ed25519PublicKey) -> dict:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint; identical to the registry's app.crypto.jwk_thumbprint."""
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "x" not in jwk:
        raise ValueError("Expected an Ed25519 OKP public JWK.")
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canonical.encode()).digest())


def jwk_to_public_key(jwk: dict) -> Ed25519PublicKey:
    jwk_thumbprint(jwk)  # validates shape
    return Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))


def encode_jws(header: dict, payload: dict, sign) -> str:
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{b64url(sign(f'{h}.{p}'.encode()))}"


def decode_jws(token: str) -> tuple[dict, dict, bytes, bytes]:
    """Split a compact JWS into (header, payload, signing_input, signature)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ProofError("Not a compact JWS.")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        signature = b64url_decode(parts[2])
    except Exception as exc:  # noqa: BLE001 — any decode failure is a bad token
        raise ProofError(f"JWS could not be decoded: {exc}")
    return header, payload, f"{parts[0]}.{parts[1]}".encode(), signature


# ── Operator signing ──────────────────────────────────────────────────────────

class Signer:
    """
    The operator's voucher-signing key.

    v1 reads a PEM file.  Anything that can produce an Ed25519 signature and a
    public JWK (a KMS, an HSM) can stand in: the rest of the service only calls
    ``kid``, ``public_jwk()`` and ``sign()``.
    """

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key
        self._jwk = public_jwk(private_key.public_key())
        raw = b64url_decode(self._jwk["x"])
        # Same kid derivation as the registry repo's operator_cli, so a JWKS from
        # either tool matches vouchers from the other.
        self.kid = b64url(hashlib.sha256(raw).digest())[:16]

    @classmethod
    def from_pem_file(cls, path: Path) -> "Signer":
        key = load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{path} is not an Ed25519 private key.")
        return cls(key)

    def public_jwk(self) -> dict:
        return {**self._jwk, "kid": self.kid}

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)


# ── Agent proofs ──────────────────────────────────────────────────────────────

def verify_agent_proof(token: str, agent_jwk: dict, audience: str, expect: dict) -> dict:
    """
    Verify a compact JWS an agent signed with its own key.

    The payload must carry ``aud`` = this service, a fresh ``iat``, and every
    key/value in *expect* (e.g. the request id), so a proof can't be replayed
    against another request or another service.
    """
    header, payload, signing_input, signature = decode_jws(token)
    if header.get("alg") != "EdDSA":
        raise ProofError(f"Unsupported proof alg: {header.get('alg')!r}")
    try:
        jwk_to_public_key(agent_jwk).verify(signature, signing_input)
    except (InvalidSignature, ValueError):
        raise ProofError("Proof is not signed by the requesting agent's key.")
    if payload.get("aud") != audience:
        raise ProofError("Proof audience does not match this service.")
    iat = payload.get("iat")
    if not isinstance(iat, int) or abs(now() - iat) > PROOF_SKEW_SECONDS:
        raise ProofError("Proof is stale or has no iat.")
    for key, value in expect.items():
        if payload.get(key) != value:
            raise ProofError(f"Proof {key!r} does not match.")
    return payload
