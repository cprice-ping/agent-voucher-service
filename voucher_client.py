"""
Agent-side client for the voucher service.

Copy this next to ``registry_client.py`` (from the Agentic-DID-Registry repo) in
the agent's codebase.  It asks the operator's voucher service for a voucher, then
hands it to the registry itself.  The service never talks to the registry on the
agent's behalf, and the agent's private key never leaves the agent.

    from registry_client import RegistryClient
    from voucher_client import VoucherClient

    registry = RegistryClient(registry_url="https://registry.example")
    vouchers = VoucherClient("https://vouchers.operator.example")

    # First charter: a human approves, the agent waits.
    did = vouchers.enroll(registry, {"name": "fire", "scope": "...", "intent": "..."},
                          capabilities=["observe", "publish"], scopes=["us-ca-napa"])

    # Later: ask to join another lexicon or region.  Policy may approve unattended.
    vouchers.amend(registry, did,
                   capabilities=["observe", "publish", "publish:dev.watershed-agent.observation"],
                   scopes=["us-ca-napa", "us-ca-sonoma"])

Requested capabilities and scopes for an amend are the full set the agent wants
afterwards, not just the additions.
"""
import base64
import json
import time
from datetime import datetime, timezone
from typing import Optional

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class VoucherDenied(Exception):
    """The operator denied the request."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _public_jwk(key: Ed25519PrivateKey) -> dict:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}


def voucher_bounds(voucher: str) -> dict:
    """What a voucher allows, read from its payload.  The registry verifies it; we only read."""
    payload = json.loads(_b64url_decode(voucher.split(".")[1]))
    return {"capabilities": payload.get("capabilities"), "scopes": payload.get("scopes")}


class VoucherClient:
    def __init__(self, service_url: str, audience: Optional[str] = None,
                 timeout: float = 10.0) -> None:
        self._url = service_url.rstrip("/")
        # Proofs are audience-bound to the service's configured SERVICE_AUDIENCE.
        self._audience = audience or self._url
        self._timeout = timeout

    # ── Low-level calls ───────────────────────────────────────────────────────

    def _proof(self, key: Ed25519PrivateKey, request_id: str) -> str:
        header = {"alg": "EdDSA", "typ": "agent-proof+jwt"}
        payload = {
            "request_id": request_id,
            "aud": self._audience,
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }
        h = _b64url(json.dumps(header, separators=(",", ":")).encode())
        p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
        return f"{h}.{p}.{_b64url(key.sign(f'{h}.{p}'.encode()))}"

    def _post(self, path: str, body: dict) -> dict:
        with httpx.Client(timeout=self._timeout) as c:
            resp = c.post(f"{self._url}{path}", json=body)
        if resp.status_code >= 400:
            raise PermissionError(f"{resp.status_code}: {resp.text}")
        return resp.json()

    def request_enrollment(self, key: Ed25519PrivateKey, capabilities: list[str],
                           scopes: list[str] = (), justification: str = "") -> dict:
        return self._post("/requests", {
            "kind": "enroll",
            "requested": {"capabilities": list(capabilities), "scopes": list(scopes)},
            "justification": justification,
            "agent_public_jwk": _public_jwk(key),
        })

    def nonce(self) -> str:
        with httpx.Client(timeout=self._timeout) as c:
            resp = c.get(f"{self._url}/nonce")
            resp.raise_for_status()
            return resp.json()["nonce"]

    def request_amend(self, presentation: dict, challenge: str, capabilities: list[str],
                      scopes: list[str] = (), justification: str = "") -> dict:
        return self._post("/requests", {
            "kind": "amend",
            "requested": {"capabilities": list(capabilities), "scopes": list(scopes)},
            "justification": justification,
            "presentation": presentation,
            "challenge": challenge,
        })

    def poll(self, request_id: str, key: Ed25519PrivateKey) -> dict:
        with httpx.Client(timeout=self._timeout) as c:
            resp = c.get(f"{self._url}/requests/{request_id}",
                         headers={"Agent-Proof": self._proof(key, request_id)})
        if resp.status_code >= 400:
            raise PermissionError(f"{resp.status_code}: {resp.text}")
        return resp.json()

    def wait(self, request_id: str, key: Ed25519PrivateKey,
             timeout: float = 600, interval: float = 5) -> dict:
        """Poll until approved (returns the request, voucher included) or denied (raises)."""
        deadline = time.monotonic() + timeout
        while True:
            state = self.poll(request_id, key)
            if state["status"] == "approved":
                return state
            if state["status"] == "denied":
                raise VoucherDenied(state.get("reason") or "denied")
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Request {request_id} still pending after {timeout}s.")
            time.sleep(interval)

    # ── End to end ────────────────────────────────────────────────────────────

    def enroll(self, registry, charter: dict, capabilities: list[str],
               scopes: list[str] = (), justification: str = "",
               timeout: float = 600, interval: float = 5) -> str:
        """
        Generate a key, ask for a voucher bound to it, wait for approval, and enrol
        at the registry.  Returns the new DID.

        The charter asserts what the agent wants; if the operator narrowed the
        request, the charter is narrowed to match before enrolling, since the
        registry would refuse anything wider.
        """
        key = Ed25519PrivateKey.generate()
        created = self.request_enrollment(key, capabilities, scopes, justification)
        approved = self.wait(created["request_id"], key, timeout, interval)
        voucher = approved["voucher"]
        bounds = voucher_bounds(voucher)

        fitted = dict(charter)
        wanted = fitted.get("capabilities", capabilities)
        fitted["capabilities"] = [c for c in wanted if c in set(bounds["capabilities"] or [])]
        if bounds["scopes"] is not None:
            wanted_scopes = fitted.get("scopes", list(scopes))
            fitted["scopes"] = [s for s in wanted_scopes if s in set(bounds["scopes"])]
        fitted["agent_id"] = approved["agent_id"]
        return registry.provision(fitted, voucher=voucher, private_key=key)

    def amend(self, registry, did: str, capabilities: list[str], scopes: list[str] = (),
              justification: str = "", key: Optional[Ed25519PrivateKey] = None,
              timeout: float = 600, interval: float = 5) -> dict:
        """
        Present the current charter, ask for a wider one, and reissue it at the
        registry with the same DID and key.  Returns the registry's response.
        """
        if key is None:
            from registry_client import _load_private_key  # the agent's own key store

            key = _load_private_key(registry._key_path(did))
        challenge = self.nonce()
        presentation = registry.present(did, challenge=challenge)
        created = self.request_amend(presentation, challenge, capabilities, scopes, justification)
        approved = self.wait(created["request_id"], key, timeout, interval)
        voucher = approved["voucher"]
        bounds = voucher_bounds(voucher)

        current = presentation["verifiableCredential"][0]["credentialSubject"]
        charter = {k: v for k, v in current.items() if k != "id"}
        charter["capabilities"] = bounds["capabilities"] or []
        if bounds["scopes"] is not None:
            charter["scopes"] = bounds["scopes"]
        return registry.reissue(did, charter=charter, voucher=voucher)
