"""
The registry, as this service sees it: a place to check a presentation and look
up an agent's current key.  Both calls use the registry's public API only;
nothing here duplicates its verification logic.
"""
from typing import Optional, Protocol

import httpx


class RegistryGateway(Protocol):
    def verify_presentation(self, presentation: dict, challenge: str) -> dict: ...

    def agent_did_document(self, agent_id: str) -> Optional[dict]: ...


class HttpRegistryGateway:
    def __init__(self, registry_url: str, timeout: float = 10.0) -> None:
        self._url = registry_url.rstrip("/")
        self._timeout = timeout

    def verify_presentation(self, presentation: dict, challenge: str) -> dict:
        """POST /verify: holder signature, registry signature, and current status."""
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(
                f"{self._url}/verify",
                json={"presentation": presentation, "challenge": challenge},
            )
            resp.raise_for_status()
            return resp.json()

    def agent_did_document(self, agent_id: str) -> Optional[dict]:
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.get(f"{self._url}/agents/{agent_id}/did.json")
            if resp.status_code != 200:
                return None
            return resp.json()


def current_key(did_document: dict) -> Optional[dict]:
    """The agent's current public JWK from its DID document."""
    for vm in did_document.get("verificationMethod", []):
        jwk = vm.get("publicKeyJwk")
        if jwk:
            return {k: v for k, v in jwk.items() if k in ("kty", "crv", "x")}
    return None
