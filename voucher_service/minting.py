"""Turning an approved request into a voucher the registry will accept."""
import uuid

from voucher_service.crypto import Signer, encode_jws, jwk_thumbprint, now
from voucher_service.policy import Policy


def mint_voucher(
    signer: Signer,
    policy: Policy,
    *,
    agent_id: str,
    agent_jwk: dict,
    purpose: str,
    capabilities: list[str],
    scopes: list[str],
) -> tuple[str, dict]:
    """
    Sign an enrollment or amend voucher.  Returns (token, payload).

    The voucher is bound to the agent's key (``cnf.jkt``), pins the operator, and
    carries exactly the approved capabilities and scopes.  The registry still
    clamps it against this key's ceiling; that check isn't ours to skip.
    """
    issued = now()
    payload = {
        "iss": policy.operator,
        "aud": policy.registry_did,
        "sub": agent_id,
        "iat": issued,
        "exp": issued + policy.voucher_ttl_seconds,
        "jti": str(uuid.uuid4()),
        "purpose": purpose,
        "capabilities": sorted(capabilities),
        "operator": policy.operator,
        "cnf": {"jkt": jwk_thumbprint(agent_jwk)},
    }
    # An operator that scopes nothing shouldn't force every charter to declare
    # an empty scope list; one that does scope always bounds them, even to none.
    if policy.max.scopes:
        payload["scopes"] = sorted(scopes)
    header = {"alg": "EdDSA", "typ": "enrollment-voucher+jwt", "kid": signer.kid}
    return encode_jws(header, payload, signer.sign), payload
