"""
The operator's policy: what it will vouch for, and what it will approve unattended.

    operator: did:web:operator.example      # pinned into every voucher
    registry_did: did:web:registry.example  # voucher audience
    voucher_ttl_seconds: 600
    max:                                    # the most any voucher may grant
      capabilities: [observe, publish, "publish:dev.watershed-agent.observation"]
      scopes: [us-ca-napa, us-ca-sonoma]
    auto_approve:
      amend:                                # charter-holding agents asking to widen
        capabilities: ["publish:dev.watershed-agent.observation"]
        scopes: [us-ca-sonoma]

First enrollment is never auto-approved: an agent with no charter has nothing
yet that a policy could check, so a human decides.  ``max`` is also what
``voucherctl jwks`` writes as this key's ceiling at the registry, so the two
limits stay the same set.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


class PolicyError(Exception):
    """A request falls outside what this operator will vouch for."""


@dataclass(frozen=True)
class Bounds:
    capabilities: frozenset[str] = field(default_factory=frozenset)
    scopes: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "Bounds":
        data = data or {}
        return cls(
            capabilities=frozenset(data.get("capabilities") or []),
            scopes=frozenset(data.get("scopes") or []),
        )

    def as_dict(self) -> dict:
        return {"capabilities": sorted(self.capabilities), "scopes": sorted(self.scopes)}


@dataclass(frozen=True)
class Policy:
    operator: str
    registry_did: str
    max: Bounds
    auto_amend: Optional[Bounds] = None
    voucher_ttl_seconds: int = 600

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        for key in ("operator", "registry_did", "max"):
            if not data.get(key):
                raise ValueError(f"Policy is missing {key!r}.")
        auto = (data.get("auto_approve") or {}).get("amend")
        return cls(
            operator=data["operator"],
            registry_did=data["registry_did"],
            max=Bounds.from_dict(data["max"]),
            auto_amend=Bounds.from_dict(auto) if auto else None,
            voucher_ttl_seconds=int(data.get("voucher_ttl_seconds", 600)),
        )

    @classmethod
    def from_file(cls, path: Path) -> "Policy":
        return cls.from_dict(yaml.safe_load(path.read_text()) or {})

    def check_within_max(self, capabilities: list[str], scopes: list[str]) -> None:
        """Refuse a request this operator would never vouch for, at submission time."""
        extra_caps = sorted(set(capabilities) - self.max.capabilities)
        extra_scopes = sorted(set(scopes) - self.max.scopes)
        if extra_caps or extra_scopes:
            raise PolicyError(
                "Outside what this operator vouches for: "
                f"capabilities {extra_caps}, scopes {extra_scopes}."
            )

    def auto_approves_amend(
        self, requested: Bounds, current_capabilities: list[str], current_scopes: list[str]
    ) -> bool:
        """
        An amend is approved unattended when everything it asks for is either
        already in the agent's charter or on the auto-approve list.
        """
        if self.auto_amend is None:
            return False
        allowed_caps = set(current_capabilities) | self.auto_amend.capabilities
        allowed_scopes = set(current_scopes) | self.auto_amend.scopes
        return requested.capabilities <= allowed_caps and requested.scopes <= allowed_scopes
