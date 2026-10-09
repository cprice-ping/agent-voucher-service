"""Persistent state: requests, single-use nonces, and the issuance log."""
import json
from typing import Optional

from sqlmodel import Column, Field, SQLModel, Text


class VoucherRequest(SQLModel, table=True):
    id: str = Field(primary_key=True)
    kind: str  # "enroll" | "amend"
    status: str = "pending"  # pending | approved | denied
    agent_id: str
    agent_did: Optional[str] = None  # amend only: the presenting agent
    agent_jwk: str = Field(sa_column=Column(Text))
    requested: str = Field(sa_column=Column(Text))  # {"capabilities": [...], "scopes": [...]}
    justification: str = ""
    created_at: int
    decided_at: Optional[int] = None
    decided_by: Optional[str] = None  # "policy" or the operator API
    reason: Optional[str] = None  # why it was denied
    voucher: Optional[str] = Field(default=None, sa_column=Column(Text))

    def get_agent_jwk(self) -> dict:
        return json.loads(self.agent_jwk)

    def get_requested(self) -> dict:
        return json.loads(self.requested)


class Nonce(SQLModel, table=True):
    """A challenge for an amend presentation.  Single use, short-lived."""

    value: str = Field(primary_key=True)
    expires_at: int


class IssuedVoucher(SQLModel, table=True):
    """The operator's accountability record: every voucher this service signed."""

    jti: str = Field(primary_key=True)
    request_id: str
    agent_id: str
    purpose: str
    jkt: str
    capabilities: str = Field(sa_column=Column(Text))
    scopes: str = Field(sa_column=Column(Text))
    approved_by: str
    issued_at: int
    expires_at: int
