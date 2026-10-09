"""
HTTP API.

Agent-facing
  GET  /nonce               challenge for an amend presentation
  POST /requests            ask for an enroll or amend voucher
  GET  /requests/{id}       poll; must carry an Agent-Proof signed by the requesting key

Operator-facing (Authorization: Bearer $ADMIN_TOKEN; disabled when unset)
  GET  /admin/requests                 list, optionally ?status=pending
  POST /admin/requests/{id}/approve    approve, optionally narrowing
  POST /admin/requests/{id}/deny       deny with a reason
  GET  /admin/issued                   the issuance log

Run with ``uvicorn --factory voucher_service.main:create_app_from_env``.
"""
import json
import secrets
import uuid
from typing import Annotated, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlmodel import Session, SQLModel, create_engine, select

from voucher_service.crypto import (
    ProofError,
    Signer,
    jwk_thumbprint,
    now,
    verify_agent_proof,
)
from voucher_service.minting import mint_voucher
from voucher_service.models import IssuedVoucher, Nonce, VoucherRequest
from voucher_service.policy import Bounds, Policy, PolicyError
from voucher_service.registry import HttpRegistryGateway, RegistryGateway, current_key

NONCE_TTL_SECONDS = 120


# ── Request / response bodies ─────────────────────────────────────────────────

class Requested(BaseModel):
    capabilities: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)


class CreateRequest(BaseModel):
    kind: Literal["enroll", "amend"]
    requested: Requested
    justification: str = ""
    agent_public_jwk: Optional[dict] = Field(
        default=None, description="enroll: the key the voucher will be bound to."
    )
    presentation: Optional[dict] = Field(
        default=None,
        description="amend: a VP of the current charter, signed by the agent's key.",
    )
    challenge: Optional[str] = Field(
        default=None, description="amend: the nonce from GET /nonce, also inside the VP."
    )


class Approve(BaseModel):
    capabilities: Optional[list[str]] = None  # None ⇒ as requested
    scopes: Optional[list[str]] = None
    approver: str = "operator"


class Deny(BaseModel):
    reason: str = ""


# ── App factory ───────────────────────────────────────────────────────────────

def create_app(
    *,
    signer: Signer,
    policy: Policy,
    gateway: RegistryGateway,
    database_url: str,
    audience: str,
    admin_token: str = "",
) -> FastAPI:
    engine = create_engine(database_url, connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)

    app = FastAPI(
        title="Agent Voucher Service",
        description=(
            "An operator's front door to the Agentic-DID-Registry. Agents request "
            "vouchers; operator policy and a human decide; vouchers are bound to the "
            "agent's key. The registry independently enforces this key's ceiling."
        ),
        version="0.1.0",
    )

    def get_session():
        with Session(engine) as session:
            yield session

    SessionDep = Annotated[Session, Depends(get_session)]

    def require_admin(authorization: Annotated[Optional[str], Header()] = None) -> None:
        if not admin_token:
            raise HTTPException(status_code=503, detail="Operator API is disabled (no ADMIN_TOKEN).")
        if not authorization or not secrets.compare_digest(
            authorization, f"Bearer {admin_token}"
        ):
            raise HTTPException(status_code=401, detail="Operator token required.")

    def issue(session: Session, req: VoucherRequest, caps: list[str], scopes: list[str],
              approved_by: str) -> None:
        purpose = "enroll" if req.kind == "enroll" else "amend"
        token, payload = mint_voucher(
            signer, policy,
            agent_id=req.agent_id, agent_jwk=req.get_agent_jwk(),
            purpose=purpose, capabilities=caps, scopes=scopes,
        )
        req.status = "approved"
        req.voucher = token
        req.decided_at = payload["iat"]
        req.decided_by = approved_by
        session.add(req)
        session.add(IssuedVoucher(
            jti=payload["jti"], request_id=req.id, agent_id=req.agent_id, purpose=purpose,
            jkt=payload["cnf"]["jkt"], capabilities=json.dumps(payload["capabilities"]),
            scopes=json.dumps(payload.get("scopes")), approved_by=approved_by,
            issued_at=payload["iat"], expires_at=payload["exp"],
        ))

    def summary(req: VoucherRequest, include_voucher: bool = False) -> dict:
        out = {
            "request_id": req.id,
            "kind": req.kind,
            "status": req.status,
            "agent_id": req.agent_id,
            "requested": req.get_requested(),
        }
        if req.agent_did:
            out["agent_did"] = req.agent_did
        if req.status == "denied":
            out["reason"] = req.reason
        if include_voucher and req.voucher:
            out["voucher"] = req.voucher
        return out

    # ── Agent-facing ──────────────────────────────────────────────────────────

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict:
        return {"ok": True}

    @app.get("/nonce", tags=["Agents"])
    def get_nonce(session: SessionDep) -> dict:
        t = now()
        for stale in session.exec(select(Nonce).where(Nonce.expires_at < t)).all():
            session.delete(stale)
        nonce = Nonce(value=secrets.token_urlsafe(24), expires_at=t + NONCE_TTL_SECONDS)
        session.add(nonce)
        session.commit()
        return {"nonce": nonce.value, "expires_at": nonce.expires_at}

    @app.post("/requests", status_code=201, tags=["Agents"])
    def create_request(body: CreateRequest, session: SessionDep) -> dict:
        try:
            policy.check_within_max(body.requested.capabilities, body.requested.scopes)
        except PolicyError as exc:
            raise HTTPException(status_code=403, detail=str(exc))

        if body.kind == "enroll":
            return create_enroll(body, session)
        return create_amend(body, session)

    def create_enroll(body: CreateRequest, session: Session) -> dict:
        # First enrollment: the agent has nothing yet a policy could check, so a
        # human decides.  The key it sends is the one the voucher will be bound to.
        if not body.agent_public_jwk:
            raise HTTPException(status_code=422, detail="enroll needs agent_public_jwk.")
        try:
            jwk_thumbprint(body.agent_public_jwk)
        except (ValueError, KeyError):
            raise HTTPException(status_code=422, detail="agent_public_jwk must be an Ed25519 OKP JWK.")
        req = VoucherRequest(
            id=uuid.uuid4().hex, kind="enroll", agent_id=uuid.uuid4().hex,
            agent_jwk=json.dumps({k: body.agent_public_jwk[k] for k in ("kty", "crv", "x")}),
            requested=body.requested.model_dump_json(), justification=body.justification,
            created_at=now(),
        )
        session.add(req)
        session.commit()
        return summary(req)

    def create_amend(body: CreateRequest, session: Session) -> dict:
        # Later vouchers: the agent proves its current charter and key, so policy
        # has something to check and can approve unattended.
        if not body.presentation or not body.challenge:
            raise HTTPException(status_code=422, detail="amend needs presentation and challenge.")
        nonce = session.get(Nonce, body.challenge)
        if nonce is None or nonce.expires_at < now():
            raise HTTPException(status_code=403, detail="Unknown, used, or expired challenge.")
        session.delete(nonce)  # single use, whatever happens next
        session.commit()

        holder = body.presentation.get("holder", "")
        prefix = f"{policy.registry_did}:agents:"
        if not holder.startswith(prefix):
            raise HTTPException(status_code=403, detail="Holder is not an agent of the configured registry.")
        agent_id = holder[len(prefix):]

        result = gateway.verify_presentation(body.presentation, body.challenge)
        # The registry reports valid only while active.  An expired charter with
        # both signatures intact may still be amended: that's the operator
        # re-confirming.  Revoked never.
        if not (result.get("holder_signature_valid") and result.get("charter_signature_valid")):
            raise HTTPException(status_code=403, detail=f"Presentation rejected: {result.get('error')}")
        if result.get("status") not in ("active", "expired"):
            raise HTTPException(status_code=403, detail=f"Agent is {result.get('status')}.")
        if result.get("holder") != holder:
            raise HTTPException(status_code=403, detail="Presentation holder mismatch.")

        did_doc = gateway.agent_did_document(agent_id)
        key = current_key(did_doc) if did_doc else None
        if key is None:
            raise HTTPException(status_code=403, detail="Could not resolve the agent's current key.")

        vcs = body.presentation.get("verifiableCredential") or [{}]
        current = vcs[0].get("credentialSubject", {})

        req = VoucherRequest(
            id=uuid.uuid4().hex, kind="amend", agent_id=agent_id, agent_did=holder,
            agent_jwk=json.dumps(key), requested=body.requested.model_dump_json(),
            justification=body.justification, created_at=now(),
        )
        session.add(req)
        requested = Bounds.from_dict(body.requested.model_dump())
        if policy.auto_approves_amend(
            requested, current.get("capabilities") or [], current.get("scopes") or []
        ):
            issue(session, req, sorted(requested.capabilities), sorted(requested.scopes), "policy")
        session.commit()
        return summary(req)

    @app.get("/requests/{request_id}", tags=["Agents"])
    def poll_request(
        request_id: str,
        session: SessionDep,
        agent_proof: Annotated[Optional[str], Header()] = None,
    ) -> dict:
        """Only the agent holding the requested key can see the request or collect its voucher."""
        req = session.get(VoucherRequest, request_id)
        if req is None:
            raise HTTPException(status_code=404, detail="No such request.")
        if not agent_proof:
            raise HTTPException(status_code=401, detail="Agent-Proof header required.")
        try:
            verify_agent_proof(agent_proof, req.get_agent_jwk(), audience,
                               {"request_id": request_id})
        except ProofError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        return summary(req, include_voucher=True)

    # ── Operator-facing ───────────────────────────────────────────────────────

    admin = [Depends(require_admin)]

    @app.get("/admin/requests", dependencies=admin, tags=["Operator"])
    def list_requests(session: SessionDep, status: Optional[str] = None) -> list[dict]:
        query = select(VoucherRequest).order_by(VoucherRequest.created_at)
        if status:
            query = query.where(VoucherRequest.status == status)
        return [
            {**summary(r), "justification": r.justification, "created_at": r.created_at,
             "decided_by": r.decided_by}
            for r in session.exec(query).all()
        ]

    def pending(session: Session, request_id: str) -> VoucherRequest:
        req = session.get(VoucherRequest, request_id)
        if req is None:
            raise HTTPException(status_code=404, detail="No such request.")
        if req.status != "pending":
            raise HTTPException(status_code=409, detail=f"Request is already {req.status}.")
        return req

    @app.post("/admin/requests/{request_id}/approve", dependencies=admin, tags=["Operator"])
    def approve(request_id: str, body: Approve, session: SessionDep) -> dict:
        """Approve as requested, or narrower.  Never wider than the agent asked for."""
        req = pending(session, request_id)
        asked = req.get_requested()
        caps = asked["capabilities"] if body.capabilities is None else body.capabilities
        scopes = asked["scopes"] if body.scopes is None else body.scopes
        wider_caps = sorted(set(caps) - set(asked["capabilities"]))
        wider_scopes = sorted(set(scopes) - set(asked["scopes"]))
        if wider_caps or wider_scopes:
            raise HTTPException(
                status_code=400,
                detail=f"Approval can only narrow the request: {wider_caps} {wider_scopes}.",
            )
        issue(session, req, caps, scopes, body.approver)
        session.commit()
        return summary(req)

    @app.post("/admin/requests/{request_id}/deny", dependencies=admin, tags=["Operator"])
    def deny(request_id: str, body: Deny, session: SessionDep) -> dict:
        req = pending(session, request_id)
        req.status = "denied"
        req.reason = body.reason
        req.decided_at = now()
        req.decided_by = "operator"
        session.add(req)
        session.commit()
        return summary(req)

    @app.get("/admin/issued", dependencies=admin, tags=["Operator"])
    def issued(session: SessionDep) -> list[dict]:
        rows = session.exec(select(IssuedVoucher).order_by(IssuedVoucher.issued_at)).all()
        return [
            {**r.model_dump(), "capabilities": json.loads(r.capabilities),
             "scopes": json.loads(r.scopes)}
            for r in rows
        ]

    return app


def create_app_from_env() -> FastAPI:
    from voucher_service import config

    return create_app(
        signer=Signer.from_pem_file(config.OPERATOR_KEY_PATH),
        policy=Policy.from_file(config.POLICY_PATH),
        gateway=HttpRegistryGateway(config.REGISTRY_URL),
        database_url=config.DATABASE_URL,
        audience=config.SERVICE_AUDIENCE,
        admin_token=config.ADMIN_TOKEN,
    )
