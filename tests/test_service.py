"""
Voucher service tests.  In-process, with a fake registry gateway so they run
without a registry.  The end-to-end path against a real registry is in README.
"""
import json
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from voucher_service.crypto import (
    Signer,
    decode_jws,
    encode_jws,
    jwk_thumbprint,
    jwk_to_public_key,
    now,
    public_jwk,
)
from voucher_service.main import create_app
from voucher_service.policy import Policy

AUDIENCE = "https://vouchers.test"
REGISTRY_DID = "did:web:registry.test"
ADMIN = {"Authorization": "Bearer admin-secret"}

POLICY = Policy.from_dict({
    "operator": "did:web:operator.test",
    "registry_did": REGISTRY_DID,
    "voucher_ttl_seconds": 600,
    "max": {
        "capabilities": ["observe", "publish", "publish:dev.watershed-agent.observation"],
        "scopes": ["us-ca-napa", "us-ca-sonoma"],
    },
    "auto_approve": {
        "amend": {
            "capabilities": ["publish:dev.watershed-agent.observation"],
            "scopes": ["us-ca-sonoma"],
        }
    },
})


class FakeRegistry:
    """Stands in for POST /verify and GET /agents/{id}/did.json."""

    def __init__(self) -> None:
        self.keys: dict[str, dict] = {}  # agent_id -> public jwk
        self.status: dict[str, str] = {}
        self.charters: dict[str, dict] = {}

    def add_agent(self, key: Ed25519PrivateKey, charter: dict, status: str = "active") -> str:
        agent_id = uuid.uuid4().hex
        self.keys[agent_id] = public_jwk(key.public_key())
        self.status[agent_id] = status
        self.charters[agent_id] = charter
        return f"{REGISTRY_DID}:agents:{agent_id}"

    def presentation(self, did: str, challenge: str) -> dict:
        agent_id = did.split(":")[-1]
        return {
            "holder": did,
            "challenge": challenge,
            "verifiableCredential": [{"credentialSubject": {"id": did, **self.charters[agent_id]}}],
        }

    def verify_presentation(self, presentation: dict, challenge: str) -> dict:
        holder = presentation["holder"]
        agent_id = holder.split(":")[-1]
        status = self.status.get(agent_id)
        ok_sigs = agent_id in self.keys and presentation.get("challenge") == challenge
        return {
            "valid": ok_sigs and status == "active",
            "holder": holder,
            "holder_signature_valid": ok_sigs,
            "charter_signature_valid": ok_sigs,
            "status": status,
            "error": None if ok_sigs else "Challenge mismatch.",
        }

    def agent_did_document(self, agent_id: str):
        jwk = self.keys.get(agent_id)
        if jwk is None:
            return None
        return {"verificationMethod": [{"publicKeyJwk": {**jwk, "kid": "key-1"}}]}


@pytest.fixture()
def signer() -> Signer:
    return Signer(Ed25519PrivateKey.generate())


@pytest.fixture()
def registry() -> FakeRegistry:
    return FakeRegistry()


@pytest.fixture()
def client(tmp_path, signer, registry):
    app = create_app(
        signer=signer, policy=POLICY, gateway=registry,
        database_url=f"sqlite:///{tmp_path / 'v.db'}", audience=AUDIENCE,
        admin_token="admin-secret",
    )
    with TestClient(app) as c:
        yield c


def proof(key: Ed25519PrivateKey, request_id: str, **overrides) -> str:
    payload = {"request_id": request_id, "aud": AUDIENCE, "iat": now(), **overrides}
    return encode_jws({"alg": "EdDSA", "typ": "agent-proof+jwt"}, payload, key.sign)


def enroll_request(client, key, caps=("observe", "publish"), scopes=("us-ca-napa",)):
    resp = client.post("/requests", json={
        "kind": "enroll",
        "requested": {"capabilities": list(caps), "scopes": list(scopes)},
        "justification": "fire monitoring, napa",
        "agent_public_jwk": public_jwk(key.public_key()),
    })
    assert resp.status_code == 201, resp.text
    return resp.json()


def collect(client, key, request_id):
    return client.get(f"/requests/{request_id}", headers={"Agent-Proof": proof(key, request_id)})


def decode_voucher(token: str, signer: Signer) -> dict:
    header, payload, signing_input, signature = decode_jws(token)
    jwk_to_public_key(signer.public_jwk()).verify(signature, signing_input)  # raises if bad
    assert header["kid"] == signer.kid
    return payload


# ── Enrollment: a human decides ──────────────────────────────────────────────

class TestEnroll:
    def test_enroll_is_pending_until_approved(self, client):
        key = Ed25519PrivateKey.generate()
        created = enroll_request(client, key)
        assert created["status"] == "pending"
        state = collect(client, key, created["request_id"]).json()
        assert state["status"] == "pending"
        assert "voucher" not in state

    def test_approve_mints_key_bound_voucher(self, client, signer):
        key = Ed25519PrivateKey.generate()
        created = enroll_request(client, key)
        resp = client.post(f"/admin/requests/{created['request_id']}/approve", json={}, headers=ADMIN)
        assert resp.status_code == 200
        state = collect(client, key, created["request_id"]).json()
        payload = decode_voucher(state["voucher"], signer)
        assert payload["purpose"] == "enroll"
        assert payload["sub"] == created["agent_id"] == state["agent_id"]
        assert payload["aud"] == REGISTRY_DID
        assert payload["operator"] == "did:web:operator.test"
        assert payload["cnf"]["jkt"] == jwk_thumbprint(public_jwk(key.public_key()))
        assert payload["capabilities"] == ["observe", "publish"]
        assert payload["scopes"] == ["us-ca-napa"]
        assert payload["exp"] - payload["iat"] == 600

    def test_agent_id_is_opaque_uuid(self, client):
        created = enroll_request(client, Ed25519PrivateKey.generate())
        assert len(created["agent_id"]) == 32
        int(created["agent_id"], 16)

    def test_approval_can_narrow(self, client, signer):
        key = Ed25519PrivateKey.generate()
        created = enroll_request(client, key)
        client.post(f"/admin/requests/{created['request_id']}/approve",
                    json={"capabilities": ["observe"]}, headers=ADMIN)
        payload = decode_voucher(collect(client, key, created["request_id"]).json()["voucher"], signer)
        assert payload["capabilities"] == ["observe"]

    def test_approval_cannot_widen(self, client):
        created = enroll_request(client, Ed25519PrivateKey.generate(), caps=("observe",))
        resp = client.post(f"/admin/requests/{created['request_id']}/approve",
                           json={"capabilities": ["observe", "publish"]}, headers=ADMIN)
        assert resp.status_code == 400

    def test_request_beyond_policy_refused(self, client):
        resp = client.post("/requests", json={
            "kind": "enroll",
            "requested": {"capabilities": ["admin"], "scopes": []},
            "agent_public_jwk": public_jwk(Ed25519PrivateKey.generate().public_key()),
        })
        assert resp.status_code == 403
        resp = client.post("/requests", json={
            "kind": "enroll",
            "requested": {"capabilities": ["observe"], "scopes": ["us-ca-marin"]},
            "agent_public_jwk": public_jwk(Ed25519PrivateKey.generate().public_key()),
        })
        assert resp.status_code == 403

    def test_enroll_needs_a_key(self, client):
        resp = client.post("/requests", json={"kind": "enroll",
                                              "requested": {"capabilities": ["observe"]}})
        assert resp.status_code == 422

    def test_deny(self, client):
        key = Ed25519PrivateKey.generate()
        created = enroll_request(client, key)
        resp = client.post(f"/admin/requests/{created['request_id']}/deny",
                           json={"reason": "not a known node"}, headers=ADMIN)
        assert resp.status_code == 200
        state = collect(client, key, created["request_id"]).json()
        assert state["status"] == "denied"
        assert state["reason"] == "not a known node"
        assert "voucher" not in state

    def test_decided_request_cannot_be_decided_again(self, client):
        created = enroll_request(client, Ed25519PrivateKey.generate())
        rid = created["request_id"]
        client.post(f"/admin/requests/{rid}/deny", json={}, headers=ADMIN)
        assert client.post(f"/admin/requests/{rid}/approve", json={}, headers=ADMIN).status_code == 409


# ── Collection: only the requesting key ──────────────────────────────────────

class TestCollection:
    def test_no_proof(self, client):
        created = enroll_request(client, Ed25519PrivateKey.generate())
        assert client.get(f"/requests/{created['request_id']}").status_code == 401

    def test_other_key_cannot_collect(self, client):
        key = Ed25519PrivateKey.generate()
        created = enroll_request(client, key)
        client.post(f"/admin/requests/{created['request_id']}/approve", json={}, headers=ADMIN)
        thief = Ed25519PrivateKey.generate()
        assert collect(client, thief, created["request_id"]).status_code == 403

    def test_proof_for_another_request_rejected(self, client):
        key = Ed25519PrivateKey.generate()
        a = enroll_request(client, key)
        b = enroll_request(client, key)
        resp = client.get(f"/requests/{a['request_id']}",
                          headers={"Agent-Proof": proof(key, b["request_id"])})
        assert resp.status_code == 403

    def test_wrong_audience_rejected(self, client):
        key = Ed25519PrivateKey.generate()
        created = enroll_request(client, key)
        rid = created["request_id"]
        resp = client.get(f"/requests/{rid}",
                          headers={"Agent-Proof": proof(key, rid, aud="https://elsewhere")})
        assert resp.status_code == 403

    def test_stale_proof_rejected(self, client):
        key = Ed25519PrivateKey.generate()
        created = enroll_request(client, key)
        rid = created["request_id"]
        resp = client.get(f"/requests/{rid}",
                          headers={"Agent-Proof": proof(key, rid, iat=now() - 3600)})
        assert resp.status_code == 403

    def test_unknown_request(self, client):
        key = Ed25519PrivateKey.generate()
        assert collect(client, key, "nope").status_code == 404


# ── Amend: charter-authenticated, policy may approve ─────────────────────────

class TestAmend:
    CHARTER = {"name": "fire", "capabilities": ["observe", "publish"], "scopes": ["us-ca-napa"],
               "operator": "did:web:operator.test"}

    def amend(self, client, registry, did, caps, scopes, challenge=None):
        challenge = challenge or client.get("/nonce").json()["nonce"]
        return client.post("/requests", json={
            "kind": "amend",
            "requested": {"capabilities": caps, "scopes": scopes},
            "presentation": registry.presentation(did, challenge),
            "challenge": challenge,
        })

    def test_within_auto_approve_is_immediate(self, client, registry, signer):
        key = Ed25519PrivateKey.generate()
        did = registry.add_agent(key, self.CHARTER)
        caps = ["observe", "publish", "publish:dev.watershed-agent.observation"]
        resp = self.amend(client, registry, did, caps, ["us-ca-napa", "us-ca-sonoma"])
        assert resp.status_code == 201
        created = resp.json()
        assert created["status"] == "approved"
        state = collect(client, key, created["request_id"]).json()
        payload = decode_voucher(state["voucher"], signer)
        assert payload["purpose"] == "amend"
        assert payload["sub"] == did.split(":")[-1]
        assert payload["cnf"]["jkt"] == jwk_thumbprint(public_jwk(key.public_key()))
        assert payload["capabilities"] == sorted(caps)

    def test_outside_auto_approve_waits_for_a_human(self, client, registry):
        """`publish` is within policy max but not on the auto-approve list."""
        key = Ed25519PrivateKey.generate()
        did = registry.add_agent(key, {**self.CHARTER, "capabilities": ["observe"]})
        resp = self.amend(client, registry, did, ["observe", "publish"], ["us-ca-napa"])
        assert resp.status_code == 201
        assert resp.json()["status"] == "pending"

    def test_challenge_single_use(self, client, registry):
        key = Ed25519PrivateKey.generate()
        did = registry.add_agent(key, self.CHARTER)
        challenge = client.get("/nonce").json()["nonce"]
        assert self.amend(client, registry, did, ["observe"], ["us-ca-napa"], challenge).status_code == 201
        assert self.amend(client, registry, did, ["observe"], ["us-ca-napa"], challenge).status_code == 403

    def test_unissued_challenge_rejected(self, client, registry):
        did = registry.add_agent(Ed25519PrivateKey.generate(), self.CHARTER)
        resp = self.amend(client, registry, did, ["observe"], ["us-ca-napa"], "made-up")
        assert resp.status_code == 403

    def test_foreign_registry_holder_rejected(self, client, registry):
        key = Ed25519PrivateKey.generate()
        registry.add_agent(key, self.CHARTER)
        challenge = client.get("/nonce").json()["nonce"]
        resp = client.post("/requests", json={
            "kind": "amend",
            "requested": {"capabilities": ["observe"], "scopes": []},
            "presentation": {"holder": "did:web:other.example:agents:x", "challenge": challenge,
                             "verifiableCredential": [{}]},
            "challenge": challenge,
        })
        assert resp.status_code == 403

    def test_revoked_agent_refused(self, client, registry):
        did = registry.add_agent(Ed25519PrivateKey.generate(), self.CHARTER, status="revoked")
        resp = self.amend(client, registry, did, ["observe"], ["us-ca-napa"])
        assert resp.status_code == 403

    def test_expired_agent_may_amend(self, client, registry):
        """An expired charter with valid signatures can be re-confirmed by the operator."""
        did = registry.add_agent(Ed25519PrivateKey.generate(), self.CHARTER, status="expired")
        resp = self.amend(client, registry, did, ["observe", "publish"], ["us-ca-napa"])
        assert resp.status_code == 201

    def test_amend_beyond_policy_refused(self, client, registry):
        did = registry.add_agent(Ed25519PrivateKey.generate(), self.CHARTER)
        resp = self.amend(client, registry, did, ["observe", "admin"], ["us-ca-napa"])
        assert resp.status_code == 403


# ── Operator API and issuance log ────────────────────────────────────────────

class TestOperatorApi:
    def test_requires_token(self, client):
        assert client.get("/admin/requests").status_code == 401
        assert client.get("/admin/requests",
                          headers={"Authorization": "Bearer wrong"}).status_code == 401

    def test_disabled_without_token(self, tmp_path, signer, registry):
        app = create_app(signer=signer, policy=POLICY, gateway=registry,
                         database_url=f"sqlite:///{tmp_path / 'x.db'}", audience=AUDIENCE)
        with TestClient(app) as c:
            assert c.get("/admin/requests", headers=ADMIN).status_code == 503

    def test_list_pending(self, client):
        enroll_request(client, Ed25519PrivateKey.generate())
        rows = client.get("/admin/requests", params={"status": "pending"}, headers=ADMIN).json()
        assert len(rows) == 1
        assert rows[0]["justification"] == "fire monitoring, napa"

    def test_issuance_logged(self, client):
        key = Ed25519PrivateKey.generate()
        created = enroll_request(client, key)
        client.post(f"/admin/requests/{created['request_id']}/approve",
                    json={"approver": "cprice"}, headers=ADMIN)
        log = client.get("/admin/issued", headers=ADMIN).json()
        assert len(log) == 1
        assert log[0]["agent_id"] == created["agent_id"]
        assert log[0]["approved_by"] == "cprice"
        assert log[0]["jkt"] == jwk_thumbprint(public_jwk(key.public_key()))


# ── Policy and the registry ceiling ──────────────────────────────────────────

class TestJwksCeiling:
    def test_jwks_ceiling_is_policy_max(self, tmp_path, signer, capsys, monkeypatch):
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat,
        )
        from voucher_service import cli

        key_path = tmp_path / "op.pem"
        key_path.write_bytes(signer._key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text(
            "operator: did:web:operator.test\n"
            f"registry_did: {REGISTRY_DID}\n"
            "max:\n  capabilities: [publish, observe]\n  scopes: [us-ca-napa]\n"
        )
        monkeypatch.setattr("sys.argv", ["voucherctl", "jwks", "--key", str(key_path),
                                         "--policy", str(policy_path)])
        cli.main()
        jwk = json.loads(capsys.readouterr().out)["keys"][0]
        assert jwk["kid"] == signer.kid
        assert jwk["ceiling"] == {"capabilities": ["observe", "publish"], "scopes": ["us-ca-napa"]}

    def test_unscoped_operator_omits_scopes(self, signer):
        from voucher_service.minting import mint_voucher
        policy = Policy.from_dict({"operator": "o", "registry_did": REGISTRY_DID,
                                   "max": {"capabilities": ["observe"]}})
        _, payload = mint_voucher(signer, policy, agent_id="a",
                                  agent_jwk=public_jwk(Ed25519PrivateKey.generate().public_key()),
                                  purpose="enroll", capabilities=["observe"], scopes=[])
        assert "scopes" not in payload
