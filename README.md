# agent-voucher-service

An operator's front door to the [Agentic-DID-Registry](https://github.com/cprice-ping/Agentic-DID-Registry).
Agents ask here for the voucher they need to get a charter. The operator's policy,
and for a first enrolment a human, decides. The service signs a short-lived voucher
bound to the agent's key, and the agent takes it to the registry itself.

It replaces running `operator_cli.py voucher` by hand for every agent. The operator
stops approving each agent and starts setting a ceiling. A human stays accountable
for the limit, and the system handles each agent within it.

## Where it sits

```
agent ──request──► voucher service ──voucher──► agent ──enrol / reissue──► registry
                   (operator policy,                     (clamps charter ≤ voucher
                    human approval,                       ≤ this key's ceiling)
                    issuance log)
```

This service is the operator, not the registry, and the split matters:

- It never runs in the registry process and never holds the registry's key.
- It never talks to the registry on an agent's behalf. It only uses the registry's
  public API to check a presentation and look up an agent's current key.
- The registry independently enforces the ceiling configured for this service's
  key, so a compromised voucher service still can't mint beyond it.

There are two limits, and they are deliberately the same set: the policy's `max`
here, and the key's ceiling at the registry. `voucherctl jwks` writes one from the
other.

## How a request is decided

| Request | Who is asking | Proven by | Decided by |
|---|---|---|---|
| `enroll` | an agent with no charter yet | nothing yet; this is where the bootstrap regress stops | a human (`voucherctl approve`), who may narrow it |
| `amend` | an agent with a charter | a presentation of its current charter, signed with its key, over a single-use challenge | policy (`auto_approve.amend`), or a human if it falls outside |

Every voucher is:

- bound to the agent's key (`cnf.jkt`), so only that key can enrol with it at the registry
- collectable only by that key: polling needs an `Agent-Proof` signed by it
- single-use and short-lived at the registry
- written to the issuance log, with who approved it

An amend asks for the full set of capabilities and scopes the agent wants afterwards,
not just the additions. Auto-approval allows anything already in the charter plus
the auto-approve list. Expired charters can be amended (that's the operator
re-confirming). Revoked ones can't.

## Run it

```bash
pip install -e ".[dev]"

# The operator key. Same format as the registry repo's operator_cli.py.
python /path/to/Agentic-DID-Registry/operator_cli.py keygen --out operator.key.pem
cp policy.example.yaml policy.yaml        # then edit

# The JWKS the registry should trust for this key, with policy max as its ceiling.
# Add the key to the registry's OPERATOR_JWKS_PATH file.
voucherctl jwks --key operator.key.pem --policy policy.yaml --out voucher-service.jwks.json

OPERATOR_KEY_PATH=operator.key.pem POLICY_PATH=policy.yaml \
REGISTRY_URL=https://registry.cpricedomain.net \
SERVICE_AUDIENCE=https://vouchers.example ADMIN_TOKEN=$(openssl rand -hex 24) \
uvicorn --factory voucher_service.main:create_app_from_env --port 8100
```

| Variable | Default | |
|---|---|---|
| `OPERATOR_KEY_PATH` | `operator.key.pem` | voucher-signing key (Ed25519 PEM) |
| `POLICY_PATH` | `policy.yaml` | see `policy.example.yaml` |
| `REGISTRY_URL` | `http://127.0.0.1:8000` | for `/verify` and DID lookups |
| `DATABASE_URL` | `sqlite:///./vouchers.db` | requests, nonces, issuance log |
| `SERVICE_AUDIENCE` | `http://127.0.0.1:8100` | this service's public URL; agent proofs are bound to it |
| `ADMIN_TOKEN` | unset | operator API token; unset disables the operator API |

Keep the operator API off the public internet. Bind it to loopback, or put it
behind your own access control. The token is a v1 convenience, not the boundary.

## Operator CLI

```bash
export VOUCHER_SERVICE_URL=http://127.0.0.1:8100 VOUCHER_ADMIN_TOKEN=...
voucherctl list --status pending
voucherctl approve <request_id> --scopes us-ca-napa     # optionally narrow
voucherctl deny <request_id> --reason "not a known node"
voucherctl issued
```

## Agent side

Copy `voucher_client.py` next to the registry's `registry_client.py`:

```python
from registry_client import RegistryClient
from voucher_client import VoucherClient

registry = RegistryClient(registry_url="https://registry.cpricedomain.net")
vouchers = VoucherClient("https://vouchers.example")

did = vouchers.enroll(registry, {"name": "fire", "scope": "...", "intent": "..."},
                      capabilities=["observe", "publish"], scopes=["us-ca-napa"])

vouchers.amend(registry, did,
               capabilities=["observe", "publish", "publish:dev.watershed-agent.observation"],
               scopes=["us-ca-napa", "us-ca-sonoma"])
```

`enroll` generates the key locally, waits for approval, narrows the charter to
whatever was approved, and enrols. `amend` presents the current charter, waits,
and reissues at the registry with the same DID and key, so pins and bindings held by
services survive. It needs the registry's `POST /agents/{id}/charter` (registry
PR #11).

## Tested

`pytest` runs 29 in-process tests against a fake registry. They cover:

- enrolment approval and narrowing
- refusals beyond policy
- collection only by the requesting key, with request, audience and staleness binding
- amend auto-approval vs. a human decision, single-use challenges, foreign registries, revoked and expired agents
- the operator API, the issuance log, and the JWKS ceiling

End to end, against the real registry (PR #11), run as separate processes:

1. An agent asked for `observe,publish` in Napa and Sonoma.
2. A different key was refused while the request was pending.
3. `voucherctl approve --scopes us-ca-napa` narrowed it, and the agent enrolled with a key-bound voucher.
4. An amend to `publish:dev.watershed-agent.observation` plus Sonoma was approved by policy with no human, and reissued with the same DID and status index.
5. A voucher signed directly with this service's key for `admin` was refused by the registry's ceiling.

## Next

- **SPIRE (phase 2).** Accept a JWT-SVID as request authentication, validated against the
  SPIRE trust bundle, with policy keyed by SPIFFE-ID patterns. That lets workloads
  in k8s or the cloud get a first voucher with no human: attestation answers *who*,
  and this policy still answers *what*. The voucher format and the registry don't
  change.
- **Key custody.** `Signer` is the seam for a KMS or HSM. v1 reads a PEM file.
- **One charter per operator** is a registry change. Until then, an amend from a
  different operator than the charter's is refused there (409).
