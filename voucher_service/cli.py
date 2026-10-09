"""
voucherctl — the operator's side of the voucher service.

  voucherctl list [--status pending]
  voucherctl approve <request_id> [--capabilities a,b] [--scopes x,y]
  voucherctl deny <request_id> --reason "..."
  voucherctl issued
  voucherctl jwks --key operator.key.pem --policy policy.yaml [--out jwks.json]

The first four talk to the running service (VOUCHER_SERVICE_URL, VOUCHER_ADMIN_TOKEN).
``jwks`` is local: it writes the public JWKS the registry should trust for this
key, with the policy's ``max`` as the key's ceiling, so the registry's limit and
this service's limit are the same set.
"""
import argparse
import json
import os
import sys
from pathlib import Path

import httpx

from voucher_service.crypto import Signer
from voucher_service.policy import Policy


def _csv(value):
    if value is None:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


def _client() -> httpx.Client:
    url = os.environ.get("VOUCHER_SERVICE_URL", "http://127.0.0.1:8100").rstrip("/")
    token = os.environ.get("VOUCHER_ADMIN_TOKEN", "")
    if not token:
        sys.exit("Set VOUCHER_ADMIN_TOKEN.")
    return httpx.Client(base_url=url, headers={"Authorization": f"Bearer {token}"}, timeout=10)


def _show(resp: httpx.Response) -> None:
    if resp.status_code >= 400:
        sys.exit(f"{resp.status_code}: {resp.text}")
    print(json.dumps(resp.json(), indent=2))


def cmd_list(args) -> None:
    params = {"status": args.status} if args.status else {}
    with _client() as c:
        _show(c.get("/admin/requests", params=params))


def cmd_approve(args) -> None:
    body = {"capabilities": _csv(args.capabilities), "scopes": _csv(args.scopes),
            "approver": args.approver}
    with _client() as c:
        _show(c.post(f"/admin/requests/{args.request_id}/approve", json=body))


def cmd_deny(args) -> None:
    with _client() as c:
        _show(c.post(f"/admin/requests/{args.request_id}/deny", json={"reason": args.reason}))


def cmd_issued(args) -> None:
    with _client() as c:
        _show(c.get("/admin/issued"))


def cmd_jwks(args) -> None:
    signer = Signer.from_pem_file(Path(args.key))
    policy = Policy.from_file(Path(args.policy))
    ceiling = {"capabilities": sorted(policy.max.capabilities)}
    if policy.max.scopes:
        ceiling["scopes"] = sorted(policy.max.scopes)
    text = json.dumps({"keys": [{**signer.public_jwk(), "ceiling": ceiling}]}, indent=2)
    if args.out:
        Path(args.out).write_text(text)
        print(f"Wrote {args.out}. Add this key to the registry's OPERATOR_JWKS_PATH file.")
    else:
        print(text)


def main() -> None:
    parser = argparse.ArgumentParser(prog="voucherctl", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("list", help="List requests")
    p.add_argument("--status", choices=["pending", "approved", "denied"])
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("approve", help="Approve a request, optionally narrowing it")
    p.add_argument("request_id")
    p.add_argument("--capabilities", help="Comma-separated; must be within what was asked")
    p.add_argument("--scopes", help="Comma-separated; must be within what was asked")
    p.add_argument("--approver", default=os.environ.get("USER", "operator"))
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("deny", help="Deny a request")
    p.add_argument("request_id")
    p.add_argument("--reason", default="")
    p.set_defaults(func=cmd_deny)

    p = sub.add_parser("issued", help="Show the issuance log")
    p.set_defaults(func=cmd_issued)

    p = sub.add_parser("jwks", help="Export this key's JWKS with the policy max as its ceiling")
    p.add_argument("--key", default="operator.key.pem")
    p.add_argument("--policy", default="policy.yaml")
    p.add_argument("--out")
    p.set_defaults(func=cmd_jwks)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
