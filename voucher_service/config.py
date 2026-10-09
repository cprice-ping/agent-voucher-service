"""Configuration, read from the environment once at import."""
import os
from pathlib import Path

#: The operator's Ed25519 signing key (PKCS#8 PEM).  The registry trusts its
#: public half via OPERATOR_JWKS_PATH; export that with ``voucherctl jwks``.
OPERATOR_KEY_PATH = Path(os.environ.get("OPERATOR_KEY_PATH", "operator.key.pem"))

#: What this operator will vouch for, and what it will auto-approve.
POLICY_PATH = Path(os.environ.get("POLICY_PATH", "policy.yaml"))

#: Base URL of the registry, used to verify presentations and resolve DIDs.
REGISTRY_URL = os.environ.get("REGISTRY_URL", "http://127.0.0.1:8000").rstrip("/")

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./vouchers.db")

#: This service's own public URL.  Agent proofs are audience-bound to it.
SERVICE_AUDIENCE = os.environ.get("SERVICE_AUDIENCE", "http://127.0.0.1:8100")

#: Bearer token for the operator API.  Unset ⇒ the operator API is disabled.
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
