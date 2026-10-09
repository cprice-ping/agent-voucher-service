"""
Operator voucher service.

An operator's always-on front door to the Agentic-DID-Registry.  Agents ask for
enrollment or amend vouchers here; the operator's policy (and, for first
enrollment, a human) decides; the service mints a short-lived voucher bound to
the agent's key.  The agent then takes the voucher to the registry itself.

This service is the operator, not the registry.  It never runs in the registry
process and never holds the registry's key.  The registry independently clamps
what this service signs against the ceiling configured for its key, so a
compromised voucher service still cannot mint beyond that ceiling.
"""
