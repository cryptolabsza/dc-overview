"""Credential-source selection for local DC Server Management."""

import os
from pathlib import Path


_VAULT_MANIFEST = Path("/etc/dc-overview/secrets/credential-sources.json")


def credential_authority():
    """Return ``local``, ``vault``, or ``invalid`` without probing a network."""
    explicit = os.environ.get("FLEET_CREDENTIAL_AUTHORITY")
    if explicit is not None:
        selected = explicit.strip().lower()
        return selected if selected in {"local", "vault"} else "invalid"
    if _VAULT_MANIFEST.exists() or os.environ.get("IPMI_BMC_CREDENTIALS_FILE", "").strip():
        return "vault"
    return "local"


def credential_mutation_error():
    """Explain why local credential writes are unavailable, if they are."""
    selected = credential_authority()
    if selected == "local":
        return None
    if selected == "vault":
        return "Credentials are vault-managed and read-only in Server Management"
    return "FLEET_CREDENTIAL_AUTHORITY must be local or vault"
