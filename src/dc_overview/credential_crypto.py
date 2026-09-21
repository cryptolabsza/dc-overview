"""Shared-key encryption primitives for DC-to-IPMI credential bundles."""

import base64
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


TRANSPORT_INFO = b"dc-overview/ipmi-credentials/v1"
AT_REST_INFO = b"dc-overview/local-bmc-credentials/v1"


class CredentialCryptoError(ValueError):
    """A credential secret or encrypted value cannot be used safely."""


def _fernet(secret: str, info: bytes) -> Fernet:
    if not isinstance(secret, str) or not secret:
        raise CredentialCryptoError("Inventory credential key is not configured")
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=info
    ).derive(secret.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_transport(payload: dict[str, Any], secret: str) -> str:
    plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _fernet(secret, TRANSPORT_INFO).encrypt(plaintext).decode("ascii")


def encrypt_bmc_password(password: str, secret: str) -> str:
    return _fernet(secret, AT_REST_INFO).encrypt(password.encode("utf-8")).decode("ascii")


def decrypt_bmc_password(token: str, secret: str) -> str:
    try:
        return _fernet(secret, AT_REST_INFO).decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeError) as error:
        raise CredentialCryptoError("Stored BMC credential cannot be decrypted") from error
