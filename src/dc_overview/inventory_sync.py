"""Durable DC-to-IPMI inventory reconciliation client."""

import hashlib
import hmac
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import requests


INTERNAL_INVENTORY_ORIGIN = "http://ipmi-monitor:5000"
INTERNAL_RECONCILE_PATH = "/api/internal/inventory/reconcile"


def configured_inventory_secret():
    path = os.environ.get("DC_IPMI_INVENTORY_SECRET_FILE")
    if not path:
        return None
    try:
        return Path(path).read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def configured_inventory_url():
    """Return the sole approved internal reconciliation endpoint, or ``None``.

    The environment may opt DC into reconciliation, but it cannot redirect the
    service secret or inventory metadata to a user-controlled destination.
    """
    raw_url = os.environ.get("IPMI_INVENTORY_URL", "").strip()
    if not raw_url:
        return None
    try:
        parsed = urlsplit(raw_url)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "http"
        or parsed.hostname != "ipmi-monitor"
        or port != 5000
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        return None
    return INTERNAL_INVENTORY_ORIGIN + INTERNAL_RECONCILE_PATH


def inventory_delivery_is_configured():
    """Whether this process is allowed to make a reconciliation request."""
    return bool(configured_inventory_secret() and configured_inventory_url())


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _request_headers(secret, payload):
    signature = hmac.new(secret.encode("utf-8"), _canonical_json(payload), hashlib.sha256).hexdigest()
    return {"Authorization": f"DC-HMAC {signature}"}


def deliver_inventory_outbox(entry):
    """Deliver a persisted desired state and accept only an exact receiver acknowledgment."""
    secret = configured_inventory_secret()
    url = configured_inventory_url()
    if not secret or not url:
        entry.last_error = "IPMI inventory service is not configured"
        entry.attempts += 1
        return False

    payload = json.loads(entry.payload)
    if payload.pop("credential_pending", False):
        entry.last_error = "IPMI credential bundle is pending a configured transport key"
        entry.attempts += 1
        return False
    response = None
    response_body = None
    try:
        response = requests.post(
            url,
            json=payload,
            headers=_request_headers(secret, payload),
            timeout=5,
            allow_redirects=False,
        )
        response_body = response.json() if response.ok else None
        accepted = response_body.get("accepted") if isinstance(response_body, dict) else None
    except (requests.RequestException, ValueError):
        accepted = None

    expected = {key: payload[key] for key in ("source_id", "server_id", "revision", "name", "server_ip", "bmc_ip")}
    expected["status"] = "deprecated" if payload["operation"] == "retire" else "active"
    expected["enabled"] = payload["operation"] != "retire"
    credential_acknowledged = True
    bundle = payload.get("credential_bundle")
    if bundle is not None:
        digest = hashlib.sha256(bundle.encode("utf-8")).hexdigest()
        signature = getattr(response, "headers", {}).get("X-DC-Response-Signature", "")
        if not isinstance(signature, str):
            signature = ""
        canonical_response = _canonical_json(response_body) if isinstance(response_body, dict) else b""
        expected_signature = hmac.new(secret.encode("utf-8"), canonical_response, hashlib.sha256).hexdigest()
        credential_acknowledged = (
            isinstance(response_body, dict)
            and hmac.compare_digest(signature, expected_signature)
            and response_body.get("credential_revision") == payload["revision"]
            and hmac.compare_digest(str(response_body.get("credential_digest", "")), digest)
        )
    if (isinstance(accepted, dict) and all(accepted.get(key) == value for key, value in expected.items())
            and credential_acknowledged):
        entry.delivered = True
        entry.last_error = None
        return True

    entry.attempts += 1
    entry.last_error = "IPMI inventory receiver did not acknowledge the desired revision"
    return False
