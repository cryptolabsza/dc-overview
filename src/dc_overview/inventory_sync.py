"""Durable DC-to-IPMI inventory reconciliation client."""

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


def deliver_inventory_outbox(entry):
    """Deliver a persisted desired state and accept only an exact receiver acknowledgment."""
    secret = configured_inventory_secret()
    url = configured_inventory_url()
    if not secret or not url:
        entry.last_error = "IPMI inventory service is not configured"
        entry.attempts += 1
        return False

    payload = json.loads(entry.payload)
    try:
        response = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {secret}"},
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
    if isinstance(accepted, dict) and all(accepted.get(key) == value for key, value in expected.items()):
        entry.delivered = True
        entry.last_error = None
        return True

    entry.attempts += 1
    entry.last_error = "IPMI inventory receiver did not acknowledge the desired revision"
    return False
