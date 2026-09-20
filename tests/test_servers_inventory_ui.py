"""Browser regressions for the Server Manager inventory controls."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from flask import Flask, jsonify, render_template
from werkzeug.serving import make_server

pytestmark = pytest.mark.skipif(
    shutil.which("agent-browser") is None,
    reason="agent-browser is required for rendered-template DOM regressions",
)

TEMPLATE_DIR = Path(__file__).parents[1] / "src/dc_overview/web_templates"


class InventoryUiScenario:
    def __init__(self, *, check_delay: float = 0, include_tombstone: bool = False):
        self.check_delay = check_delay
        self.include_tombstone = include_tombstone
        self.check_started = threading.Event()
        self.inventory_requested = threading.Event()
        self.check_count = 0
        self.retried = False

    def inventory_payload(self):
        return {
            "id": 1,
            "name": "ccc90",
            "server_ip": "10.10.0.90",
            "bmc_ip": "10.20.0.90",
            "inventory": {
                "state": "synchronized" if self.retried else "pending",
                "revision": 4,
                "retry_id": None if self.retried else 73,
                "error": None if self.retried else "receiver <offline>",
            },
        }


def _rendered_server():
    return SimpleNamespace(
        id=1,
        name="ccc90",
        server_name="ccc90",
        server_ip="10.10.0.90",
        bmc_ip="10.20.0.90",
        ssh_user="root",
        ssh_port=22,
        ssh_key=None,
        ssh_password=None,
        node_exporter_installed=False,
        node_exporter_enabled=False,
        dc_exporter_installed=False,
        dc_exporter_enabled=False,
        dcgm_exporter_installed=False,
        dcgm_exporter_enabled=False,
        watchdog_agent_installed=False,
        watchdog_agent_enabled=False,
        exporters=[],
        inventory={},
    )


@contextmanager
def _serve_servers_template(scenario: InventoryUiScenario):
    app = Flask("inventory-ui-test", template_folder=str(TEMPLATE_DIR))

    @app.get("/dc/servers")
    def servers_page():
        return render_template(
            "servers.html",
            servers=[_rendered_server()],
            ssh_keys=[],
            version="test",
            is_dev=True,
        )

    @app.get("/dc/api/auth/status")
    def auth_status():
        return jsonify(
            {
                "role": "admin",
                "permissions": {"can_read": True, "can_write": True, "can_admin": True},
            }
        )

    @app.post("/dc/api/watchdog-agents/sync")
    def watchdog_sync():
        return jsonify({"status": "ok"})

    @app.get("/dc/api/servers/1/check")
    def check_server():
        scenario.check_count += 1
        scenario.check_started.set()
        if scenario.check_delay:
            time.sleep(scenario.check_delay)
        return jsonify(
            {
                "status": "offline",
                "last_seen": "2026-09-12T12:00:00Z",
                "node_exporter": {"running": False, "version": "1.2.3"},
                "dc_exporter": {"running": False},
                "dcgm_exporter": {"running": False},
                "watchdog_agent": {"running": False},
            }
        )

    @app.get("/dc/api/servers")
    def servers_api():
        scenario.inventory_requested.set()
        return jsonify([scenario.inventory_payload()])

    @app.get("/dc/api/inventory/outbox")
    def outbox_api():
        if scenario.retried or not scenario.include_tombstone:
            return jsonify([])
        return jsonify(
            [
                {
                    "id": 73,
                    "operation": "retire",
                    "name": "retired-ccc91",
                    "bmc_ip": "10.20.0.91",
                    "attempts": 2,
                    "error": "receiver <offline>",
                }
            ]
        )

    @app.post("/dc/api/inventory/outbox/73/retry")
    def retry_outbox():
        scenario.retried = True
        return jsonify({"state": "synchronized", "retry_id": 73})

    server = make_server(
        "127.0.0.1", int(os.environ.get("DC_UI_TEST_PORT", "0")), app, threaded=True
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/dc/servers"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def _browser(session: str, *arguments: str) -> str:
    result = subprocess.run(
        ["agent-browser", "--session", session, *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout.strip()


def _browser_value(session: str, expression: str):
    return json.loads(_browser(session, "eval", expression))


def _browser_json(session: str, expression: str):
    return json.loads(_browser_value(session, expression))


def _eventually(session: str, expression: str, timeout: float = 3) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _browser_value(session, expression):
            return
        time.sleep(0.1)
    assert _browser_value(session, expression), expression


@contextmanager
def _browser_page(url: str):
    session = os.environ.get("DC_UI_BROWSER_SESSION", f"dc-ui-{uuid.uuid4().hex}")
    _browser(session, "open", url)
    try:
        yield session
    finally:
        _browser(session, "close")


def test_server_check_keeps_action_controls_clickable():
    scenario = InventoryUiScenario()
    with _serve_servers_template(scenario) as url, _browser_page(url) as session:
        _eventually(
            session,
            "document.querySelector('.exporter-status').textContent.includes('1.2.3')",
        )
        assert _browser_json(
            session,
            "JSON.stringify(Array.from(document.querySelectorAll('#serversTable tr[data-id] td:last-child button')).map(button => button.textContent))",
        ) == ["Manage", "Edit", "Map BMC", "Check", "Delete"]
        _browser_value(
            session,
            "Array.from(document.querySelectorAll('#serversTable tr[data-id] td:last-child button')).find(button => button.textContent === 'Check').click(); true",
        )
        deadline = time.monotonic() + 2
        while scenario.check_count < 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert scenario.check_count == 2


def test_inventory_state_refreshes_while_a_server_check_is_slow():
    scenario = InventoryUiScenario(check_delay=2)
    with _serve_servers_template(scenario) as url, _browser_page(url) as session:
        assert scenario.check_started.wait(timeout=2), "the rendered page never began its check"
        assert scenario.inventory_requested.wait(timeout=0.75), (
            "inventory state waited for the slow server check"
        )
        _eventually(
            session,
            "document.getElementById('inventory-1').textContent.includes('Pending revision 4')",
        )


def test_pending_retirement_retry_is_visible_safe_and_refreshes_state():
    scenario = InventoryUiScenario(include_tombstone=True)
    with _serve_servers_template(scenario) as url, _browser_page(url) as session:
        _eventually(
            session,
            "document.getElementById('pendingInventorySection') && !document.getElementById('pendingInventorySection').hidden",
        )
        pending = _browser_json(
            session,
            "JSON.stringify({text: document.getElementById('pendingInventorySection').textContent, image: Boolean(document.querySelector('#pendingInventorySection img'))})",
        )
        assert "retired-ccc91" in pending["text"]
        assert "BMC 10.20.0.91" in pending["text"]
        assert "Retire" in pending["text"]
        assert "receiver <offline>" in pending["text"]
        assert pending["image"] is False
        _browser_value(
            session,
            "document.querySelector(\"[data-inventory-retry='73']\").click(); true",
        )
        _eventually(
            session,
            "document.getElementById('pendingInventorySection').hidden && document.getElementById('inventory-1').textContent.includes('Synchronized revision 4')",
        )


def test_outbox_api_exposes_pending_retirement_metadata_and_retry_state(
    app, client, auth_headers
):
    """A real DC deletion leaves the UI its retryable retirement metadata."""
    from dc_overview.app import Server, db

    with app.app_context():
        server = Server(
            name="retired-ccc91", server_ip="10.10.0.91", bmc_ip="10.20.0.91"
        )
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    with patch("dc_overview.app.deliver_inventory_outbox", return_value=False):
        deleted = client.delete(f"/api/servers/{server_id}", headers=auth_headers)
    assert deleted.get_json()["inventory"]["state"] == "pending"

    response = client.get("/api/inventory/outbox", headers=auth_headers)
    assert response.status_code == 200
    pending = response.get_json()[0]
    assert {
        key: pending[key]
        for key in ("operation", "name", "bmc_ip", "source_server_id")
    } == {
        "operation": "retire",
        "name": "retired-ccc91",
        "bmc_ip": "10.20.0.91",
        "source_server_id": pending["source_server_id"],
    }

    with patch("dc_overview.app.deliver_inventory_outbox", return_value=True):
        retried = client.post(
            f"/api/inventory/outbox/{pending['id']}/retry", headers=auth_headers
        )
    assert retried.get_json()["state"] == "synchronized"
