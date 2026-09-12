"""Regression coverage for DC's durable IPMI inventory sender."""

from unittest.mock import Mock, patch
from types import SimpleNamespace
import os
import sqlite3
import subprocess
import sys
import threading

import requests


def _configure_inventory(monkeypatch, tmp_path):
    secret_file = tmp_path / "dc-ipmi-inventory-secret"
    secret_file.write_text("test-inventory-secret\n")
    monkeypatch.setenv("DC_IPMI_INVENTORY_SECRET_FILE", str(secret_file))
    monkeypatch.setenv("IPMI_INVENTORY_URL", "http://ipmi-monitor:5000")


def _acknowledgment(payload):
    accepted = {
        key: payload[key]
        for key in ("source_id", "server_id", "revision", "name", "server_ip", "bmc_ip")
    }
    accepted["status"] = "deprecated" if payload["operation"] == "retire" else "active"
    accepted["enabled"] = payload["operation"] != "retire"
    return Mock(ok=True, json=lambda: {"accepted": accepted})


def test_add_server_persists_and_delivers_revisioned_inventory(app, client, auth_headers, monkeypatch, tmp_path):
    """The public create entry point persists a durable message before a fixed-URL delivery."""
    _configure_inventory(monkeypatch, tmp_path)

    with patch("dc_overview.inventory_sync.requests.post") as post:
        post.side_effect = lambda _url, json, **_kwargs: _acknowledgment(json)
        response = client.post(
            "/api/servers",
            json={"name": "ccc90", "server_ip": "10.10.0.90", "bmc_ip": "10.20.0.90"},
            headers=auth_headers,
        )

    assert response.status_code == 201
    assert post.call_args.args[0] == "http://ipmi-monitor:5000/api/internal/inventory/reconcile"
    payload = post.call_args.kwargs["json"]
    assert payload["operation"] == "upsert"
    assert payload["revision"] == 1
    assert post.call_args.kwargs["headers"] == {"Authorization": "Bearer test-inventory-secret"}

    from dc_overview.app import InventoryOutbox, Server, db
    with app.app_context():
        server = Server.query.filter_by(name="ccc90").one()
        outbox = InventoryOutbox.query.filter_by(source_server_id=server.inventory_server_id).one()
        assert outbox.delivered is True
        assert outbox.revision == 1


def test_delete_keeps_tombstone_outbox_when_receiver_is_unavailable(app, client, auth_headers, monkeypatch, tmp_path):
    """A failed retire delivery cannot lose the retry record when its DC parent is deleted."""
    _configure_inventory(monkeypatch, tmp_path)
    from dc_overview.app import InventoryOutbox, Server, db

    with app.app_context():
        server = Server(name="ccc91", server_ip="10.10.0.91", bmc_ip="10.20.0.91")
        db.session.add(server)
        db.session.commit()
        server_id = server.id
        source_server_id = server.inventory_server_id

    with patch("dc_overview.inventory_sync.requests.post", side_effect=requests.ConnectionError("offline")):
        response = client.delete(f"/api/servers/{server_id}", headers=auth_headers)

    assert response.status_code == 200
    with app.app_context():
        assert Server.query.get(server_id) is None
        tombstone = InventoryOutbox.query.filter_by(source_server_id=source_server_id).one()
        assert tombstone.delivered is False
        assert tombstone.revision == 1
        assert '"operation": "retire"' in tombstone.payload


def test_non_object_receiver_ack_stays_pending_without_crashing(app, client, auth_headers, monkeypatch, tmp_path):
    """Malformed acknowledgments cannot be mistaken for a completed reconciliation."""
    _configure_inventory(monkeypatch, tmp_path)
    response = Mock(ok=True, json=lambda: ["not", "an", "acknowledgment"])
    with patch("dc_overview.inventory_sync.requests.post", return_value=response):
        created = client.post(
            "/api/servers",
            json={"name": "ccc92", "server_ip": "10.10.0.92", "bmc_ip": "10.20.0.92"},
            headers=auth_headers,
        )
    assert created.status_code == 201
    assert created.get_json()["inventory"]["state"] == "pending"


def test_existing_server_mapping_update_and_pending_outbox_are_visible_and_retryable(app, client, auth_headers, monkeypatch, tmp_path):
    """The actual HTTP operator flow keeps identity stable and exposes a durable retry."""
    _configure_inventory(monkeypatch, tmp_path)
    from dc_overview.app import InventoryOutbox, Server, db
    with app.app_context():
        server = Server(name="vm-without-bmc", server_ip="10.10.0.50")
        db.session.add(server)
        db.session.commit()
        server_id = server.id
        stable_id = server.inventory_server_id

    with patch("dc_overview.inventory_sync.requests.post", side_effect=requests.ConnectionError("offline")):
        mapped = client.put(f"/api/servers/{server_id}/inventory", json={"bmc_ip": "10.20.0.50"}, headers=auth_headers)
        assert mapped.status_code == 200
        edited = client.put(
            f"/api/servers/{server_id}",
            json={"name": "vm-renamed", "server_ip": "10.10.0.51"}, headers=auth_headers,
        )
        assert edited.status_code == 200

    inventory = client.get("/api/servers", headers=auth_headers).get_json()
    listed = next(item for item in inventory if item["id"] == server_id)
    assert listed["inventory"]["state"] == "pending"
    assert listed["inventory"]["revision"] == 2
    with app.app_context():
        server = Server.query.get(server_id)
        assert server.inventory_server_id == stable_id
        pending = InventoryOutbox.query.filter_by(source_server_id=stable_id, delivered=False).one()
        assert pending.revision == 2

    with patch("dc_overview.inventory_sync.requests.post") as post:
        post.side_effect = lambda _url, json, **_kwargs: _acknowledgment(json)
        retried = client.post(f"/api/inventory/outbox/{pending.id}/retry", headers=auth_headers)
    assert retried.get_json()["state"] == "synchronized"


def test_invalid_or_duplicate_existing_bmc_mapping_returns_4xx(app, client, auth_headers):
    """Operator mapping mistakes are validation responses, never a database 500."""
    from dc_overview.app import Server, db
    with app.app_context():
        first = Server(name="one", server_ip="10.10.1.1", bmc_ip="10.20.1.1")
        second = Server(name="two", server_ip="10.10.1.2")
        db.session.add_all([first, second])
        db.session.commit()
        second_id = second.id
    assert client.put(f"/api/servers/{second_id}/inventory", json={"bmc_ip": "bad"}, headers=auth_headers).status_code == 400
    assert client.put(f"/api/servers/{second_id}/inventory", json={"bmc_ip": "10.20.1.1"}, headers=auth_headers).status_code == 409


def test_server_inventory_endpoints_reject_non_object_json_and_duplicate_bmc(app, client, auth_headers):
    """Malformed JSON and an already-bound BMC are client errors, never SQLite 500s."""
    from dc_overview.app import Server, db
    with app.app_context():
        server = Server(name="existing", server_ip="10.10.2.1", bmc_ip="10.20.2.1")
        second = Server(name="without-bmc", server_ip="10.10.2.2")
        db.session.add_all([server, second])
        db.session.commit()
        second_id = second.id

    assert client.post("/api/servers", json=["not-an-object"], headers=auth_headers).status_code == 400
    assert client.put(f"/api/servers/{second_id}", json=["not-an-object"], headers=auth_headers).status_code == 400
    assert client.put(f"/api/servers/{second_id}/inventory", json=["not-an-object"], headers=auth_headers).status_code == 400
    duplicate = client.post(
        "/api/servers",
        json={"name": "new-server", "server_ip": "10.10.2.3", "bmc_ip": "10.20.2.1"},
        headers=auth_headers,
    )
    assert duplicate.status_code == 409


def test_retrying_a_superseded_outbox_reports_the_latest_pending_revision(app, client, auth_headers):
    """A superseded record was not delivered and must never be reported synchronized."""
    from dc_overview.app import InventoryOutbox, db
    with app.app_context():
        old = InventoryOutbox(
            source_id="source", source_server_id="stable-server", revision=1,
            payload='{"source_id":"source","server_id":"stable-server","revision":1,"operation":"upsert","name":"old","server_ip":"10.0.0.1","bmc_ip":"10.0.1.1"}',
            delivered=True, last_error="Superseded by a newer inventory revision",
        )
        current = InventoryOutbox(
            source_id="source", source_server_id="stable-server", revision=2,
            payload='{"source_id":"source","server_id":"stable-server","revision":2,"operation":"upsert","name":"current","server_ip":"10.0.0.2","bmc_ip":"10.0.1.1"}',
            delivered=False,
        )
        db.session.add_all([old, current])
        db.session.commit()
        old_id, current_id = old.id, current.id

    response = client.post(f"/api/inventory/outbox/{old_id}/retry", headers=auth_headers)
    assert response.get_json() == {
        "state": "superseded", "retry_id": current_id, "revision": 2,
    }


def test_external_inventory_url_is_rejected_without_an_egress_attempt(monkeypatch, tmp_path):
    """The service secret must never be sent to an arbitrary configured host."""
    secret_file = tmp_path / "dc-ipmi-inventory-secret"
    secret_file.write_text("test-inventory-secret\n")
    monkeypatch.setenv("DC_IPMI_INVENTORY_SECRET_FILE", str(secret_file))
    monkeypatch.setenv("IPMI_INVENTORY_URL", "https://outside.example/collector?copy=1")
    entry = SimpleNamespace(
        payload='{"source_id":"source","server_id":"server","revision":1,"operation":"upsert","name":"ccc","server_ip":"10.0.0.1","bmc_ip":"10.0.1.1"}',
        attempts=0,
        last_error=None,
        delivered=False,
    )

    with patch("dc_overview.inventory_sync.requests.post") as post:
        from dc_overview.inventory_sync import deliver_inventory_outbox
        assert deliver_inventory_outbox(entry) is False

    post.assert_not_called()
    assert entry.attempts == 1


def test_missing_secret_prevents_egress_even_for_the_internal_receiver(monkeypatch):
    """An unprovisioned DC sender must leave the durable record pending locally."""
    monkeypatch.delenv("DC_IPMI_INVENTORY_SECRET_FILE", raising=False)
    monkeypatch.setenv("IPMI_INVENTORY_URL", "http://ipmi-monitor:5000")
    entry = SimpleNamespace(
        payload='{"source_id":"source","server_id":"server","revision":1,"operation":"upsert","name":"ccc","server_ip":"10.0.0.1","bmc_ip":"10.0.1.1"}',
        attempts=0,
        last_error=None,
        delivered=False,
    )

    with patch("dc_overview.inventory_sync.requests.post") as post:
        from dc_overview.inventory_sync import deliver_inventory_outbox
        assert deliver_inventory_outbox(entry) is False

    post.assert_not_called()
    assert entry.attempts == 1


def test_missing_internal_destination_prevents_egress(monkeypatch, tmp_path):
    """The secret alone cannot enable reconciliation to an implicit destination."""
    secret_file = tmp_path / "dc-ipmi-inventory-secret"
    secret_file.write_text("test-inventory-secret\n")
    monkeypatch.setenv("DC_IPMI_INVENTORY_SECRET_FILE", str(secret_file))
    monkeypatch.delenv("IPMI_INVENTORY_URL", raising=False)
    entry = SimpleNamespace(
        payload='{"source_id":"source","server_id":"server","revision":1,"operation":"upsert","name":"ccc","server_ip":"10.0.0.1","bmc_ip":"10.0.1.1"}',
        attempts=0,
        last_error=None,
        delivered=False,
    )

    with patch("dc_overview.inventory_sync.requests.post") as post:
        from dc_overview.inventory_sync import deliver_inventory_outbox
        assert deliver_inventory_outbox(entry) is False

    post.assert_not_called()
    assert entry.attempts == 1


def test_restart_retry_only_delivers_the_latest_durable_revision(app, monkeypatch, tmp_path):
    """A restart retries the current desired state and never resurrects an old revision."""
    _configure_inventory(monkeypatch, tmp_path)
    from dc_overview.app import InventoryOutbox, db, retry_pending_inventory_outbox

    newest_payload = {
        "source_id": "source", "server_id": "stable-server", "revision": 2,
        "operation": "upsert", "name": "ccc-new", "server_ip": "10.0.0.2", "bmc_ip": "10.0.1.1",
    }
    with app.app_context():
        db.session.add_all([
            InventoryOutbox(
                source_id="source", source_server_id="stable-server", revision=1,
                payload='{"source_id":"source","server_id":"stable-server","revision":1,"operation":"upsert","name":"ccc-old","server_ip":"10.0.0.1","bmc_ip":"10.0.1.1"}',
            ),
            InventoryOutbox(source_id="source", source_server_id="stable-server", revision=2, payload=__import__("json").dumps(newest_payload)),
        ])
        db.session.commit()
        db.session.remove()  # emulate the fresh session used after a process restart

        with patch("dc_overview.inventory_sync.requests.post") as post:
            post.side_effect = lambda _url, json, **_kwargs: _acknowledgment(json)
            result = retry_pending_inventory_outbox(limit=5)

    assert result == {"attempted": 1, "delivered": 1}
    assert post.call_args.kwargs["json"]["revision"] == 2


def test_periodic_retry_runs_one_bounded_internal_batch(app, monkeypatch, tmp_path):
    """Configured internal reconciliation retries in the background without blocking startup."""
    _configure_inventory(monkeypatch, tmp_path)
    from dc_overview.app import inventory_retry_loop

    stop_event = threading.Event()
    with patch("dc_overview.app.retry_pending_inventory_outbox") as retry:
        retry.side_effect = lambda limit: stop_event.set()
        inventory_retry_loop(stop_event, interval_seconds=60)

    retry.assert_called_once_with(limit=10)


def test_file_sqlite_serializes_two_independent_inventory_writer_processes(tmp_path):
    """Separate worker processes keep one source ID and monotonic durable revisions."""
    data_dir = tmp_path / "dc-data"
    data_dir.mkdir()
    environment = {
        **os.environ,
        "PYTHONPATH": str(__import__("pathlib").Path(__file__).parents[1] / "src"),
        "DC_OVERVIEW_DATA": str(data_dir),
        "SECRET_KEY": "test-secret",
        "SESSION_COOKIE_SECURE": "false",
        "IPMI_INVENTORY_URL": "",
        "DC_IPMI_INVENTORY_SECRET_FILE": "",
    }
    setup = """
from dc_overview.app import Server, app, db
with app.app_context():
    db.session.add(Server(name='ccc-base', server_ip='10.0.0.1', bmc_ip='10.0.1.1'))
    db.session.commit()
"""
    subprocess.run([sys.executable, "-c", setup], check=True, env=environment, capture_output=True, text=True)

    start = tmp_path / "start-writers"
    worker = """
import os
import time
from pathlib import Path
from dc_overview.app import app
while not Path(os.environ['INVENTORY_TEST_START']).exists():
    time.sleep(0.01)
headers = {
    'X-Fleet-Authenticated': 'true',
    'X-Fleet-Auth-User': 'writer',
    'X-Fleet-Auth-Role': 'admin',
}
with app.test_client() as client:
    response = client.put('/api/servers/1', json={
        'name': os.environ['INVENTORY_TEST_NAME'],
        'server_ip': os.environ['INVENTORY_TEST_IP'],
    }, headers=headers)
    raise SystemExit(0 if response.status_code == 200 else response.status_code)
"""
    workers = []
    for name, address in (("ccc-first", "10.0.0.2"), ("ccc-second", "10.0.0.3")):
        workers.append(subprocess.Popen(
            [sys.executable, "-c", worker],
            env={
                **environment,
                "INVENTORY_TEST_START": str(start),
                "INVENTORY_TEST_NAME": name,
                "INVENTORY_TEST_IP": address,
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ))
    start.touch()
    outputs = [process.communicate(timeout=10) for process in workers]
    assert [process.returncode for process in workers] == [0, 0], outputs

    with sqlite3.connect(data_dir / "dc_overview.db") as connection:
        revision, stable_id = connection.execute(
            "SELECT inventory_revision, inventory_server_id FROM server WHERE id = 1"
        ).fetchone()
        source_ids = connection.execute(
            "SELECT value FROM app_settings WHERE key = 'inventory_source_id'"
        ).fetchall()
        outbox = connection.execute(
            "SELECT source_server_id, revision FROM inventory_outbox ORDER BY revision"
        ).fetchall()

    assert revision == 2
    assert len(source_ids) == 1
    assert outbox == [(stable_id, 1), (stable_id, 2)]
