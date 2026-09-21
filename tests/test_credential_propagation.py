"""Regression coverage for DC's encrypted local credential propagation."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _configure_inventory(monkeypatch, tmp_path):
    secret_file = tmp_path / "dc-ipmi-inventory-secret"
    secret_file.write_text("test-inventory-secret\n")
    monkeypatch.setenv("DC_IPMI_INVENTORY_SECRET_FILE", str(secret_file))
    monkeypatch.setenv("IPMI_INVENTORY_URL", "http://ipmi-monitor:5000")
    monkeypatch.setenv("FLEET_CREDENTIAL_AUTHORITY", "local")
    return "test-inventory-secret"


def _private_key(path: Path) -> None:
    path.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()))


def _credential_ack(payload, secret="test-inventory-secret"):
    accepted = {key: payload[key] for key in ("source_id", "server_id", "revision", "name", "server_ip", "bmc_ip")}
    accepted.update(status="active", enabled=True)
    body = {"accepted": accepted, "credential_revision": payload["revision"],
            "credential_digest": hashlib.sha256(payload["credential_bundle"].encode("utf-8")).hexdigest()}
    signature = hmac.new(secret.encode("utf-8"), json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"), hashlib.sha256).hexdigest()
    return Mock(ok=True, headers={"X-DC-Response-Signature": signature}, json=lambda: body)


def test_local_credential_save_queues_only_an_encrypted_bundle_and_requires_credential_ack(app, client, auth_headers, monkeypatch, tmp_path):
    """Credential updates persist a retry-safe encrypted token and reject old acks."""
    secret = _configure_inventory(monkeypatch, tmp_path)
    key_path = tmp_path / "fleet_key"
    _private_key(key_path)
    from dc_overview.app import InventoryOutbox, SSHKey, Server, db
    with app.app_context():
        key = SSHKey(name="fleet", key_path=str(key_path))
        server = Server(name="ccc90", server_ip="10.10.0.90", bmc_ip="10.20.0.90")
        db.session.add_all((key, server)); db.session.commit()
        server_id, key_id = server.id, key.id
    old_receiver = Mock(ok=True, headers={}, json=lambda: {"accepted": {}})
    with patch("dc_overview.inventory_sync.requests.post", return_value=old_receiver):
        response = client.post(f"/api/servers/{server_id}/ssh-config", json={"ssh_user": "root", "ssh_port": 2222, "ssh_key_id": key_id, "ssh_password": "ssh-secret", "bmc_username": "ADMIN", "bmc_password": "bmc-secret"}, headers=auth_headers)
    assert response.status_code == 200
    assert response.get_json()["inventory"]["state"] == "pending"
    with app.app_context():
        outbox = InventoryOutbox.query.one()
        assert "ssh-secret" not in outbox.payload and "bmc-secret" not in outbox.payload
        assert "credential_bundle" in outbox.payload
        assert Server.query.get(server_id).bmc_password != "bmc-secret"
        outbox_id = outbox.id
    with patch("dc_overview.inventory_sync.requests.post") as post:
        post.side_effect = lambda _url, json, **_kwargs: _credential_ack(json)
        response = client.post(f"/api/inventory/outbox/{outbox_id}/retry", headers=auth_headers)
    assert response.get_json()["state"] == "synchronized"
    payload = post.call_args.kwargs["json"]
    assert "credential_bundle" in payload and "ssh-secret" not in json.dumps(payload) and "bmc-secret" not in json.dumps(payload)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert post.call_args.kwargs["headers"] == {"Authorization": "DC-HMAC " + hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()}


def test_bmc_blank_preserves_and_explicit_clear_propagates(app, client, auth_headers, monkeypatch, tmp_path):
    _configure_inventory(monkeypatch, tmp_path)
    from dc_overview.app import Server, db
    with app.app_context():
        server = Server(name="ccc91", server_ip="10.10.0.91", bmc_ip="10.20.0.91")
        db.session.add(server); db.session.commit(); server_id = server.id
    with patch("dc_overview.inventory_sync.requests.post", side_effect=lambda *_a, **_kw: _credential_ack(_kw["json"])):
        assert client.post(f"/api/servers/{server_id}/ssh-config", json={"bmc_username": "ADMIN", "bmc_password": "initial"}, headers=auth_headers).status_code == 200
        assert client.post(f"/api/servers/{server_id}/ssh-config", json={"ssh_port": 2223}, headers=auth_headers).status_code == 200
    details = client.get(f"/api/servers/{server_id}/ssh-config", headers=auth_headers).get_json()
    assert details["bmc_username"] == "ADMIN" and details["has_bmc_password"] is True
    with patch("dc_overview.inventory_sync.requests.post", side_effect=lambda *_a, **_kw: _credential_ack(_kw["json"])):
        cleared = client.post(f"/api/servers/{server_id}/ssh-config", json={"clear_bmc_credentials": True}, headers=auth_headers)
    assert cleared.status_code == 200
    details = client.get(f"/api/servers/{server_id}/ssh-config", headers=auth_headers).get_json()
    assert details["bmc_managed"] is True and details["bmc_username"] is None and details["has_bmc_password"] is False


def test_saved_bmc_username_with_blank_password_preserves_existing_secret_on_ssh_edit(app, client, auth_headers, monkeypatch, tmp_path):
    _configure_inventory(monkeypatch, tmp_path)
    from dc_overview.app import Server, db
    with app.app_context():
        server = Server(name='ccc911', server_ip='10.10.0.111', bmc_ip='10.20.0.111')
        db.session.add(server); db.session.commit(); server_id = server.id
    with patch('dc_overview.inventory_sync.requests.post', side_effect=lambda *_a, **_kw: _credential_ack(_kw['json'])):
        assert client.post(f'/api/servers/{server_id}/ssh-config', json={'bmc_username': 'ADMIN', 'bmc_password': 'initial'}, headers=auth_headers).status_code == 200
    with app.app_context():
        ciphertext = Server.query.get(server_id).bmc_password
    with patch('dc_overview.inventory_sync.requests.post', side_effect=lambda *_a, **_kw: _credential_ack(_kw['json'])):
        saved_form_payload = {'ssh_port': 2223, 'bmc_username': 'ADMIN', 'bmc_password': ''}
        response = client.post(f'/api/servers/{server_id}/ssh-config', json=saved_form_payload, headers=auth_headers)
    assert response.status_code == 200
    with app.app_context():
        server = Server.query.get(server_id)
        assert server.ssh_port == 2223 and server.bmc_password == ciphertext


def test_vault_mode_blocks_credential_mutations_without_changing_local_state(app, client, auth_headers, monkeypatch):
    monkeypatch.setenv("FLEET_CREDENTIAL_AUTHORITY", "vault")
    from dc_overview.app import Server, db
    with app.app_context():
        server = Server(name="ccc92", server_ip="10.10.0.92", ssh_port=22)
        db.session.add(server); db.session.commit(); server_id = server.id
    response = client.post(f"/api/servers/{server_id}/ssh-config", json={"ssh_port": 2222}, headers=auth_headers)
    assert response.status_code == 409
    with app.app_context(): assert Server.query.get(server_id).ssh_port == 22


def test_vault_mode_allows_metadata_add_but_rejects_explicit_ssh_credentials(app, client, auth_headers, monkeypatch):
    monkeypatch.setenv('FLEET_CREDENTIAL_AUTHORITY', 'vault')
    metadata = client.post('/api/servers', json={'name': 'ccc-vault-meta', 'server_ip': '10.10.0.201'}, headers=auth_headers)
    assert metadata.status_code == 201
    credentialed = client.post('/api/servers', json={'name': 'ccc-vault-ssh', 'server_ip': '10.10.0.202', 'ssh_password': 'secret'}, headers=auth_headers)
    assert credentialed.status_code == 409
    key_creation = client.post('/api/ssh-keys', json={'name': 'vault-key', 'key_path': '/tmp/key'}, headers=auth_headers)
    assert key_creation.status_code == 409


def test_invalid_bmc_input_and_missing_transport_key_do_not_mutate(app, client, auth_headers, monkeypatch):
    monkeypatch.setenv("FLEET_CREDENTIAL_AUTHORITY", "local")
    monkeypatch.delenv("DC_IPMI_INVENTORY_SECRET_FILE", raising=False)
    from dc_overview.app import Server, db
    with app.app_context():
        server = Server(name="ccc93", server_ip="10.10.0.93", bmc_ip="10.20.0.93")
        db.session.add(server); db.session.commit(); server_id = server.id
    missing_key = client.post(f"/api/servers/{server_id}/ssh-config", json={"bmc_username": "ADMIN", "bmc_password": "new-password"}, headers=auth_headers)
    assert missing_key.status_code == 503
    invalid = client.post(f"/api/servers/{server_id}/ssh-config", json={"ssh_port": 70000}, headers=auth_headers)
    assert invalid.status_code == 400
    with app.app_context():
        server = Server.query.get(server_id)
        assert server.ssh_port == 22 and server.bmc_password is None


def test_bmc_username_is_attribute_escaped_in_server_management_ui():
    template = (Path(__file__).parents[1] / 'src/dc_overview/web_templates/servers.html').read_text()
    assert 'function escapeHtmlAttribute(value)' in template
    assert 'value="${escapeHtmlAttribute(data.bmc_username)}"' in template


def test_lost_response_retries_the_same_persisted_credential_token(app, client, auth_headers, monkeypatch, tmp_path):
    """A receiver-side commit followed by a lost response cannot regenerate its token."""
    _configure_inventory(monkeypatch, tmp_path)
    from dc_overview.app import InventoryOutbox, Server, db
    with app.app_context():
        server = Server(name='ccc94', server_ip='10.10.0.94', bmc_ip='10.20.0.94')
        db.session.add(server); db.session.commit(); server_id = server.id
    seen = []
    def lost_response(_url, json, **_kwargs):
        seen.append(json['credential_bundle'])
        raise __import__('requests').ConnectionError('response lost after receiver commit')
    with patch('dc_overview.inventory_sync.requests.post', side_effect=lost_response):
        response = client.post(f'/api/servers/{server_id}/ssh-config', json={'ssh_password': 'ssh-secret'}, headers=auth_headers)
    assert response.get_json()['inventory']['state'] == 'pending'
    with app.app_context():
        entry = InventoryOutbox.query.one()
        persisted = json.loads(entry.payload)['credential_bundle']
        entry_id = entry.id
    assert seen == [persisted]
    with patch('dc_overview.inventory_sync.requests.post', side_effect=lambda _url, json, **_kwargs: _credential_ack(json)) as post:
        retried = client.post(f'/api/inventory/outbox/{entry_id}/retry', headers=auth_headers)
    assert retried.get_json()['state'] == 'synchronized'
    assert post.call_args.kwargs['json']['credential_bundle'] == persisted
