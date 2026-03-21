"""Tests for SSH key management — view pubkey, generate, deploy, IPMI sync."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from dc_overview.app import db, SSHKey, Server


class TestViewPublicKey:
    """GET /api/ssh-keys/<id>/pubkey must return the .pub file content."""

    def test_returns_pubkey_content(self, app, auth_headers):
        """Valid key with .pub file should return its content."""
        with app.app_context():
            tmpdir = tempfile.mkdtemp()
            key_path = os.path.join(tmpdir, "test_key")
            pub_path = key_path + ".pub"
            Path(key_path).write_text("PRIVATE KEY CONTENT")
            Path(pub_path).write_text(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest dc-overview-fleet"
            )

            key = SSHKey(name="test-key", key_path=key_path, fingerprint="SHA256:test")
            db.session.add(key)
            db.session.commit()
            key_id = key.id

        client = app.test_client()
        resp = client.get(f"/api/ssh-keys/{key_id}/pubkey", headers=auth_headers)

        assert resp.status_code == 200
        data = resp.get_json()
        assert "ssh-ed25519" in data["public_key"]
        assert data["name"] == "test-key"

    def test_returns_404_for_missing_key(self, app, auth_headers):
        client = app.test_client()
        resp = client.get("/api/ssh-keys/9999/pubkey", headers=auth_headers)
        assert resp.status_code == 404

    def test_returns_error_when_pubfile_missing(self, app, auth_headers):
        """Key exists in DB but .pub file is gone from disk."""
        with app.app_context():
            key = SSHKey(
                name="orphan-key",
                key_path="/nonexistent/path/key",
                fingerprint="SHA256:orphan",
            )
            db.session.add(key)
            db.session.commit()
            key_id = key.id

        client = app.test_client()
        resp = client.get(f"/api/ssh-keys/{key_id}/pubkey", headers=auth_headers)
        assert resp.status_code == 404
        assert "not found" in resp.get_json()["error"].lower()


class TestGenerateKey:
    """POST /api/ssh-keys/generate must create a key pair and register it."""

    @patch("dc_overview.app.subprocess.run")
    def test_generates_key_and_registers(self, mock_run, app, auth_headers):
        """Should create files on disk and return the new key record."""
        tmpdir = tempfile.mkdtemp()

        mock_run.return_value = MagicMock(
            returncode=0, stdout="256 SHA256:abc123 dc-overview (ED25519)\n", stderr=""
        )

        def fake_keygen(*args, **kwargs):
            cmd = args[0]
            if "ssh-keygen" in cmd and "-t" in cmd:
                f_idx = cmd.index("-f") + 1
                key_file = cmd[f_idx]
                Path(key_file).write_text("PRIVATE")
                Path(key_file + ".pub").write_text(
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 dc-overview-fleet"
                )
            return MagicMock(
                returncode=0,
                stdout="256 SHA256:abc123 dc-overview (ED25519)\n",
                stderr="",
            )

        mock_run.side_effect = fake_keygen

        client = app.test_client()
        resp = client.post(
            "/api/ssh-keys/generate",
            data=json.dumps({"name": "rotation-key", "keys_dir": tmpdir}),
            content_type="application/json",
            headers=auth_headers,
        )

        assert resp.status_code == 201, resp.get_json()
        data = resp.get_json()
        assert data["name"] == "rotation-key"
        assert "public_key" in data
        assert data["id"] is not None

    def test_rejects_duplicate_name(self, app, auth_headers):
        with app.app_context():
            key = SSHKey(name="dup-key", key_path="/tmp/dup", fingerprint="SHA256:dup")
            db.session.add(key)
            db.session.commit()

        client = app.test_client()
        resp = client.post(
            "/api/ssh-keys/generate",
            data=json.dumps({"name": "dup-key"}),
            content_type="application/json",
            headers=auth_headers,
        )
        assert resp.status_code == 409


class TestDeployKey:
    """POST /api/ssh-keys/<id>/deploy must push the pubkey to workers."""

    @patch("dc_overview.app.subprocess.run")
    def test_deploys_to_all_servers(self, mock_run, app, auth_headers):
        """Should SSH into each server and append the pub key."""
        with app.app_context():
            tmpdir = tempfile.mkdtemp()
            key_path = os.path.join(tmpdir, "deploy_key")
            pub_path = key_path + ".pub"
            Path(key_path).write_text("PRIVATE")
            Path(pub_path).write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test")
            os.chmod(key_path, 0o600)

            key = SSHKey(name="deploy-test", key_path=key_path, fingerprint="SHA256:d")
            db.session.add(key)

            s1 = Server(name="worker-1", server_ip="10.0.0.1")
            s2 = Server(name="worker-2", server_ip="10.0.0.2")
            db.session.add_all([s1, s2])
            db.session.commit()
            key_id = key.id

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        client = app.test_client()
        resp = client.post(
            f"/api/ssh-keys/{key_id}/deploy",
            data=json.dumps({}),
            content_type="application/json",
            headers=auth_headers,
        )

        assert resp.status_code == 200, resp.get_json()
        data = resp.get_json()
        assert data["total"] == 2
        assert data["deployed"] >= 0

    @patch("dc_overview.app.subprocess.run")
    def test_deploys_to_selected_servers(self, mock_run, app, auth_headers):
        """Should only deploy to specified server IDs."""
        with app.app_context():
            tmpdir = tempfile.mkdtemp()
            key_path = os.path.join(tmpdir, "sel_key")
            Path(key_path).write_text("PRIVATE")
            Path(key_path + ".pub").write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test")
            os.chmod(key_path, 0o600)

            key = SSHKey(name="sel-test", key_path=key_path, fingerprint="SHA256:s")
            db.session.add(key)

            s1 = Server(name="w1", server_ip="10.0.0.1")
            s2 = Server(name="w2", server_ip="10.0.0.2")
            db.session.add_all([s1, s2])
            db.session.commit()
            key_id = key.id
            s1_id = s1.id

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        client = app.test_client()
        resp = client.post(
            f"/api/ssh-keys/{key_id}/deploy",
            data=json.dumps({"server_ids": [s1_id]}),
            content_type="application/json",
            headers=auth_headers,
        )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 1


class TestSyncIPMI:
    """POST /api/ssh-keys/<id>/sync-ipmi must push the key to IPMI Monitor."""

    @patch("dc_overview.app.http_requests.post")
    def test_syncs_key_to_ipmi_monitor(self, mock_post, app, auth_headers):
        with app.app_context():
            tmpdir = tempfile.mkdtemp()
            key_path = os.path.join(tmpdir, "sync_key")
            Path(key_path).write_text("PRIVATE KEY CONTENT")
            Path(key_path + ".pub").write_text("ssh-ed25519 AAAA test")

            key = SSHKey(name="sync-test", key_path=key_path, fingerprint="SHA256:sync")
            db.session.add(key)
            db.session.commit()
            key_id = key.id

        mock_post.return_value = MagicMock(status_code=201, json=lambda: {"id": 1})

        client = app.test_client()
        resp = client.post(
            f"/api/ssh-keys/{key_id}/sync-ipmi",
            content_type="application/json",
            headers=auth_headers,
        )

        assert resp.status_code == 200
        mock_post.assert_called_once()
        call_data = json.loads(mock_post.call_args[1].get("data", "{}"))
        assert call_data["name"] == "sync-test"
        assert "PRIVATE KEY CONTENT" in call_data["key_content"]
