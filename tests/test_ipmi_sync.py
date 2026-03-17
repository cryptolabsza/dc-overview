"""Tests for IPMI monitor sync — adding and removing servers."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import yaml

from dc_overview.app import db, Server
from dc_overview.web_prometheus import sync_ipmi_monitor_targets


class TestIpmiMonitorSync:
    """sync_ipmi_monitor_targets must add new servers and remove deleted ones."""

    def test_adds_new_server_to_ipmi_config(self, app):
        """A server in the DB must appear in the IPMI monitor servers.yaml."""
        with app.app_context():
            server = Server(name="new-worker", server_ip="10.0.0.99")
            db.session.add(server)
            db.session.commit()

            with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
                cfg_path = Path(f.name)
            cfg_path.write_text(yaml.dump({"servers": []}))

            sync_ipmi_monitor_targets([server], str(cfg_path))

            result = yaml.safe_load(cfg_path.read_text())
            names = [s["name"] for s in result["servers"]]

            assert "new-worker" in names
            entry = next(s for s in result["servers"] if s["name"] == "new-worker")
            assert entry["server_ip"] == "10.0.0.99"

            cfg_path.unlink()

    def test_removes_deleted_server_from_ipmi_config(self, app):
        """A server deleted from DB must be removed from IPMI servers.yaml."""
        with app.app_context():
            existing = {
                "servers": [
                    {"name": "old-server", "server_ip": "10.0.0.50"},
                    {"name": "keeper", "server_ip": "10.0.0.1", "bmc_ip": "10.0.0.2"},
                ]
            }
            with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
                cfg_path = Path(f.name)
            cfg_path.write_text(yaml.dump(existing))

            keeper = Server(name="keeper", server_ip="10.0.0.1")
            db.session.add(keeper)
            db.session.commit()

            sync_ipmi_monitor_targets([keeper], str(cfg_path))

            result = yaml.safe_load(cfg_path.read_text())
            names = [s["name"] for s in result["servers"]]

            assert "old-server" not in names, "Deleted server must be removed"
            assert "keeper" in names, "Active server must be preserved"

            keeper_entry = next(s for s in result["servers"] if s["name"] == "keeper")
            assert keeper_entry.get("bmc_ip") == "10.0.0.2", "Existing IPMI fields must be preserved"

            cfg_path.unlink()

    def test_preserves_existing_ipmi_fields(self, app):
        """Adding a server that already exists must not overwrite BMC/IPMI fields."""
        with app.app_context():
            existing = {
                "servers": [
                    {
                        "name": "worker1",
                        "server_ip": "10.0.0.1",
                        "bmc_ip": "10.0.0.83",
                        "ipmi_user": "admin",
                        "ipmi_pass": "secret",
                    }
                ]
            }
            with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
                cfg_path = Path(f.name)
            cfg_path.write_text(yaml.dump(existing))

            server = Server(name="worker1", server_ip="10.0.0.1")
            db.session.add(server)
            db.session.commit()

            sync_ipmi_monitor_targets([server], str(cfg_path))

            result = yaml.safe_load(cfg_path.read_text())
            entry = result["servers"][0]

            assert entry["bmc_ip"] == "10.0.0.83"
            assert entry["ipmi_user"] == "admin"
            assert entry["ipmi_pass"] == "secret"

            cfg_path.unlink()
