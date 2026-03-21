"""Tests for separate Install vs Toggle exporter UX.

Install uses POST /api/servers/<id>/install-exporters with a list of exporters.
Toggle (start/stop) uses POST /api/servers/<id>/exporters/<name>/toggle and
should only be called on already-installed exporters.
The background live check must correctly reflect installed/enabled state.
"""

import json
from unittest.mock import patch, MagicMock

from dc_overview.app import db, Server


class TestInstallSingleExporter:
    """POST /install-exporters with a single exporter in the list."""

    def test_install_single_node_exporter(self, app, client, auth_headers, sample_server):
        with app.app_context():
            server = db.session.get(Server, sample_server)
            assert server.node_exporter_installed is False

            with patch("dc_overview.app.install_exporter_remote", return_value=True) as mock_install:
                with patch("dc_overview.app.update_prometheus_targets"):
                    resp = client.post(
                        f"/api/servers/{sample_server}/install-exporters",
                        headers=auth_headers,
                        data=json.dumps({"exporters": ["node_exporter"]}),
                        content_type="application/json",
                    )

            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert data["node_exporter"] == "installed"
            mock_install.assert_called_once()

    def test_install_single_dc_exporter(self, app, client, auth_headers, sample_server):
        with app.app_context():
            with patch("dc_overview.app.install_exporter_remote", return_value=True):
                with patch("dc_overview.app.update_prometheus_targets"):
                    resp = client.post(
                        f"/api/servers/{sample_server}/install-exporters",
                        headers=auth_headers,
                        data=json.dumps({"exporters": ["dc_exporter"]}),
                        content_type="application/json",
                    )

            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert data["dc_exporter"] == "installed"


class TestToggleOnlyStartStop:
    """Toggle endpoint should start/stop an already-installed exporter."""

    def test_toggle_start_installed_exporter(self, app, client, auth_headers, sample_server):
        with app.app_context():
            server = db.session.get(Server, sample_server)
            server.node_exporter_installed = True
            server.node_exporter_enabled = False
            server.node_exporter_version = "1.10.2"
            db.session.commit()

            with patch("dc_overview.app.toggle_exporter_service", return_value=(True, None)):
                with patch("dc_overview.app.update_prometheus_targets"):
                    resp = client.post(
                        f"/api/servers/{sample_server}/exporters/node_exporter/toggle",
                        headers=auth_headers,
                        data=json.dumps({"enabled": True}),
                        content_type="application/json",
                    )

            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert data["success"] is True
            assert data["enabled"] is True

    def test_toggle_stop_installed_exporter(self, app, client, auth_headers, sample_server):
        with app.app_context():
            server = db.session.get(Server, sample_server)
            server.node_exporter_installed = True
            server.node_exporter_enabled = True
            server.node_exporter_version = "1.10.2"
            db.session.commit()

            with patch("dc_overview.app.toggle_exporter_service", return_value=(True, None)):
                with patch("dc_overview.app.update_prometheus_targets"):
                    resp = client.post(
                        f"/api/servers/{sample_server}/exporters/node_exporter/toggle",
                        headers=auth_headers,
                        data=json.dumps({"enabled": False}),
                        content_type="application/json",
                    )

            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert data["success"] is True
            assert data["enabled"] is False


class TestLiveCheckInstalledState:
    """Background live-check must use systemctl to determine installed state."""

    NO_SERVICES = {
        "node_exporter": {"installed": False, "active": False},
        "dc_exporter": {"installed": False, "active": False},
        "dcgm_exporter": {"installed": False, "active": False},
    }

    def test_no_service_on_device_clears_installed(self, app, client, auth_headers, sample_server):
        """When systemctl says service doesn't exist, installed must be False."""
        with app.app_context():
            server = db.session.get(Server, sample_server)
            server.node_exporter_installed = True
            server.node_exporter_enabled = True
            db.session.commit()

            with patch("dc_overview.app.check_services_installed", return_value=self.NO_SERVICES):
                with patch("dc_overview.app.check_exporter", return_value={"running": False}):
                    with patch("dc_overview.app.check_watchdog_agent", return_value={"source": "none"}):
                        with patch("dc_overview.exporters.check_for_updates", return_value={}):
                            from dc_overview.app import _do_live_exporter_check
                            _do_live_exporter_check(sample_server)

            db.session.refresh(server)
            assert server.node_exporter_installed is False
            assert server.node_exporter_enabled is False

    def test_service_exists_but_stopped(self, app, client, auth_headers, sample_server):
        """When systemctl knows the service but it's inactive: installed=True, enabled=False."""
        with app.app_context():
            server = db.session.get(Server, sample_server)
            db.session.commit()

            svc_status = {
                "node_exporter": {"installed": True, "active": False},
                "dc_exporter": {"installed": False, "active": False},
                "dcgm_exporter": {"installed": False, "active": False},
            }

            with patch("dc_overview.app.check_services_installed", return_value=svc_status):
                with patch("dc_overview.app.check_exporter", return_value={"running": False}):
                    with patch("dc_overview.app.check_watchdog_agent", return_value={"source": "none"}):
                        with patch("dc_overview.exporters.check_for_updates", return_value={}):
                            with patch("dc_overview.exporters.get_all_exporter_versions", return_value={
                                "node_exporter": "1.10.2", "dc_exporter": None, "dcgm_exporter": None,
                            }):
                                from dc_overview.app import _do_live_exporter_check
                                _do_live_exporter_check(sample_server)

            db.session.refresh(server)
            assert server.node_exporter_installed is True
            assert server.node_exporter_enabled is False
            assert server.node_exporter_version == "1.10.2"

    def test_service_active_and_port_open(self, app, client, auth_headers, sample_server):
        """When systemctl shows active and port is open: installed=True, enabled=True."""
        with app.app_context():
            server = db.session.get(Server, sample_server)
            db.session.commit()

            svc_status = {
                "node_exporter": {"installed": True, "active": True},
                "dc_exporter": {"installed": False, "active": False},
                "dcgm_exporter": {"installed": False, "active": False},
            }

            def mock_check_exporter(ip, port):
                if port == 9100:
                    return {"running": True}
                return {"running": False}

            with patch("dc_overview.app.check_services_installed", return_value=svc_status):
                with patch("dc_overview.app.check_exporter", side_effect=mock_check_exporter):
                    with patch("dc_overview.app.check_watchdog_agent", return_value={"source": "none"}):
                        with patch("dc_overview.exporters.check_for_updates", return_value={}):
                            with patch("dc_overview.exporters.get_all_exporter_versions", return_value={
                                "node_exporter": "1.10.2", "dc_exporter": None, "dcgm_exporter": None,
                            }):
                                from dc_overview.app import _do_live_exporter_check
                                _do_live_exporter_check(sample_server)

            db.session.refresh(server)
            assert server.node_exporter_installed is True
            assert server.node_exporter_enabled is True

    def test_no_services_skips_version_ssh(self, app, client, auth_headers, sample_server):
        """When no services are installed, should not SSH for versions."""
        with app.app_context():
            with patch("dc_overview.app.check_services_installed", return_value=self.NO_SERVICES):
                with patch("dc_overview.app.check_exporter", return_value={"running": False}):
                    with patch("dc_overview.app.check_watchdog_agent", return_value={"source": "none"}):
                        with patch("dc_overview.exporters.check_for_updates", return_value={}):
                            with patch("dc_overview.exporters.get_all_exporter_versions") as mock_versions:
                                from dc_overview.app import _do_live_exporter_check
                                _do_live_exporter_check(sample_server)
                                mock_versions.assert_not_called()
