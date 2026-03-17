"""Tests for exporter toggle — UI state consistency after install."""

import json
from unittest.mock import patch

from dc_overview.app import db, Server


class TestExporterToggleState:
    """After toggling an exporter on (install), the versions endpoint must
    report the exporter as installed, enabled, and include a version so the
    frontend doesn't flip the toggle back off."""

    def test_toggle_sets_version_after_install(self, app, client, auth_headers, sample_server):
        """After a successful install-via-toggle, the server record should have
        a version set so the cached /exporters/versions response includes it."""
        with app.app_context():
            server = db.session.get(Server, sample_server)
            assert server.node_exporter_installed is False
            assert server.node_exporter_version is None

            with patch("dc_overview.app.install_exporter_remote", return_value=True):
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
            assert data["installed"] is True

            db.session.refresh(server)
            assert server.node_exporter_installed is True
            assert server.node_exporter_enabled is True
            assert server.node_exporter_version is not None, (
                "Version must be set after install so the UI shows the toggle as ON"
            )

    def test_versions_endpoint_reflects_install(self, app, client, auth_headers, sample_server):
        """GET /exporters/versions must return installed=True and a version
        immediately after a toggle-install, even from cached data."""
        with app.app_context():
            with patch("dc_overview.app.install_exporter_remote", return_value=True):
                with patch("dc_overview.app.update_prometheus_targets"):
                    client.post(
                        f"/api/servers/{sample_server}/exporters/node_exporter/toggle",
                        headers=auth_headers,
                        data=json.dumps({"enabled": True}),
                        content_type="application/json",
                    )

            resp = client.get(
                f"/api/servers/{sample_server}/exporters/versions",
                headers=auth_headers,
            )
            data = json.loads(resp.data)

            assert data["installed"]["node_exporter"] is True
            assert data["enabled"]["node_exporter"] is True
            assert data["versions"].get("node_exporter"), (
                "Cached response must include a version after install so the "
                "frontend toggle stays ON"
            )
