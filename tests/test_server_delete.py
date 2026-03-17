"""Tests for server DELETE endpoint — CSRF exemption and error handling."""

import json

from dc_overview.app import db, Server


class TestServerDelete:
    """DELETE /api/servers/<id> must work without a CSRF token."""

    def test_delete_server_without_csrf_token_succeeds(self, app, client, auth_headers, sample_server):
        """Deleting a server via API should not require a CSRF token.

        This is the bug: the endpoint was missing @csrf.exempt, so DELETE
        requests from the frontend (which don't send a CSRF token) were
        silently rejected with a 400.
        """
        with app.app_context():
            assert Server.query.get(sample_server) is not None

            resp = client.delete(
                f"/api/servers/{sample_server}",
                headers=auth_headers,
            )

            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.data}"
            data = json.loads(resp.data)
            assert "removed" in data.get("message", "").lower()

            assert Server.query.get(sample_server) is None

    def test_delete_nonexistent_server_returns_404(self, app, client, auth_headers):
        """Deleting a server that doesn't exist should return 404."""
        with app.app_context():
            resp = client.delete(
                "/api/servers/9999",
                headers=auth_headers,
            )
            assert resp.status_code == 404

    def test_delete_server_unauthenticated_returns_401(self, app, client, sample_server):
        """Deleting a server without auth should be rejected."""
        with app.app_context():
            resp = client.delete(f"/api/servers/{sample_server}")
            assert resp.status_code in (401, 302)

            assert Server.query.get(sample_server) is not None
