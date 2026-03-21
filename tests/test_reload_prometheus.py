"""Tests for reload_prometheus — HTTP lifecycle API with fallbacks."""

from unittest.mock import patch, MagicMock

import requests

from dc_overview.web_prometheus import reload_prometheus


class TestReloadPrometheus:
    """reload_prometheus must prefer HTTP lifecycle API over docker exec."""

    @patch("dc_overview.web_prometheus.subprocess.run")
    @patch("dc_overview.web_prometheus.requests.post")
    def test_uses_http_lifecycle_api_first(self, mock_post, mock_run):
        """Primary reload path should POST to Prometheus /-/reload endpoint."""
        mock_post.return_value = MagicMock(status_code=200)

        reload_prometheus()

        mock_post.assert_called_once()
        call_url = mock_post.call_args[0][0]
        assert "/-/reload" in call_url
        mock_run.assert_not_called()

    @patch("dc_overview.web_prometheus.subprocess.run")
    @patch("dc_overview.web_prometheus.requests.post")
    def test_tries_both_url_patterns(self, mock_post, mock_run):
        """Should try /prometheus/-/reload then /-/reload (or vice versa)."""
        mock_post.side_effect = requests.ConnectionError("refused")

        reload_prometheus()

        assert mock_post.call_count >= 2, (
            "Should try multiple URL patterns before falling back"
        )
        urls = [c[0][0] for c in mock_post.call_args_list]
        assert any("prometheus/-/reload" in u for u in urls)
        assert any(u.endswith("/-/reload") and "prometheus/-/reload" not in u for u in urls)

    @patch("dc_overview.web_prometheus.subprocess.run")
    @patch("dc_overview.web_prometheus.requests.post")
    def test_falls_back_to_docker_exec_on_http_failure(self, mock_post, mock_run):
        """When HTTP fails, fall back to docker exec kill -HUP."""
        mock_post.side_effect = requests.ConnectionError("refused")

        reload_prometheus()

        mock_run.assert_called()
        args = mock_run.call_args_list[0][0][0]
        assert "docker" in args
        assert "prometheus" in args

    @patch("dc_overview.web_prometheus.subprocess.run")
    @patch("dc_overview.web_prometheus.requests.post")
    def test_does_not_raise_when_all_methods_fail(self, mock_post, mock_run):
        """reload_prometheus must never raise — all failures are logged."""
        mock_post.side_effect = requests.ConnectionError("refused")
        mock_run.side_effect = FileNotFoundError("docker not found")

        reload_prometheus()

    @patch("dc_overview.web_prometheus.subprocess.run")
    @patch("dc_overview.web_prometheus.requests.post")
    def test_http_non_200_falls_back(self, mock_post, mock_run):
        """Non-200 HTTP responses (e.g. lifecycle API disabled) trigger fallback."""
        resp = MagicMock(status_code=403)
        resp.raise_for_status.side_effect = requests.HTTPError("forbidden")
        mock_post.return_value = resp

        reload_prometheus()

        mock_run.assert_called()
