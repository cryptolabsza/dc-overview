"""Tests for Prometheus target sync — adding and removing servers."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import yaml

from dc_overview.app import db, Server
from dc_overview.web_prometheus import update_prometheus_yml_targets, update_prometheus_targets


class TestPrometheusYmlSync:
    """update_prometheus_yml_targets must ADD new servers and REMOVE deleted ones."""

    def _write_base_config(self, path):
        config = {
            "global": {"scrape_interval": "15s"},
            "scrape_configs": [
                {
                    "job_name": "prometheus",
                    "static_configs": [{"targets": ["localhost:9090"]}],
                },
                {
                    "job_name": "existing-server",
                    "static_configs": [
                        {"labels": {"instance": "existing-server"}, "targets": ["10.0.0.1:9100"]}
                    ],
                },
            ],
        }
        path.write_text(yaml.dump(config))
        return config

    def test_adds_new_server_to_prometheus_yml(self, app):
        """A server present in the DB but missing from prometheus.yml must be added."""
        with app.app_context():
            server = Server(
                name="new-worker",
                server_ip="10.0.0.99",
                node_exporter_installed=True,
                node_exporter_enabled=True,
                dc_exporter_installed=True,
                dc_exporter_enabled=True,
            )
            db.session.add(server)
            db.session.commit()

            with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as f:
                yml_path = Path(f.name)

            self._write_base_config(yml_path)

            with patch("dc_overview.web_prometheus.Path") as MockPath:
                def path_side_effect(p):
                    if "prometheus.yml" in str(p):
                        return yml_path
                    return Path(p)
                MockPath.side_effect = path_side_effect

                with patch("dc_overview.web_prometheus.reload_prometheus"):
                    update_prometheus_yml_targets([server])

            result = yaml.safe_load(yml_path.read_text())
            job_names = [sc["job_name"] for sc in result["scrape_configs"]]

            assert "new-worker" in job_names, (
                f"New server must be added to prometheus.yml. Got: {job_names}"
            )

            new_job = next(sc for sc in result["scrape_configs"] if sc["job_name"] == "new-worker")
            targets = new_job["static_configs"][0]["targets"]
            assert "10.0.0.99:9100" in targets
            assert "10.0.0.99:9835" in targets

            yml_path.unlink()

    def test_removes_deleted_server_from_prometheus_yml(self, app):
        """A server that was deleted from DB must be removed from prometheus.yml."""
        with app.app_context():
            with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as f:
                yml_path = Path(f.name)

            config = {
                "global": {"scrape_interval": "15s"},
                "scrape_configs": [
                    {
                        "job_name": "prometheus",
                        "static_configs": [{"targets": ["localhost:9090"]}],
                    },
                    {
                        "job_name": "old-server",
                        "static_configs": [
                            {"labels": {"instance": "old-server"}, "targets": ["10.0.0.50:9100"]}
                        ],
                    },
                ],
            }
            yml_path.write_text(yaml.dump(config))

            with patch("dc_overview.web_prometheus.Path") as MockPath:
                def path_side_effect(p):
                    if "prometheus.yml" in str(p):
                        return yml_path
                    return Path(p)
                MockPath.side_effect = path_side_effect

                with patch("dc_overview.web_prometheus.reload_prometheus"):
                    update_prometheus_yml_targets([])

            result = yaml.safe_load(yml_path.read_text())
            job_names = [sc["job_name"] for sc in result["scrape_configs"]]

            assert "old-server" not in job_names, (
                f"Deleted server must be removed from prometheus.yml. Got: {job_names}"
            )
            assert "prometheus" in job_names, "Infrastructure jobs must be preserved"

            yml_path.unlink()
