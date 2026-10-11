"""Prometheus inventory sync owns discovery and explicitly retired legacy jobs."""

from pathlib import Path

import yaml

from dc_overview.app import db, Server
from dc_overview.web_prometheus import update_prometheus_yml_targets, build_discovery_targets


class TestPrometheusYmlSync:
    def _write_base_config(self, path):
        config = {
            'global': {'scrape_interval': '15s'},
            'scrape_configs': [
                {'job_name':'prometheus', 'static_configs':[{'targets':['localhost:9090']}]},
                {'job_name':'existing-server', 'static_configs':[
                    {'labels':{'instance':'existing-server'}, 'targets':['10.0.0.1:9100']}]},
            ],
        }
        path.write_text(yaml.safe_dump(config))
        return config

    def test_adds_live_inventory_to_prometheus_yml(self, app, tmp_path):
        """New exporters flow through live discovery without replacing unknown jobs."""
        with app.app_context():
            server = Server(name='new-worker', server_ip='10.0.0.99',
                node_exporter_installed=True, node_exporter_enabled=True,
                dc_exporter_installed=True, dc_exporter_enabled=True)
            db.session.add(server)
            db.session.commit()
            path = tmp_path / 'prometheus.yml'
            prior = self._write_base_config(path)
            assert update_prometheus_yml_targets([server], config_path=path,
                legacy_managed_jobs=[], reload_callback=lambda:True) is True
            result = yaml.safe_load(path.read_text())
            assert prior['scrape_configs'][1] in result['scrape_configs']
            discovery = next(row for row in result['scrape_configs'] if row['job_name'] == 'dc-managed')
            assert discovery['http_sd_configs'][0]['url'].endswith('/api/prometheus/discovery')
            assert [row['targets'] for row in build_discovery_targets([server])] == [
                ['10.0.0.99:9100'], ['10.0.0.99:9835']]

    def test_removes_only_explicitly_adopted_deleted_server_job(self, app, tmp_path):
        path = tmp_path / 'prometheus.yml'
        unknown = {'job_name':'customer-storage','static_configs':[{'targets':['storage:9100']}]}
        config = {'global':{'scrape_interval':'15s'}, 'scrape_configs':[
            {'job_name':'prometheus','static_configs':[{'targets':['localhost:9090']}]},
            {'job_name':'old-server','static_configs':[{'targets':['10.0.0.50:9100']}]}, unknown]}
        path.write_text(yaml.safe_dump(config))
        assert update_prometheus_yml_targets([], config_path=path,
            legacy_managed_jobs=['old-server'], reload_callback=lambda:True) is True
        result = yaml.safe_load(path.read_text())
        names = [row['job_name'] for row in result['scrape_configs']]
        assert 'old-server' not in names
        assert 'prometheus' in names and unknown in result['scrape_configs']
        assert 'dc-managed' in names

    def test_legacy_writer_preserves_http_discovery_job(self, app, tmp_path):
        path = tmp_path / 'prometheus.yml'
        discovery = {'job_name':'dc-managed', 'http_sd_configs':[
            {'url':'http://dc-overview:5001/api/prometheus/discovery','refresh_interval':'30s'}]}
        path.write_text(yaml.safe_dump({'scrape_configs':[discovery]}))
        assert update_prometheus_yml_targets([], config_path=path,
            legacy_managed_jobs=[], reload_callback=lambda:True) is True
        assert yaml.safe_load(path.read_text())['scrape_configs'] == [discovery]
