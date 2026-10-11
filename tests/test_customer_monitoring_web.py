"""Inventory synchronization preserves customer ownership and effective reload proof."""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import requests
import yaml

from dc_overview.web_prometheus import update_prometheus_yml_targets, update_prometheus_targets, reload_prometheus


def server(**overrides):
    fields = dict(name='worker', monitoring_name='alias', server_ip='2001:db8::1')
    for name in ('node_exporter', 'dc_exporter', 'dcgm_exporter', 'watchdog_agent'):
        fields[name + '_installed'] = False
        fields[name + '_enabled'] = False
    fields.update(overrides)
    return SimpleNamespace(**fields)


def test_inventory_sync_preserves_deleted_unknown_jobs_rules_and_settings(tmp_path):
    path = tmp_path / 'prometheus.yml'
    unknown = {'job_name':'customer-storage', 'scrape_interval':'41s', 'static_configs':[{'targets':['storage:9100']}]}
    prior = {'global':{'scrape_interval':'37s'}, 'rule_files':['/etc/prometheus/customer/alerts.yml'],
             'scrape_configs':[unknown, {'job_name':'retired', 'static_configs':[{'targets':['old:9100']}]}]}
    path.write_text(yaml.safe_dump(prior))
    assert update_prometheus_yml_targets([], config_path=path, legacy_managed_jobs=['retired'], reload_callback=lambda: True) is True
    result = yaml.safe_load(path.read_text())
    assert result['global'] == prior['global']
    assert result['rule_files'] == prior['rule_files']
    assert unknown in result['scrape_configs']
    assert [row['job_name'] for row in result['scrape_configs']] == ['customer-storage','dc-managed']


def test_file_discovery_uses_same_alias_ipv6_and_install_enable_contract(tmp_path):
    host = server(node_exporter_installed=True, node_exporter_enabled=True,
                  dc_exporter_installed=False, dc_exporter_enabled=True,
                  watchdog_agent_installed=True, watchdog_agent_enabled=False)
    with patch('dc_overview.web_prometheus.update_prometheus_yml_targets', return_value=True):
        assert update_prometheus_targets([host], str(tmp_path)) is True
    targets = json.loads((tmp_path / 'prometheus_targets.json').read_text())
    assert targets == [{'targets':['[2001:db8::1]:9100'], 'labels':{'instance':'alias','job':'alias','exporter':'node'}}]


def test_inventory_duplicate_unknown_endpoint_requires_explicit_owner_adoption(tmp_path):
    path = tmp_path / 'prometheus.yml'
    path.write_text(yaml.safe_dump({'scrape_configs':[{'job_name':'unknown-customer', 'static_configs':[{'targets':['[2001:db8::1]:9100']}]}]}))
    before = path.read_bytes()
    result = update_prometheus_yml_targets([server(node_exporter_installed=True,node_exporter_enabled=True)],
        config_path=path, reload_callback=lambda: pytest.fail('must not reload'))
    assert result is False
    assert path.read_bytes() == before


def test_failed_web_reload_restores_previous_bytes_and_reports_false(tmp_path):
    path = tmp_path / 'prometheus.yml'
    before = b'# original\nscrape_configs: []\n'
    path.write_bytes(before)
    outcomes = iter([False, True])
    result = update_prometheus_yml_targets([], config_path=path, reload_callback=lambda: next(outcomes))
    assert result is False
    assert path.read_bytes() == before


def test_reload_rejects_failed_commands_and_stale_loaded_config():
    with (patch('dc_overview.web_prometheus.requests.post', side_effect=requests.ConnectionError('synthetic')),
         patch('dc_overview.web_prometheus.requests.get', side_effect=requests.ConnectionError('synthetic')),
         patch('dc_overview.web_prometheus.subprocess.run', return_value=SimpleNamespace(returncode=1))):
        assert reload_prometheus() is False
    response = SimpleNamespace(status_code=200, raise_for_status=lambda:None)
    loaded = SimpleNamespace(status_code=200, raise_for_status=lambda:None,
        json=lambda:{'status':'success','data':{'yaml':'scrape_configs: []\n'}})
    with (patch('dc_overview.web_prometheus.requests.post', return_value=response),
         patch('dc_overview.web_prometheus.requests.get', return_value=loaded),
         patch('dc_overview.web_prometheus.subprocess.run') as run):
        assert reload_prometheus(expected_config={'scrape_configs':[{'job_name':'new'}]}) is False
        run.assert_not_called()


def test_successful_http_reload_requires_effective_declared_config():
    expected = {'global':{'scrape_interval':'37s'}, 'scrape_configs':[{'job_name':'customer','static_configs':[{'targets':['synthetic:9100']}]}]}
    loaded_config = dict(expected, global_config_unused='server-added-default')
    loaded_config['global'] = dict(expected['global'], evaluation_interval='1m')
    response = SimpleNamespace(status_code=200, raise_for_status=lambda:None)
    loaded = SimpleNamespace(status_code=200, raise_for_status=lambda:None,
        json=lambda:{'status':'success','data':{'yaml':yaml.safe_dump(loaded_config)}})
    with (patch('dc_overview.web_prometheus.requests.post', return_value=response),
          patch('dc_overview.web_prometheus.requests.get', return_value=loaded),
          patch('dc_overview.web_prometheus.subprocess.run') as run):
        assert reload_prometheus(expected_config=expected) is True
        run.assert_not_called()


def test_zero_exit_fallback_requires_fresh_successful_runtime_acceptance():
    from datetime import datetime, timedelta, timezone
    def runtime(success, fresh):
        stamp = datetime.now(timezone.utc) + timedelta(hours=1 if fresh else -1)
        return SimpleNamespace(status_code=200, raise_for_status=lambda:None,
            json=lambda:{'status':'success','data':{'reloadConfigSuccess':success,'lastConfigTime':stamp.isoformat()}})
    with (patch('dc_overview.web_prometheus.requests.post', side_effect=requests.ConnectionError('synthetic')),
          patch('dc_overview.web_prometheus.subprocess.run', return_value=SimpleNamespace(returncode=0)),
          patch('dc_overview.web_prometheus.requests.get', return_value=runtime(True,False))):
        assert reload_prometheus() is False
    with (patch('dc_overview.web_prometheus.requests.post', side_effect=requests.ConnectionError('synthetic')),
          patch('dc_overview.web_prometheus.subprocess.run', return_value=SimpleNamespace(returncode=0)),
          patch('dc_overview.web_prometheus.requests.get', return_value=runtime(False,True))):
        assert reload_prometheus() is False
    with (patch('dc_overview.web_prometheus.requests.post', side_effect=requests.ConnectionError('synthetic')),
          patch('dc_overview.web_prometheus.subprocess.run', return_value=SimpleNamespace(returncode=0)),
          patch('dc_overview.web_prometheus.requests.get', return_value=runtime(True,True))):
        assert reload_prometheus() is True


def test_declared_product_config_directory_override_is_absolute(tmp_path, monkeypatch):
    from dc_overview.web_prometheus import _configuration_path
    path = tmp_path / 'prometheus' / 'prometheus.yml'
    monkeypatch.setenv('PROMETHEUS_CONFIG_PATH', str(path))
    assert _configuration_path() == path
    monkeypatch.setenv('PROMETHEUS_CONFIG_PATH','relative/prometheus.yml')
    with pytest.raises(ValueError,match='absolute'):
        _configuration_path()


def test_web_merge_passes_exact_snapshot_and_preserves_competing_edit(tmp_path, monkeypatch):
    import dc_overview.web_prometheus as web
    from dc_overview.monitoring import apply_prometheus_config
    path = tmp_path / 'prometheus.yml'
    original = b'# original comments\nscrape_configs: []\n'
    operator = b'# later customer change\nscrape_configs: []\n'
    path.write_bytes(original)
    def competing_apply(target, config, **kwargs):
        assert kwargs['expected_previous_bytes'] == original
        target.write_bytes(operator)
        return apply_prometheus_config(target, config, **kwargs)
    monkeypatch.setattr(web,'apply_prometheus_config',competing_apply)
    assert web.update_prometheus_yml_targets([],config_path=path,legacy_managed_jobs=[],
        reload_callback=lambda:pytest.fail('must not reload')) is False
    assert path.read_bytes() == operator
