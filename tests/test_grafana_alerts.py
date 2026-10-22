"""Selected custom datasource caller regression; no Grafana service."""
import copy
from types import SimpleNamespace

import pytest
import yaml

from dc_overview import grafana_alerts
from dc_overview.cli import _sync_alerts_for_upgrade


def queries(document):
    return [query for group in document['groups'] for rule in group['rules'] for query in rule['data']]


def test_custom_datasource_remaps_only_owned_prometheus_query_references(tmp_path):
    default = yaml.safe_load(grafana_alerts.render_grafana_alerts())
    path = grafana_alerts.install_grafana_alerts(tmp_path, datasource_uid='customer-stable')
    custom = yaml.safe_load(path.read_bytes())
    before = queries(default); after = queries(custom)
    assert any(q['datasourceUid'] == 'prometheus' for q in before)
    assert len(before) == len(after)
    for old, new in zip(before, after):
        if old['datasourceUid'] == 'prometheus':
            assert new['datasourceUid'] == 'customer-stable'
            assert new['model']['datasource'] == {'type': 'prometheus', 'uid': 'customer-stable'}
            expected = copy.deepcopy(old); expected['datasourceUid'] = 'customer-stable'; expected['model']['datasource'] = new['model']['datasource']
            assert new == expected
        else: assert new == old
    assert [r['uid'] for g in default['groups'] for r in g['rules']] == [r['uid'] for g in custom['groups'] for r in g['rules']]


@pytest.mark.parametrize('uid', ['', '__expr__', '-100', 'unsafe uid', 'a' * 41, None])
def test_invalid_uid_fails_before_provisioning_writes(tmp_path, uid):
    with pytest.raises(ValueError, match='datasource'):
        grafana_alerts.install_grafana_alerts(tmp_path, datasource_uid=uid)
    assert not list(tmp_path.iterdir())


def test_fresh_custom_uid_then_normal_cli_upgrade_and_repeat_preserves_identity(tmp_path, monkeypatch):
    (tmp_path / 'fleet-config.yaml').write_text('grafana:\n  prometheus_datasource_uid: customer-stable\n  admin_password: synthetic-not-live\n')
    path = grafana_alerts.install_grafana_alerts(tmp_path, datasource_uid='customer-stable')
    before = path.read_bytes()
    monkeypatch.setattr(grafana_alerts.requests, 'get', lambda url, **k: SimpleNamespace(raise_for_status=lambda: None,
        json=lambda: [{'type': 'prometheus', 'uid': 'customer-stable'}, {'type': 'prometheus', 'uid': 'external-not-owned'}]))
    monkeypatch.setattr(grafana_alerts, 'reload_grafana_alerts', lambda *a, **k: True)
    for _ in range(2):
        assert _sync_alerts_for_upgrade(tmp_path).success
        assert path.read_bytes() == before


@pytest.mark.parametrize('document', [[], {}, [{'type': 'prometheus', 'uid': 'wrong'}],
    [{'type': 'prometheus', 'uid': 'customer-stable'}, {'type': 'prometheus', 'uid': 'customer-stable'}]])
def test_sync_holds_missing_malformed_or_ambiguous_live_uid_before_writes(tmp_path, monkeypatch, document):
    (tmp_path / 'fleet-config.yaml').write_text('grafana: {prometheus_datasource_uid: customer-stable}\n')
    before = (tmp_path / 'fleet-config.yaml').read_bytes()
    monkeypatch.setattr(grafana_alerts.requests, 'get', lambda *a, **k: SimpleNamespace(raise_for_status=lambda: None, json=lambda: document))
    with pytest.raises((ValueError, RuntimeError), match='datasource|Grafana'):
        _sync_alerts_for_upgrade(tmp_path)
    assert list(tmp_path.iterdir()) == [tmp_path / 'fleet-config.yaml']
    assert (tmp_path / 'fleet-config.yaml').read_bytes() == before
