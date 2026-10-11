"""Customer monitoring configuration survives ordinary product maintenance."""
import copy
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

from dc_overview.monitoring import (merge_prometheus_config, apply_prometheus_config,
    atomic_write_bytes, prepare_grafana_dashboards, select_prometheus_datasource,
    validate_customer_directory, load_customer_dashboards)


def job(name, endpoint):
    return {'job_name': name, 'static_configs': [{'targets': [endpoint]}]}


def test_merge_retains_customer_jobs_rules_globals_and_alert_receivers():
    existing = {'global': {'scrape_interval': '37s', 'external_labels': {'site': 'customer'}},
        'alerting': {'alertmanagers': [{'static_configs': [{'targets': ['alerts:9093']}]}]},
        'rule_files': ['/etc/prometheus/customer/alerts.yml'],
        'scrape_configs': [job('prometheus', 'old-prometheus:9090'), job('storage', 'storage:9100'), job('retired-worker', 'worker:9100')]}
    original = copy.deepcopy(existing)
    generated = {'global': {'scrape_interval': '15s', 'evaluation_interval': '15s'},
        'rule_files': ['/etc/prometheus/recording_rules.yml'],
        'scrape_configs': [job('prometheus', 'prometheus:9090'), job('dc-managed', 'discovery:9100')]}
    result = merge_prometheus_config(existing, generated, [job('ceph', 'ceph:9283')],
        ['/etc/prometheus/customer/storage.yml'], ['retired-worker'])
    assert existing == original
    assert result['global'] == {'scrape_interval': '37s', 'external_labels': {'site': 'customer'}, 'evaluation_interval': '15s'}
    assert result['alerting'] == existing['alerting']
    assert {row['job_name'] for row in result['scrape_configs']} == {'prometheus', 'dc-managed', 'storage', 'ceph'}
    assert result['rule_files'] == ['/etc/prometheus/customer/alerts.yml', '/etc/prometheus/recording_rules.yml', '/etc/prometheus/customer/storage.yml']
    assert merge_prometheus_config(result, generated, [job('ceph', 'ceph:9283')], ['/etc/prometheus/customer/storage.yml'], ['retired-worker']) == result


@pytest.mark.parametrize('extra', [[job('dc-managed', 'a:9100')],
    [job('dup', 'a:9100'), job('dup', 'b:9100')],
    [job('another', 'storage:9100')],
    [dict(job('private', 'private:9100'), authorization={'credentials': 'synthetic-secret'})],
    [dict(job('private', 'private:9100'), bearer_token_file='/outside/key')]])
def test_invalid_customer_job_collision_endpoint_or_inline_secret_fails(extra):
    with pytest.raises(ValueError):
        merge_prometheus_config({'scrape_configs': [job('storage', 'storage:9100')]},
                                {'scrape_configs': [job('dc-managed', 'worker:9100')]}, extra)


def test_old_reference_requires_explicit_adoption_and_is_not_rewritten():
    existing = {'scrape_configs': [dict(job('old-feed', 'feed:9100'), basic_auth={'username':'reader','password_file':'/old/customer.key'})]}
    with pytest.raises(ValueError, match='reference'):
        merge_prometheus_config(existing, {'scrape_configs': []})
    result = merge_prometheus_config(existing, {'scrape_configs': []}, adopted_file_references=('/old/customer.key',))
    assert result == existing


def test_failed_reload_restores_previous_bytes_and_permissions(tmp_path):
    path = tmp_path / 'prometheus.yml'
    before = b'# customer comment\nscrape_configs: []\n'
    path.write_bytes(before)
    path.chmod(0o640)
    outcomes = iter([False, True])
    observed = []
    def reload():
        observed.append(path.read_bytes())
        return next(outcomes)
    with pytest.raises(RuntimeError, match='restored'):
        apply_prometheus_config(path, {'scrape_configs':[job('new', 'new:9100')]}, validate_candidate=lambda candidate: True, reload_config=reload)
    assert path.read_bytes() == before
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert len(observed) == 2 and observed[-1] == before


def test_validation_failure_never_replaces_file_or_reloads(tmp_path):
    path = tmp_path / 'prometheus.yml'
    path.write_bytes(b'scrape_configs: []\n')
    with pytest.raises(RuntimeError, match='validation'):
        apply_prometheus_config(path, {'scrape_configs': []}, validate_candidate=lambda candidate: False,
            reload_config=lambda: pytest.fail('must not reload'))
    assert path.read_bytes() == b'scrape_configs: []\n'


def test_real_promtool_validates_rules_and_rejects_broken_rule_before_write(tmp_path):
    executable = shutil.which('promtool')
    if not executable:
        pytest.skip('promtool unavailable: actual selected-artifact validation is a Linux gate')
    rule = tmp_path / 'customer-rules.yml'
    rule.write_text('groups:\n- name: customer\n  rules:\n  - alert: CustomerHostDown\n    expr: up == 0\n')
    path = tmp_path / 'prometheus.yml'
    path.write_text('scrape_configs: []\n')
    config = {'rule_files':[str(rule)], 'scrape_configs':[job('synthetic', '127.0.0.1:9090')]}
    def validate(candidate):
        return subprocess.run([executable, 'check', 'config', str(candidate)], capture_output=True).returncode == 0
    assert apply_prometheus_config(path, config, validate_candidate=validate, reload_config=lambda: True) is True
    before = path.read_bytes()
    rule.write_text('groups:\n- name: customer\n  rules:\n  - alert: Broken\n    expr: "up + ("\n')
    with pytest.raises(RuntimeError, match='validation'):
        apply_prometheus_config(path, config, validate_candidate=validate, reload_config=lambda: pytest.fail('must not reload'))
    assert path.read_bytes() == before


def test_dashboard_defaults_preserve_edits_and_customer_datasources():
    product = [{'uid':'product', 'title':'Product', 'panels':[{'datasource':{'type':'prometheus','uid':'${DS_PROMETHEUS}'}}]}]
    customer = [{'uid':'customer', 'title':'Customer', 'panels':[{'datasource':{'type':'loki','uid':'logs'}}]}]
    existing = [{'uid':'product','title':'Edited', 'panels':[{'datasource':{'type':'prometheus','uid':'alternate-prom'}}]}]
    result = prepare_grafana_dashboards(product, customer, existing, prometheus_datasource_uid='stable-prom')
    assert result['skipped_uids'] == ['product']
    assert len(result['payloads']) == 1
    assert result['payloads'][0]['dashboard'] == customer[0]
    assert result['payloads'][0]['overwrite'] is False
    overwritten = prepare_grafana_dashboards(product, customer, existing, prometheus_datasource_uid='stable-prom', overwrite_product_dashboards=True)
    assert overwritten['payloads'][0]['dashboard']['panels'][0]['datasource']['uid'] == 'stable-prom'
    assert overwritten['payloads'][0]['overwrite'] is True
    assert product[0]['panels'][0]['datasource']['uid'] == '${DS_PROMETHEUS}'


def test_customer_uid_product_collision_fails_before_preparation():
    with pytest.raises(ValueError, match='UID'):
        prepare_grafana_dashboards([{'uid':'product'}], [{'uid':'product'}], [], prometheus_datasource_uid='stable')


def test_datasource_selection_reuses_stable_identity_and_refuses_ambiguity():
    sources = [{'uid':'logs', 'type':'loki'}, {'uid':'stable', 'type':'prometheus', 'isDefault':True},
               {'uid':'other', 'type':'prometheus'}]
    assert select_prometheus_datasource(sources) == 'stable'
    assert select_prometheus_datasource(sources, 'other') == 'other'
    with pytest.raises(ValueError, match='ambiguous'):
        select_prometheus_datasource([dict(source, isDefault=False) for source in sources])


def test_customer_dashboard_loading_rejects_symlink(tmp_path):
    directory = tmp_path / 'dashboards'
    directory.mkdir()
    (directory / 'customer.json').write_text(json.dumps({'uid':'customer','panels':[]}))
    assert load_customer_dashboards(str(directory))[0]['uid'] == 'customer'
    (directory / 'unsafe.json').symlink_to(directory / 'customer.json')
    with pytest.raises(ValueError, match='symlink'):
        load_customer_dashboards(str(directory))


@pytest.mark.parametrize('headers', [
    {'Authorization': {'values': ['synthetic-token']}},
    {'X-API-Key': {'secrets': ['synthetic-token']}},
    {'Authorization': {'files': ['/outside/header.key']}},
])
def test_http_header_credentials_require_customer_file_reference(headers):
    with pytest.raises(ValueError, match='file|inline|reference'):
        merge_prometheus_config({}, {'scrape_configs': []},
            [dict(job('private', 'private:9100'), http_headers=headers)])


def test_customer_header_file_reference_is_preserved():
    private = dict(job('private', 'private:9100'),
        http_headers={'Authorization': {'files': ['/etc/prometheus/customer/header.key']}})
    assert merge_prometheus_config({}, {'scrape_configs': []}, [private])['scrape_configs'] == [private]


@pytest.mark.parametrize('reference', ['/etc/prometheus/customer/key\n', '/etc/prometheus/customer/../key'])
def test_unsafe_file_reference_is_rejected(reference):
    with pytest.raises(ValueError, match='reference'):
        merge_prometheus_config({}, {'scrape_configs': []},
            [dict(job('private','private:9100'), bearer_token_file=reference)])


def test_duplicate_datasource_authority_and_empty_prepared_uid_fail_closed():
    sources = [{'uid':'stable','type':'prometheus','isDefault':True}, {'uid':'stable','type':'loki'}]
    with pytest.raises(ValueError, match='duplicated|duplicate'):
        select_prometheus_datasource(sources)
    with pytest.raises(ValueError, match='UID'):
        prepare_grafana_dashboards([{'uid':'product'}], [], [], prometheus_datasource_uid='')


def test_atomic_file_sd_retains_metadata_and_complete_document(tmp_path):
    path = tmp_path / 'prometheus_targets.json'
    path.write_text('[]')
    path.chmod(0o600)
    before = path.stat()
    payload = json.dumps([{'targets':['synthetic:9100'], 'labels':{'job':'customer'}}]).encode()
    atomic_write_bytes(path, payload)
    after = path.stat()
    assert json.loads(path.read_bytes()) == json.loads(payload)
    assert (stat.S_IMODE(after.st_mode), after.st_uid, after.st_gid) == (0o600, before.st_uid, before.st_gid)
    assert after.st_ino != before.st_ino


def test_unverified_recovery_never_reports_success(tmp_path):
    path = tmp_path / 'prometheus.yml'
    before = b'# prior\nscrape_configs: []\n'
    path.write_bytes(before)
    with pytest.raises(RuntimeError, match='unverified'):
        apply_prometheus_config(path, {'scrape_configs':[job('new','new:9100')]},
            validate_candidate=lambda _:True, reload_config=lambda:None)
    assert path.read_bytes() == before


def test_empty_prepared_datasource_uid_fails_closed():
    with pytest.raises(ValueError, match='UID'):
        prepare_grafana_dashboards([{'uid':'product'}], [], [], prometheus_datasource_uid='')


def test_stale_merge_snapshot_never_overwrites_operator_edit(tmp_path):
    path = tmp_path / 'prometheus.yml'
    snapshot = b'scrape_configs: []\n'
    path.write_bytes(snapshot)
    operator = b'# concurrent customer edit\nscrape_configs: []\n'
    path.write_bytes(operator)
    with pytest.raises(RuntimeError, match='changed'):
        apply_prometheus_config(path, {'scrape_configs':[job('new','new:9100')]},
            expected_previous_bytes=snapshot, validate_candidate=lambda _:pytest.fail('must not validate stale merge'),
            reload_config=lambda:pytest.fail('must not reload stale merge'))
    assert path.read_bytes() == operator


def test_operator_edit_during_candidate_validation_is_preserved(tmp_path):
    path = tmp_path / 'prometheus.yml'
    path.write_bytes(b'scrape_configs: []\n')
    operator = b'# edit during validation\nscrape_configs: []\n'
    def validate(_):
        path.write_bytes(operator)
        return True
    with pytest.raises(RuntimeError,match='changed'):
        apply_prometheus_config(path, {'scrape_configs':[job('new','new:9100')]},
            validate_candidate=validate, reload_config=lambda:pytest.fail('must not overwrite/reload'))
    assert path.read_bytes() == operator
