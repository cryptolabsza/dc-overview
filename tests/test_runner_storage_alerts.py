"""Real PromQL contracts for storage pressure, unknown data and quota demand."""
from pathlib import Path
import shutil
import subprocess

import yaml
from dc_overview import grafana_alerts


ROOT = Path(__file__).parents[1]
GIB = 1024**3


def rules():
    document = yaml.safe_load(grafana_alerts.render_grafana_alerts())
    return {rule['uid']: rule for group in document['groups'] for rule in group['rules']
            if rule['uid'].startswith('runner-storage-')}


def test_storage_rules_are_owned_and_have_an_independent_unknown_signal():
    owned = rules()
    assert 'runner-storage-telemetry' in owned
    assert 'runner-storage-pool-critical' in owned
    assert 'runner-storage-quota-pressure' in owned
    assert set(owned) <= grafana_alerts.MANAGED_ALERT_UIDS
    assert owned['runner-storage-telemetry']['noDataState'] == 'Alerting'
    assert owned['runner-storage-telemetry']['execErrState'] == 'Alerting'
    for uid, rule in owned.items():
        expr = rule['data'][0]['model']['expr']
        if uid != 'runner-storage-raid':
            assert 'ci_storage_' in expr
        if uid != 'runner-storage-telemetry' and uid != 'runner-storage-raid':
            assert 'ci_storage_observed_timestamp_seconds' in expr
        if uid != 'runner-storage-telemetry':
            assert rule['noDataState'] == 'KeepLast'
            assert rule['execErrState'] == 'KeepLast'
    assert owned['runner-storage-cache-high']['labels']['severity'] == 'warning'


def test_storage_pressure_and_missing_data_with_real_promql(tmp_path):
    owned = rules()
    assert owned
    cases = []
    def series(host, changes=None, omit=()):
        values = {'up': 1, 'ci_storage_valid': 1, 'ci_storage_pool_valid': 1,
                  'ci_storage_observed_timestamp_seconds': '0+30x8',
                  'ci_storage_pool_effective_free_bytes': 1000*GIB,
                  'ci_storage_quota_valid': 1, 'ci_storage_artifact_valid': 1,
                  'ci_storage_quota_effective_remaining_bytes': 400*GIB,
                  'ci_pool_inventory_valid': 1, 'ci_pool_capacity_slots': 2,
                  'ci_pool_occupied_slots': 1,
                  'ci_pool_collection_timestamp_seconds': '0+30x8',
                  'ci_pool_memory_observed_timestamp_seconds': '0+30x8',
                  'ci_pool_queue_valid': 1, 'ci_pool_queue_waiting_jobs': 0,
                  'ci_pool_queue_observed_timestamp_seconds': '0+30x8'}
        values.update(changes or {})
        labels = f'job="{host}",instance="{host}",exporter="node"'
        rows = [{'series': f'{name}{{{labels}}}', 'values': value if type(value) is str else f'{value}+0x8'}
                for name, value in values.items() if name not in omit]
        rows += [{'series': f'ci_storage_volume_valid{{{labels},volume="{volume}"}}', 'values': '1+0x8'}
                 for volume in ('root', 'pool', 'artifact' if host == 'wk01' else 'quota')]
        if 'core-volume' in omit:
            rows = [row for row in rows if 'ci_storage_volume_valid' not in row['series'] or 'volume="root"' not in row['series']]
        return rows
    def expect(uid, value):
        return {'expr': 'sum(('+owned[uid]['data'][0]['model']['expr']+')'+(' and on(job,instance) up{job="wk01",exporter="node"}' if uid == 'runner-storage-pool-critical' else '')+')', 'eval_time': '120s',
                'exp_samples': [] if value is None else [{'labels': '{}', 'value': value}]}
    for name, change, omit, telemetry, critical in [
        ('healthy', {}, (), 0, 0),
        ('low conservative headroom', {'ci_storage_pool_effective_free_bytes': 640*GIB}, (), 0, 1),
        ('negative conservative headroom', {'ci_storage_pool_effective_free_bytes': -1}, (), 0, 1),
        ('stale observation', {'ci_storage_observed_timestamp_seconds': '0+0x8'}, (), 1, None),
        ('invalid storage', {'ci_storage_valid': 0}, (), 1, None),
        ('missing observation', {}, ('ci_storage_valid',), 1, None),
        ('missing core volume', {}, ('core-volume',), 1, 0),
    ]:
        cases.append({'name': name, 'interval': '30s',
                      'input_series': series('wk01', change, omit)+series('master'),
                      'promql_expr_test': [expect('runner-storage-telemetry', telemetry),
                                           expect('runner-storage-pool-critical', critical)]})
    for name, waiting, occupied, expected in [('no demand', 0, 1, 0),
                                               ('demand and vacant slot', 3, 1, 1),
                                               ('normal full occupancy', 3, 2, 0)]:
        cases.append({'name': name, 'interval': '30s',
                      'input_series': series('wk01', {'ci_pool_queue_waiting_jobs': waiting})+
                                      series('master', {'ci_storage_quota_effective_remaining_bytes': 32*GIB,
                                                        'ci_pool_occupied_slots': occupied}),
                      'promql_expr_test': [expect('runner-storage-quota-pressure', expected)]})
    # A read-only but correctly identified cache must warn and later resolve.
    labels = 'job="wk01",instance="wk01",exporter="node",volume="apt"'
    for readonly in (0, 1):
        cases.append({'name': 'cache readonly '+str(readonly), 'interval': '30s',
                      'input_series': series('wk01')+[
                          {'series': 'ci_storage_volume_valid{'+labels+'}', 'values': '1+0x8'},
                          {'series': 'ci_storage_volume_readonly{'+labels+'}', 'values': f'{readonly}+0x8'}],
                      'promql_expr_test': [expect('runner-storage-cache-mount', readonly)]})
    cases.append({'name': 'demand ends after quota pressure', 'interval': '30s',
                  'input_series': series('wk01', {'ci_pool_queue_waiting_jobs': '3 3 3 0 0 0 0 0 0'})+
                                  series('master', {'ci_storage_quota_effective_remaining_bytes': 32*GIB}),
                  'promql_expr_test': [expect('runner-storage-quota-pressure', 0)]})
    fixture = tmp_path/'runner-storage.test.yml'
    fixture.write_text(yaml.safe_dump({'evaluation_interval': '30s', 'tests': cases}, sort_keys=False))
    executable = shutil.which('promtool')
    assert executable, 'promtool is required for storage alert acceptance'
    result = subprocess.run([executable, 'test', 'rules', str(fixture)], text=True, capture_output=True)
    assert result.returncode == 0, result.stdout+result.stderr
