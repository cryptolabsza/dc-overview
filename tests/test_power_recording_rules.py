"""Machine power uses bounded recording rules; exercise real producer rules in promtool."""
import ast
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

ROOT = Path(__file__).parents[1]
CANONICAL = ('dashboards/Vast_Dashboard.json', 'src/dc_overview/dashboards/Vast_Dashboard.json')
CPU = 'job:cpu_busy:ratio5m'
CPU_EXPR = 'sum by (job) (rate(node_cpu_seconds_total{mode!="idle"}[5m])) / sum by (job) (rate(node_cpu_seconds_total[5m]))'
FAST = 'job:cpu_busy:ratio5m * $CPU_Max_Power + sum by (job) (gpu:power_usage:watts or DCGM_FI_DEV_POWER_USAGE{UUID="VM-PASSTHROUGH"}) + $BasePower'
RAW = '(sum by (job) (rate(node_cpu_seconds_total{mode!="idle"}[$__rate_interval])) / sum by (job) (rate(node_cpu_seconds_total[$__rate_interval]))) * $CPU_Max_Power + sum by (job) (DCGM_FI_DEV_POWER_USAGE) + $BasePower'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def rules(producer):
    if producer == 'template':
        return yaml.safe_load((ROOT / 'config-templates/recording_rules.yml').read_text())
    tree = ast.parse((ROOT / 'src/dc_overview/fleet_manager.py').read_text())
    function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == '_generate_recording_rules')
    # Read the actual literal returned by the producer without importing deployment dependencies.
    return yaml.safe_load(ast.literal_eval(next(n.value for n in function.body if isinstance(n, ast.Return))))


@pytest.mark.parametrize('producer', ['generator', 'template'])
def test_new_group_and_predecessor_groups(producer):
    actual = rules(producer)
    added = [g for g in actual['groups'] if g['name'] == 'machine_power_estimate']
    assert added == [{'name': 'machine_power_estimate', 'interval': '30s', 'rules': [{'record': CPU, 'expr': CPU_EXPR}]}]
    previous = {'groups': [g for g in actual['groups'] if g['name'] != 'machine_power_estimate']}
    assert digest(previous) == 'c2182f5c6fe5e05e3183dc638f20b1091c5bf8bd95f411d03fd18bb440ec19c0'


@pytest.mark.parametrize('path', CANONICAL)
def test_only_power_panel_changes_and_history_is_explicit(path):
    dashboard = json.loads((ROOT / path).read_text())
    power = next(p for p in dashboard['panels'] if p['id'] == 26)
    fast, raw = power['targets']
    assert fast['refId'] == 'A' and fast['expr'] == FAST
    assert fast['range'] is True and fast.get('instant', False) is False
    assert fast.get('hide', False) is False
    assert fast['interval'] == '30s' and power['maxDataPoints'] == 1440
    assert raw['refId'] == 'B' and raw['expr'] == RAW and raw['hide'] is True
    assert raw['range'] is True and raw['datasource'] == fast['datasource']
    assert '5-minute' in power['description'] and 'activation' in power['description']
    assert 'disable A' in power['description'] and 'enable B' in power['description']
    assert 'no backfill' in power['description']
    # Gaps must remain visible at rule activation and missing-source periods.
    assert power['fieldConfig']['defaults']['custom']['spanNulls'] is False
    dashboard['panels'] = [p for p in dashboard['panels'] if p['id'] != 26]
    assert digest(dashboard) == '9da6d9671eab2afae54603b6126a5401cc269eee921e1f6ad8e3f4fac2f1c8f5'


def test_legacy_rule_variant_remains_unchanged():
    # This unreferenced older variant changes GPU labels/semantics; do not silently migrate it.
    assert hashlib.sha256((ROOT / 'prometheus/recording_rules.yml').read_bytes()).hexdigest() == '009b7aabe6e3d1cfefed53451af9ed096319b67ea69152e36bdec85b051c34d1'


def counter(job, mode, values, instance='a', cpu='0'):
    return {'series': f'node_cpu_seconds_total{{job="{job}",instance="{instance}",cpu="{cpu}",mode="{mode}"}}', 'values': values}


def expected(job, value, metric=CPU):
    name = metric or ''
    return {'labels': f'{name}{{job="{job}"}}', 'value': value}


def cpu_pair(job, busy='0+7.5x40', idle='0+7.5x40'):
    return [counter(job, 'user', busy), counter(job, 'idle', idle)]


def query_test(expr, at, samples):
    return {'expr': expr, 'eval_time': at, 'exp_samples': samples}


def native_cases():
    # Unequal instance rates and multiple cores/modes distinguish a ratio of sums
    # from an average of idle fractions. Weighted busy=(.8+.2+.5)/(4+1)=.3.
    weighted = [counter('weighted', 'user', '0+12x40'), counter('weighted', 'iowait', '0+3x40'),
                counter('weighted', 'idle', '0+45x40'),
                counter('weighted', 'system', '0+7.5x40', 'b', '1'),
                counter('weighted', 'idle', '0+7.5x40', 'b', '1')]
    reset = '0+7.5x11 0+7.5x28'
    cases = [{'name': 'weighted, multiple CPUs/instances/modes, two jobs and reset',
              'interval': '15s', 'input_series': weighted + cpu_pair('second', '0+3x40', '0+12x40') + cpu_pair('reset', reset, reset),
              'promql_expr_test': [query_test(CPU, '10m', [expected('weighted', .3), expected('second', .2), expected('reset', .5)]),
                                  query_test(CPU, '4m', [expected('weighted', .3), expected('second', .2), expected('reset', .5)])]},
             {'name': 'idle zero, zero denominator, missing inputs and insufficient first sample',
              'interval': '15s', 'input_series': cpu_pair('idle', '0+0x40', '0+15x40') + cpu_pair('zero', '0+0x40', '0+0x40') + [counter('idle-only', 'idle', '0+15x40')],
              'promql_expr_test': [query_test(CPU, '0s', []), query_test(CPU + '{job!="zero"}', '10m', [expected('idle', 0)]),
                                  query_test('count(job:cpu_busy:ratio5m{job="zero"} != job:cpu_busy:ratio5m{job="zero"})', '10m', [{'labels': '{}', 'value': 1}])]},
             {'name': 'stale input disappears after rate window', 'interval': '15s',
              'input_series': cpu_pair('stale', '0+7.5x20 stale _x23', '0+7.5x20 stale _x23'),
              'promql_expr_test': [query_test(CPU, '5m', [expected('stale', .5)]), query_test(CPU, '11m', [])]}]
    gpu = [
        {'series': 'DCGM_FI_DEV_POWER_USAGE{job="machine",UUID="real",source="host",gpu="0"}', 'values': '100+0x40'},
        {'series': 'DCGM_FI_DEV_POWER_USAGE{job="machine",UUID="vm",source="vm",gpu="1"}', 'values': '50+0x40'},
        {'series': 'DCGM_FI_DEV_POWER_USAGE{job="machine",gpu="2"}', 'values': '10+0x40'},
        {'series': 'DCGM_FI_DEV_POWER_USAGE{job="machine",UUID="other",source="extra",rack="a"}', 'values': '20+0x40'},
        {'series': 'DCGM_FI_DEV_POWER_USAGE{job="machine",UUID="VM-PASSTHROUGH",source="host"}', 'values': '7+0x40'},
        {'series': 'DCGM_FI_DEV_POWER_USAGE{job="placeholder",UUID="VM-PASSTHROUGH"}', 'values': '0+0x40'},
        {'series': 'DCGM_FI_DEV_POWER_USAGE{job="gpu-only",UUID="real"}', 'values': '90+0x40'},
    ]
    expr = FAST.replace('$CPU_Max_Power', '200').replace('$BasePower', '40')
    raw5m = RAW.replace('$__rate_interval', '5m').replace('$CPU_Max_Power', '200').replace('$BasePower', '40')
    cases.append({'name': 'actual fast target GPU compatibility, variable scaling, absent CPU/GPU and job matching', 'interval': '15s',
                  'input_series': gpu + cpu_pair('machine') + cpu_pair('placeholder') + cpu_pair('cpu-only'),
                  'promql_expr_test': [query_test(expr, '10m', [expected('machine', 327, ''), expected('placeholder', 140, '')]),
                                      query_test(raw5m, '10m', [expected('machine', 327, ''), expected('placeholder', 140, '')]),
                                      query_test(expr.replace('200', '400').replace('+ 40', '+ 60'), '10m', [expected('machine', 447, ''), expected('placeholder', 260, '')]) ]})
    return cases


@pytest.mark.parametrize('producer', ['generator', 'template'])
def test_native_promtool_recording_and_final_power_semantics(producer, tmp_path):
    executable = shutil.which('promtool')
    assert executable, 'promtool is required for power recording acceptance'
    rule_file = tmp_path / 'recording_rules.yml'
    rule_file.write_text(yaml.safe_dump(rules(producer), sort_keys=False))
    fixture = tmp_path / 'power.test.yml'
    fixture.write_text(yaml.safe_dump({'rule_files': [str(rule_file)], 'evaluation_interval': '30s',
                                    'fuzzy_compare': True, 'tests': native_cases()}, sort_keys=False))
    check = subprocess.run([executable, 'check', 'rules', str(rule_file)], text=True, capture_output=True)
    assert check.returncode == 0, check.stdout + check.stderr
    result = subprocess.run([executable, 'test', 'rules', str(fixture)], text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
