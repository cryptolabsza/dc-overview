"""Current-inventory dashboard controls must not read stale range data."""
import json
from pathlib import Path
import ast
import shutil
import subprocess

import pytest
import yaml


ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize('path', [
    ROOT / 'src/dc_overview/dashboards/DC_Overview.json',
    ROOT / 'dashboards/DC_Overview.json',
    ROOT / 'src/dc_overview/dashboards/Vast_Dashboard.json',
    ROOT / 'dashboards/Vast_Dashboard.json',
])
def test_machine_overview_uses_instant_queries_only(path):
    dashboard = json.loads(path.read_text())
    table = next(panel for panel in dashboard['panels'] if panel.get('title') == 'Machine Overview')
    assert table['targets']
    assert all(target.get('instant') is True and target.get('range') is False
               for target in table['targets'])
    assert any(target.get('range') is True for panel in dashboard['panels']
               if panel is not table for target in panel.get('targets', []))


@pytest.mark.parametrize('path', [
    ROOT / 'src/dc_overview/dashboards/Node_Exporter_Full.json',
    ROOT / 'dashboards/Node_Exporter_Full.json',
])
def test_node_exporter_variables_select_current_labels(path):
    variables = {item['name']: item for item in json.loads(path.read_text())['templating']['list']}
    assert variables['job']['query']['query'] == 'query_result(count by (job) (node_uname_info))'
    assert variables['job']['regex'] == '/job="([^\"]+)"/'
    assert variables['node']['query']['query'] == 'query_result(node_uname_info{job="$job"})'
    assert variables['node']['regex'] == '/instance="([^\"]+)"/'


POOL_PATH = ROOT / 'src/dc_overview/dashboards/shared-runner-pool.json'
POOL_LABELS = 'job="wk01",instance="wk01",exporter="node"'
SAMPLED_TIME_TITLES = {'Running VM time (sampled)', 'Charged VM time (sampled)', 'Per-slot running time (sampled)'}


def pool_dashboard():
    return json.loads(POOL_PATH.read_text())


def pool_targets(dashboard):
    for panel in dashboard['panels']:
        for target in panel.get('targets', []):
            yield panel, target


def test_shared_pool_ships_and_uses_current_stats_with_bounded_slot_states():
    dashboard = pool_dashboard()
    assert dashboard['uid'] == 'shared-runner-pool'
    assert '"dashboards/*.json"' in (ROOT / 'pyproject.toml').read_text()
    tree = ast.parse((ROOT / 'src/dc_overview/quickstart.py').read_text())
    configure = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'configure_grafana')
    registrations = next(ast.literal_eval(node.value) for node in configure.body
                         if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'dashboards' for t in node.targets))
    assert any(item['local_file'] == POOL_PATH.name for item in registrations)
    for panel, target in pool_targets(dashboard):
        assert target['datasource'] == {'type': 'prometheus', 'uid': 'prometheus'}
        assert POOL_LABELS in target['expr']
        assert 'rate(' not in target['expr']  # CPU is already an interval gauge.
        assert '$__to' not in target['expr']  # Historical freshness must use evaluation time.
        if panel['type'] in {'stat', 'bargauge', 'gauge'}:
            assert target.get('instant') is True and target.get('range') is False
        else:
            assert target.get('range') is True and target.get('instant') is False
        if 'ci_pool_slot_' in target['expr']:
            assert 'slot=~"[0-9]"' in target['expr']
    timeline = next(p for p in dashboard['panels'] if p['type'] == 'state-timeline')
    mappings = timeline['fieldConfig']['defaults']['mappings'][0]['options']
    assert {int(code): value['text'].lower() for code, value in mappings.items()} == {
        0: 'empty', 1: 'warm', 2: 'reserved', 3: 'preparing', 4: 'launching',
        5: 'running', 6: 'quarantined', 7: 'destroying', 8: 'ready', 9: 'unknown', 10: 'disabled',
    }
    assert timeline['fieldConfig']['defaults']['custom']['spanNulls'] is False
    assert any(panel['type'] == 'heatmap' for panel in dashboard['panels'])


def pool_series(overrides=None, omit=(), gone=False):
    """Real sanitized interface, including two out-of-bound slot labels to reject."""
    metrics = {
        'collection_timestamp_seconds': '0+30x8',
        'memory_observed_timestamp_seconds': '0+30x8',
        'cpu_observed_timestamp_seconds': '0+30x8',
        'inventory_valid': '1+0x8', 'cpu_valid': '1+0x8',
        'capacity_slots': '6+0x8', 'occupied_slots': '5+0x8', 'warm_slots': '1+0x8',
        'cpu_used_cores': '4+0x8', 'cpu_limit_cores': '16+0x8',
        'memory_used_bytes': '8589934592+0x8', 'memory_reserved_bytes': '12884901888+0x8',
        'memory_limit_bytes': '34359738368+0x8',
    }
    metrics.update(overrides or {})
    series = []
    for metric, values in metrics.items():
        if metric not in omit:
            series.append({'series': f'ci_pool_{metric}{{{POOL_LABELS}}}', 'values': values if not gone else '0 stale'})
    for slot, state in enumerate([0, 1, 5, 6, 7, 2, 10, 10, 10, 10, 5, 5]):
        for metric, value in [('slot_state', state), ('slot_memory_used_bytes', 536870912),
                              ('slot_memory_reserved_bytes', 1073741824),
                              ('slot_guest_memory_used_bytes', 268435456),
                              ('slot_guest_memory_reserved_bytes', 1073741824)]:
            if metric not in omit:
                series.append({'series': f'ci_pool_{metric}{{{POOL_LABELS},slot="{slot}"}}',
                               'values': f'{value}+0x8' if not gone else f'{value} stale'})
    return series


def test_shared_pool_actual_queries_hide_stale_invalid_and_missing_measurements(tmp_path):
    """Execute shipped PromQL, rather than a second implementation of freshness."""
    executable = shutil.which('promtool')
    assert executable, 'promtool is required for shared runner query acceptance'
    dashboard = pool_dashboard()
    measured = [(p, t) for p, t in pool_targets(dashboard)
                if p['title'] != 'Source health' and not p['title'].startswith('Waiting jobs') and p['title'] not in SAMPLED_TIME_TITLES]
    # Each tuple is (source overrides, omitted metrics, eval time, CPU valid, inventory valid, source gone).
    scenarios = [
        ({}, (), '60s', True, True, False),
        ({'collection_timestamp_seconds': '0+0x8', 'memory_observed_timestamp_seconds': '0+0x8', 'cpu_observed_timestamp_seconds': '0+0x8'}, (), '90s', True, True, False),
        ({'collection_timestamp_seconds': '0+0x8'}, (), '120s', False, False, False),
        ({'memory_observed_timestamp_seconds': '0+0x8'}, (), '120s', True, False, False),
        ({'cpu_observed_timestamp_seconds': '0+0x8'}, (), '120s', False, True, False),
        ({'collection_timestamp_seconds': '180+0x8'}, (), '60s', False, False, False),
        ({'memory_observed_timestamp_seconds': '180+0x8'}, (), '60s', True, False, False),
        ({'cpu_observed_timestamp_seconds': '180+0x8'}, (), '60s', False, True, False),
        ({'inventory_valid': '0+0x8'}, (), '60s', True, False, False),
        ({'cpu_valid': '0+0x8'}, (), '60s', False, True, False),
        ({}, ('collection_timestamp_seconds',), '60s', False, False, False),
        ({}, ('memory_observed_timestamp_seconds',), '60s', True, False, False),
        ({}, ('cpu_observed_timestamp_seconds',), '60s', False, True, False),
        ({'inventory_valid': '0+0x8'}, ('capacity_slots',), '60s', True, False, False),
        ({}, (), '60s', False, False, True),
    ]
    cases = []
    for index, (overrides, omit, at, cpu_ok, inventory_ok, gone) in enumerate(scenarios):
        queries = []
        for panel, target in measured:
            expr = target['expr']
            timeline = panel['type'] == 'state-timeline'
            valid = cpu_ok if 'ci_pool_cpu_used_cores' in expr or 'ci_pool_cpu_limit_cores' in expr else inventory_ok
            per_slot = 'ci_pool_slot_' in expr and panel['title'] != 'Quarantined slots'
            count = (10 if per_slot else 1) if valid or (timeline and not gone) else None
            queries.append({'expr': f'count(({expr}))', 'eval_time': at,
                            'exp_samples': [] if count is None else [{'labels': '{}', 'value': count}]})
            if timeline and index in (0, 2):
                # Exact label identities must survive fresh → unknown transitions.
                # A retained metric name on only one branch creates 20 range series.
                states = [0, 1, 5, 6, 7, 2, 10, 10, 10, 10] if inventory_ok else [9] * 10
                queries.append({'expr': expr, 'eval_time': at, 'exp_samples': [
                    {'labels': f'{{{POOL_LABELS},slot="{slot}"}}', 'value': state}
                    for slot, state in enumerate(states)]})
            if timeline and not inventory_ok and not gone:
                for reduction in ('min', 'max'):
                    queries.append({'expr': f'{reduction}(({expr}))', 'eval_time': at,
                                    'exp_samples': [{'labels': '{}', 'value': 9}]})
        cases.append({'name': f'freshness scenario {index}', 'interval': '30s',
                      'input_series': pool_series(overrides, omit, gone), 'promql_expr_test': queries})
    # Missing gauges must leave a gap even with a fresh, valid inventory.
    omissions = ['memory_used_bytes', 'memory_reserved_bytes', 'memory_limit_bytes',
                 'capacity_slots', 'occupied_slots', 'warm_slots', 'cpu_used_cores', 'cpu_limit_cores', 'slot_memory_used_bytes',
                 'slot_guest_memory_used_bytes', 'slot_memory_reserved_bytes', 'slot_guest_memory_reserved_bytes']
    for metric in omissions:
        queries = [{'expr': t['expr'], 'eval_time': '60s', 'exp_samples': []}
                   for p, t in measured if f'ci_pool_{metric}{{' in t['expr']]
        assert queries
        cases.append({'name': f'missing {metric}', 'interval': '30s',
                      'input_series': pool_series(omit=(metric,)), 'promql_expr_test': queries})
    # Validate available capacity arithmetic and interval CPU gauge units.
    for panel_title, expected in [('Available slots', 1), ('CPU utilization heatmap', 25)]:
        panel = next(p for p in dashboard['panels'] if p['title'] == panel_title)
        cases[0]['promql_expr_test'].append({'expr': f'sum(({panel["targets"][0]["expr"]}))',
                                           'eval_time': '60s', 'exp_samples': [{'labels': '{}', 'value': expected}]})
    fixture = tmp_path / 'shared-pool.test.yml'
    fixture.write_text(yaml.safe_dump({'evaluation_interval': '30s', 'tests': cases}, sort_keys=False))
    result = subprocess.run([executable, 'test', 'rules', str(fixture)], text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_shared_pool_sampled_time_excludes_unknown_and_gaps_and_counts_quarantine(tmp_path):
    dashboard = pool_dashboard()
    panels = {panel['title']: panel for panel in dashboard['panels']}
    for title in SAMPLED_TIME_TITLES:
        panel = panels[title]
        assert panel['fieldConfig']['defaults']['unit'] == 'dtdurations'
        assert panel['fieldConfig']['defaults']['noValue'] == 'No data'
        assert '[$__range:30s]' in panel['targets'][0]['expr']
        assert panel['interval'] == '30s'
    assert 'job success/failure is not collected' in panels['Shared VM runner pool · WK01']['options']['content'].lower()

    def expr(title):
        return panels[title]['targets'][0]['expr'].replace('$__range', '180s')

    def query(expression, expected, at='180s'):
        return {'expr': expression, 'eval_time': at,
                'exp_samples': [] if expected is None else [{'labels': '{}', 'value': expected}]}

    # In the six 30-second samples in (0,180], slot0 runs at30/60; its
    # t90 is unknown, t120 has a stale source, t150 disappears, t180 is empty.
    # Slot1 contributes five charged samples: warm/quarantine/destroying/reserved/ready.
    samples = [s for s in pool_series({'memory_observed_timestamp_seconds': '0 30 60 90 0 150 180'})
               if not s['series'].startswith('ci_pool_slot_state{')]
    for slot, values in {0: '5 5 5 9 5 stale 0', 1: '1 1 6 7 5 2 8',
                         2: '9+0x6', 3: '10+0x6', 4: '0+0x6'}.items():
        samples.append({'series': f'ci_pool_slot_state{{{POOL_LABELS},slot="{slot}"}}', 'values': values})
    running = expr('Running VM time (sampled)')
    charged = expr('Charged VM time (sampled)')
    per_slot = expr('Per-slot running time (sampled)')
    quarantine = expr('Quarantined slots')
    cases = [{'name': 'sampled VM lifecycle time is not exact job time', 'interval': '30s', 'input_series': samples,
              'promql_expr_test': [query('sum(('+running+'))', 60), query('sum(('+charged+'))', 210),
                                  query('sum(('+per_slot+'))', 60), query('count(('+per_slot+'))', 3),
                                  query('max(('+per_slot+'))', 60), query('min(('+per_slot+'))', 0)]}]
    latest_stale = [dict(s, values='0 30 60 90 0 150 0')
                    if s['series'].startswith('ci_pool_memory_observed_timestamp_seconds{') else s for s in samples]
    cases.append({'name': 'past valid time survives latest stale inventory', 'interval': '30s',
                  'input_series': latest_stale,
                  'promql_expr_test': [query('sum(('+running+'))', 60), query('sum(('+charged+'))', 180)]})
    for name, input_series in [('missing window', pool_series(gone=True)),
                               ('unknown window', [dict(s, values='9+0x8') if s['series'].startswith('ci_pool_slot_state{') else s
                                                   for s in pool_series()])]:
        cases.append({'name': name, 'interval': '30s', 'input_series': input_series,
                      'promql_expr_test': [query(e, None) for e in (running, charged, per_slot)]})
    for name, input_series, expected in [
        ('one quarantine', pool_series(), 1),
        ('known zero quarantine', [dict(s, values='1+0x8') if s['series'].startswith('ci_pool_slot_state{') else s
                                  for s in pool_series()], 0),
        ('missing slot does not mean zero quarantine', [s for s in pool_series()
                                                       if not (s['series'].startswith('ci_pool_slot_state{') and 'slot="3"' in s['series'])], None),
        ('unknown slot does not mean zero quarantine', [dict(s, values='9+0x8') if s['series'].startswith('ci_pool_slot_state{') and 'slot="3"' in s['series'] else s
                                                       for s in pool_series()], None),
    ]:
        cases.append({'name': name, 'interval': '30s', 'input_series': input_series,
                      'promql_expr_test': [query('sum(('+quarantine+'))', expected)]})
    fixture = tmp_path / 'shared-pool-time.test.yml'
    fixture.write_text(yaml.safe_dump({'evaluation_interval': '30s', 'tests': cases}, sort_keys=False))
    result = subprocess.run([shutil.which('promtool'), 'test', 'rules', str(fixture)], text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_shared_pool_waiting_jobs_have_independent_freshness_and_high_slots_are_retained(tmp_path):
    dashboard=pool_dashboard()
    panels={p['title']:p for p in dashboard['panels']}
    for title in ('Occupied slots','Available slots'):
        assert panels[title]['type']=='gauge'
        assert panels[title]['fieldConfig']['defaults']['max']==10
    queue_panels=[p for p in dashboard['panels'] if p['title'].startswith('Waiting jobs')]
    assert {p['type'] for p in queue_panels}=={'stat','timeseries'}
    cases=[]
    def query(expr,value):
        return {'expr':f'sum(({expr}))','eval_time':'60s',
                'exp_samples':[] if value is None else [{'labels':'{}','value':value}]}
    for name,extra,omit,expected in (
        ('full pool waiting',{},(),4),
        ('known zero',{'queue_waiting_jobs':'0+0x8'},(),0),
        ('fresh at300',{'queue_observed_timestamp_seconds':'0+0x8'},(),4),
        ('stale',{'queue_observed_timestamp_seconds':'0+0x8'},(),None),
        ('invalid',{'queue_valid':'0+0x8'},(),None),
        ('future',{'queue_observed_timestamp_seconds':'90+0x8'},(),None),
        ('missing',{},('queue_waiting_jobs',),None),
        ('missing valid',{},('queue_valid',),None),
        ('missing timestamp',{},('queue_observed_timestamp_seconds',),None),
        ('invalid inventory independent',{'inventory_valid':'0+0x8'},(),4),
        ('stale export',{'collection_timestamp_seconds':'0+0x8'},(),None),
    ):
        overrides={'queue_waiting_jobs':'4+0x12','queue_valid':'1+0x12',
                   'queue_observed_timestamp_seconds':'0+30x12',
                   'capacity_slots':'10+0x12','occupied_slots':'10+0x12',**extra}
        at='300s' if name=='fresh at300' else '330s' if name=='stale' else '120s' if name=='stale export' else '60s'
        if at in ('300s','330s'):
            overrides['collection_timestamp_seconds']='0+30x12'
        queries=[{**query(t['expr'],expected),'eval_time':at} for p in queue_panels for t in p['targets']]
        cases.append({'name':name,'interval':'30s','input_series':pool_series(overrides,omit),'promql_expr_test':queries})
    series=pool_series({'capacity_slots':'10+0x8'})
    series=[dict(row,values='5+0x8') if row['series'].startswith('ci_pool_slot_state{') and any(f'slot="{slot}"' in row['series'] for slot in (8,9)) else row for row in series]
    timeline=panels['Slot state history']['targets'][0]['expr']
    queries=[query(f'({timeline}) and on (slot) ci_pool_slot_state{{{POOL_LABELS},slot=~"[89]"}}',10),
             query(f'({timeline}) and on (slot) ci_pool_slot_state{{{POOL_LABELS},slot="10"}}',None)]
    for title in SAMPLED_TIME_TITLES:
        expr=panels[title]['targets'][0]['expr'].replace('$__range','60s')
        # Three real running slots (2,8,9), two samples each; rogue10/11 excluded.
        queries.append(query(expr,180 if title!='Charged VM time (sampled)' else 420))
    cases.append({'name':'high slots and timing','interval':'30s','input_series':series,'promql_expr_test':queries})
    fixture=tmp_path/'shared-pool-queue.test.yml'
    fixture.write_text(yaml.safe_dump({'evaluation_interval':'30s','tests':cases},sort_keys=False))
    result=subprocess.run([shutil.which('promtool'),'test','rules',str(fixture)],text=True,capture_output=True)
    assert result.returncode==0,result.stdout+result.stderr
