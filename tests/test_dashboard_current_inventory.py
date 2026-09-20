"""Current-inventory dashboard controls must not read stale range data."""
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize('path', [
    ROOT / 'src/dc_overview/dashboards/DC_Overview.json',
    ROOT / 'dashboards/DC_Overview.json',
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
