"""Vast income panels must display provider earnings, without client fees."""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
DASHBOARDS = [
    "src/dc_overview/dashboards/Vast_Dashboard.json",
    "dashboards/Vast_Dashboard.json",
    "server/grafana/dashboards/Vast_Dashboard.json",
    "server/grafana/dashboards/vast-dashboard.json",
]


@pytest.mark.parametrize("filename", DASHBOARDS)
@pytest.mark.parametrize(
    "panel_id,title,expression",
    [
        (19, "Machine earnings / hour", "sum(vastai_machine_earn_hour) by (hostname)"),
        (21, "Reported earnings / hour", "sum(vastai_machine_earn_hour)"),
        (12, "Reported earnings / day", "sum(vastai_machine_earn_day)"),
    ],
)
def test_income_panels_use_matching_provider_fields(filename, panel_id, title, expression):
    dashboard = json.loads((ROOT / filename).read_text())
    panel = next(panel for panel in dashboard["panels"] if panel.get("id") == panel_id)
    assert panel["title"] == title
    assert [target["expr"] for target in panel["targets"]] == [expression]
    assert "Vast-reported host earnings" in panel["description"]
    assert "client surcharge" in panel["description"]


@pytest.mark.parametrize("filename", DASHBOARDS)
def test_pending_payout_remains_separate_from_income(filename):
    dashboard = json.loads((ROOT / filename).read_text())
    panel = next(panel for panel in dashboard["panels"] if panel.get("id") == 42)
    assert panel["title"] == "Pending Payout"
    assert panel["targets"][0]["expr"] == "vastai_current_total"
