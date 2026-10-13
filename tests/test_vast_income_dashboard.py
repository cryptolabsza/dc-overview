# TRACEWEAVER: file-role=earnings-dashboard-verification; req=REQ-EARN-002; trace=TRACE-EARN-002; ver=VER-EARN-002
# TRACEWEAVER: verifies=VER-EARN-002; req=REQ-EARN-002; trace=TRACE-EARN-002
# TRACEWEAVER: file-role=earnings-dashboard-verification; req=REQ-EARN-002; trace=TRACE-EARN-002; ver=VER-EARN-002
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


DAILY_METRICS = {15: ["gpu"], 16: ["sto"], 17: ["bwu", "bwd"],
                 14: ["gpu", "sto", "bwu", "bwd"]}
DAILY_SOURCE_LABELS = "job,instance,provider_account_id,account,machine_id"
DAILY_ACCOUNT_LABELS = "job,instance,provider_account_id,account"


def daily_panel(filename, panel_id):
    dashboard = json.loads((ROOT / filename).read_text())
    return next(panel for panel in dashboard["panels"] if panel.get("id") == panel_id)


def frozen_daily_expression(panel_id):
    # This is the owner-approved full-source template, not an evaluator.
    terms = ["vastai_per_machine_" + category + "_earn" for category in DAILY_METRICS[panel_id]]
    amounts = (" + on(" + DAILY_SOURCE_LABELS + ") ").join(terms)
    return "(" + amounts + ")" + "\n" + "\n".join([
        "and on(" + DAILY_ACCOUNT_LABELS + ") (vastai_earnings_report_day_timestamp_seconds == (time() - (time() % 86400) - 86400))",
        "and on(" + DAILY_ACCOUNT_LABELS + ") (vastai_earnings_report_valid == 1)",
        "and on(" + DAILY_ACCOUNT_LABELS + ") ((time() - vastai_earnings_last_success_timestamp_seconds >= 0) and (time() - vastai_earnings_last_success_timestamp_seconds <= 7200))",
        'and on(provider_account_id) (count by(provider_account_id) (vastai_earnings_report_day_timestamp_seconds{provider_account_id!=""}) == 1)',
    ])


@pytest.mark.parametrize("filename", DASHBOARDS)
@pytest.mark.parametrize("panel_id", [14, 15, 16, 17])
def test_daily_income_query_matches_frozen_full_source_contract(filename, panel_id):
    expr = daily_panel(filename, panel_id)["targets"][0]["expr"]
    assert "".join(expr.split()) == "".join(frozen_daily_expression(panel_id).split())


@pytest.mark.parametrize("filename", DASHBOARDS)
@pytest.mark.parametrize("panel_id", [14, 15, 16, 17])
def test_daily_income_explains_observation_time_and_preserves_unknown_gaps(filename, panel_id):
    panel = daily_panel(filename, panel_id)
    assert "observed previous utc day" in panel["title"].lower()
    description = panel["description"].lower()
    for concept in ["observation", "utc", "backfill", "repeated", "coarse"]:
        assert concept in description
    custom = panel["fieldConfig"]["defaults"]["custom"]
    assert custom["spanNulls"] is False
    assert custom.get("lineInterpolation") in ["stepAfter", "stepBefore"] or custom.get("drawStyle") == "points"
    assert panel["targets"][0].get("range") is True
    assert all("integral" not in json.dumps(transform).lower() for transform in panel.get("transformations", []))


@pytest.mark.parametrize("filename", DASHBOARDS)
def test_daily_income_status_panel_has_live_date_success_status_and_scrape_targets(filename):
    dashboard = json.loads((ROOT / filename).read_text())
    candidates = [panel for panel in dashboard["panels"] if panel.get("id") == 90]
    assert len(candidates) == 1, "earnings readiness/status panel 90 is missing"
    panel = candidates[0]
    assert panel["type"] in ["table", "stat"]
    expressions = " ".join(target["expr"] for target in panel["targets"])
    for metric in ["vastai_earnings_status", "vastai_earnings_report_day_timestamp_seconds",
                   "vastai_earnings_last_success_timestamp_seconds", "up"]:
        assert metric in expressions
    assert "absent" in expressions, "an absent exporter must have an observable state"
    rendered = json.dumps(panel).lower()
    for text in ["provider_account_id", "account", "awaiting", "partial", "empty", "error", "expired", "configuration"]:
        assert text in rendered
    # Codes must be mapped, rather than offered only as descriptive static prose.
    mapping_text = json.dumps([panel.get("fieldConfig", {}), panel.get("options", {})])
    for code in range(7):
        assert '"' + str(code) + '"' in mapping_text


def test_daily_shipped_income_and_status_definitions_are_identical():
    panels = [[daily_panel(filename, pid) for pid in [14, 15, 16, 17, 90]] for filename in DASHBOARDS]
    assert all(panels[0] == variant for variant in panels[1:])
