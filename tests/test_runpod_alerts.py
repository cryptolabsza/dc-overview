"""Contract tests for the RunPod Grafana managed-alert rule factory."""

from __future__ import annotations

import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "runpod-exporter" / "grafana_alerts.py"


def load_alerts_module():
    spec = importlib.util.spec_from_file_location("runpod_grafana_alerts", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rules_by_uid(*, account="RunpodCCC", uid_prefix="runpod"):
    module = load_alerts_module()
    rules = module.build_alert_rules(
        account=account,
        folder_uid="alerts-folder",
        datasource_uid="prometheus-main",
        uid_prefix=uid_prefix,
    )
    return {rule["uid"]: rule for rule in rules}


def expression(rule):
    return next(query["model"]["expr"] for query in rule["data"] if query["refId"] == "A")


def test_legacy_account_retains_existing_rule_uids_and_account_scoping():
    rules = rules_by_uid()

    assert set(rules) == {
        "runpod-machine-unlisted",
        "runpod-exporter-unavailable",
        "runpod-api-poll-failed",
        "runpod-api-data-stale",
        "runpod-machine-missing",
        "runpod-machine-health-unknown",
        "runpod-machine-health-stale",
        "runpod-state-persistence-failed",
        "runpod-machine-provider-note",
        "runpod-machine-maintenance-mode",
        "runpod-machine-last-sync-unavailable",
        "runpod-machine-telemetry-unavailable",
        "runpod-exporter-contract-unavailable",
    }
    for rule in rules.values():
        assert rule["labels"]["account"] == "RunpodCCC"
        assert rule["folderUID"] == "alerts-folder"
        assert rule["data"][0]["datasourceUid"] == "prometheus-main"
        assert "Vast" not in expression(rule)


def test_explicit_uid_prefix_keeps_multiple_accounts_unique_and_scoped():
    alpha = rules_by_uid(account="alpha", uid_prefix="alpha-runpod")
    beta = rules_by_uid(account="beta", uid_prefix="beta-runpod")

    assert set(alpha).isdisjoint(beta)
    for rules, account in ((alpha, "alpha"), (beta, "beta")):
        for rule in rules.values():
            assert rule["labels"]["account"] == account
            assert f'account="{account}"' in expression(rule) or rule["uid"].endswith((
                "exporter-unavailable",
                "state-persistence-failed",
            ))


def test_unknown_rule_requires_a_present_machine_and_resolves_when_data_is_absent():
    rule = rules_by_uid()["runpod-machine-health-unknown"]

    assert rule["noDataState"] == "OK"
    assert rule["execErrState"] == "KeepLast"
    assert 'runpod_machine_health_known{account="RunpodCCC"}' in expression(rule)
    assert 'runpod_machine_present{account="RunpodCCC"} == 1' in expression(rule)


def test_contract_alert_is_single_account_service_alert_and_does_not_depend_on_machines():
    rule = rules_by_uid()["runpod-exporter-contract-unavailable"]
    expr = expression(rule)

    assert rule["noDataState"] == "OK"
    assert rule["execErrState"] == "Alerting"
    assert rule["annotations"]["summary"] == "RunPod exporter health contract unavailable"
    assert "runpod_api_poll_success{account=\"RunpodCCC\"}" in expr
    assert "runpod_health_state_persist_success" in expr
    assert "runpod_health_state_schema_version" in expr
    assert "runpod_health_state_schema_version != bool 1" in expr
    assert expr.endswith("or vector(0)")
    assert expr.startswith("(max(")
    assert "runpod_machine_" not in expr


def test_machine_annotations_use_hostname_machine_id_account_fallback_without_site_mapping():
    rules = rules_by_uid()
    machine_summaries = [
        rule["annotations"]["summary"]
        for rule in rules.values()
        if "machine" in rule["uid"]
    ]

    assert all("$labels.hostname" in summary for summary in machine_summaries)
    assert all("$labels.machine_id" in summary for summary in machine_summaries)
    assert all("$labels.account" in summary for summary in machine_summaries)
    assert all("RunPod machine" in summary for summary in machine_summaries)
    assert all("Charlotte" not in summary and "CCC9" not in summary for summary in machine_summaries)
