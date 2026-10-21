"""Vast listing observations must survive gaps without inventing transitions."""

import importlib.util
import json
import math
import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml
from jinja2 import Template
from prometheus_client.parser import text_string_to_metric_families

from dc_overview.grafana_alerts import (
    MANAGED_ALERT_UIDS,
    GrafanaReceiverError,
    configure_grafana_telegram_receiver,
    install_grafana_alerts,
    render_grafana_alerts,
    sync_grafana_alerts,
)


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def exporter():
    spec = importlib.util.spec_from_file_location(
        "vast_listing_exporter", ROOT / "vastai-exporter/vastai_exporter.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Provider:
    def __init__(self, account="alpha"):
        self.account_name = account
        self.machines = [{"id": 42, "hostname": "gpu-42", "listed": True}]

    def get_user_info(self):
        return {}

    def get_machines(self):
        if isinstance(self.machines, Exception):
            raise self.machines
        return self.machines


def sample(metrics, name, **labels):
    return [
        item.value
        for family in text_string_to_metric_families(metrics)
        for item in family.samples
        if item.name == name and all(item.labels.get(k) == v for k, v in labels.items())
    ]


def collector_for(exporter, tmp_path):
    collector = exporter.MetricsCollector([], state_path=tmp_path / "listing-state.json")
    collector.cache_ttl = 0
    provider = Provider()
    collector.clients = [provider]
    return collector, provider


def test_confirmed_listing_changes_both_directions_and_survives_restart(exporter, tmp_path):
    collector, provider = collector_for(exporter, tmp_path)
    for listed in (True, False, False, True):
        provider.machines[0]["listed"] = listed
        metrics = collector.collect()
        assert sample(metrics, "vast_machine_listing_listed") == [int(listed)]
    provider.machines[0]["listed"] = False
    collector.collect()
    state_path = tmp_path / "listing-state.json"
    saved = state_path.read_text()
    assert "api_key" not in saved
    assert state_path.stat().st_mode & 0o777 == 0o600
    restarted = exporter.MetricsCollector([], state_path=state_path)
    provider.machines = None
    restarted.clients = [provider]
    assert sample(restarted.collect(), "vast_machine_listing_listed") == [0]


@pytest.mark.parametrize("gap", [None, [], RuntimeError("offline"), [{"id": 42}],
    [{"id": 42, "listed": None}], [{"id": 42, "listed": "false"}],
    [{"id": 42, "listed": 0}], {"error": "unauthorized"}])
def test_gaps_never_change_confirmed_status_or_identity(exporter, tmp_path, gap):
    collector, provider = collector_for(exporter, tmp_path)
    provider.machines[0]["listed"] = False
    collector.collect()
    provider.machines = gap
    metrics = collector.collect()
    assert sample(metrics, "vast_machine_listing_listed", hostname="gpu-42") == [0]
    if gap == []:
        assert sample(metrics, "vast_machine_listing_present") == [0]
    else:
        assert sample(metrics, "vast_listing_poll_success") == [0]


def test_first_unknown_observation_does_not_report_unlisted(exporter):
    collector = exporter.MetricsCollector([])
    provider = Provider()
    del provider.machines[0]["listed"]
    collector.clients = [provider]
    metrics = collector.collect()
    assert sample(metrics, "vast_machine_listing_listed") == []
    assert math.isnan(sample(metrics, "vast_machine_Listed")[0])


def test_accounts_are_independent_and_labels_are_escaped(exporter, tmp_path):
    collector, alpha = collector_for(exporter, tmp_path)
    beta = Provider('beta"\\\n')
    beta.machines[0]["listed"] = False
    beta.machines[0]["hostname"] = 'gpu"\\\n'
    collector.clients = [*collector.clients, beta]
    metrics = collector.collect()
    assert sample(metrics, "vast_machine_listing_listed", account="alpha") == [1]
    assert sample(metrics, "vast_machine_listing_listed", account=beta.account_name) == [0]
    alpha.machines = None
    beta.machines[0]["listed"] = True
    metrics = collector.collect()
    assert sample(metrics, "vast_machine_listing_listed", account="alpha") == [1]
    assert sample(metrics, "vast_machine_listing_listed", account=beta.account_name) == [1]


def test_write_failure_cannot_publish_false_recovery(exporter, tmp_path, monkeypatch):
    collector, provider = collector_for(exporter, tmp_path)
    provider.machines[0]["listed"] = False
    collector.collect()
    provider.machines[0]["listed"] = True
    with monkeypatch.context() as context:
        context.setattr(exporter.os, "replace", lambda *args: (_ for _ in ()).throw(OSError()))
        metrics = collector.collect()
    assert sample(metrics, "vast_machine_listing_listed") == [0]
    assert sample(metrics, "vast_listing_state_persist_success") == [0]
    assert sample(collector.collect(), "vast_machine_listing_listed") == [1]


def test_invalid_saved_state_is_unknown_until_provider_confirms(exporter, tmp_path):
    (tmp_path / "listing-state.json").write_text(json.dumps({"version": 1, "accounts": []}))
    collector, provider = collector_for(exporter, tmp_path)
    provider.machines = None
    metrics = collector.collect()
    assert sample(metrics, "vast_machine_listing_listed") == []
    assert sample(metrics, "vast_listing_state_persist_success") == [0]


def test_account_removal_forgets_old_observations_before_name_reuse(exporter, tmp_path):
    collector, provider = collector_for(exporter, tmp_path)
    collector.collect()
    manager = exporter.AccountManager(collector)
    manager._save = lambda: None
    assert manager.remove_account("alpha")["success"]
    provider.machines = None
    collector.clients = [provider]
    assert sample(collector.collect(), "vast_machine_listing_listed") == []


def test_hostname_changes_keep_the_same_alert_identity(exporter, tmp_path):
    collector, provider = collector_for(exporter, tmp_path)
    collector.collect()
    provider.machines[0].update(hostname="renamed", listed=False)
    assert sample(collector.collect(), "vast_machine_listing_listed", hostname="gpu-42") == [0]


def test_missing_machine_does_not_block_other_confirmed_changes(exporter, tmp_path):
    collector, provider = collector_for(exporter, tmp_path)
    provider.machines.append({"id": 43, "hostname": "gpu-43", "listed": True})
    collector.collect()
    provider.machines = [{"id": 43, "hostname": "gpu-43", "listed": False}]
    metrics = collector.collect()
    assert sample(metrics, "vast_machine_listing_listed", machine_id="42") == [1]
    assert sample(metrics, "vast_machine_listing_present", machine_id="42") == [0]
    assert sample(metrics, "vast_machine_listing_listed", machine_id="43") == [0]


@patch("dc_overview.grafana_alerts.wait_for_grafana_telegram_receiver", return_value=True)
@patch("dc_overview.grafana_alerts._put_contact_point")
@patch("dc_overview.grafana_alerts._get_telegram_contact_points")
def test_receiver_with_recovery_disabled_cannot_silently_suppress_listed(get_points, put_point, wait):
    get_points.return_value = ({"uid": "telegram", "settings": {}, "disableResolveMessage": True},)
    with pytest.raises(GrafanaReceiverError, match="resolved notifications"):
        configure_grafana_telegram_receiver("http://grafana", "test", receiver="Existing Telegram")
    put_point.assert_not_called()


def test_generated_compose_retains_vast_state_volume():
    from dc_overview.templates import DOCKER_COMPOSE_TEMPLATE

    legacy = yaml.safe_load(Template(DOCKER_COMPOSE_TEMPLATE).render(vast_api_key="placeholder"))
    modern_path = ROOT / "src/dc_overview/templates/docker-compose.yml.j2"
    modern = yaml.safe_load(Template(modern_path.read_text()).render(vast_enabled=True))
    for document in (legacy, modern):
        mount = document["services"]["vastai-exporter"]["volumes"]
        assert any(value.endswith(":/data") for value in mount)
        name = next(value.split(":")[0] for value in mount if value.endswith(":/data"))
        assert name in document["volumes"]


def vast_rules(rendered=None):
    document = yaml.safe_load(rendered or render_grafana_alerts())
    return {rule["uid"]: rule for group in document["groups"] for rule in group["rules"]
            if rule["uid"].startswith("vast-")}


def test_listing_rule_holds_on_missing_data_and_routes_to_telegram():
    rules = vast_rules(render_grafana_alerts(receiver="Existing Telegram"))
    rule = rules["vast-machine-unlisted"]
    assert rule["uid"] in MANAGED_ALERT_UIDS
    assert rule["noDataState"] == rule["execErrState"] == "KeepLast"
    assert rule["for"] == "0s"
    assert rule.get("keepFiringFor", "0s") == "0s"
    assert "1 - vast_machine_listing_listed" in rule["data"][0]["model"]["expr"]
    assert rule["notification_settings"]["receiver"] == "Existing Telegram"
    assert "hostname" in rule["annotations"]["summary"]
    assert "machine_id" in rule["annotations"]["summary"]
    assert "account" in rule["annotations"]["summary"]
    assert {"vast-listing-telemetry-unavailable", "vast-listing-state-unavailable"} <= rules.keys()


@patch("dc_overview.grafana_alerts.configure_grafana_telegram_receiver")
@patch("dc_overview.grafana_alerts.reload_grafana_alerts", return_value=True)
@patch("dc_overview.grafana_alerts.requests.get")
def test_upgrade_routes_new_vast_rules_to_existing_receiver(get, reload, configure, tmp_path):
    get.return_value = SimpleNamespace(raise_for_status=lambda: None, json=lambda: [
        {"uid": "prometheus", "name": "Prometheus", "type": "prometheus", "access": "proxy",
         "url": "http://prometheus:9090/prometheus/"}])
    path = install_grafana_alerts(tmp_path, receiver="Existing Telegram")
    document = yaml.safe_load(path.read_text())
    for group in document["groups"]:
        group["rules"] = [rule for rule in group["rules"] if not rule["uid"].startswith("vast-")]
    path.write_text(yaml.safe_dump(document))
    result = sync_grafana_alerts(tmp_path, grafana_url="http://grafana:3000", admin_password="test")
    assert result.success
    assert vast_rules(path.read_text())
    for rule in vast_rules(path.read_text()).values():
        assert rule["notification_settings"]["receiver"] == "Existing Telegram"


def test_telegram_template_explains_firing_and_recovery_states(tmp_path):
    path = install_grafana_alerts(tmp_path)
    template = yaml.safe_load(path.with_name("dc-overview-notifications.yml").read_text())
    content = template["templates"][0]["template"]
    assert 'eq .Labels.alert_category "vast_listing"' in content
    assert "Vast UNLISTED" in content
    assert "Vast LISTED" in content


@pytest.mark.skipif(shutil.which("promtool") is None, reason="promtool unavailable")
def test_promtool_listing_transitions_and_telemetry_gaps(tmp_path):
    rules = vast_rules()
    listing = rules["vast-machine-unlisted"]["data"][0]["model"]["expr"]
    telemetry = rules["vast-listing-telemetry-unavailable"]["data"][0]["model"]["expr"]
    state = rules["vast-listing-state-unavailable"]["data"][0]["model"]["expr"]
    machine = '{account="alpha",hostname="gpu-42",machine_id="42"}'
    query_tests = [
        {"expr": listing, "eval_time": f"{minute}m", "exp_samples": [
            {"labels": machine, "value": value}]} for minute, value in enumerate([0, 1, 1, 0])
    ]
    query_tests += [
        {"expr": telemetry, "eval_time": "1m", "exp_samples": [
            {"labels": '{account="alpha"}', "value": 1}]},
        {"expr": telemetry, "eval_time": "3m", "exp_samples": [
            {"labels": '{account="alpha"}', "value": 0}]},
        {"expr": state, "eval_time": "3m", "exp_samples": [{"labels": "{}", "value": 0}]},
    ]
    tests = [{"interval": "1m", "input_series": [
        {"series": "vast_machine_listing_listed" + machine, "values": "1 0 0 1"},
        {"series": "vast_machine_listing_present" + machine, "values": "1 1 0 1"},
        {"series": 'vast_listing_poll_success{account="alpha"}', "values": "1 0 1 1"},
        {"series": 'vast_listing_last_success_timestamp_seconds{account="alpha"}', "values": "0 0 120 180"},
        {"series": 'vast_listing_state_persist_success{job="vastai",instance="exporter"}', "values": "1 1 1 1"},
        {"series": 'up{job="vastai",instance="exporter"}', "values": "1 1 1 1"},
    ], "promql_expr_test": query_tests}]
    for series, expected in [([], []), ([{"series": 'up{job="vastai",instance="exporter"}', "values": "0"}],
                                      [{"labels": "{}", "value": 1}])]:
        tests.append({"interval": "1m", "input_series": series,
                      "promql_expr_test": [{"expr": state, "eval_time": "0m", "exp_samples": expected}]})
    path = tmp_path / "vast-promql-tests.yml"
    path.write_text(yaml.safe_dump({"rule_files": [], "evaluation_interval": "1m", "tests": tests}))
    result = subprocess.run(["promtool", "test", "rules", str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(shutil.which("go") is None, reason="Go unavailable")
def test_actual_telegram_template_renders_listing_recovery_and_missing_series(tmp_path):
    path = install_grafana_alerts(tmp_path)
    document = yaml.safe_load(path.with_name("dc-overview-notifications.yml").read_text())
    template = tmp_path / "message.tmpl"
    template.write_text(document["templates"][0]["template"])
    program = tmp_path / "render.go"
    program.write_text('''package main
import ("encoding/json"; "os"; "text/template")
func main() {
 var data map[string]interface{}
 if err := json.NewDecoder(os.Stdin).Decode(&data); err != nil { panic(err) }
 t := template.Must(template.ParseFiles(os.Args[1]))
 if err := t.ExecuteTemplate(os.Stdout, "cryptolabs.telegram.message", data); err != nil { panic(err) }
}
''')
    binary = tmp_path / "render"
    environment = {**os.environ, "GOCACHE": str(tmp_path / "go-cache"), "GOTOOLCHAIN": "local"}
    compiled = subprocess.run(["go", "build", "-o", str(binary), str(program)], env=environment,
                              capture_output=True, text=True, timeout=60)
    assert compiled.returncode == 0, compiled.stderr
    cases = [(True, "", "Vast UNLISTED"), (False, "", "Vast LISTED")]
    cases.extend((False, reason, "Vast listing monitoring changed")
                 for reason in ("MissingSeries", "Paused", "RuleDeleted", "Updated"))
    for firing, reason, expected in cases:
        alert = {"Labels": {"alert_category": "vast_listing"}, "Annotations": {
            "summary": "gpu-42 (machine 42, account alpha)", "grafana_state_reason": reason}}
        data = {"Alerts": {"Firing": [alert] if firing else [], "Resolved": [] if firing else [alert]}}
        result = subprocess.run([str(binary), str(template)], input=json.dumps(data),
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert expected in result.stdout
        if reason:
            assert "Vast LISTED" not in result.stdout
