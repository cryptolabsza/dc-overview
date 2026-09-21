"""Regression coverage for durable RunPod health observations."""

import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "runpod-exporter" / "health_state.py"


@pytest.fixture()
def health_module():
    spec = importlib.util.spec_from_file_location("runpod_health_state", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record(machine_id="machine-1", name="Provider Host", listed=True, **overrides):
    value = {
        "id": machine_id,
        "name": name,
        "listed": listed,
        "note": None,
        "maintenanceNote": None,
        "maintenanceMode": False,
        "lastSyncAt": "2026-09-21T12:00:00Z",
        "latestTelemetry": {"time": "2026-09-21T12:01:00Z"},
    }
    value.update(overrides)
    return value


def samples(metrics, metric):
    return re.findall(rf"^{re.escape(metric)}\{{([^}}]*)\}} (.+)$", metrics, re.MULTILINE)


def test_unknown_listed_value_is_not_an_unlisted_machine(health_module, tmp_path):
    state = health_module.HealthState(["account"], path=tmp_path / "state.json")

    assert state.success("account", [record(listed=False)], now=10)
    assert not state.success("account", [record(listed="unknown")], now=20)

    metrics = state.format_metrics(["account"])
    assert samples(metrics, "runpod_api_poll_success") == [('account="account"', "0")]
    assert samples(metrics, "runpod_machine_health_listed") == [
        ('account="account",machine_id="machine-1",hostname="provider host"', "0")
    ]


def test_invalid_first_record_is_unknown_not_unlisted(health_module, tmp_path):
    state = health_module.HealthState(["account"], path=tmp_path / "state.json")

    assert not state.success("account", [record(listed="unknown")], now=10)

    metrics = state.format_metrics(["account"])
    assert not samples(metrics, "runpod_machine_health_listed")
    assert not samples(metrics, "runpod_machine_health_known")


def test_absence_and_restart_retain_last_confirmed_listing(health_module, tmp_path):
    path = tmp_path / "state.json"
    state = health_module.HealthState(["account"], path=path)

    assert state.success("account", [record(listed=True)], now=10)
    assert state.success("account", [], now=20)

    restored = health_module.HealthState(["account"], path=path)
    metrics = restored.format_metrics(["account"])
    assert samples(metrics, "runpod_machine_health_known")
    assert samples(metrics, "runpod_machine_present") == [
        ('account="account",machine_id="machine-1",hostname="provider host"', "0")
    ]
    assert samples(metrics, "runpod_machine_health_listed") == [
        ('account="account",machine_id="machine-1",hostname="provider host"', "1")
    ]


def test_accounts_keep_provider_records_separate(health_module, tmp_path):
    state = health_module.HealthState(["first", "second"], path=tmp_path / "state.json")

    assert state.success("first", [record(machine_id="same-id", name="First Host")], now=10)
    assert state.success("second", [record(machine_id="same-id", name="Second Host", listed=False)], now=11)

    listed = samples(state.format_metrics(["first", "second"]), "runpod_machine_health_listed")
    assert listed == [
        ('account="first",machine_id="same-id",hostname="first host"', "1"),
        ('account="second",machine_id="same-id",hostname="second host"', "0"),
    ]


def test_only_observed_provider_records_create_machines(health_module, tmp_path):
    state = health_module.HealthState(["RunpodCCC"], path=tmp_path / "state.json")

    assert not samples(state.format_metrics(["RunpodCCC"]), "runpod_machine_health_known")
    assert state.success("RunpodCCC", [record(machine_id="actual-provider-id", name="Actual Provider Name")], now=10)

    labels = [labels for labels, _ in samples(
        state.format_metrics(["RunpodCCC"]), "runpod_machine_health_known"
    )]
    assert labels == [
        'account="RunpodCCC",machine_id="actual-provider-id",hostname="actual provider name"'
    ]


def test_complete_provider_record_emits_the_health_contract(health_module, tmp_path):
    state = health_module.HealthState(["account"], path=tmp_path / "state.json")

    assert state.success("account", [record()], now=100)
    metrics = state.format_metrics(["account"])

    for metric in (
        "runpod_health_state_schema_version",
        "runpod_api_poll_success",
        "runpod_api_last_attempt_timestamp_seconds",
        "runpod_api_last_success_timestamp_seconds",
        "runpod_health_state_persist_success",
        "runpod_machine_health_known",
        "runpod_machine_health_last_success_timestamp_seconds",
        "runpod_machine_present",
        "runpod_machine_health_listed",
        "runpod_machine_api_note_present",
        "runpod_machine_network_outage_note",
        "runpod_machine_maintenance_note_present",
        "runpod_machine_maintenance_mode",
        "runpod_machine_last_sync_known",
        "runpod_machine_last_sync_timestamp_seconds",
        "runpod_machine_telemetry_known",
        "runpod_machine_telemetry_timestamp_seconds",
    ):
        assert metric in metrics


def test_schema_version_is_one_without_accounts_or_machines(health_module, tmp_path):
    state = health_module.HealthState(path=tmp_path / "state.json")

    assert "# HELP runpod_health_state_schema_version" in state.format_metrics([])
    assert "# TYPE runpod_health_state_schema_version gauge" in state.format_metrics([])
    assert "runpod_health_state_schema_version 1" in state.format_metrics([])


def test_failed_state_save_keeps_last_confirmed_machine_values(health_module, tmp_path, monkeypatch):
    state = health_module.HealthState(["account"], path=tmp_path / "state.json")
    assert state.success("account", [record(listed=True)], now=10)

    monkeypatch.setattr(state, "_save", lambda candidate: False)
    assert not state.success("account", [record(listed=False)], now=20)

    metrics = state.format_metrics(["account"])
    assert samples(metrics, "runpod_api_poll_success") == [('account="account"', "1")]
    assert samples(metrics, "runpod_machine_health_listed") == [
        ('account="account",machine_id="machine-1",hostname="provider host"', "1")
    ]


def test_failed_account_reset_retains_the_prior_durable_observation(health_module, tmp_path, monkeypatch):
    state = health_module.HealthState(["account"], path=tmp_path / "state.json")
    assert state.success("account", [record()], now=10)

    monkeypatch.setattr(state, "_save", lambda candidate: False)
    assert not state.clear_account("account")

    assert samples(state.format_metrics(["account"]), "runpod_machine_health_known")
