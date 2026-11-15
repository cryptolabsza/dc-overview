"""Regression coverage for durable RunPod health observations."""

import importlib.util
import json
import re
from pathlib import Path
from types import SimpleNamespace

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


def note_samples(state, accounts=("account",)):
    """Decode this metric's labels without adding dependencies to pytest-only CI."""
    result = []
    label_pattern = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)=("(?:[^"\\]|\\.)*")(?:,|$)')
    for line in state.format_metrics(accounts).splitlines():
        if not line.startswith("runpod_machine_note_info{"):
            continue
        metric = re.fullmatch(r"runpod_machine_note_info\{(.*)\} (\S+)", line)
        assert metric, f"Invalid note metric: {line}"
        raw_labels, value = metric.groups()
        labels = {}
        position = 0
        while position < len(raw_labels):
            label = label_pattern.match(raw_labels, position)
            assert label, f"Invalid note label at {raw_labels[position:]}"
            # Exported quotes, backslashes and newlines use JSON-compatible escapes.
            labels[label[1]] = json.loads(label[2])
            position = label.end()
        result.append(SimpleNamespace(labels=labels, value=float(value)))
    return result


def test_note_metric_roundtrips_provider_text_and_keeps_blank_machine_fields(health_module, tmp_path):
    state = health_module.HealthState(path=tmp_path / "state.json")
    note = '  Network\n outage\t"quoted" \\rack <b>café 東京</b>  '
    maintenance = '\n Planned\r\n reboot: "GPU" \\maintenance ☃  '
    assert state.success("account", [
        record(note=note, maintenanceNote=maintenance), record(machine_id="blank", name="Blank Host")
    ], now=10)

    actual = {sample.labels["machine_id"]: sample for sample in note_samples(state)}
    assert len(actual) == 2
    assert actual["machine-1"].labels == {
        "account": "account", "machine_id": "machine-1", "hostname": "provider host",
        "note": 'Network outage "quoted" \\rack <b>café 東京</b>',
        "maintenance_note": 'Planned reboot: "GPU" \\maintenance ☃',
    }
    assert actual["machine-1"].value == 1
    assert actual["blank"].labels["note"] == ""
    assert actual["blank"].labels["maintenance_note"] == ""
    assert actual["blank"].value == 1


def test_note_text_is_bounded_and_normalized_before_persistence(health_module, tmp_path):
    path = tmp_path / "state.json"
    state = health_module.HealthState(path=path)
    assert state.success("account", [record(note="  " + "é" * 600, maintenanceNote="x" * 513)], now=10)

    for field in ("note", "maintenance_note"):
        value = note_samples(state)[0].labels[field]
        assert len(value) == 512
        assert value.endswith("…")
        assert json.loads(path.read_text())["accounts"]["account"]["machines"]["machine-1"][field] == value


def test_note_edits_failures_missing_inventory_restart_and_explicit_clear(health_module, tmp_path):
    path = tmp_path / "state.json"
    state = health_module.HealthState(path=path)
    assert state.success("account", [record(note="first", maintenanceNote="first maintenance")], now=10)
    assert state.success("account", [record(note="edited", maintenanceNote="edited maintenance")], now=20)
    state.failure("account", now=30)
    assert not state.success("account", [record(note=123)], now=40)
    assert state.success("account", [], now=50)

    restored = health_module.HealthState(path=path)
    sample = note_samples(restored)[0]
    assert sample.labels["note"] == "edited"
    assert sample.labels["maintenance_note"] == "edited maintenance"
    assert restored.success("account", [record(note=None, maintenanceNote=" \n ")], now=60)
    cleared = note_samples(health_module.HealthState(path=path))[0]
    assert cleared.labels["note"] == cleared.labels["maintenance_note"] == ""


def test_note_text_is_separate_for_same_machine_id_across_accounts(health_module, tmp_path):
    state = health_module.HealthState(path=tmp_path / "state.json")
    for account in ("first", "second"):
        assert state.success(account, [record(note=account)], now=10)

    assert {(sample.labels["account"], sample.labels["note"]) for sample in note_samples(state, ("first", "second"))} == {
        ("first", "first"), ("second", "second"),
    }


def test_unknown_machine_has_no_note_metric(health_module, tmp_path):
    state = health_module.HealthState(path=tmp_path / "state.json")
    assert not state.success("account", [record(listed="unknown", note="unconfirmed")], now=10)
    assert note_samples(state) == []


def test_version_one_state_without_text_loads_blank_note_fields(health_module, tmp_path):
    path = tmp_path / "state.json"
    state = health_module.HealthState(path=path)
    assert state.success("account", [record(note="old")], now=10)
    saved = json.loads(path.read_text())
    machine = saved["accounts"]["account"]["machines"]["machine-1"]
    machine.pop("note", None)
    machine.pop("maintenance_note", None)
    path.write_text(json.dumps(saved))

    restored = health_module.HealthState(path=path)
    assert restored.storage_success == 1
    assert note_samples(restored)[0].labels["note"] == ""
    assert note_samples(restored)[0].labels["maintenance_note"] == ""


@pytest.mark.parametrize("field", ["note", "maintenance_note"])
@pytest.mark.parametrize("value", [None, True, 12, []])
def test_invalid_saved_note_text_rejects_state(health_module, tmp_path, field, value):
    path = tmp_path / "state.json"
    state = health_module.HealthState(path=path)
    assert state.success("account", [record()], now=10)
    saved = json.loads(path.read_text())
    saved["accounts"]["account"]["machines"]["machine-1"][field] = value
    path.write_text(json.dumps(saved))

    restored = health_module.HealthState(path=path)
    assert restored.storage_success == 0
    assert note_samples(restored) == []


def test_loaded_note_text_is_normalized_and_bounded(health_module, tmp_path):
    path = tmp_path / "state.json"
    state = health_module.HealthState(path=path)
    assert state.success("account", [record()], now=10)
    saved = json.loads(path.read_text())
    saved["accounts"]["account"]["machines"]["machine-1"].update(
        note="  old\n text  ", maintenance_note="z" * 600
    )
    path.write_text(json.dumps(saved))

    labels = note_samples(health_module.HealthState(path=path))[0].labels
    assert labels["note"] == "old text"
    assert labels["maintenance_note"] == "z" * 511 + "…"


def test_failed_atomic_save_retains_both_live_and_durable_note_text(health_module, tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    state = health_module.HealthState(path=path)
    assert state.success("account", [record(note="confirmed", maintenanceNote="confirmed maintenance")], now=10)

    def fail_replace(*_args):
        raise OSError("storage unavailable")

    monkeypatch.setattr(health_module.os, "replace", fail_replace)
    assert not state.success("account", [record(note="unsaved", maintenanceNote="unsaved maintenance")], now=20)
    assert state.storage_success == 0
    for observed in (state, health_module.HealthState(path=path)):
        labels = note_samples(observed)[0].labels
        assert labels["note"] == "confirmed"
        assert labels["maintenance_note"] == "confirmed maintenance"


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
