"""Regression coverage for RunPod income and health collection isolation."""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXPORTER_DIR = ROOT / "runpod-exporter"
EXPORTER_PATH = EXPORTER_DIR / "runpod_exporter.py"


@pytest.fixture()
def exporter_module():
    sys.path.insert(0, str(EXPORTER_DIR))
    try:
        spec = importlib.util.spec_from_file_location("runpod_exporter_under_test", EXPORTER_PATH)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(EXPORTER_DIR))


def health_record(listed=True):
    return {
        "id": "machine-1",
        "name": "Actual Provider Host",
        "listed": listed,
        "note": None,
        "maintenanceNote": None,
        "maintenanceMode": False,
        "lastSyncAt": None,
        "latestTelemetry": None,
    }


class FakeClient:
    def __init__(self, account_name, income, health):
        self.account_name = account_name
        self.income = income
        self.health = health

    def get_host_metrics(self):
        if isinstance(self.income, Exception):
            raise self.income
        return self.income

    def get_machine_health(self):
        if isinstance(self.health, Exception):
            raise self.health
        return self.health


def income_response():
    return {
        "myself": {
            "hostBalance": 1.5,
            "machines": [{"id": "machine-1", "name": "Income Host", "gpuTotal": 1}],
            "machineEarnings": [],
        }
    }


def health_response(listed=True):
    return {"myself": {"machines": [health_record(listed)]}}


def test_health_query_succeeds_when_income_query_fails(exporter_module, tmp_path):
    collector = exporter_module.MetricsCollector([], health_state_path=tmp_path / "state.json")
    collector.clients = [FakeClient("account", RuntimeError("income unavailable"), health_response())]

    metrics = collector.collect()

    assert 'runpod_api_poll_success{account="account"} 1' in metrics
    assert 'runpod_machine_health_listed{account="account",machine_id="machine-1",hostname="actual provider host"} 1' in metrics
    assert "runpod_host_balance{" not in metrics


def test_health_failure_does_not_clear_income_or_last_confirmed_listing(exporter_module, tmp_path):
    collector = exporter_module.MetricsCollector([], health_state_path=tmp_path / "state.json")
    client = FakeClient("account", income_response(), health_response(listed=True))
    collector.clients = [client]
    collector.cache_ttl = 0
    assert 'runpod_machine_health_listed{account="account",machine_id="machine-1",hostname="actual provider host"} 1' in collector.collect()

    client.health = RuntimeError("health unavailable")
    metrics = collector.collect()

    assert 'runpod_host_balance{account="account"} 1.5' in metrics
    assert 'runpod_api_poll_success{account="account"} 0' in metrics
    assert 'runpod_machine_health_listed{account="account",machine_id="machine-1",hostname="actual provider host"} 1' in metrics


def test_removing_and_readding_an_account_name_cannot_revive_old_machine_state(exporter_module, tmp_path, monkeypatch):
    collector = exporter_module.MetricsCollector([], health_state_path=tmp_path / "state.json")
    collector.clients = [FakeClient("tenant", income_response(), health_response())]
    assert 'runpod_host_balance{account="tenant"} 1.5' in collector.collect()
    manager = exporter_module.AccountManager(collector)
    monkeypatch.setattr(manager, "_save", lambda: None)

    assert manager.remove_account("tenant") == {"success": True, "name": "tenant"}
    collector.clients = [FakeClient("tenant", RuntimeError("income unavailable"), RuntimeError("health unavailable"))]
    metrics = collector.collect()

    assert 'runpod_api_poll_success{account="tenant"} 0' in metrics
    assert "runpod_machine_health_known{" not in metrics
    assert 'runpod_host_balance{account="tenant"} 1.5' not in metrics


def test_query_errors_do_not_log_provider_error_payloads(exporter_module, monkeypatch, caplog):
    class Response:
        def read(self):
            return b'{"errors":[{"message":"rpa_super_secret"}]}'

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    monkeypatch.setattr(exporter_module.urllib.request, "urlopen", lambda *args, **kwargs: Response())

    assert exporter_module.RunPodClient("test-key", "account").query("query") is None
    assert "rpa_super_secret" not in caplog.text


def test_failed_health_state_reset_rejects_account_removal_without_mutation(exporter_module, tmp_path, monkeypatch):
    collector = exporter_module.MetricsCollector([], health_state_path=tmp_path / "state.json")
    collector.clients = [FakeClient("tenant", income_response(), health_response())]
    manager = exporter_module.AccountManager(collector)
    monkeypatch.setattr(collector.health_state, "clear_account", lambda name: False)

    result = manager.remove_account("tenant")

    assert result["status"] == 503
    assert [client.account_name for client in collector.clients] == ["tenant"]
