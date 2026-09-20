"""Fresh Vast exporter prerequisite coverage for first VPM installation."""

import json
import urllib.request
from pathlib import Path

import pytest

from dc_overview.vpm_service import (
    VPMServiceManager,
    VPMServiceSpec,
    _VAST_EXPORTER_PREREQUISITE_PROBE,
)
from dc_overview.fleet_wizard import FleetWizard


PIN = "ghcr.io/cryptolabsza/vast-price-manager@sha256:" + "a" * 64


class Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _manager(tmp_path: Path, calls: list, running: Result, probe: Result) -> VPMServiceManager:
    def runner(command, **_kwargs):
        calls.append(command)
        if command == ["docker", "inspect", "-f", "{{.State.Running}}", "vastai-exporter"]:
            return running
        if command[:3] == ["docker", "exec", "vastai-exporter"]:
            return probe
        if command[:3] == ["systemctl", "is-active", "--quiet"]:
            return Result(3)
        if command[:2] == ["systemctl", "is-enabled"]:
            return Result(1)
        if command[:2] == ["systemctl", "is-active"]:
            return Result(3)
        if command[:2] == ["docker", "inspect"]:
            return Result(stdout="healthy\n")
        return Result()

    manager = VPMServiceManager(tmp_path, unit_dir=tmp_path / "units", runner=runner, sleeper=lambda _seconds: None)
    manager._validate_master_key = lambda _spec: None
    return manager


@pytest.mark.parametrize(
    "running, probe, expected",
    [
        (Result(stdout="false\n"), Result(), {"configured": False, "reason": "exporter-not-running", "connected_account_count": 0}),
        (Result(stdout="true\n"), Result(stdout=json.dumps({"configured": True, "reason": "ready", "connected_account_count": 1})), {"configured": True, "reason": "ready", "connected_account_count": 1}),
        (Result(stdout="true\n"), Result(stdout=json.dumps({"configured": False, "reason": "no-connected-account", "connected_account_count": 0})), {"configured": False, "reason": "no-connected-account", "connected_account_count": 0}),
        (Result(stdout="true\n"), Result(stdout="not json"), {"configured": False, "reason": "unavailable", "connected_account_count": 0}),
        (Result(stdout="true\n"), Result(1, stderr="unauthorized"), {"configured": False, "reason": "unavailable", "connected_account_count": 0}),
    ],
)
def test_vast_exporter_prerequisite_returns_only_the_sanitized_contract(tmp_path, running, probe, expected):
    calls = []
    status = _manager(tmp_path, calls, running, probe).vast_exporter_prerequisite()

    assert status == expected
    assert set(status) == {"configured", "reason", "connected_account_count"}
    assert all("api/accounts" not in " ".join(command) or command[:3] == ["docker", "exec", "vastai-exporter"] for command in calls)


@pytest.mark.parametrize(
    "running, probe",
    [
        (Result(stdout="false\n"), Result()),
        (Result(stdout="true\n"), Result(stdout=json.dumps({"configured": False, "reason": "no-connected-account", "connected_account_count": 0}))),
        (Result(stdout="true\n"), Result(stdout="not json")),
        (Result(stdout="true\n"), Result(1, stderr="unauthorized")),
    ],
)
def test_each_failed_exporter_prerequisite_blocks_first_install_before_mutation(tmp_path, running, probe):
    calls = []
    manager = _manager(tmp_path, calls, running, probe)

    with pytest.raises(RuntimeError, match="requires a running Vast.ai exporter"):
        manager.install(VPMServiceSpec(image=PIN, allowed_host="dc.example.com"))

    assert not manager.root.exists()
    assert ["systemctl", "disable", "--now", *manager.timer_names] not in calls
    assert ["systemctl", "stop", *manager.service_names] not in calls
    assert not any(command[-1:] == ["config"] for command in calls)


def test_connected_exporter_account_allows_first_install(tmp_path):
    calls = []
    manager = _manager(
        tmp_path,
        calls,
        Result(stdout="true\n"),
        Result(stdout=json.dumps({"configured": True, "reason": "ready", "connected_account_count": 2})),
    )

    manager.install(VPMServiceSpec(image=PIN, allowed_host="dc.example.com"))

    assert manager.compose_file.exists()
    assert ["systemctl", "disable", "--now", *manager.timer_names] in calls


def test_existing_vpm_install_maintenance_does_not_recheck_exporter_prerequisite(tmp_path):
    calls = []
    manager = _manager(tmp_path, calls, Result(stdout="false\n"), Result())
    manager.root.mkdir(parents=True)
    manager.compose_file.write_text("existing-compose\n")

    original_runner = manager.runner

    def runner(command, **kwargs):
        if command == [
            "docker", "inspect", "-f",
            '{{.Name}} {{index .Config.Labels "com.docker.compose.project"}}',
            "vast-price-manager",
        ]:
            calls.append(command)
            return Result(stdout="/vast-price-manager vast-price-manager\n")
        return original_runner(command, **kwargs)

    manager.runner = runner
    manager.vast_exporter_prerequisite = lambda: (_ for _ in ()).throw(AssertionError("must not recheck exporter"))

    manager.install(VPMServiceSpec(image=PIN, allowed_host="dc.example.com"))

    assert manager.compose_file.exists()


def test_saved_compose_without_managed_vpm_container_does_not_bypass_first_install_gate(tmp_path):
    calls = []
    manager = _manager(tmp_path, calls, Result(stdout="true\n"), Result(stdout="not json"))
    manager.root.mkdir(parents=True)
    manager.compose_file.write_text("failed-first-install-compose\n")

    with pytest.raises(RuntimeError, match="requires a running Vast.ai exporter"):
        manager.install(VPMServiceSpec(image=PIN, allowed_host="dc.example.com"))

    assert manager.compose_file.read_text() == "failed-first-install-compose\n"
    assert not any(command[-1:] == ["config"] for command in calls)


def test_exporter_probe_disables_proxy_inheritance_and_redirects():
    assert "ProxyHandler({})" in _VAST_EXPORTER_PREREQUISITE_PROBE
    assert "HTTPRedirectHandler" in _VAST_EXPORTER_PREREQUISITE_PROBE


@pytest.mark.parametrize("token", [None, "", "  "])
def test_exporter_probe_with_empty_management_token_never_queries_accounts(monkeypatch, capsys, token):
    opener_calls = []

    def forbidden_opener(*_args, **_kwargs):
        opener_calls.append(True)
        raise AssertionError("empty token must not be sent to /api/accounts")

    if token is None:
        monkeypatch.delenv("MGMT_TOKEN", raising=False)
    else:
        monkeypatch.setenv("MGMT_TOKEN", token)
    monkeypatch.setattr(urllib.request, "build_opener", forbidden_opener)

    exec(_VAST_EXPORTER_PREREQUISITE_PROBE, {})

    assert opener_calls == []
    assert json.loads(capsys.readouterr().out) == {
        "configured": False,
        "reason": "unavailable",
        "connected_account_count": 0,
    }


def test_wizard_defers_vpm_choice_until_after_vast_exporter_setup(monkeypatch, tmp_path):
    selected = ["dc_overview", "vast_exporter"]
    observed = {}

    class Prompt:
        def ask(self):
            return selected

    def checkbox(_message, choices, **_kwargs):
        observed["values"] = [choice.value for choice in choices]
        return Prompt()

    wizard = FleetWizard(tmp_path)
    monkeypatch.setattr(wizard, "_detect_local_gpus", lambda: 0)
    monkeypatch.setattr(wizard, "_detect_existing_ipmi", lambda: False)
    monkeypatch.setattr("dc_overview.fleet_wizard.questionary.checkbox", checkbox)

    wizard._collect_components()

    assert "vast_price_manager" not in observed["values"]
    assert wizard.config.components.vast_exporter is True
    assert wizard.config.components.vast_price_manager is False
