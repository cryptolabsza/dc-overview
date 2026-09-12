from pathlib import Path
import subprocess
import stat
import multiprocessing
import time
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
import yaml
from click.testing import CliRunner

import dc_overview.cli as cli_module
from dc_overview.cli import load_config_from_file, main
from dc_overview.fleet_config import FleetConfig
from dc_overview.vpm_service import VPMServiceSpec, VPMServiceManager


PIN = "ghcr.io/cryptolabsza/vast-price-manager@sha256:" + "a" * 64


def _concurrent_configure_worker(config_dir: str, expected_account_id: str, hold_seconds: float, fail: bool):
    """Model the CLI configure transaction in a separate process."""
    path = Path(config_dir)
    manager = VPMServiceManager(path)
    with manager.operation_lock():
        config = FleetConfig.load(path)
        snapshot = config.snapshot_public_config()
        config.vast_price_manager.expected_account_id = expected_account_id
        config.persist_vast_price_manager_settings()
        time.sleep(hold_seconds)
        if fail:
            config.restore_public_config(snapshot)


def test_vpm_component_defaults_off_and_round_trips_both_config_loaders(tmp_path: Path):
    config = FleetConfig(config_dir=tmp_path)
    assert config.components.vast_price_manager is False
    config.components.vast_price_manager = True
    config.vast_price_manager.image = PIN
    config.vast_price_manager.master_key_file = "/etc/dc-overview/secrets/vpm-master.key"
    config.save()

    persisted = yaml.safe_load((tmp_path / "fleet-config.yaml").read_text())
    assert persisted["components"]["vast_price_manager"] is True
    assert "master_key_file" in persisted["vast_price_manager"]
    assert "VAST" not in (tmp_path / "fleet-config.yaml").read_text()
    assert FleetConfig.load(tmp_path).vast_price_manager.image == PIN

    unattended = tmp_path / "unattended.yaml"
    unattended.write_text((tmp_path / "fleet-config.yaml").read_text())
    loaded = load_config_from_file(str(unattended))
    assert loaded.components.vast_price_manager is True
    assert loaded.vast_price_manager.image == PIN


def test_vpm_public_settings_update_does_not_rewrite_secret_file(tmp_path: Path):
    config = FleetConfig(config_dir=tmp_path)
    config.save()
    secret_path = tmp_path / ".secrets.yaml"
    original_secrets = secret_path.read_text()
    config.vast_price_manager.expected_account_id = "account-123"
    config.persist_vast_price_manager_settings()
    assert secret_path.read_text() == original_secrets
    assert yaml.safe_load((tmp_path / "fleet-config.yaml").read_text())["vast_price_manager"]["expected_account_id"] == "account-123"


def test_vpm_renderer_requires_immutable_image_and_exact_dns_host():
    with pytest.raises(ValueError, match="immutable"):
        VPMServiceSpec(image="ghcr.io/cryptolabsza/vast-price-manager:latest", allowed_host="dc.example.com")
    with pytest.raises(ValueError, match="exact DNS"):
        VPMServiceSpec(image=PIN, allowed_host="*.example.com")
    with pytest.raises(ValueError, match="account ID"):
        VPMServiceSpec(image=PIN, allowed_host="dc.example.com", expected_account_id="bad id")


def test_vpm_master_key_rejects_world_readable_mode(monkeypatch, tmp_path: Path):
    manager = VPMServiceManager(tmp_path)
    monkeypatch.setattr(Path, "is_file", lambda _self: True)
    monkeypatch.setattr(
        Path,
        "stat",
        lambda _self: SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=999, st_gid=999),
    )
    with pytest.raises(ValueError, match="only by UID"):
        manager._validate_master_key(VPMServiceSpec(image=PIN, allowed_host="dc.example.com"))


def test_vpm_renderer_uses_container_contract_without_public_port_or_secret_value():
    rendered = VPMServiceManager.render(
        VPMServiceSpec(
            image=PIN,
            allowed_host="dc.example.com",
            master_key_file="/etc/dc-overview/secrets/vpm-master.key",
        )
    )
    compose = rendered.compose
    assert "ports:" not in compose
    assert "cryptolabs:" in compose
    assert "external: true" in compose
    assert "VPM_DEPLOYMENT_MODE=container_proxy" in compose
    assert "VPM_BASE_PATH=/vast-pricing" in compose
    assert "VPM_ALLOWED_HOSTS=dc.example.com" in compose
    assert "VPM_DATA_DIR=/data" in compose
    assert "VPM_CREDENTIAL_MASTER_KEY_FILE=/run/secrets/vpm-master.key" in compose
    assert "VPM_WRITES_ENABLED=false" in compose
    assert "VPM_SESSION_INSECURE" not in compose
    assert "VPM_EXPECTED_ACCOUNT_ID" not in compose
    assert "/etc/dc-overview/secrets/vpm-master.key:/run/secrets/vpm-master.key:ro" in compose
    assert "user: \"999:999\"" in compose
    assert "vpm sync" in rendered.units["vast-price-manager-sync.service"]
    assert "vpm cycle --all" in rendered.units["vast-price-manager-cycle.service"]
    assert "vpm reconcile-horizons" in rendered.units["vast-price-manager-horizon.service"]
    assert "RandomizedDelaySec=30s" in rendered.units["vast-price-manager-sync.timer"]

    configured = VPMServiceManager.render(
        VPMServiceSpec(image=PIN, allowed_host="dc.example.com", expected_account_id="account-123")
    ).compose
    assert "VPM_EXPECTED_ACCOUNT_ID=account-123" in configured


def test_rendered_compose_is_accepted_by_docker_compose(tmp_path: Path):
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(
        VPMServiceManager.render(
            VPMServiceSpec(image=PIN, allowed_host="dc.example.com")
        ).compose
    )
    result = subprocess.run(
        ["docker-compose", "-f", str(compose_file), "config"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_install_installs_units_quiesces_old_work_and_waits_for_health(tmp_path: Path):
    calls = []
    health_states = iter(["starting\n", "healthy\n"])

    class Result:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode, self.stdout, self.stderr = returncode, stdout, stderr

    def runner(command, **_kwargs):
        calls.append(command)
        if command[:3] == ["systemctl", "is-active", "--quiet"]:
            return Result(3)
        if command[:2] == ["systemctl", "is-enabled"]:
            return Result(1, "disabled\n")
        if command[:2] == ["systemctl", "is-active"]:
            return Result(3, "inactive\n")
        if command[:2] == ["docker", "inspect"]:
            return Result(stdout=next(health_states))
        return Result()

    manager = VPMServiceManager(
        tmp_path,
        unit_dir=tmp_path / "systemd-system",
        runner=runner,
        sleeper=lambda _seconds: None,
    )
    manager._validate_master_key = lambda _spec: None
    manager.install(VPMServiceSpec(image=PIN, allowed_host="dc.example.com"))

    assert (tmp_path / "systemd-system" / "vast-price-manager-sync.timer").exists()
    assert ["systemctl", "disable", "--now", *manager.timer_names] in calls
    assert ["systemctl", "stop", "vast-price-manager-sync.service", "vast-price-manager-cycle.service", "vast-price-manager-horizon.service"] in calls
    assert sum(command[:2] == ["docker", "inspect"] for command in calls) == 2
    assert ["systemctl", "enable", "--now", *manager.timer_names] in calls


def test_logs_returns_captured_project_output(tmp_path: Path):
    class Result:
        returncode = 0
        stdout = "vpm log line\n"
        stderr = ""

    manager = VPMServiceManager(tmp_path, runner=lambda *_args, **_kwargs: Result())
    assert manager.logs() == "vpm log line\n"


def test_cli_logs_prints_captured_project_output(monkeypatch, tmp_path: Path):
    class FakeManager:
        def __init__(self, _config_dir):
            pass

        def operation_lock(self):
            return nullcontext()

        def logs(self, _lines):
            return "vpm log line\n"

    monkeypatch.setattr(cli_module, "VPMServiceManager", FakeManager)
    result = CliRunner().invoke(main, ["vpm", "--config-dir", str(tmp_path), "logs"])
    assert result.exit_code == 0
    assert result.output == "vpm log line\n"


def test_install_route_failure_stops_new_vpm_project(monkeypatch, tmp_path: Path):
    class FakeManager:
        calls = []

        def __init__(self, _config_dir):
            pass

        def operation_lock(self):
            return nullcontext()

        def install(self, _spec, promote_route=None):
            self.calls.append("install")
            try:
                if promote_route:
                    promote_route()
            except RuntimeError:
                self.stop()
                raise

        def enable_proxy_route(self):
            self.calls.append("enable-route")
            raise RuntimeError("proxy registration failed")

        def stop(self):
            self.calls.append("stop")

    config = FleetConfig(config_dir=tmp_path)
    config.ssl.domain = "dc.example.com"
    config.save()
    monkeypatch.setattr(cli_module, "VPMServiceManager", FakeManager)
    result = CliRunner().invoke(main, ["vpm", "--config-dir", str(tmp_path), "install", "--image", PIN])
    assert result.exit_code != 0
    assert FakeManager.calls == ["install", "enable-route", "stop"]


def test_configure_rolls_back_public_settings_when_reinstall_fails(monkeypatch, tmp_path: Path):
    class FakeManager:
        def __init__(self, _config_dir):
            pass

        def operation_lock(self):
            return nullcontext()

        def install(self, _spec):
            raise RuntimeError("candidate unhealthy")

    config = FleetConfig(config_dir=tmp_path)
    config.ssl.domain = "dc.example.com"
    config.vast_price_manager.expected_account_id = "old-account"
    config.save()
    monkeypatch.setattr(cli_module, "VPMServiceManager", FakeManager)
    result = CliRunner().invoke(
        main,
        ["vpm", "--config-dir", str(tmp_path), "configure", "--expected-account-id", "new-account", "--image", PIN],
    )
    assert result.exit_code != 0
    assert FleetConfig.load(tmp_path).vast_price_manager.expected_account_id == "old-account"


def test_concurrent_configure_rollback_cannot_overwrite_later_success(tmp_path: Path):
    config = FleetConfig(config_dir=tmp_path)
    config.vast_price_manager.expected_account_id = "initial-account"
    config.save()
    context = multiprocessing.get_context("spawn")
    failed = context.Process(
        target=_concurrent_configure_worker,
        args=(str(tmp_path), "failed-account", 0.25, True),
    )
    successful = context.Process(
        target=_concurrent_configure_worker,
        args=(str(tmp_path), "winning-account", 0, False),
    )
    failed.start()
    time.sleep(0.05)
    successful.start()
    failed.join(10)
    successful.join(10)
    assert failed.exitcode == 0
    assert successful.exitcode == 0
    assert FleetConfig.load(tmp_path).vast_price_manager.expected_account_id == "winning-account"


def test_vpm_lifecycle_is_scoped_and_stop_preserves_data(tmp_path: Path):
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        class Result:
            returncode = 0
            stdout = "active\n"
            stderr = ""
        return Result()

    manager = VPMServiceManager(tmp_path, unit_dir=tmp_path / "systemd-system", runner=runner)
    manager.stop()
    assert ["systemctl", "disable", "--now", "vast-price-manager-sync.timer", "vast-price-manager-cycle.timer", "vast-price-manager-horizon.timer"] in calls
    assert any(command[-1] == "stop" and "vast-price-manager" in command for command in calls)
    assert all("down" not in command for command in calls)
    assert all("dc-overview" not in command for command in calls)


def test_vpm_health_failure_restores_previous_compose_after_candidate_validation(tmp_path: Path):
    class Result:
        returncode = 0
        stdout = "unhealthy\n"
        stderr = ""

    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        result = Result()
        if command[:3] == ["systemctl", "is-active", "--quiet"]:
            result.returncode = 3
        return result

    manager = VPMServiceManager(tmp_path, unit_dir=tmp_path / "systemd-system", runner=runner)
    manager.root.mkdir(parents=True)
    manager.compose_file.write_text("previous-compose\n")
    manager._validate_master_key = lambda _spec: None

    with pytest.raises(RuntimeError, match="did not pass /healthz"):
        manager.install(VPMServiceSpec(image=PIN, allowed_host="dc.example.com"))

    assert manager.compose_file.read_text() == "previous-compose\n"
    assert ["systemctl", "daemon-reload"] in calls
    assert ["systemctl", "enable", "vast-price-manager-sync.timer"] in calls
    assert ["systemctl", "start", "vast-price-manager-sync.timer"] in calls


def test_failed_fresh_install_removes_only_fresh_project_container(tmp_path: Path):
    calls = []

    class Result:
        returncode = 0
        stdout = "unhealthy\n"
        stderr = ""

    def runner(command, **_kwargs):
        calls.append(command)
        result = Result()
        if command[:3] == ["systemctl", "is-active", "--quiet"]:
            result.returncode = 3
        return result

    manager = VPMServiceManager(tmp_path, unit_dir=tmp_path / "systemd-system", runner=runner)
    manager._validate_master_key = lambda _spec: None
    with pytest.raises(RuntimeError, match="did not pass /healthz"):
        manager.install(VPMServiceSpec(image=PIN, allowed_host="dc.example.com"))

    assert not manager.compose_file.exists()
    assert any(command[-2:] == ["rm", "-f"] and manager.project_name in command for command in calls)


def test_route_promotion_failure_restores_existing_project_and_timers(tmp_path: Path):
    calls = []

    class Result:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode, self.stdout, self.stderr = returncode, stdout, stderr

    def runner(command, **_kwargs):
        calls.append(command)
        if command[:3] == ["systemctl", "is-active", "--quiet"]:
            return Result(3)
        if command[:2] == ["systemctl", "is-enabled"]:
            return Result(0, "enabled\n")
        if command[:2] == ["systemctl", "is-active"]:
            return Result(0, "active\n")
        if command[:2] == ["docker", "inspect"]:
            return Result(0, "healthy\n")
        return Result()

    manager = VPMServiceManager(tmp_path, unit_dir=tmp_path / "systemd-system", runner=runner)
    manager.root.mkdir(parents=True)
    manager.compose_file.write_text("old-image-compose\n")
    manager._validate_master_key = lambda _spec: None

    with pytest.raises(RuntimeError, match="proxy registration failed"):
        manager.install(
            VPMServiceSpec(image=PIN, allowed_host="dc.example.com"),
            promote_route=lambda: (_ for _ in ()).throw(RuntimeError("proxy registration failed")),
        )

    assert manager.compose_file.read_text() == "old-image-compose\n"
    assert sum(command[-2:] == ["up", "-d"] for command in calls) == 2
    assert ["systemctl", "enable", "vast-price-manager-sync.timer"] in calls
    assert ["systemctl", "start", "vast-price-manager-sync.timer"] in calls


def test_vpm_cli_exposes_scoped_lifecycle_commands():
    result = CliRunner().invoke(main, ["vpm", "--help"])
    assert result.exit_code == 0
    for command in ("install", "start", "stop", "status", "logs", "update", "configure", "disable", "enable"):
        assert command in result.output
