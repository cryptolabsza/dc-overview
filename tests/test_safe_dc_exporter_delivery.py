"""Safety regressions for installing and updating dc-exporter-rs."""

from __future__ import annotations

import hashlib
import importlib
import inspect
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from dc_overview.exporters import (
    DC_EXPORTER_CALLER_TIMEOUT_SECONDS,
    DC_EXPORTER_ROLLBACK_GRACE_SECONDS,
    DC_EXPORTER_SCRIPT_TIMEOUT_SECONDS,
    DC_EXPORTER_RS_VERSION,
    ExporterInstaller,
    build_dc_exporter_remote_command,
    build_dc_exporter_install_script,
)
from dc_overview import web_exporters


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o755)


def _fake_delivery_environment(
    tmp_path: Path,
    *,
    candidate_version: str = DC_EXPORTER_RS_VERSION,
    metrics_version: str = DC_EXPORTER_RS_VERSION,
    valid_checksum: bool = True,
    initially_active: bool = False,
    initially_enabled: bool = False,
):
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    released_binary = tmp_path / "released-dc-exporter-rs"
    _write_executable(
        released_binary,
        "#!/bin/sh\n"
        "if [ \"${1:-}\" = \"--version\" ]; then\n"
        f"  echo 'dc-exporter {candidate_version}'\n"
        "  exit 0\n"
        "fi\n"
        "exit 0\n",
    )

    checksum = hashlib.sha256(released_binary.read_bytes()).hexdigest()
    if not valid_checksum:
        checksum = "0" * 64
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text(f"{checksum}  dc-exporter-rs\n")

    systemctl_log = tmp_path / "systemctl.log"
    restart_count = tmp_path / "restart-count"
    active_state = tmp_path / "active-state"
    enabled_state = tmp_path / "enabled-state"
    service_path = tmp_path / "etc-systemd" / "dc-exporter.service"
    active_state.write_text("active" if initially_active else "inactive")
    enabled_state.write_text("enabled" if initially_enabled else "disabled")
    proc_exe = tmp_path / "proc" / "4242" / "exe"
    proc_exe.parent.mkdir(parents=True)
    proc_exe.write_bytes(released_binary.read_bytes())
    proc_exe.chmod(0o755)
    _write_executable(
        fake_bin / "timeout",
        """#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
  case "$1" in
    --signal=*|--kill-after=*) shift ;;
    [0-9]*|[0-9]*s) shift; break ;;
    *) break ;;
  esac
done
exec "$@"
""",
    )
    _write_executable(fake_bin / "flock", "#!/bin/sh\nexit 0\n")
    _write_executable(
        fake_bin / "curl",
        """#!/bin/sh
set -eu
output=''
url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output|-o) output="$2"; shift 2 ;;
    http://*|https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
case "$url" in
  *SHA256SUMS) cp "$FAKE_MANIFEST" "$output" ;;
  *dc-exporter-rs) cp "$FAKE_RELEASE_BINARY" "$output" ;;
  */metrics) printf 'dc_exporter_build_info{version="%s"} 1\n' "$FAKE_METRICS_VERSION" ;;
  *) exit 22 ;;
esac
""",
    )
    _write_executable(
        fake_bin / "systemctl",
        """#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FAKE_SYSTEMCTL_LOG"
case "${1:-}" in
  is-active)
    case "${FAKE_ACTIVE_PROBE_MODE:-}" in
      timeout) exit 124 ;;
      unknown) printf 'activating\n'; exit 3 ;;
      dbus) printf 'Failed to connect to bus\n' >&2; exit 1 ;;
    esac
    if [ ! -e "$FAKE_SERVICE_PATH" ] && [ ! -L "$FAKE_SERVICE_PATH" ]; then
      printf 'inactive\n'
      exit 3
    fi
    state=$(cat "$FAKE_ACTIVE_STATE")
    printf '%s\n' "$state"
    if [ "$state" = active ]; then exit 0; fi
    exit 3
    ;;
  is-enabled)
    case "${FAKE_ENABLED_PROBE_MODE:-}" in
      timeout) exit 124 ;;
      unknown) printf 'garbled-state\n'; exit 1 ;;
      dbus) printf 'Failed to connect to bus\n' >&2; exit 1 ;;
    esac
    if [ ! -e "$FAKE_SERVICE_PATH" ] && [ ! -L "$FAKE_SERVICE_PATH" ]; then
      if [ "${FAKE_MISSING_ENABLED_OUTPUT:-not-found}" = not-found ]; then
        printf 'not-found\n'
      fi
      exit 1
    fi
    state=$(cat "$FAKE_ENABLED_STATE")
    printf '%s\n' "$state"
    [ "$state" = enabled ]
    ;;
  show)
    case " $* " in
      *' --property LoadState '*)
        case "${FAKE_LOAD_STATE_PROBE_MODE:-}" in
          timeout) exit 124 ;;
          unknown) printf 'error\n'; exit 1 ;;
          dbus) printf 'Failed to connect to bus\n' >&2; exit 1 ;;
        esac
        if [ -e "$FAKE_SERVICE_PATH" ] || [ -L "$FAKE_SERVICE_PATH" ]; then
          printf 'loaded\n'
        else
          printf 'not-found\n'
        fi
        ;;
      *) printf '4242\n' ;;
    esac
    ;;
  restart)
    count=0
    if [ -f "$FAKE_RESTART_COUNT" ]; then count=$(cat "$FAKE_RESTART_COUNT"); fi
    count=$((count + 1))
    printf '%s' "$count" > "$FAKE_RESTART_COUNT"
    if [ "${HANG_FIRST_RESTART:-0}" = 1 ] && [ "$count" -eq 1 ]; then sleep 30; fi
    if [ "${FAIL_ALL_RESTARTS:-0}" = 1 ]; then exit 1; fi
    if [ "${FAIL_FIRST_RESTART:-0}" = 1 ] && [ "$count" -eq 1 ]; then exit 1; fi
    printf active > "$FAKE_ACTIVE_STATE"
    ;;
  start) printf active > "$FAKE_ACTIVE_STATE" ;;
  stop) printf inactive > "$FAKE_ACTIVE_STATE" ;;
  enable)
    if [ "${IGNORE_ENABLE:-0}" != 1 ]; then printf enabled > "$FAKE_ENABLED_STATE"; fi
    ;;
  disable) printf disabled > "$FAKE_ENABLED_STATE" ;;
esac
exit 0
""",
    )

    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "FAKE_MANIFEST": str(manifest),
        "FAKE_RELEASE_BINARY": str(released_binary),
        "FAKE_SYSTEMCTL_LOG": str(systemctl_log),
        "FAKE_RESTART_COUNT": str(restart_count),
        "FAKE_ACTIVE_STATE": str(active_state),
        "FAKE_ENABLED_STATE": str(enabled_state),
        "FAKE_SERVICE_PATH": str(service_path),
        "FAKE_METRICS_VERSION": metrics_version,
        "FAKE_PROC_EXE": str(proc_exe),
    }
    return env, systemctl_log, active_state, enabled_state


def _test_script(
    tmp_path: Path, *, mode: str = "install"
) -> tuple[str, Path, Path, Path]:
    target = tmp_path / "usr-local-bin" / "dc-exporter-rs"
    target.parent.mkdir()
    service_path = tmp_path / "etc-systemd" / "dc-exporter.service"
    service_path.parent.mkdir()
    backup_dir = tmp_path / "backups"
    script = build_dc_exporter_install_script(
        mode=mode,
        binary_path=str(target),
        service_path=str(service_path),
        backup_dir=str(backup_dir),
        temp_parent=str(tmp_path),
        lock_path=str(tmp_path / "dc-exporter-install.lock"),
        proc_root=str(tmp_path / "proc"),
        verification_attempts=1,
    )
    return script, target, service_path, backup_dir


def test_safe_script_installs_pinned_verified_candidate(tmp_path):
    env, systemctl_log, active_state, enabled_state = _fake_delivery_environment(tmp_path)
    script, target, service_path, backup_dir = _test_script(tmp_path)

    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env
    )

    assert result.returncode == 0, result.stderr
    assert target.is_file()
    assert target.stat().st_mode & 0o777 == 0o755
    assert f"dc-exporter {DC_EXPORTER_RS_VERSION}" in subprocess.check_output(
        [str(target), "--version"], text=True
    )
    assert service_path.is_file()
    assert "restart dc-exporter" in systemctl_log.read_text()
    assert "docker" not in script.lower()
    assert "reboot" not in script.lower()
    assert backup_dir.is_dir()
    assert active_state.read_text() == "active"
    assert enabled_state.read_text() == "enabled"


def test_clean_host_is_detected_as_absent_before_fresh_install(tmp_path):
    env, systemctl_log, _, _ = _fake_delivery_environment(tmp_path)
    script, target, service_path, _ = _test_script(tmp_path, mode="install")

    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env
    )

    assert result.returncode == 0, result.stderr
    assert target.is_file()
    assert service_path.is_file()
    log_lines = systemctl_log.read_text().splitlines()
    assert "is-active dc-exporter" in log_lines
    assert "is-enabled dc-exporter" in log_lines
    assert "show --property LoadState --value dc-exporter" in log_lines


def test_clean_host_with_empty_is_enabled_output_is_verified_as_absent(tmp_path):
    env, systemctl_log, _, _ = _fake_delivery_environment(tmp_path)
    env["FAKE_MISSING_ENABLED_OUTPUT"] = "empty"
    script, target, service_path, _ = _test_script(tmp_path, mode="install")

    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env
    )

    assert result.returncode == 0, result.stderr
    assert target.is_file()
    assert service_path.is_file()
    assert "show --property LoadState --value dc-exporter" in systemctl_log.read_text()


@pytest.mark.parametrize("load_state_mode", ["timeout", "unknown", "dbus"])
def test_absence_requires_successful_systemd_load_path_confirmation(
    tmp_path, load_state_mode
):
    env, systemctl_log, _, _ = _fake_delivery_environment(tmp_path)
    env["FAKE_LOAD_STATE_PROBE_MODE"] = load_state_mode
    script, target, service_path, _ = _test_script(tmp_path, mode="install")

    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env
    )

    assert result.returncode != 0
    assert "could not determine original dc-exporter service state" in result.stderr
    assert not target.exists()
    assert not service_path.exists()
    mutating_commands = {
        "daemon-reload",
        "disable",
        "enable",
        "restart",
        "start",
        "stop",
    }
    assert not any(
        line.split(maxsplit=1)[0] in mutating_commands
        for line in systemctl_log.read_text().splitlines()
    )


def test_fresh_install_rollback_restores_absent_service(tmp_path):
    env, systemctl_log, _, _ = _fake_delivery_environment(tmp_path)
    env["FAIL_FIRST_RESTART"] = "1"
    script, target, service_path, _ = _test_script(tmp_path, mode="install")

    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env
    )

    assert result.returncode != 0
    assert not target.exists()
    assert not service_path.exists()
    assert "previous binary and service state restored" in result.stderr
    assert systemctl_log.read_text().splitlines().count(
        "show --property LoadState --value dc-exporter"
    ) >= 2


def test_install_mode_repairs_partial_install_and_finishes_active_enabled(tmp_path):
    env, _, active_state, enabled_state = _fake_delivery_environment(tmp_path)
    script, target, service_path, _ = _test_script(tmp_path, mode="install")
    target.write_text("partial-old-binary")
    service_path.write_text("partial-broken-service")

    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env
    )

    assert result.returncode == 0, result.stderr
    assert active_state.read_text() == "active"
    assert enabled_state.read_text() == "enabled"
    assert "ExecStart=/usr/local/bin/dc-exporter-rs --port 9835" in service_path.read_text()


@pytest.mark.parametrize(
    ("candidate_version", "valid_checksum"),
    [("0.2.7", True), (DC_EXPORTER_RS_VERSION, False)],
)
def test_safe_script_rejects_unverified_candidate_before_mutation(
    tmp_path, candidate_version, valid_checksum
):
    env, systemctl_log, _, _ = _fake_delivery_environment(
        tmp_path,
        candidate_version=candidate_version,
        valid_checksum=valid_checksum,
    )
    script, target, service_path, _ = _test_script(tmp_path, mode="update")
    target.write_text("known-good-binary")
    service_path.write_text("known-good-service")

    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env
    )

    assert result.returncode != 0
    assert target.read_text() == "known-good-binary"
    assert service_path.read_text() == "known-good-service"
    assert not systemctl_log.exists(), "service must not be touched before validation"


def test_safe_script_rolls_back_binary_and_unit_after_restart_failure(tmp_path):
    env, systemctl_log, _, _ = _fake_delivery_environment(
        tmp_path, initially_active=True, initially_enabled=True
    )
    env["FAIL_FIRST_RESTART"] = "1"
    script, target, service_path, backup_dir = _test_script(tmp_path)
    target.write_text("known-good-binary")
    service_path.write_text("known-good-service")

    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env
    )

    assert result.returncode != 0
    assert target.read_text() == "known-good-binary"
    assert service_path.read_text() == "known-good-service"
    assert systemctl_log.read_text().count("restart dc-exporter") == 2
    assert list(backup_dir.glob("dc-exporter-rs.*"))


@pytest.mark.parametrize(
    ("mode", "probe_variable", "probe_mode"),
    [
        ("install", "FAKE_ACTIVE_PROBE_MODE", "timeout"),
        ("update", "FAKE_ACTIVE_PROBE_MODE", "unknown"),
        ("install", "FAKE_ACTIVE_PROBE_MODE", "dbus"),
        ("install", "FAKE_ENABLED_PROBE_MODE", "timeout"),
        ("update", "FAKE_ENABLED_PROBE_MODE", "unknown"),
        ("update", "FAKE_ENABLED_PROBE_MODE", "dbus"),
    ],
)
def test_unknown_original_systemd_state_aborts_before_mutation(
    tmp_path, mode, probe_variable, probe_mode
):
    env, systemctl_log, _, _ = _fake_delivery_environment(
        tmp_path, initially_active=True, initially_enabled=True
    )
    env[probe_variable] = probe_mode
    script, target, service_path, _ = _test_script(tmp_path, mode=mode)
    target.write_text("known-good-binary")
    service_path.write_text("known-good-service")

    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env
    )

    assert result.returncode != 0
    assert "could not determine original dc-exporter service state" in result.stderr
    assert target.read_text() == "known-good-binary"
    assert service_path.read_text() == "known-good-service"
    mutating_commands = {
        "daemon-reload",
        "disable",
        "enable",
        "restart",
        "start",
        "stop",
    }
    assert not any(
        line.split(maxsplit=1)[0] in mutating_commands
        for line in systemctl_log.read_text().splitlines()
    )


@pytest.mark.parametrize(
    ("initially_active", "initially_enabled"),
    [(False, False), (False, True), (True, False), (True, True)],
)
def test_safe_update_preserves_service_state(
    tmp_path, initially_active, initially_enabled
):
    env, systemctl_log, active_state, enabled_state = _fake_delivery_environment(
        tmp_path,
        initially_active=initially_active,
        initially_enabled=initially_enabled,
    )
    script, target, service_path, _ = _test_script(tmp_path, mode="update")
    target.write_text("known-good-binary")
    service_path.write_text("known-good-service")

    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env
    )

    assert result.returncode == 0, result.stderr
    assert active_state.read_text() == ("active" if initially_active else "inactive")
    assert enabled_state.read_text() == ("enabled" if initially_enabled else "disabled")
    log = systemctl_log.read_text()
    if initially_active:
        assert "restart dc-exporter" in log
    else:
        assert "start dc-exporter" in log
        assert "stop dc-exporter" in log


def test_safe_script_rolls_back_when_metrics_are_not_from_pinned_version(tmp_path):
    env, _, _, _ = _fake_delivery_environment(
        tmp_path,
        metrics_version="0.2.7",
        initially_active=True,
        initially_enabled=True,
    )
    script, target, service_path, _ = _test_script(tmp_path)
    target.write_text("known-good-binary")
    service_path.write_text("known-good-service")

    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env
    )

    assert result.returncode != 0
    assert target.read_text() == "known-good-binary"
    assert service_path.read_text() == "known-good-service"


def test_safe_script_rolls_back_when_main_pid_binary_checksum_differs(tmp_path):
    env, _, _, _ = _fake_delivery_environment(
        tmp_path, initially_active=True, initially_enabled=True
    )
    Path(env["FAKE_PROC_EXE"]).write_text("different-running-binary")
    script, target, service_path, _ = _test_script(tmp_path, mode="update")
    target.write_text("known-good-binary")
    service_path.write_text("known-good-service")

    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env
    )

    assert result.returncode != 0
    assert target.read_text() == "known-good-binary"


def test_install_mode_verifies_requested_final_service_state(tmp_path):
    env, _, _, _ = _fake_delivery_environment(tmp_path)
    env["IGNORE_ENABLE"] = "1"
    script, target, service_path, _ = _test_script(tmp_path, mode="install")

    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env
    )

    assert result.returncode != 0
    assert not target.exists()
    assert not service_path.exists()


def test_safe_script_reports_incomplete_rollback(tmp_path):
    env, _, _, _ = _fake_delivery_environment(
        tmp_path, initially_active=True, initially_enabled=True
    )
    env["FAIL_ALL_RESTARTS"] = "1"
    script, target, service_path, _ = _test_script(tmp_path)
    target.write_text("known-good-binary")
    service_path.write_text("known-good-service")

    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env
    )

    assert result.returncode != 0
    assert "rollback incomplete" in result.stderr.lower()


def test_term_during_mutation_runs_rollback_before_exit(tmp_path):
    env, systemctl_log, _, _ = _fake_delivery_environment(
        tmp_path, initially_active=True, initially_enabled=True
    )
    env["HANG_FIRST_RESTART"] = "1"
    script, target, service_path, _ = _test_script(tmp_path, mode="update")
    target.write_text("known-good-binary")
    service_path.write_text("known-good-service")
    process = subprocess.Popen(
        ["bash", "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True,
    )

    for _ in range(200):
        if systemctl_log.exists() and "restart dc-exporter" in systemctl_log.read_text():
            break
        time.sleep(0.01)
    else:
        process.kill()
        pytest.fail("installer never reached the post-mutation restart")

    os.killpg(process.pid, signal.SIGTERM)
    _, stderr = process.communicate(timeout=5)

    assert process.returncode != 0
    assert target.read_text() == "known-good-binary"
    assert service_path.read_text() == "known-good-service"
    assert "previous binary and service state restored" in stderr


def test_cli_installer_executes_shared_safe_script(monkeypatch):
    completed = subprocess.CompletedProcess([], 0, "DC_EXPORTER_INSTALL_SUCCESS\n", "")
    run = Mock(return_value=completed)
    monkeypatch.setattr("dc_overview.exporters.subprocess.run", run)
    installer = ExporterInstaller.__new__(ExporterInstaller)

    assert installer.install_dc_exporter() is True

    command = run.call_args.args[0]
    assert command[-2:] == ["bash", "-s"]
    assert "timeout" in command[0]
    script = run.call_args.kwargs["input"]
    assert "MODE=install" in script
    assert "SHA256SUMS" in script
    assert f"/v{DC_EXPORTER_RS_VERSION}/dc-exporter-rs" in script


def test_web_install_and_update_use_same_safe_script(monkeypatch):
    server = SimpleNamespace(name="gpu-1", server_ip="10.0.0.1", ssh_port=22, ssh_user="root")
    monkeypatch.setattr(web_exporters, "build_ssh_cmd", lambda *a, **k: (["ssh"], {}))
    run = Mock(return_value=subprocess.CompletedProcess([], 0, "DC_EXPORTER_INSTALL_SUCCESS\n", ""))
    monkeypatch.setattr(web_exporters.subprocess, "run", run)

    assert web_exporters.install_exporter_remote(server, "dc_exporter") is True
    install_call = run.call_args
    install_script = install_call.kwargs["input"]

    success, error = web_exporters.update_exporter_remote(
        server, "dc_exporter", DC_EXPORTER_RS_VERSION, "main"
    )
    update_call = run.call_args
    update_script = update_call.kwargs["input"]

    assert success is True
    assert error is None
    assert "MODE=install" in install_script
    assert "MODE=update" in update_script
    assert "SHA256SUMS" in update_script
    for call in (install_call, update_call):
        remote_command = call.args[0][-1]
        assert remote_command.endswith("bash -s")
        assert "timeout --signal=TERM" in remote_command
        assert call.kwargs["timeout"] == DC_EXPORTER_CALLER_TIMEOUT_SECONDS


def test_remote_delivery_does_not_depend_on_login_shell_being_bash(monkeypatch):
    server = SimpleNamespace(name="dash-host", server_ip="10.0.0.2", ssh_port=22, ssh_user="root")
    monkeypatch.setattr(
        web_exporters,
        "build_ssh_cmd",
        lambda *a, **k: (["ssh", "root@dash-host"], {}),
    )
    run = Mock(return_value=subprocess.CompletedProcess([], 0, "DC_EXPORTER_INSTALL_SUCCESS\n", ""))
    monkeypatch.setattr(web_exporters.subprocess, "run", run)

    assert web_exporters.install_exporter_remote(server, "dc_exporter") is True

    assert run.call_args.args[0][-1].endswith("bash -s")
    assert run.call_args.kwargs["input"].startswith("set -Eeuo pipefail")
    assert run.call_args.args[0][-1] != run.call_args.kwargs["input"]


def test_outer_timeout_exceeds_remote_timeout_and_rollback_grace():
    assert DC_EXPORTER_CALLER_TIMEOUT_SECONDS > (
        DC_EXPORTER_SCRIPT_TIMEOUT_SECONDS + DC_EXPORTER_ROLLBACK_GRACE_SECONDS + 15
    )


def test_rollback_grace_covers_all_bounded_systemctl_recovery_calls():
    # Worst case: stop, disable, daemon-reload, enable, restart, and two state
    # checks. Each systemctl call has a 5-second timeout and 2-second kill grace.
    assert DC_EXPORTER_ROLLBACK_GRACE_SECONDS > 7 * (5 + 2)


def test_encoded_remote_command_invokes_explicit_bash_without_embedding_script():
    script = "set -Eeuo pipefail\nprintf 'safe script executed\\n'\n"

    command = build_dc_exporter_remote_command(script)

    assert command.endswith("bash -s")
    assert "base64 --decode" in command
    assert script not in command


def test_encoded_remote_command_executes_when_login_shell_is_dash(tmp_path):
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    _write_executable(
        fake_bin / "timeout",
        """#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
  case "$1" in
    --signal=*|--kill-after=*) shift ;;
    [0-9]*|[0-9]*s) shift; break ;;
    *) break ;;
  esac
done
exec "$@"
""",
    )
    command = build_dc_exporter_remote_command(
        "set -Eeuo pipefail\nprintf 'EXPLICIT_BASH_OK\\n'\n"
    )

    result = subprocess.run(
        ["dash", "-c", command],
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "EXPLICIT_BASH_OK\n"


def test_fleet_manager_routes_dc_exporter_through_safe_install_mode(monkeypatch):
    fleet_manager = importlib.import_module("dc_overview.fleet_manager")
    manager = fleet_manager.FleetManager.__new__(fleet_manager.FleetManager)
    creds = SimpleNamespace(username="root", port=22, key_path="/fleet-key")
    manager.config = SimpleNamespace(
        ssh=SimpleNamespace(key_path="/global-key"),
        get_server_ssh_creds=lambda _server: creds,
    )
    manager.ssh = Mock()
    manager.ssh.test_connection.return_value = True
    manager.ssh.run_command.side_effect = [
        SimpleNamespace(success=True, output="node ready", exit_code=0),
        SimpleNamespace(
            success=True,
            output="DC_EXPORTER_INSTALL_SUCCESS version=0.2.8",
            exit_code=0,
        ),
        SimpleNamespace(success=True, output="8\n", exit_code=0),
    ]
    server = SimpleNamespace(name="gpu-1", server_ip="10.0.0.1", has_gpu=False)
    build_script = Mock(return_value="SAFE_INSTALL_SCRIPT")
    build_command = Mock(return_value="SAFE_REMOTE_BASH")
    monkeypatch.setattr(fleet_manager, "build_dc_exporter_install_script", build_script)
    monkeypatch.setattr(fleet_manager, "build_dc_exporter_remote_command", build_command)

    assert manager._install_exporters_on_server(server) is True

    build_script.assert_called_once_with(mode="install")
    build_command.assert_called_once_with("SAFE_INSTALL_SCRIPT", sudo=False)
    dc_call = manager.ssh.run_command.call_args_list[1]
    assert dc_call.kwargs["command"] == "SAFE_REMOTE_BASH"
    assert dc_call.kwargs["timeout"] == DC_EXPORTER_CALLER_TIMEOUT_SECONDS
    assert dc_call.kwargs["sudo"] is False


def test_quickstart_delegates_to_shared_safe_installer(monkeypatch):
    quickstart = importlib.import_module("dc_overview.quickstart")
    installer = Mock()
    installer.install_dc_exporter.return_value = True
    installer_class = Mock(return_value=installer)
    monkeypatch.setattr(quickstart, "ExporterInstaller", installer_class)

    assert quickstart.install_dc_exporter() is True

    installer_class.assert_called_once_with()
    installer.install_dc_exporter.assert_called_once_with()


class _FakeParamikoChannel:
    def __init__(self, exit_code=0):
        self._exit_code = exit_code

    def exit_status_ready(self):
        return True

    def recv_exit_status(self):
        return self._exit_code


class _FakeParamikoStream:
    def __init__(self, content="", exit_code=0):
        self._content = content.encode()
        self.channel = _FakeParamikoChannel(exit_code)

    def read(self):
        return self._content


class _FakeParamikoClient:
    def __init__(self, dc_output=""):
        self.commands = []
        self.dc_output = dc_output
        self.closed = False

    def set_missing_host_key_policy(self, _policy):
        pass

    def connect(self, *args, **kwargs):
        pass

    def exec_command(self, command, timeout=None):
        self.commands.append((command, timeout))
        if command == "SAFE_NODE_BASH":
            output = "NODE_EXPORTER_INSTALL_SUCCESS\n"
        elif command == "SAFE_REMOTE_BASH":
            output = self.dc_output
        else:
            output = ""
        return (
            _FakeParamikoStream(),
            _FakeParamikoStream(output),
            _FakeParamikoStream(),
        )

    def close(self):
        self.closed = True


def _install_with_fake_paramiko(monkeypatch, *, dc_output):
    quickstart = importlib.import_module("dc_overview.quickstart")
    client = _FakeParamikoClient(dc_output)
    paramiko = SimpleNamespace(
        SSHClient=Mock(return_value=client),
        AutoAddPolicy=Mock(return_value=object()),
    )
    monkeypatch.setitem(sys.modules, "paramiko", paramiko)
    build_script = Mock(return_value="SAFE_INSTALL_SCRIPT")
    build_command = Mock(side_effect=["SAFE_NODE_BASH", "SAFE_REMOTE_BASH"])
    monkeypatch.setattr(
        quickstart, "build_dc_exporter_install_script", build_script, raising=False
    )
    monkeypatch.setattr(
        quickstart, "build_dc_exporter_remote_command", build_command, raising=False
    )

    result = quickstart.install_exporters_remote(
        "10.0.0.10", "root", password="secret", port=22
    )
    return result, client, build_script, build_command


def test_paramiko_install_requires_verified_dc_exporter_success_marker(monkeypatch):
    result, client, build_script, build_command = _install_with_fake_paramiko(
        monkeypatch, dc_output=""
    )

    assert result is False
    build_script.assert_called_once_with(mode="install")
    build_command.assert_any_call("SAFE_INSTALL_SCRIPT", sudo=False)
    assert ("SAFE_REMOTE_BASH", DC_EXPORTER_CALLER_TIMEOUT_SECONDS) in client.commands
    assert all("pip3 install dc-overview" not in command for command, _ in client.commands)
    assert all("dc-overview install-exporters" not in command for command, _ in client.commands)


def test_paramiko_install_accepts_only_verified_safe_delivery(monkeypatch):
    result, client, _, _ = _install_with_fake_paramiko(
        monkeypatch,
        dc_output=f"DC_EXPORTER_INSTALL_SUCCESS version={DC_EXPORTER_RS_VERSION}\n",
    )

    assert result is True
    assert client.closed is True


def test_paramiko_command_polling_has_a_terminal_state_deadline(monkeypatch):
    quickstart = importlib.import_module("dc_overview.quickstart")

    class NeverReadyChannel:
        closed = False

        def exit_status_ready(self):
            return False

        def close(self):
            self.closed = True

    channel = NeverReadyChannel()
    stdout = _FakeParamikoStream()
    stdout.channel = channel
    client = Mock()
    client.exec_command.return_value = (
        _FakeParamikoStream(),
        stdout,
        _FakeParamikoStream(),
    )
    monkeypatch.setattr(quickstart.time, "monotonic", Mock(side_effect=[10.0, 11.1]))
    monkeypatch.setattr(quickstart.time, "sleep", Mock())

    exit_code, output, error = quickstart._run_paramiko_command(
        client, "SAFE_REMOTE_BASH", 1
    )

    assert (exit_code, output, error) == (-1, "", "remote command timed out")
    assert channel.closed is True


def test_open_exporter_port_does_not_skip_safe_dc_exporter_delivery(monkeypatch):
    quickstart = importlib.import_module("dc_overview.quickstart")
    monkeypatch.setattr(quickstart, "test_machine_connection", lambda *args: True)
    install = Mock(return_value=True)
    monkeypatch.setattr(quickstart, "install_exporters_remote", install)

    machines = quickstart.parse_server_list(
        ["global:root,secret", "10.0.0.20"]
    )

    assert machines == [{"name": "gpu-01", "ip": "10.0.0.20"}]
    install.assert_called_once_with(
        ip="10.0.0.20",
        user="root",
        password="secret",
        key_path=None,
        port=22,
    )


def test_no_quickstart_paramiko_flow_trusts_an_open_port_as_install_proof():
    quickstart = importlib.import_module("dc_overview.quickstart")

    assert "if test_machine_connection(ip, 9835):" not in inspect.getsource(
        quickstart.setup_master_docker
    )
    for flow in (quickstart.parse_server_list, quickstart.add_machines_manual):
        assert "if test_machine_connection(ip):" not in inspect.getsource(flow)


def test_web_update_refuses_unpinned_dc_exporter_release(monkeypatch):
    server = SimpleNamespace(name="gpu-1", server_ip="10.0.0.1", ssh_port=22, ssh_user="root")
    run = Mock()
    monkeypatch.setattr(web_exporters.subprocess, "run", run)

    success, error = web_exporters.update_exporter_remote(
        server, "dc_exporter", "99.0.0", "main"
    )

    assert success is False
    assert "pinned" in error.lower()
    run.assert_not_called()


def test_failed_auto_update_is_surfaced_without_database_version_change(app, monkeypatch):
    app_module = importlib.import_module("dc_overview.app")
    server = SimpleNamespace(
        server_ip="10.0.0.1",
        ssh_user="root",
        ssh_port=22,
        ssh_password=None,
        exporter_update_branch="main",
        node_exporter_auto_update=False,
        node_exporter_installed=False,
        node_exporter_version=None,
        dc_exporter_auto_update=True,
        dc_exporter_installed=True,
        dc_exporter_version="0.2.7",
        dcgm_exporter_auto_update=False,
        dcgm_exporter_installed=False,
        dcgm_exporter_version=None,
    )
    monkeypatch.setattr(app_module, "resolve_ssh_key_path", lambda _server: None)
    monkeypatch.setattr(
        "dc_overview.exporters.check_for_updates",
        lambda *args, **kwargs: {
            "dc_exporter": {
                "installed": "0.2.7",
                "latest": DC_EXPORTER_RS_VERSION,
                "update_available": True,
            }
        },
    )
    monkeypatch.setattr(
        app_module,
        "update_exporter_remote",
        lambda *args, **kwargs: (False, "candidate verification failed"),
    )

    with (
        app.app_context(),
        patch.object(app_module.db.session, "commit") as commit,
        patch.object(app_module.app.logger, "error") as log_error,
    ):
        updates = app_module.check_and_apply_auto_updates(server)

    assert updates == [
        {
            "exporter": "dc_exporter",
            "status": "failed",
            "from_version": "0.2.7",
            "to_version": DC_EXPORTER_RS_VERSION,
            "error": "candidate verification failed",
        }
    ]
    assert server.dc_exporter_version == "0.2.7"
    commit.assert_not_called()
    log_error.assert_called_once()
