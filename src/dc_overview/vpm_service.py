"""Scoped lifecycle support for the optional Vast Price Manager container."""

from __future__ import annotations

import fcntl
import json
import os
import re
import shutil
import stat
import subprocess
import time
from dataclasses import dataclass
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Dict, Optional


_PINNED_IMAGE = re.compile(r"^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$")
_LOCAL_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_DNS_HOST = re.compile(
    r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
_ACCOUNT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

# This program runs inside the exporter: the management token never leaves the
# container, and the host receives only the three-field prerequisite contract.
_VAST_EXPORTER_PREREQUISITE_PROBE = r'''
import json
import os
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None

result = {"configured": False, "reason": "unavailable", "connected_account_count": 0}
try:
    token = os.environ.get("MGMT_TOKEN")
    if not isinstance(token, str) or not token.strip():
        raise ValueError("missing management token")
    request = Request(
        "http://localhost:8622/api/accounts",
        headers={"X-Mgmt-Token": token},
    )
    opener = build_opener(ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=5) as response:
        if response.status != 200:
            raise RuntimeError("unexpected status")
        payload = json.load(response)
    accounts = payload.get("accounts")
    if not isinstance(accounts, list):
        raise ValueError("malformed accounts response")
    connected = sum(isinstance(account, dict) and account.get("status") == "connected" for account in accounts)
    result = {
        "configured": bool(connected),
        "reason": "ready" if connected else "no-connected-account",
        "connected_account_count": connected,
    }
except Exception:
    pass
print(json.dumps(result, separators=(",", ":")))
'''

_VAST_EXPORTER_PREREQUISITE_UNAVAILABLE = {
    "configured": False,
    "reason": "unavailable",
    "connected_account_count": 0,
}


@dataclass(frozen=True)
class VPMServiceSpec:
    image: str
    allowed_host: str
    master_key_file: str = "/etc/dc-overview/secrets/vpm-master.key"
    expected_account_id: Optional[str] = None

    def __post_init__(self) -> None:
        if _PINNED_IMAGE.fullmatch(self.image) is None and _LOCAL_IMAGE_ID.fullmatch(self.image) is None:
            raise ValueError("VPM image must be an immutable image@sha256 pin or full local sha256 image ID")
        if _DNS_HOST.fullmatch(self.allowed_host) is None:
            raise ValueError("VPM container proxy requires one exact DNS hostname")
        key_path = Path(self.master_key_file)
        if not key_path.is_absolute() or "\n" in self.master_key_file or ":" in self.master_key_file:
            raise ValueError("VPM master key must be an absolute provisioned file path")
        if self.expected_account_id and _ACCOUNT_ID.fullmatch(self.expected_account_id) is None:
            raise ValueError("VPM expected account ID has invalid syntax")


@dataclass(frozen=True)
class VPMRenderedFiles:
    compose: str
    units: Dict[str, str]


class VPMServiceManager:
    """Operate only the VPM Compose project and its three timer pairs."""

    project_name = "vast-price-manager"
    container_name = "vast-price-manager"
    timer_names = (
        "vast-price-manager-sync.timer",
        "vast-price-manager-cycle.timer",
        "vast-price-manager-horizon.timer",
    )
    native_conflicts = ("vpm.service", "vpm-sync.timer", "vpm-cycle.timer", "vpm-horizon.timer")

    def __init__(
        self,
        config_dir: Path,
        runner: Callable = subprocess.run,
        *,
        unit_dir: Path = Path("/etc/systemd/system"),
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        health_timeout: float = 90,
        health_interval: float = 2,
    ):
        self.config_dir = Path(config_dir)
        self.root = self.config_dir / self.project_name
        self.compose_file = self.root / "docker-compose.yml"
        self.unit_dir = Path(unit_dir)
        self.runner = runner
        self.sleeper = sleeper
        self.monotonic = monotonic
        self.health_timeout = health_timeout
        self.health_interval = health_interval

    @classmethod
    def render(cls, spec: VPMServiceSpec) -> VPMRenderedFiles:
        expected_account = (
            f"      - VPM_EXPECTED_ACCOUNT_ID={spec.expected_account_id}\n"
            if spec.expected_account_id else ""
        )
        compose = f'''services:
  vast-price-manager:
    image: {spec.image}
    container_name: vast-price-manager
    user: "999:999"
    restart: unless-stopped
    environment:
      - VPM_DEPLOYMENT_MODE=container_proxy
      - VPM_BASE_PATH=/vast-pricing
      - VPM_ALLOWED_HOSTS={spec.allowed_host}
      - VPM_DATA_DIR=/data
      - VPM_CREDENTIAL_MASTER_KEY_FILE=/run/secrets/vpm-master.key
      - VPM_AUTH_MODE=fleet
      - VPM_FLEET_AUTH_URL=http://cryptolabs-proxy:8081
      - VPM_WRITES_ENABLED=false
{expected_account}    volumes:
      - vast-price-manager-data:/data
      - {spec.master_key_file}:/run/secrets/vpm-master.key:ro
    networks:
      - cryptolabs
networks:
  cryptolabs:
    external: true
volumes:
  vast-price-manager-data:
    name: vast-price-manager-data
'''
        units: Dict[str, str] = {}
        commands = {
            "sync": "vpm sync",
            "cycle": "vpm cycle --all",
            "horizon": "vpm reconcile-horizons",
        }
        for name, command in commands.items():
            timeout = "25min" if name in {"cycle", "horizon"} else "5min"
            units[f"vast-price-manager-{name}.service"] = f'''[Unit]
Description=Vast Price Manager {name}
After=docker.service

[Service]
Type=oneshot
TimeoutStartSec={timeout}
ExecStart=/usr/bin/docker exec vast-price-manager {command}
'''
            cadence = {"sync": "*:0/5", "cycle": "hourly", "horizon": "daily"}[name]
            jitter = "RandomizedDelaySec=30s\n" if name == "sync" else ""
            units[f"vast-price-manager-{name}.timer"] = f'''[Unit]
Description=Schedule Vast Price Manager {name}

[Timer]
OnCalendar={cadence}
{jitter}Persistent=true
Unit=vast-price-manager-{name}.service

[Install]
WantedBy=timers.target
'''
        return VPMRenderedFiles(compose=compose, units=units)

    @contextmanager
    def operation_lock(self):
        """Serialize all VPM lifecycle/configuration mutations per DC host."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.config_dir / "vast-price-manager.lock"
        with lock_path.open("a+") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _run(self, command, *, check: bool = True, timeout: float = 300):
        try:
            result = self.runner(command, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f"VPM lifecycle command timed out: {' '.join(command[:3])}") from error
        if check and result.returncode != 0:
            detail = (getattr(result, "stderr", "") or getattr(result, "stdout", "")).strip()
            raise RuntimeError(detail or "VPM lifecycle command failed")
        return result

    def _compose_prefix(self, compose_file: Optional[Path] = None):
        # BBmain has docker-compose standalone; prefer it where installed.
        executable = "docker-compose" if shutil.which("docker-compose") else "docker"
        prefix = [executable]
        if executable == "docker":
            prefix.append("compose")
        return prefix + ["-p", self.project_name, "-f", str(compose_file or self.compose_file)]

    def _assert_no_native_conflict(self) -> None:
        for unit in self.native_conflicts:
            if self._run(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0:
                raise RuntimeError(f"conflicting native VPM unit is active: {unit}")

    def _validate_master_key(self, spec: VPMServiceSpec) -> None:
        key = Path(spec.master_key_file)
        if not key.is_file():
            raise ValueError("VPM provisioned master-key file is missing")
        metadata = key.stat()
        mode = stat.S_IMODE(metadata.st_mode)
        owner_only = (
            metadata.st_uid == 999
            and bool(mode & stat.S_IRUSR)
            and not mode & 0o077
        )
        vpm_group_only = (
            metadata.st_gid == 999
            and bool(mode & stat.S_IRGRP)
            and not mode & 0o027
        )
        if not owner_only and not vpm_group_only:
            raise ValueError("VPM master key must be readable only by UID 999 or GID 999")

    def _ensure_exact_image_available(self, spec: VPMServiceSpec) -> None:
        """Resolve immutable references without substituting a different local image."""
        if _LOCAL_IMAGE_ID.fullmatch(spec.image) is not None:
            present = self._run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", spec.image],
                check=False,
            )
            if present.returncode != 0 or present.stdout.strip() != spec.image:
                raise RuntimeError("offline image missing: exact local immutable image ID is unavailable")
            return

        # Repository digest references preserve the existing inspect/pull
        # behavior. Unlike a local content ID, an absent repository image can
        # be fetched under its exact immutable reference.
        present = self._run(["docker", "image", "inspect", spec.image], check=False)
        if present.returncode != 0:
            self._run(["docker", "pull", spec.image])

    def vast_exporter_prerequisite(self) -> dict:
        """Return only whether the exporter has a connected Vast account.

        The authenticated accounts request runs inside the exporter so its
        management token and account fields never enter lifecycle output.
        """
        try:
            running = self._run(
                ["docker", "inspect", "-f", "{{.State.Running}}", "vastai-exporter"],
                check=False,
                timeout=10,
            )
        except Exception:
            return dict(_VAST_EXPORTER_PREREQUISITE_UNAVAILABLE)
        if running.returncode != 0 or running.stdout.strip().lower() != "true":
            return {
                "configured": False,
                "reason": "exporter-not-running",
                "connected_account_count": 0,
            }
        try:
            probe = self._run(
                ["docker", "exec", "vastai-exporter", "python3", "-c", _VAST_EXPORTER_PREREQUISITE_PROBE],
                check=False,
                timeout=15,
            )
            if probe.returncode != 0:
                return dict(_VAST_EXPORTER_PREREQUISITE_UNAVAILABLE)
            result = json.loads(probe.stdout)
        except Exception:
            return dict(_VAST_EXPORTER_PREREQUISITE_UNAVAILABLE)
        if (
            not isinstance(result, dict)
            or set(result) != {"configured", "reason", "connected_account_count"}
            or not isinstance(result["configured"], bool)
            or result["reason"] not in {"ready", "no-connected-account"}
            or not isinstance(result["connected_account_count"], int)
            or isinstance(result["connected_account_count"], bool)
            or result["connected_account_count"] < 0
        ):
            return dict(_VAST_EXPORTER_PREREQUISITE_UNAVAILABLE)
        if result["configured"] != (result["reason"] == "ready" and result["connected_account_count"] >= 1):
            return dict(_VAST_EXPORTER_PREREQUISITE_UNAVAILABLE)
        if not result["configured"] and result["connected_account_count"] != 0:
            return dict(_VAST_EXPORTER_PREREQUISITE_UNAVAILABLE)
        return result

    def _require_vast_exporter_for_first_install(self) -> None:
        if self.vast_exporter_prerequisite()["configured"]:
            return
        raise RuntimeError(
            "VPM requires a running Vast.ai exporter with at least one connected account. "
            "Set up Vast.ai Integration with an API key first."
        )

    def _has_existing_managed_vpm(self) -> bool:
        """Return whether the canonical Compose-managed VPM already exists.

        A leftover compose file is not installation evidence: a failed first
        install must still prove the exporter prerequisite before it can create
        a usable VPM container.
        """
        if not self.compose_file.is_file():
            return False
        try:
            container = self._run(
                [
                    "docker", "inspect", "-f",
                    '{{.Name}} {{index .Config.Labels "com.docker.compose.project"}}',
                    self.container_name,
                ],
                check=False,
                timeout=10,
            )
        except Exception:
            return False
        return (
            container.returncode == 0
            and container.stdout.strip() == f"/{self.container_name} {self.project_name}"
        )

    @property
    def service_names(self):
        return tuple(timer.removesuffix(".timer") + ".service" for timer in self.timer_names)

    def _timer_state(self):
        return {
            timer: {
                "enabled": self._run(["systemctl", "is-enabled", timer], check=False).returncode == 0,
                "active": self._run(["systemctl", "is-active", timer], check=False).returncode == 0,
            }
            for timer in self.timer_names
        }

    def _quiesce(self) -> None:
        self._run(["systemctl", "disable", "--now", *self.timer_names], check=False)
        self._run(["systemctl", "stop", *self.service_names], check=False)

    def _restore_timer_state(self, state) -> None:
        self._quiesce()
        for timer, prior in state.items():
            if prior["enabled"]:
                self._run(["systemctl", "enable", timer], check=False)
            if prior["active"]:
                self._run(["systemctl", "start", timer], check=False)

    def _install_units(self, rendered: VPMRenderedFiles) -> None:
        self.unit_dir.mkdir(parents=True, exist_ok=True)
        for name, content in rendered.units.items():
            (self.unit_dir / name).write_text(content)

    def _wait_for_health(self) -> None:
        deadline = self.monotonic() + self.health_timeout
        last_status = "unknown"
        while self.monotonic() <= deadline:
            result = self._run(
                ["docker", "inspect", "-f", "{{.State.Health.Status}}", self.container_name],
                check=False,
                timeout=10,
            )
            last_status = result.stdout.strip() or result.stderr.strip() or "unknown"
            if result.returncode == 0 and last_status == "healthy":
                return
            if last_status == "unhealthy":
                break
            self.sleeper(self.health_interval)
        raise RuntimeError(f"VPM container did not pass /healthz (last state: {last_status})")

    def install(self, spec: VPMServiceSpec, promote_route: Optional[Callable[[], None]] = None) -> None:
        self._validate_master_key(spec)
        self._assert_no_native_conflict()
        # The initial route/container creation is gated, while an already
        # installed VPM can still be updated or recovered during an exporter
        # outage without taking away existing access.
        if not self._has_existing_managed_vpm():
            self._require_vast_exporter_for_first_install()
        rendered = self.render(spec)
        old_compose = self.compose_file.read_text() if self.compose_file.exists() else None
        old_units = {
            name: (self.unit_dir / name).read_text()
            for name in rendered.units
            if (self.unit_dir / name).exists()
        }
        self.root.mkdir(parents=True, exist_ok=True)
        candidate_file = self.root / ".vpm-compose-candidate.yml"
        candidate_file.write_text(rendered.compose)
        try:
            # Parse the exact generated candidate before it can replace a project.
            self._run(self._compose_prefix(candidate_file) + ["config"])
            # Resolve the exact immutable image before quiescing a working project.
            self._ensure_exact_image_available(spec)
        finally:
            candidate_file.unlink(missing_ok=True)

        timer_state = self._timer_state()
        self._quiesce()
        self.compose_file.write_text(rendered.compose)
        self._install_units(rendered)
        try:
            self._run(["systemctl", "daemon-reload"])
            self._run(self._compose_prefix() + ["up", "-d"])
            self._wait_for_health()
            if promote_route is not None:
                promote_route()
            self._run(["systemctl", "enable", "--now", *self.timer_names])
        except Exception:
            self._run(self._compose_prefix() + ["stop"], check=False)
            if old_compose is not None:
                self.compose_file.write_text(old_compose)
            else:
                self._run(self._compose_prefix() + ["rm", "-f"], check=False)
                self.compose_file.unlink(missing_ok=True)
            for name in rendered.units:
                path = self.unit_dir / name
                if name in old_units:
                    path.write_text(old_units[name])
                else:
                    path.unlink(missing_ok=True)
            self._run(["systemctl", "daemon-reload"], check=False)
            if old_compose is not None:
                self._run(self._compose_prefix() + ["up", "-d"], check=False)
            self._restore_timer_state(timer_state)
            raise

    def stop(self) -> None:
        self._quiesce()
        self._run(self._compose_prefix() + ["stop"])

    def start(self) -> None:
        self._run(self._compose_prefix() + ["up", "-d"])
        self._wait_for_health()
        self._run(["systemctl", "enable", "--now", *self.timer_names])

    def logs(self, lines: int = 100) -> str:
        result = self._run(self._compose_prefix() + ["logs", "--tail", str(lines), "vast-price-manager"])
        return result.stdout + result.stderr

    def status(self) -> str:
        return self._run(["docker", "inspect", "-f", "{{.State.Status}} {{.State.Health.Status}}", self.container_name], check=False).stdout.strip()

    def enable_proxy_route(self) -> None:
        self._run([
            "cryptolabs-proxy", "register", "vast-price-manager", "vast-price-manager",
            "--path", "/vast-pricing/", "--port", "8088",
            "--display-name", "Vast Price Manager",
        ])

    def disable_proxy_route(self) -> None:
        self._run(["cryptolabs-proxy", "unregister", "vast-price-manager"])
