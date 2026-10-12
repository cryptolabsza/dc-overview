"""Scoped lifecycle support for the optional Vast Price Manager container."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import shlex
import tempfile
import threading
from dataclasses import replace
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional

from cryptography.fernet import Fernet

_PINNED_IMAGE = re.compile(r"^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$")
_LOCAL_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")

# The image this dc-overview release installs when the operator does not
# supply one: the public, cosign-signed VPM 0.3.2 release (tag v0.3.2).
DEFAULT_VPM_IMAGE = "ghcr.io/cryptolabsza/vast-price-manager@sha256:b99d1c88723e0182ca297725219ed65e603ed3fa939d1d8caa61b1417940e927"
_DNS_HOST = re.compile(
    r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
_ACCOUNT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_OWNER_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
# VPM images declare VOLUME /keys, but canonical custody lives under /run/secrets.
# Cover the unused parent explicitly so Docker cannot create persistent storage
# outside the declared data/key contract. Never infer anonymity from a volume name.
_KEYS_TMPFS_OPTIONS = "ro,nosuid,nodev,noexec,size=1048576"


def _reconcile_tmpfs_mounts(mounts: list, tmpfs: Optional[dict]) -> list:
    """Include HostConfig-only mounts and reject conflicting inspect metadata."""
    if not isinstance(mounts, list) or not all(isinstance(mount, dict) for mount in mounts):
        raise ValueError("malformed mounts")
    if tmpfs is None:
        tmpfs = {}
    if not isinstance(tmpfs, dict):
        raise ValueError("malformed tmpfs mounts")
    result = list(mounts)
    for target, options in tmpfs.items():
        _absolute_reference(target)
        if not isinstance(options, str) or not options:
            raise ValueError("malformed tmpfs options")
        parts = options.split(",")
        if len(set(parts)) != len(parts) or {"ro", "rw"} <= set(parts) or any(
            re.fullmatch(r"[a-zA-Z0-9_-]+(?:=[a-zA-Z0-9._/-]+)?", part) is None for part in parts
        ):
            raise ValueError("malformed tmpfs options")
        writable = "ro" not in parts
        existing = [mount for mount in result if mount["Destination"] == target]
        if len(existing) > 1:
            raise ValueError("duplicate tmpfs binding")
        if existing:
            mount = existing[0]
            if mount["Type"] != "tmpfs" or mount.get("Source") != "" or mount.get("Name") is not None or mount["RW"] is not writable:
                raise ValueError("conflicting tmpfs binding")
        else:
            result.append({"Type": "tmpfs", "Source": "", "Destination": target, "RW": writable})
    return result


def _canonical_persistent_mounts(mounts: list, tmpfs: Optional[dict]) -> list:
    """Validate the rendered /keys mask in both Docker inspection fields."""
    mounts = _reconcile_tmpfs_mounts(mounts, tmpfs)
    if tmpfs is None:
        tmpfs = {}
    if not isinstance(tmpfs, dict) or set(tmpfs) - {"/keys"}:
        raise ValueError("unknown tmpfs mount")
    if tmpfs:
        options = tmpfs["/keys"]
        if not isinstance(options, str) or sorted(options.split(",")) != sorted(_KEYS_TMPFS_OPTIONS.split(",")):
            raise ValueError("different tmpfs options")
    masks = [mount for mount in mounts if mount["Destination"] == "/keys"]
    # Engine versions may expose tmpfs via HostConfig.Tmpfs alone, or also Mounts.
    # HostConfig is required in either case; a destination alone is never trusted.
    if masks:
        if not tmpfs or len(masks) != 1:
            raise ValueError("ambiguous keys mask")
        mask = masks[0]
        if mask["Type"] != "tmpfs" or mask["RW"] is not False or mask.get("Source") != "" or mask.get("Name") is not None:
            raise ValueError("different keys mask")
    return [mount for mount in mounts if mount not in masks]


def _absolute_reference(value: str) -> None:
    if not isinstance(value, str) or not value.startswith("/") or any(
        part == ".." for part in value.split("/")
    ) or re.search(r"[\s\x00:,%]", value):
        raise ValueError("VPM reference must be a safe absolute path")


@dataclass(frozen=True)
class VPMLayout:
    """Declared non-secret ownership and bindings for an existing Compose service.

    Timer order is sync, cycle, horizon. The runtime key reference is the existing
    mount source; encrypted custody additionally declares its encrypted reference.
    The Compose service name scopes mutations in multi-service assembly files.
    """

    project_name: str
    container_name: str
    compose_file: str
    data_source: str
    data_kind: str
    master_key_file: str
    credential_mode: str = "file"
    credential_reference: Optional[str] = None
    data_target: str = "/data"
    database_relative_path: str = "vpm.sqlite3"
    service_name: str = "vast-price-manager"
    owner_unit: Optional[str] = None
    timer_names: tuple[str, ...] = (
        "vast-price-manager-sync.timer", "vast-price-manager-cycle.timer",
        "vast-price-manager-horizon.timer",
    )
    obsolete_auth_unit: Optional[str] = None
    retired_mount_targets: tuple[str, ...] = ()

    def __post_init__(self):
        for value in (self.project_name, self.container_name, self.service_name):
            if not isinstance(value, str) or _OWNER_NAME.fullmatch(value) is None:
                raise ValueError("VPM owner identity has invalid syntax")
        for value in (self.compose_file, self.master_key_file, self.data_target):
            _absolute_reference(value)
        if self.data_kind == "bind":
            _absolute_reference(self.data_source)
        elif self.data_kind != "volume" or _OWNER_NAME.fullmatch(self.data_source) is None:
            raise ValueError("VPM data binding must be a declared bind or named volume")
        if self.credential_mode not in {"file", "systemd-encrypted"}:
            raise ValueError("unsupported VPM credential custody")
        if self.credential_reference is not None:
            _absolute_reference(self.credential_reference)
        if self.credential_mode == "systemd-encrypted" and not self.credential_reference:
            raise ValueError("encrypted VPM custody requires its encrypted reference")
        if not self.database_relative_path or Path(self.database_relative_path).is_absolute() or any(
            part in {"..", "."} for part in self.database_relative_path.split("/")
        ) or re.search(r"[\s\x00]", self.database_relative_path):
            raise ValueError("VPM database must be within the declared data binding")
        units = (*self.timer_names, self.owner_unit, self.obsolete_auth_unit)
        present = [unit for unit in units if unit is not None]
        if len(self.timer_names) != 3 or len(set(present)) != len(present):
            raise ValueError("VPM owner identities must be unique, with three timers")
        if any(not timer.endswith(".timer") for timer in self.timer_names) or any(
            unit and not unit.endswith(".service") for unit in (self.owner_unit, self.obsolete_auth_unit)
        ):
            raise ValueError("VPM timers and service owners require their matching unit types")
        for unit in present:
            if _OWNER_NAME.fullmatch(unit) is None or not unit.endswith((".service", ".timer")):
                raise ValueError("VPM declared unit identity has invalid syntax")
        if len(set(self.retired_mount_targets)) != len(self.retired_mount_targets):
            raise ValueError("VPM retired mount targets must be unique")
        for target in self.retired_mount_targets:
            _absolute_reference(target)
            if target == self.data_target or target.startswith(self.data_target.rstrip("/") + "/") or self.data_target.startswith(target.rstrip("/") + "/") or target.startswith(("/run/secrets", "/run/credentials")):
                raise ValueError("VPM data/credential mounts cannot be retired")

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

_VPM_AUTOMATION_PAUSED_PROBE = r'''
import json
import sqlite3
from vast_price_manager.config import Settings

result = {"writes_enabled": False, "automation_paused": False}
try:
    settings = Settings.from_env()
    connection = sqlite3.connect(f"{settings.database_path.resolve().as_uri()}?mode=ro", uri=True)
    row = connection.execute(
        "SELECT automation_paused FROM settings WHERE singleton=1"
    ).fetchone()
    connection.close()
    if row is not None and type(row[0]) is int and row[0] == 1:
        result["automation_paused"] = True
    result["writes_enabled"] = settings.writes_enabled
except Exception:
    pass
print(json.dumps(result, separators=(",", ":")))
'''

_VPM_STOPPED_AUTOMATION_PAUSED_PROBE = r'''
import json
import os
import shutil
import sqlite3
from urllib.parse import quote

result = {"automation_paused": False}
connection = None
try:
    path = os.environ["VPM_FINAL_PAUSE_DB"]
    snapshot_dir = os.environ["VPM_FINAL_PAUSE_SNAPSHOT_DIR"]
    snapshot = os.path.join(snapshot_dir, "state.sqlite3")
    for suffix in ("", "-wal", "-shm"):
        source = path + suffix
        if suffix or os.path.isfile(source):
            if os.path.isfile(source):
                shutil.copyfile(source, snapshot + suffix)
    if not os.path.isfile(snapshot):
        raise RuntimeError("database snapshot is missing")
    connection = sqlite3.connect(
        "file:" + quote(snapshot, safe="/") + "?mode=ro", uri=True
    )
    row = connection.execute(
        "SELECT automation_paused FROM settings WHERE singleton=1"
    ).fetchone()
    result["automation_paused"] = bool(
        row is not None and type(row[0]) is int and row[0] == 1
    )
except Exception:
    pass
finally:
    if connection is not None:
        connection.close()
print(json.dumps(result, separators=(",", ":")))
'''

_VPM_PAUSE_PROBE_ENV = frozenset({"VPM_DATA_DIR", "VPM_DATABASE_PATH"})

# These bounded probes never print credentials, accounts, policies or environment
# values. Data/key fingerprints remain internal to the transaction; public results
# carry continuity booleans only. Import Settings, never Database (which migrates).
_VPM_CONTINUITY_PROBE = r'''
import hashlib
import json
import sqlite3
from cryptography.fernet import Fernet
from vast_price_manager.config import Settings

result = {"ok": False}
try:
    settings = Settings.from_env()
    connection = sqlite3.connect(settings.database_path.resolve().as_uri() + "?mode=ro", uri=True)
    schema = connection.execute("SELECT name, sql FROM sqlite_master WHERE type IN ('table','index') ORDER BY name").fetchall()
    tables = {name for name, _ in schema}
    if not {"settings", "policies", "credential_slots"}.issubset(tables):
        raise ValueError("unsupported state schema")
    selected = {}
    row = connection.execute("SELECT automation_paused, writes_enabled, account_id FROM settings WHERE singleton=1").fetchone()
    if row is None or row[0] not in (0, 1) or row[1] not in (0, 1):
        raise ValueError("unknown control state")
    if settings.expected_account_id and str(row[2]) != settings.expected_account_id:
        raise ValueError("account identity mismatch")
    authority = row[2]
    # Account identity is not a mutable policy/Pause/provider-slot control.
    # Compare every current-state account-bearing row, including setup_state.
    account_tables = ("settings", "setup_state", "policies", "credential_slots", "admin", "operators",
                      "storage_projection_settings", "volume_offer_capacity_settings", "machine_offer_settings",
                      "machine_maintenance", "machine_provider_maintenance", "listing_suppression", "maintenance_holds")
    for table in account_tables:
        if table in tables and "account_id" in {column[1] for column in connection.execute('PRAGMA table_info("' + table + '")')}:
            if any(value[0] != authority for value in connection.execute('SELECT account_id FROM "' + table + '"')):
                raise ValueError("inconsistent account authority")
    selected["settings"] = row
    for table in ("policies", "credential_slots", "setup_state", "admin", "operators",
                  "storage_projection_settings", "volume_offer_capacity_settings",
                  "machine_offer_settings", "machine_maintenance", "machine_provider_maintenance",
                  "listing_suppression", "maintenance_holds"):
        if table in tables:
            selected[table] = sorted(connection.execute('SELECT * FROM "' + table + '"').fetchall(), key=repr)
    key = settings.credential_master_key_file.read_bytes().strip()
    fernet = Fernet(key)
    ciphertexts = []
    credentials = settings.data_dir / "credentials"
    for path in sorted(credentials.glob("*.enc")):
        if path.is_symlink() or not path.is_file():
            raise ValueError("unsafe credential binding")
        cipher = path.read_bytes()
        fernet.decrypt(cipher)
        ciphertexts.append((path.name, hashlib.sha256(cipher).hexdigest()))
    for kind, slot in connection.execute("SELECT kind, slot FROM credential_slots WHERE active=1"):
        if kind not in ("reader", "writer") or slot not in ("a", "b") or not (credentials / (kind + '-' + slot + '.enc')).is_file():
            raise ValueError("active credential unavailable")
    connection.close()
    digest = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, default=repr).encode()).hexdigest()
    result = {"ok": True, "schema": digest(schema), "controls": digest(selected),
              "key": hashlib.sha256(key).hexdigest(), "ciphertexts": digest(ciphertexts),
              "expected_account": digest(settings.expected_account_id),
              "account_authority": digest(authority),
              "writes_enabled": settings.writes_enabled, "automation_paused": bool(row[0])}
except Exception:
    pass
print(json.dumps(result, separators=(",", ":")))
'''

_VPM_DATA_RECOVERY_PROGRAM = r'''
import json
import os
import shutil
import sqlite3
from pathlib import Path

try:
    data = Path(os.environ["VPM_RECOVERY_DATA"])
    root = Path(os.environ.get("VPM_RECOVERY_ROOT", "/recovery"))
    snapshot = root / "data"
    relative = os.environ["VPM_RECOVERY_DATABASE"]
    if os.environ["VPM_RECOVERY_ACTION"] == "backup":
        if any(path.is_symlink() for path in data.rglob("*")):
            raise ValueError("symlink in persistent state")
        shutil.copytree(data, snapshot)
        # copytree preserves modes/times, but not UID/GID. Recovery must preserve
        # VPM's UID 999 ownership rather than leaving root-owned restored files.
        for original in (data, *data.rglob("*")):
            copied = snapshot / original.relative_to(data)
            metadata = original.stat()
            os.chown(copied, metadata.st_uid, metadata.st_gid)
        source = sqlite3.connect((data / relative).resolve().as_uri() + "?mode=ro", uri=True)
        target = sqlite3.connect(snapshot / (relative + ".backup"))
        source.backup(target)
        if target.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ValueError("invalid snapshot")
        source.close()
        target.close()
        for suffix in ("", "-wal", "-shm"):
            (snapshot / (relative + suffix)).unlink(missing_ok=True)
        (snapshot / (relative + ".backup")).replace(snapshot / relative)
        metadata = (data / relative).stat()
        os.chown(snapshot / relative, metadata.st_uid, metadata.st_gid)
        os.chmod(snapshot / relative, metadata.st_mode & 0o777)
    else:
        if os.environ["VPM_RECOVERY_ACTION"] != "restore" or not (snapshot / relative).is_file():
            raise ValueError("invalid restoration")
        connection = sqlite3.connect((snapshot / relative).resolve().as_uri() + "?mode=ro", uri=True)
        if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ValueError("invalid snapshot")
        connection.close()
        for path in data.iterdir():
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()
        shutil.copytree(snapshot, data, dirs_exist_ok=True)
        for original in (snapshot, *snapshot.rglob("*")):
            restored = data / original.relative_to(snapshot)
            metadata = original.stat()
            os.chown(restored, metadata.st_uid, metadata.st_gid)
    print('{"ok":true}')
except Exception:
    print('{"ok":false}')
    raise SystemExit(1)
'''

_VPM_AUTH_BOUNDARY_PROBE = r'''
import json
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None
ok = False
try:
    opener = build_opener(ProxyHandler({}), NoRedirect())
    opener.open(Request("http://cryptolabs-proxy:8081/auth/vast-price-manager/session", headers={"Accept":"application/json"}), timeout=5)
except HTTPError as error:
    ok = error.code == 401
except Exception:
    pass
print(json.dumps({"auth_boundary":ok}, separators=(",", ":")))
'''


def create_master_key_if_missing(master_key_file: str) -> bool:
    """Create a Fernet VPM master key at ``master_key_file`` if none exists.

    Used only on the first-install path (fleet_manager._deploy_vast_price_manager
    -> VPMServiceManager.install); `vpm configure` and `vpm update` never call
    this. An existing key is never overwritten or rewritten -- doing so would
    make credentials already encrypted with it undecryptable -- and a lost
    O_EXCL race (another process created the file first) is treated the same
    as a pre-existing key.

    The key is written with mode 0o400 and owned by UID/GID 999 so it
    immediately satisfies VPMServiceManager._validate_master_key. The VPM
    container reads it with `.read_bytes().strip()` before constructing a
    Fernet instance, so a trailing newline would be tolerated, but none is
    written here.

    Returns True if this call created the key, False if a key already existed
    (including the lost-race case).
    """
    path = Path(master_key_file)
    if path.is_file():
        return False

    parent = path.parent
    if not parent.is_dir():
        parent.mkdir(parents=True, mode=0o700)
        os.chmod(parent, 0o700)  # enforce exact mode regardless of umask

    key = Fernet.generate_key()
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    except FileExistsError:
        # Another process won the race; that key is now the existing one.
        return False
    try:
        os.chmod(str(path), 0o400)  # enforce exact mode regardless of umask
        os.write(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chown(str(path), 999, 999)
    return True


@dataclass(frozen=True)
class VPMServiceSpec:
    image: str
    allowed_host: str
    master_key_file: str = "/etc/dc-overview/secrets/vpm-master.key"
    expected_account_id: Optional[str] = None
    writes_enabled: bool = False
    data_source: str = "vast-price-manager-data"
    data_kind: str = "volume"
    credential_mode: str = "file"
    credential_reference: Optional[str] = None
    database_relative_path: str = "vpm.sqlite3"

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
        if type(self.writes_enabled) is not bool:
            raise ValueError("VPM writes_enabled must be a boolean")
        VPMLayout(
            "vast-price-manager", "vast-price-manager", "/etc/dc-overview/vpm.yml",
            self.data_source, self.data_kind, self.master_key_file,
            credential_mode=self.credential_mode,
            credential_reference=self.credential_reference,
            database_relative_path=self.database_relative_path,
        )


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
        self._operation_mutex = threading.RLock()
        self._operation_depth = 0

    @classmethod
    def render(cls, spec: VPMServiceSpec) -> VPMRenderedFiles:
        expected_account = (
            f"      - VPM_EXPECTED_ACCOUNT_ID={spec.expected_account_id}\n"
            if spec.expected_account_id else ""
        )
        key_source = (
            "/run/credentials/vast-price-manager-container.service/vpm-master.key"
            if spec.credential_mode == "systemd-encrypted" else spec.master_key_file
        )
        external = "    external: true\n" if spec.data_source != "vast-price-manager-data" else ""
        volumes = (
            f"volumes:\n  vast-price-manager-data:\n{external}    name: {spec.data_source}\n"
            if spec.data_kind == "volume" else ""
        )
        data_source = "vast-price-manager-data" if spec.data_kind == "volume" else spec.data_source
        compose = f'''services:
  vast-price-manager:
    image: {spec.image}
    container_name: vast-price-manager
    user: "999:999"
    restart: unless-stopped
    labels:
      com.centurylinklabs.watchtower.enable: "false"
    environment:
      - VPM_DEPLOYMENT_MODE=container_proxy
      - VPM_BASE_PATH=/vast-pricing
      - VPM_ALLOWED_HOSTS={spec.allowed_host}
      - VPM_DATA_DIR=/data
      - VPM_DATABASE_PATH=/data/{spec.database_relative_path}
      - VPM_CREDENTIAL_MASTER_KEY_FILE=/run/secrets/vpm-master.key
      - VPM_AUTH_MODE=fleet
      - VPM_FLEET_AUTH_URL=http://cryptolabs-proxy:8081
      - VPM_WRITES_ENABLED={str(spec.writes_enabled).lower()}
{expected_account}    volumes:
      - {data_source}:/data
      - {key_source}:/run/secrets/vpm-master.key:ro
    tmpfs:
      - /keys:{_KEYS_TMPFS_OPTIONS}
    networks:
      - cryptolabs
networks:
  cryptolabs:
    external: true
{volumes}'''
        units: Dict[str, str] = {}
        if spec.credential_mode == "systemd-encrypted":
            units["vast-price-manager-container.service"] = f'''[Unit]
Description=Vast Price Manager encrypted credential container owner
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=999
Group=999
SupplementaryGroups=docker
LoadCredentialEncrypted=vpm-master.key:{spec.credential_reference}
ExecStart=/usr/bin/docker compose -p vast-price-manager -f @VPM_COMPOSE_FILE@ up -d
ExecStop=/usr/bin/docker compose -p vast-price-manager -f @VPM_COMPOSE_FILE@ stop

[Install]
WantedBy=multi-user.target
'''
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
        with self._operation_mutex:
            if self._operation_depth:
                self._operation_depth += 1
                try:
                    yield
                finally:
                    self._operation_depth -= 1
                return
            self.config_dir.mkdir(parents=True, exist_ok=True)
            lock_path = self.config_dir / "vast-price-manager.lock"
            with lock_path.open("a+") as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                self._operation_depth = 1
                try:
                    yield
                finally:
                    self._operation_depth = 0
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
        if spec.credential_mode == "systemd-encrypted":
            reference = Path(spec.credential_reference)
            if not reference.is_file() or reference.is_symlink():
                raise ValueError("VPM encrypted credential reference is missing or unsafe")
            metadata = reference.stat()
            if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077:
                raise ValueError("VPM encrypted credential reference must be root-owned and private")
            return
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

    def current_managed_image(self) -> Optional[str]:
        """Return the immutable image of the existing managed container only."""
        if not self._has_existing_managed_vpm():
            return None
        try:
            result = self._run(
                ["docker", "inspect", "-f", "{{.Config.Image}}", self.container_name],
                check=False,
                timeout=10,
            )
        except Exception:
            return None
        image = result.stdout.strip() if result.returncode == 0 else ""
        if _PINNED_IMAGE.fullmatch(image) is None and _LOCAL_IMAGE_ID.fullmatch(image) is None:
            return None
        return image

    def managed_runtime_state(self) -> Optional[dict]:
        """Read only VPM's process capability and persisted pause state.

        No environment values are returned: the in-container probe emits only
        two booleans. Missing or malformed state is unknown and therefore
        unsafe for a write-capability transition.
        """
        if not self._has_existing_managed_vpm():
            return None
        try:
            result = self._run(
                ["docker", "exec", self.container_name, "python3", "-c", _VPM_AUTOMATION_PAUSED_PROBE],
                check=False,
                timeout=10,
            )
            payload = json.loads(result.stdout) if result.returncode == 0 else None
        except Exception:
            return None
        if (
            not isinstance(payload, dict)
            or set(payload) != {"writes_enabled", "automation_paused"}
            or type(payload["writes_enabled"]) is not bool
            or type(payload["automation_paused"]) is not bool
        ):
            return None
        return payload

    def persistent_automation_paused(self) -> bool:
        """Compatibility helper for callers that require the positive pause proof."""
        state = self.managed_runtime_state()
        return state is not None and state["automation_paused"] is True

    def _stopped_managed_database_path(self) -> Optional[str]:
        """Read only the database-path inputs needed for an offline Pause proof."""
        try:
            result = self._run(
                [
                    "docker", "inspect", "-f",
                    '{{range .Config.Env}}{{if or '
                    '(eq (index (split . "=") 0) "VPM_DATA_DIR") '
                    '(eq (index (split . "=") 0) "VPM_DATABASE_PATH")}}'
                    '{{println .}}{{end}}{{end}}',
                    self.container_name,
                ],
                check=False,
                timeout=10,
            )
        except Exception:
            return None
        if result.returncode != 0:
            return None
        values: dict[str, str] = {}
        for line in result.stdout.splitlines():
            key, separator, value = line.partition("=")
            if key not in _VPM_PAUSE_PROBE_ENV:
                continue
            if not separator or key in values:
                return None
            values[key] = value
        data_dir = values.get("VPM_DATA_DIR", "/var/lib/vast-price-manager")
        database_path = values.get("VPM_DATABASE_PATH", f"{data_dir}/vpm.sqlite3")
        if (
            not database_path.startswith("/")
            or len(database_path) > 4096
            or any(character in database_path for character in ("\x00", "\n", "\r"))
        ):
            return None
        return database_path

    def _stopped_persistent_automation_paused(self, image: str) -> bool:
        """Prove Pause from a stopped managed container without app startup or network."""
        database_path = self._stopped_managed_database_path()
        if database_path is None:
            return False
        try:
            result = self._run(
                [
                    "docker", "run", "--rm", "--network", "none", "--read-only",
                    "--volumes-from", f"{self.container_name}:ro",
                    "--tmpfs", "/probe:rw,nosuid,nodev,noexec,size=64m",
                    "--entrypoint", "python3",
                    "--env", "PYTHONDONTWRITEBYTECODE=1",
                    "--env", f"VPM_FINAL_PAUSE_DB={database_path}",
                    "--env", "VPM_FINAL_PAUSE_SNAPSHOT_DIR=/probe",
                    image, "-c", _VPM_STOPPED_AUTOMATION_PAUSED_PROBE,
                ],
                check=False,
                timeout=15,
            )
            payload = json.loads(result.stdout) if result.returncode == 0 else None
        except Exception:
            return False
        return (
            isinstance(payload, dict)
            and set(payload) == {"automation_paused"}
            and type(payload["automation_paused"]) is bool
            and payload["automation_paused"] is True
        )

    @staticmethod
    def _disabled_rollback_compose(compose: str, image: str) -> Optional[str]:
        """Keep a failed capability transition on the exact prior image with writes off."""
        image_matches = list(re.finditer(r"(?m)^    image: .+$", compose))
        write_matches = list(
            re.finditer(r"(?m)^(\s*- VPM_WRITES_ENABLED=)(?:true|false)\s*$", compose)
        )
        if len(image_matches) != 1 or len(write_matches) != 1:
            return None
        restored = re.sub(r"(?m)^    image: .+$", f"    image: {image}", compose, count=1)
        return re.sub(
            r"(?m)^(\s*- VPM_WRITES_ENABLED=)(?:true|false)\s*$",
            r"\1false",
            restored,
            count=1,
        )

    def _restore_after_final_pause_failure(
        self, old_compose: Optional[str], old_image: str, timer_state: dict
    ) -> Optional[str]:
        if old_compose is None:
            return "previous managed Compose file is unavailable"
        rollback_compose = self._disabled_rollback_compose(old_compose, old_image)
        if rollback_compose is None:
            return "previous managed Compose file cannot be restored with process writes disabled"
        try:
            self.compose_file.write_text(rollback_compose)
            self._run(self._compose_prefix() + ["up", "-d"])
            self._restore_timer_state(timer_state)
        except Exception as error:
            return str(error) or "previous project restoration failed"
        return None

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

    def _quiesce(self, *, check: bool = False) -> None:
        self._run(["systemctl", "disable", "--now", *self.timer_names], check=check)
        self._run(["systemctl", "stop", *self.service_names], check=check)

    def _restore_timer_state(self, state) -> None:
        self._quiesce()
        for timer, prior in state.items():
            self._restore_unit_state(timer, prior)

    def _unit_state(self, name: str) -> dict:
        enabled = self._run(["systemctl", "is-enabled", name], check=False)
        active = self._run(["systemctl", "is-active", name], check=False)
        if enabled.returncode not in {0, 1} or active.returncode not in {0, 3}:
            raise RuntimeError("VPM unit state cannot be verified")
        return {"enabled": enabled.returncode == 0, "active": active.returncode == 0}

    def _restore_unit_state(self, name: str, prior: dict) -> None:
        self._run(["systemctl", "enable" if prior["enabled"] else "disable", name])
        self._run(["systemctl", "start" if prior["active"] else "stop", name])
        if self._unit_state(name) != prior:
            raise RuntimeError("VPM restored unit state cannot be verified")

    @staticmethod
    def _write_adoption_marker(marker: Path, content: dict) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=".adoption-marker-", dir=marker.parent)
        candidate = Path(temporary)
        try:
            with os.fdopen(descriptor, "w") as handle:
                os.fchmod(handle.fileno(), 0o600)
                json.dump(content, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            if marker.exists() or marker.is_symlink():
                raise RuntimeError("VPM adoption marker changed during transfer")
            os.replace(candidate, marker)
        finally:
            candidate.unlink(missing_ok=True)

    def _install_units(self, rendered: VPMRenderedFiles) -> None:
        self.unit_dir.mkdir(parents=True, exist_ok=True)
        for name, content in rendered.units.items():
            (self.unit_dir / name).write_text(self._unit_content(name, content))

    def _unit_content(self, name: str, content: str) -> str:
        content = content.replace("@VPM_COMPOSE_FILE@", shlex.quote(str(self.compose_file)))
        if name == "vast-price-manager-container.service":
            prefix = self._compose_prefix()
            prefix[0] = shutil.which(prefix[0]) or "/usr/bin/" + prefix[0]
            old = "/usr/bin/docker compose -p vast-price-manager -f " + shlex.quote(str(self.compose_file))
            content = content.replace("ExecStart=" + old, "ExecStart=" + shlex.join(prefix))
            content = content.replace("ExecStop=" + old, "ExecStop=" + shlex.join(prefix))
        return content

    def _effective_units(self, names, *, required=()) -> dict:
        """Inspect loaded ownership, including inactive/runtime/vendor overrides.

        No layout currently declares drop-ins or aliases. Keep them untouched and
        refuse transfer rather than infer ownership from a writable base file.
        """
        result = {}
        properties = "Id,Names,LoadState,FragmentPath,DropInPaths,NeedDaemonReload,ActiveState,UnitFileState,ExecStart,ExecStop,Triggers,User,Group,SupplementaryGroups,LoadCredentialEncrypted"
        for name in sorted(set(names)):
            response = self._run(["systemctl", "show", name, "--property=" + properties, "--no-pager"], check=False)
            if response.returncode != 0:
                raise RuntimeError("VPM effective unit ownership inspection failed")
            values = dict(line.split("=", 1) for line in response.stdout.splitlines() if "=" in line)
            if values.get("Id") != name or set(values.get("Names", "").split()) != {name}:
                raise RuntimeError("VPM effective unit alias ownership is undeclared")
            if values.get("DropInPaths") or any((self.unit_dir / (name + ".d")).glob("*.conf")):
                raise RuntimeError("VPM effective unit drop-in ownership is undeclared")
            if values.get("NeedDaemonReload") != "no":
                raise RuntimeError("VPM effective unit ownership requires review of pending daemon reload")
            fragment = values.get("FragmentPath", "")
            load = values.get("LoadState")
            path = self.unit_dir / name
            if load == "not-found" and not fragment and not path.exists():
                if name in required:
                    raise RuntimeError("declared VPM source unit fragment is missing")
            elif load != "loaded" or fragment != str(path) or path.is_symlink() or not path.is_file():
                raise RuntimeError("VPM effective unit fragment ownership differs from declaration")
            result[name] = values
        return result

    def _credential_references(self, name: str) -> dict:
        """Read typed reference metadata; systemctl renders even empty loads unprintable."""
        destination = "org.freedesktop.systemd1"

        def read(command, signature):
            response = self._run(command, check=False, timeout=10)
            try:
                if response.returncode != 0 or len(response.stdout) > 65536:
                    raise ValueError("unavailable")
                value = json.loads(response.stdout)
                if (not isinstance(value, dict) or set(value) != {"type", "data"}
                        or value["type"] != signature or not isinstance(value["data"], list)
                        or len(value["data"]) > 32):
                    raise ValueError("invalid metadata")
                return value["data"]
            except (ValueError, TypeError):
                raise RuntimeError("VPM structured credential custody metadata cannot be verified") from None

        paths = read(["busctl", "--json=short", "call", destination,
            "/org/freedesktop/systemd1", destination + ".Manager", "LoadUnit", "s", name], "o")
        if (len(paths) != 1 or not isinstance(paths[0], str)
                or re.fullmatch(r"/org/freedesktop/systemd1/unit/[A-Za-z0-9_]{1,1024}", paths[0]) is None):
            raise RuntimeError("VPM structured credential custody unit identity is invalid")
        references = {}
        for key, signature in (("LoadCredential", "a(ss)"),
                               ("LoadCredentialEncrypted", "a(ss)"), ("ImportCredential", "as")):
            rows = read(["busctl", "--json=short", "get-property", destination,
                paths[0], destination + ".Service", key], signature)
            for row in rows:
                strings = row if signature == "a(ss)" else [row]
                if (not isinstance(strings, list) or len(strings) != (2 if signature == "a(ss)" else 1)
                        or any(not isinstance(value, str) or not value or len(value) > 4096
                               or any(character in value for character in "\x00\r\n") for value in strings)):
                    raise RuntimeError("VPM structured credential custody references are invalid")
            references[key] = rows
        return references

    def _verify_loaded_product_units(self, rendered: VPMRenderedFiles, *, allow_missing=False) -> None:
        canonical = {*self.timer_names, *self.service_names, "vast-price-manager-container.service"}
        effective = self._effective_units(set(rendered.units) | canonical,
            required=() if allow_missing else rendered.units)
        for name in canonical - set(rendered.units):
            if effective[name].get("LoadState") != "not-found":
                raise RuntimeError("VPM canonical lifecycle ownership is undeclared by generated owner")
        for name, content in rendered.units.items():
            values = effective[name]
            if allow_missing and values["LoadState"] == "not-found":
                continue
            expected = self._unit_content(name, content)
            for key in ("ExecStart", "ExecStop"):
                declared = re.findall(r"(?m)^" + key + r"=(.*)$", expected)
                actual = re.findall(r"argv\[\]=([^;]+)\s*;", values.get(key, ""))
                if [shlex.split(value) for value in actual] != [shlex.split(value) for value in declared]:
                    raise RuntimeError("VPM loaded product executable ownership differs from generated owner")
            if name.endswith(".timer") and values.get("Triggers", "").split() != [name.removesuffix(".timer") + ".service"]:
                raise RuntimeError("VPM loaded product timer service ownership differs from generated owner")
            if name.endswith(".service"):
                custody = self._credential_references(name)
                declared = re.findall(r"(?m)^LoadCredentialEncrypted=(.*)$", expected)
                expected_encrypted = [value.split(":", 1) for value in declared]
                if (custody["LoadCredential"] or custody["ImportCredential"]
                        or custody["LoadCredentialEncrypted"] != expected_encrypted):
                    raise RuntimeError("VPM loaded product credential custody differs from generated owner")
            if name == "vast-price-manager-container.service":
                for key in ("User", "Group", "SupplementaryGroups"):
                    declared = re.search(r"(?m)^" + key + r"=(.*)$", expected)
                    if declared is None or values.get(key) != declared[1]:
                        raise RuntimeError("VPM loaded encrypted credential owner custody differs from declaration")
            elif name.endswith(".service") and any(values.get(key) for key in ("User", "Group", "SupplementaryGroups")):
                raise RuntimeError("VPM loaded product execution user ownership differs from generated owner")

    @staticmethod
    def _preserve_timer_settings(content: str, product: str, service: str) -> str:
        """Carry supported timing settings into a fixed product-owned timer."""
        allowed = {
            "OnCalendar", "OnActiveSec", "OnBootSec", "OnStartupSec", "OnUnitActiveSec",
            "OnUnitInactiveSec", "AccuracySec", "RandomizedDelaySec", "RandomizedOffsetSec",
            "FixedRandomDelay", "Persistent", "WakeSystem", "RemainAfterElapse", "DeferReactivation",
        }
        settings = []
        section = ""
        seen_timer = 0
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                section = stripped
                if section == "[Timer]":
                    seen_timer += 1
                continue
            if section != "[Timer]" or not stripped or stripped.startswith(("#", ";")):
                continue
            key, separator, value = stripped.partition("=")
            if not separator or key not in allowed | {"Unit"} or "\\" in value:
                raise RuntimeError("VPM timer contains unsupported timing configuration")
            if key != "Unit":
                settings.append(stripped)
        if seen_timer != 1:
            raise RuntimeError("VPM timer has ambiguous timing configuration")
        timer_section = "[Timer]\n" + "\n".join(settings) + "\nUnit=" + service + "\n\n"
        return re.sub(r"(?ms)^\[Timer\]\n.*?(?=^\[|\Z)", lambda _: timer_section, product)

    def _launch(self, spec: VPMServiceSpec) -> None:
        if spec.credential_mode == "systemd-encrypted":
            self._run(["systemctl", "restart", "vast-price-manager-container.service"])
        else:
            self._run(self._compose_prefix() + ["up", "-d"])

    def _hold_candidate_for_forward_repair(self) -> list[str]:
        """Leave the rendered candidate in place without any VPM work running."""
        failures = []
        commands = [
            ("candidate stop", self._compose_prefix() + ["stop"]),
            ("timer disable", ["systemctl", "disable", "--now", *self.timer_names]),
            ("oneshot stop", ["systemctl", "stop", *self.service_names]),
        ]
        if (self.unit_dir / "vast-price-manager-container.service").is_file():
            commands.append(("credential owner disable", ["systemctl", "disable", "--now", "vast-price-manager-container.service"]))
        for label, command in commands:
            try:
                result = self._run(command, check=False)
                if result.returncode != 0:
                    detail = (result.stderr or result.stdout).strip()
                    failures.append(f"{label}: {detail or f'exit {result.returncode}'}")
            except (RuntimeError, OSError) as cleanup_error:
                failures.append(f"{label}: {cleanup_error}")
        return failures

    def _wait_for_health(self, container_name: Optional[str] = None) -> None:
        deadline = self.monotonic() + self.health_timeout
        last_status = "unknown"
        while self.monotonic() <= deadline:
            result = self._run(
                ["docker", "inspect", "-f", "{{.State.Health.Status}}", container_name or self.container_name],
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

    def inspect_layout(self, layout: VPMLayout) -> dict:
        """Validate a declared layout using bounded identity/mount metadata only."""
        return self._inspect_layout(layout)

    @staticmethod
    def _layout_units(layout: VPMLayout) -> set:
        return {name for name in (layout.owner_unit, layout.obsolete_auth_unit, *layout.timer_names,
            *(timer.removesuffix(".timer") + ".service" for timer in layout.timer_names)) if name}

    def _inspect_layout(self, layout: VPMLayout, *, retired_units=(), canonical_mounts=False) -> dict:
        if not Path(layout.compose_file).is_file():
            raise RuntimeError("declared VPM Compose owner file is missing")
        inventory = self._run([
            "docker", "ps", "-a", "--filter", f"label=com.docker.compose.service={layout.service_name}",
            "--format", "{{.Names}}",
        ])
        owners = inventory.stdout.split()
        if owners != [layout.container_name]:
            raise RuntimeError("unknown or duplicate VPM container owners; adoption refused")
        metadata = self._run([
            "docker", "inspect", "-f",
            '{"name":{{json .Name}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
            '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
            '"image":{{json .Config.Image}},"mounts":{{json .Mounts}},"tmpfs":{{json .HostConfig.Tmpfs}}}',
            layout.container_name,
        ])
        try:
            info = json.loads(metadata.stdout)
            if info["name"] != "/" + layout.container_name or info["project"] != layout.project_name or info["service"] != layout.service_name:
                raise ValueError("identity")
            image = info["image"]
            if not (_PINNED_IMAGE.fullmatch(image) or _LOCAL_IMAGE_ID.fullmatch(image)):
                raise ValueError("mutable image")
            mounts = info["mounts"]
            if canonical_mounts:
                mounts = _canonical_persistent_mounts(mounts, info["tmpfs"])
            else:
                mounts = _reconcile_tmpfs_mounts(mounts, info["tmpfs"])
            data = [mount for mount in mounts if mount["Destination"] == layout.data_target]
            keys = [mount for mount in mounts if mount["Source"] == layout.master_key_file]
            if len(data) != 1 or len(keys) != 1 or keys[0]["RW"] is not False:
                raise ValueError("ambiguous binding")
            if canonical_mounts and (keys[0]["Type"] != "bind" or keys[0]["Destination"] != "/run/secrets/vpm-master.key"):
                raise ValueError("canonical key binding")
            source = data[0].get("Name") if layout.data_kind == "volume" else data[0]["Source"]
            if data[0]["Type"] != layout.data_kind or source != layout.data_source or data[0]["RW"] is not True:
                raise ValueError("data binding")
            # Extra executable/data mounts cannot silently enter the new owner.
            extra = [mount for mount in mounts if mount not in data and mount not in keys]
            if {mount["Destination"] for mount in extra} != set(layout.retired_mount_targets) or len(extra) != len(layout.retired_mount_targets):
                raise ValueError("undeclared mount")
        except (KeyError, TypeError, ValueError):
            raise RuntimeError("VPM identity, immutable image or custody binding does not match declaration") from None
        declared = self._layout_units(layout)
        canonical = {*self.timer_names, *self.service_names, "vast-price-manager-container.service"}
        effective = self._effective_units(declared | canonical | set(retired_units), required=declared)
        for timer in layout.timer_names:
            worker = timer.removesuffix(".timer") + ".service"
            if effective[timer].get("Triggers", "").split() != [worker]:
                raise RuntimeError("VPM declared timer service ownership differs from declared worker")
        for name in canonical - declared:
            if effective[name].get("LoadState") != "not-found":
                raise RuntimeError("VPM canonical lifecycle ownership is undeclared")
        for name in (canonical - declared) | set(retired_units):
            if effective[name].get("ActiveState") not in {"inactive", "failed"}:
                raise RuntimeError("unknown or duplicate active VPM effective lifecycle ownership")
        units = self._run([
            "systemctl", "list-units", "--all", "--type=service,timer",
            "--no-legend", "--plain",
        ])
        files = self._run(["systemctl", "list-unit-files", "--type=service,timer", "--no-legend", "--no-pager"])
        for line in (units.stdout + '\n' + files.stdout).splitlines():
            unit = line.split()[0] if line.split() else ""
            if (unit.startswith(("vpm", "vast-price-manager")) or unit in self.native_conflicts) and unit not in declared | canonical | set(retired_units):
                raise RuntimeError("unknown or duplicate VPM lifecycle owner; adoption refused")
        return {
            "project_name": layout.project_name, "container_name": layout.container_name,
            "image": image, "data_kind": layout.data_kind, "data_source": layout.data_source,
            "credential_mode": layout.credential_mode, "owner_unit": layout.owner_unit,
            "timer_names": list(layout.timer_names), "ownership_verified": True,
            "retired_mount_targets": list(layout.retired_mount_targets),
        }

    def _continuity(self, container_name: Optional[str] = None) -> dict:
        result = self._run([
            "docker", "exec", container_name or self.container_name, "python3", "-c", _VPM_CONTINUITY_PROBE,
        ], check=False, timeout=30)
        try:
            proof = json.loads(result.stdout)
            if result.returncode != 0 or set(proof) != {
                "ok", "schema", "controls", "key", "ciphertexts", "expected_account", "account_authority", "writes_enabled", "automation_paused"
            } or proof["ok"] is not True:
                raise ValueError("unavailable")
            if any(not isinstance(proof[name], str) or re.fullmatch(r"[0-9a-f]{64}", proof[name]) is None
                   for name in ("schema", "controls", "key", "ciphertexts", "expected_account", "account_authority")):
                raise ValueError("invalid fingerprint")
            if any(type(proof[name]) is not bool for name in ("writes_enabled", "automation_paused")):
                raise ValueError("invalid controls")
        except (ValueError, TypeError):
            raise RuntimeError("VPM account, policy, Pause or credential continuity cannot be verified") from None
        return proof

    def _verify_auth_boundary(self) -> bool:
        """Check the fixed Fleet auth endpoint rejects unauthenticated callers.

        Normal authenticated operator acceptance remains a deployment gate. This
        request uses no session or provider credential and cannot authorize writes.
        """
        result = self._run([
            "docker", "exec", self.container_name, "python3", "-c", _VPM_AUTH_BOUNDARY_PROBE,
        ], check=False, timeout=10)
        try:
            return result.returncode == 0 and json.loads(result.stdout) == {"auth_boundary": True}
        except (ValueError, TypeError):
            return False

    def _data_recovery(self, spec: VPMServiceSpec, recovery: Path, action: str) -> None:
        mount = f"{spec.data_source}:/state" + (":ro" if action == "backup" else "")
        result = self._run([
            "docker", "run", "--rm", "--network", "none", "--read-only", "--user", "0:0",
            "--volume", mount, "--volume", f"{recovery}:/recovery",
            "--entrypoint", "python3", "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--env", "VPM_RECOVERY_DATA=/state", "--env", f"VPM_RECOVERY_ACTION={action}",
            "--env", f"VPM_RECOVERY_DATABASE={spec.database_relative_path}",
            spec.image, "-c", _VPM_DATA_RECOVERY_PROGRAM,
        ], check=False, timeout=300)
        try:
            successful = result.returncode == 0 and json.loads(result.stdout) == {"ok": True}
        except (ValueError, TypeError):
            successful = False
        if not successful:
            raise RuntimeError(f"VPM consistent data {action} failed; recovery is unverified")

    def _assert_data_binding(self, spec: VPMServiceSpec) -> None:
        """Reject stale config that would replace an existing data/key binding."""
        result = self._run(["docker", "inspect", "-f",
            '{"mounts":{{json .Mounts}},"tmpfs":{{json .HostConfig.Tmpfs}}}', self.container_name])
        try:
            info = json.loads(result.stdout)
            mounts = _canonical_persistent_mounts(info["mounts"], info["tmpfs"])
            data = [mount for mount in mounts if mount["Destination"] == "/data"]
            keys = [mount for mount in mounts if mount["Destination"] == "/run/secrets/vpm-master.key"]
            expected_key = (
                "/run/credentials/vast-price-manager-container.service/vpm-master.key"
                if spec.credential_mode == "systemd-encrypted" else spec.master_key_file
            )
            if len(data) != 1 or len(keys) != 1 or len(mounts) != 2:
                raise ValueError("ambiguous binding")
            source = data[0].get("Name") if spec.data_kind == "volume" else data[0]["Source"]
            if data[0]["Type"] != spec.data_kind or source != spec.data_source or data[0]["RW"] is not True or keys[0]["Type"] != "bind" or keys[0]["Source"] != expected_key or keys[0]["RW"] is not False:
                raise ValueError("different binding")
        except (KeyError, TypeError, ValueError):
            raise RuntimeError("existing VPM data/key binding differs from declared config; use adoption") from None

    def _new_recovery_path(self, prefix: str) -> Path:
        recovery_root = self.root / "recovery"
        recovery_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(recovery_root, 0o700)
        return Path(tempfile.mkdtemp(prefix=prefix, dir=recovery_root))

    @staticmethod
    def _adoption_spec(spec: VPMServiceSpec, layout: VPMLayout) -> VPMServiceSpec:
        return replace(
            spec, data_source=layout.data_source, data_kind=layout.data_kind,
            master_key_file=layout.master_key_file, credential_mode=layout.credential_mode,
            credential_reference=layout.credential_reference,
            database_relative_path=layout.database_relative_path,
        )

    @staticmethod
    def adopted_spec(spec: VPMServiceSpec, layout: VPMLayout) -> VPMServiceSpec:
        """Public config handoff: persist the canonical runtime custody reference."""
        target = VPMServiceManager._adoption_spec(spec, layout)
        if target.credential_mode == "systemd-encrypted":
            target = replace(target, master_key_file="/run/credentials/vast-price-manager-container.service/vpm-master.key")
        return target

    def plan_adoption(self, spec: VPMServiceSpec, layout: VPMLayout) -> dict:
        """Return a sanitized plan; this method never changes runtime state."""
        inventory = self.inspect_layout(layout)
        proof = self._continuity(layout.container_name)
        if spec.writes_enabled != proof["writes_enabled"]:
            raise RuntimeError("adoption must preserve existing process write capability")
        expected_account = hashlib.sha256(json.dumps(spec.expected_account_id).encode()).hexdigest()
        if proof["expected_account"] != expected_account:
            raise RuntimeError("adoption must preserve existing expected account authority")
        if layout.obsolete_auth_unit and not layout.owner_unit:
            raise RuntimeError("obsolete auth retirement requires a declared lifecycle owner")
        if layout.obsolete_auth_unit:
            consumers = self._run([
                "systemctl", "list-dependencies", "--reverse", "--plain", "--no-legend",
                layout.obsolete_auth_unit,
            ])
            allowed = {layout.obsolete_auth_unit, layout.owner_unit,
                       "multi-user.target", "graphical.target", "default.target"}
            if any(line.split()[0] not in allowed for line in consumers.stdout.splitlines() if line.split()):
                raise RuntimeError("obsolete VPM auth dependency has unknown/shared consumers")
        return {
            "source": inventory, "target_project": self.project_name,
            "target_image": spec.image, "credential_mode": layout.credential_mode,
            "writes_enabled": proof["writes_enabled"], "automation_paused": proof["automation_paused"],
            "schema_recovery": "consistent-snapshot-required", "activate_automation": False,
            "retire_auth_unit_after_proof": layout.obsolete_auth_unit,
        }

    @staticmethod
    def _source_identity(layout: VPMLayout) -> list:
        return [layout.project_name, layout.container_name, layout.compose_file,
                layout.data_kind, layout.data_source, layout.credential_mode,
                layout.credential_reference, layout.master_key_file, layout.owner_unit,
                list(layout.timer_names), layout.obsolete_auth_unit, layout.service_name,
                layout.database_relative_path, layout.data_target, list(layout.retired_mount_targets)]

    def is_adopted(self, layout: VPMLayout) -> bool:
        """Read-only proof for recovering a failed public-config save.

        Marker presence alone is insufficient: verify the canonical Docker and
        data/custody bindings, immutable release and original master/account
        authority. Mutable operator policies/Pause/provider slots stay current.
        """
        marker = self.root / "adoption.json"
        if not marker.is_file():
            return False
        if marker.is_symlink() or stat.S_IMODE(marker.stat().st_mode) & 0o077:
            raise RuntimeError("VPM adoption marker custody is unsafe")
        try:
            recorded = json.loads(marker.read_text())
            if recorded["source_identity"] != self._source_identity(layout):
                raise ValueError("different source")
            image = recorded["target_image"]
            original = recorded["continuity"]
        except (KeyError, TypeError, ValueError):
            raise RuntimeError("VPM adoption marker does not match the declared source binding") from None
        canonical = replace(
            layout, project_name=self.project_name, container_name=self.container_name,
            compose_file=str(self.compose_file), data_target="/data", service_name="vast-price-manager",
            master_key_file=("/run/credentials/vast-price-manager-container.service/vpm-master.key"
                if layout.credential_mode == "systemd-encrypted" else layout.master_key_file),
            owner_unit=("vast-price-manager-container.service" if layout.credential_mode == "systemd-encrypted" else None),
            timer_names=self.timer_names, obsolete_auth_unit=None, retired_mount_targets=(),
        )
        inventory = self._inspect_layout(canonical, retired_units=self._layout_units(layout) - self._layout_units(canonical), canonical_mounts=True)
        if inventory["image"] != image:
            raise RuntimeError("adopted VPM immutable image differs from recorded identity")
        target = VPMServiceSpec(image=image, allowed_host="vpm.example.com",
            data_kind=layout.data_kind, data_source=layout.data_source,
            master_key_file=canonical.master_key_file, credential_mode=layout.credential_mode,
            credential_reference=layout.credential_reference,
            database_relative_path=layout.database_relative_path)
        self._verify_loaded_product_units(self.render(target))
        proof = self._continuity()
        if any(proof[name] != original.get(name) for name in ("key", "expected_account", "account_authority")):
            raise RuntimeError("adopted VPM master/account authority differs from recorded identity")
        return True

    def adopt(self, spec: VPMServiceSpec, layout: VPMLayout) -> dict:
        """Adopt only the declared Compose service, preserving custody and controls.

        A stopped, consistent full-data snapshot permits schema-aware restoration.
        If candidate stop or restoration fails, no previous owner/image/timer is
        restarted. Original Compose/unit files and protected recovery data remain.
        """
        with self.operation_lock():
            marker = self.root / "adoption.json"
            source_identity = self._source_identity(layout)
            if marker.is_file():
                self.is_adopted(layout)
                recorded = json.loads(marker.read_text())
                if recorded.get("source_identity") != source_identity:
                    raise RuntimeError("VPM adoption owner differs from the recorded owner")
                proof = self._continuity()
                recorded_proof = recorded.get("continuity", {})
                # Operator policies/Pause and encrypted provider slots may change
                # through ordinary product operation after adoption. Repeating
                # adoption verifies the binding/master/account authority without
                # freezing that mutable control state or restoring old choices.
                if any(proof[name] != recorded_proof.get(name) for name in ("key", "expected_account", "account_authority")):
                    raise RuntimeError("adopted VPM state/key identity continuity differs from recorded proof")
                self._assert_data_binding(self._adoption_spec(spec, layout))
                if recorded.get("target_image") != spec.image or proof["writes_enabled"] != spec.writes_enabled:
                    raise RuntimeError("existing adoption differs from requested release/capability; use supported update")
                self._wait_for_health()
                if not self._verify_auth_boundary():
                    raise RuntimeError("adopted VPM auth boundary is unavailable")
                return {"status": "already-adopted", "state_preserved": True,
                        "credential_mode": layout.credential_mode, "activate_automation": False}
            self.plan_adoption(spec, layout)
            target = self._adoption_spec(spec, layout)
            self._validate_master_key(target)
            self._ensure_exact_image_available(target)
            self.root.mkdir(parents=True, exist_ok=True)
            rendered = self.render(target)
            # Keep the old cadence/Persistent/jitter declarations, changing only
            # the service identity the timer invokes. Never activate a new timer.
            units = dict(rendered.units)
            for old, new in zip(layout.timer_names, self.timer_names):
                source = self.unit_dir / old
                if not source.is_file():
                    raise RuntimeError("declared VPM timer file is missing")
                if any((self.unit_dir / (old + ".d")).glob("*.conf")):
                    raise RuntimeError("VPM timer drop-ins require explicit declarative import before adoption")
                content = source.read_text()
                units[new] = self._preserve_timer_settings(
                    content, units[new], new.removesuffix(".timer") + ".service"
                )
            rendered = VPMRenderedFiles(rendered.compose, units)
            self._verify_loaded_product_units(rendered, allow_missing=True)
            candidate = self.root / ".vpm-compose-candidate.yml"
            candidate.write_text(rendered.compose)
            try:
                self._run(self._compose_prefix(candidate) + ["config", "--quiet"])
            finally:
                candidate.unlink(missing_ok=True)
            old_compose = self.compose_file.read_text() if self.compose_file.is_file() else None
            old_units = {name: (self.unit_dir / name).read_text() for name in units if (self.unit_dir / name).is_file()}
            timer_state = {name: self._unit_state(name) for name in layout.timer_names}
            owner_state = self._unit_state(layout.owner_unit) if layout.owner_unit else {"active":False,"enabled":False}
            owner_active, owner_enabled = owner_state["active"], owner_state["enabled"]
            auth_state = self._unit_state(layout.obsolete_auth_unit) if layout.obsolete_auth_unit else None
            try:
                self._run(["systemctl", "disable", "--now", *layout.timer_names])
                self._run(["systemctl", "stop", *(name.removesuffix(".timer") + ".service" for name in layout.timer_names)])
                # Capture final control/key proof after scheduled writers quiesce.
                before = self._continuity(layout.container_name)
            except Exception:
                self._restore_timer_state(timer_state)
                raise
            source_prefix = self._compose_prefix(Path(layout.compose_file))
            project_index = source_prefix.index("-p") + 1
            source_prefix[project_index] = layout.project_name
            recovery = self._new_recovery_path("adopt-")
            snapshot_ready = False
            candidate_started = False
            try:
                self._run(source_prefix + ["stop", layout.service_name])
                self._data_recovery(target, recovery, "backup")
                snapshot_ready = True
                if layout.owner_unit:
                    self._run(["systemctl", "disable", "--now", layout.owner_unit])
                # Only the declared service is removed; assembly siblings remain.
                self._run(source_prefix + ["rm", "-f", layout.service_name])
                self.compose_file.write_text(rendered.compose)
                self._install_units(rendered)
                self._run(["systemctl", "daemon-reload"])
                self._verify_loaded_product_units(rendered)
                candidate_started = True
                self._launch(target)
                self._wait_for_health()
                after = self._continuity()
                if any(after[name] != before[name] for name in ("controls", "key", "ciphertexts", "expected_account", "account_authority", "writes_enabled", "automation_paused")):
                    raise RuntimeError("VPM replacement did not preserve account, policies, Pause, key or write capability")
                if not self._verify_auth_boundary():
                    raise RuntimeError("VPM replacement Fleet auth boundary proof failed")
                # No obsolete dependency is retired before replacement proof.
                if layout.obsolete_auth_unit:
                    self._run(["systemctl", "disable", "--now", layout.obsolete_auth_unit])
                if target.credential_mode == "systemd-encrypted" and owner_enabled:
                    self._run(["systemctl", "enable", "vast-price-manager-container.service"])
                self._restore_timer_state(dict(zip(self.timer_names, timer_state.values())))
                self._write_adoption_marker(marker, {"source_identity": source_identity, "target_image": target.image, "continuity": after})
                return {"status": "adopted", "state_preserved": True, "credential_mode": target.credential_mode,
                        "activate_automation": False, "recovery_path": str(recovery), "schema_changed": before["schema"] != after["schema"],
                        "auth_boundary_verified": True, "authenticated_operator_acceptance": "required"}
            except Exception as error:
                try:
                    if candidate_started:
                        self._quiesce(check=True)
                        self._run(self._compose_prefix() + ["stop"])
                        if target.credential_mode == "systemd-encrypted":
                            self._run(["systemctl", "stop", "vast-price-manager-container.service"])
                        self._run(self._compose_prefix() + ["rm", "-f", "vast-price-manager"])
                    if snapshot_ready:
                        self._data_recovery(target, recovery, "restore")
                    for name in units:
                        path = self.unit_dir / name
                        if name in old_units:
                            path.write_text(old_units[name])
                        else:
                            path.unlink(missing_ok=True)
                    if old_compose is not None:
                        self.compose_file.write_text(old_compose)
                    else:
                        self.compose_file.unlink(missing_ok=True)
                    self._run(["systemctl", "daemon-reload"])
                    # The candidate container was removed. Verify loaded unit
                    # ownership before auth/source restart; inspect Docker only
                    # after the original owner has recreated its container.
                    self._effective_units(self._layout_units(layout) | {
                        *self.timer_names, *self.service_names, "vast-price-manager-container.service"
                    }, required=self._layout_units(layout))
                    if layout.obsolete_auth_unit:
                        # After= does not start a dependency. Recover auth first,
                        # preserving independently enabled and active states.
                        self._restore_unit_state(layout.obsolete_auth_unit, auth_state)
                    if layout.owner_unit and owner_active:
                        self._restore_unit_state(layout.owner_unit, {"enabled":owner_enabled,"active":owner_active})
                    else:
                        if layout.owner_unit:
                            self._restore_unit_state(layout.owner_unit, {"enabled":owner_enabled,"active":owner_active})
                        self._run(source_prefix + ["up", "-d", layout.service_name])
                    self._wait_for_health(layout.container_name)
                    self.inspect_layout(layout)
                    restored = self._continuity(layout.container_name)
                    if restored != before:
                        raise RuntimeError("restored state proof differs from stopped source")
                    self._restore_timer_state(timer_state)
                except Exception:
                    self._hold_candidate_for_forward_repair()
                    commands = [["systemctl", "disable", "--now", *layout.timer_names],
                                source_prefix + ["stop", layout.service_name]]
                    if layout.owner_unit:
                        commands.append(["systemctl", "stop", layout.owner_unit])
                    for command in commands:
                        try:
                            self._run(command, check=False)
                        except (RuntimeError, OSError):
                            pass
                    raise RuntimeError("VPM adoption recovery is unverified; forward repair required, stop requests issued but owner hold must be verified") from None
                raise RuntimeError("VPM adoption failed; consistent state restored and prior owner recovered") from error

    def install(
        self,
        spec: VPMServiceSpec,
        promote_route: Optional[Callable[[], None]] = None,
        *,
        schema_migration_forward_hold: bool = False,
    ) -> None:
        with self.operation_lock():
            self._install(spec, promote_route, schema_migration_forward_hold=schema_migration_forward_hold)

    def _install(
        self, spec: VPMServiceSpec, promote_route: Optional[Callable[[], None]] = None,
        *, schema_migration_forward_hold: bool = False,
    ) -> None:
        self._validate_master_key(spec)
        self._assert_no_native_conflict()
        # The initial route/container creation is gated, while an already
        # installed VPM can still be updated or recovered during an exporter
        # outage without taking away existing access.
        existing_managed = self._has_existing_managed_vpm()
        final_pause_proof_image: Optional[str] = None
        if spec.writes_enabled:
            runtime_state = self.managed_runtime_state() if existing_managed else None
            # Only a false/unknown-to-true process transition requires pause.
            # Existing true->true maintenance preserves the operator's choice.
            capability_enabling = (
                runtime_state is None
                or runtime_state["writes_enabled"] is not True
            )
            if capability_enabling:
                if runtime_state is None or runtime_state["automation_paused"] is not True:
                    raise RuntimeError(
                        "Enabling VPM process writes requires an existing managed VPM with persistent automation pause enabled."
                    )
                final_pause_proof_image = self.current_managed_image()
                if final_pause_proof_image is None:
                    raise RuntimeError(
                        "Enabling VPM process writes requires the exact current managed image for final Pause proof."
                    )
        if not existing_managed:
            self._require_vast_exporter_for_first_install()
        else:
            self._assert_data_binding(spec)
        rendered = self.render(spec)
        self._effective_units({*self.timer_names, *self.service_names, "vast-price-manager-container.service"})
        self._verify_loaded_product_units(rendered, allow_missing=True)
        old_compose = self.compose_file.read_text() if self.compose_file.exists() else None
        old_units = {
            name: (self.unit_dir / name).read_text()
            for name in rendered.units
            if (self.unit_dir / name).exists()
        }
        if existing_managed:
            units = dict(rendered.units)
            for name in self.timer_names:
                if name in old_units:
                    units[name] = self._preserve_timer_settings(
                        old_units[name], units[name], name.removesuffix(".timer") + ".service"
                    )
            rendered = VPMRenderedFiles(rendered.compose, units)
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
        before = self._continuity() if existing_managed else None
        self._quiesce(check=existing_managed)
        if final_pause_proof_image is not None:
            try:
                self._run(self._compose_prefix() + ["stop"])
                pause_confirmed = self._stopped_persistent_automation_paused(
                    final_pause_proof_image
                )
            except Exception:
                pause_confirmed = False
            if not pause_confirmed:
                restore_error = self._restore_after_final_pause_failure(
                    old_compose, final_pause_proof_image, timer_state
                )
                if restore_error is not None:
                    raise RuntimeError(
                        "Enabling VPM process writes requires persistent automation pause after "
                        "the managed container is stopped; restoration of the prior process-disabled "
                        f"project failed: {restore_error}"
                    )
                raise RuntimeError(
                    "Enabling VPM process writes requires persistent automation pause after "
                    "the managed container is stopped; the prior process-disabled project was restored."
                )
        recovery = self._new_recovery_path("update-") if existing_managed else None
        snapshot_ready = False
        candidate_started = False
        try:
            if existing_managed:
                self._run(self._compose_prefix() + ["stop"])
                self._data_recovery(spec, recovery, "backup")
                snapshot_ready = True
            self.compose_file.write_text(rendered.compose)
            self._install_units(rendered)
            self._run(["systemctl", "daemon-reload"])
            self._verify_loaded_product_units(rendered)
            candidate_started = True
            self._launch(spec)
            self._wait_for_health()
            after = self._continuity()
            if before is not None and any(after[name] != before[name] for name in ("controls", "key", "ciphertexts", "account_authority", "expected_account", "automation_paused")):
                raise RuntimeError("VPM update did not preserve account, policies, Pause or key custody")
            if after["writes_enabled"] != spec.writes_enabled or not self._verify_auth_boundary():
                raise RuntimeError("VPM replacement capability or Fleet auth proof failed")
            if promote_route is not None:
                promote_route()
            if existing_managed:
                self._restore_timer_state(timer_state)
        except Exception as error:
            if schema_migration_forward_hold and candidate_started:
                cleanup_failures = self._hold_candidate_for_forward_repair()
                cleanup_status = (
                    "Candidate stop and timer-disable commands completed."
                    if not cleanup_failures
                    else "Candidate hold is unverified because cleanup failed: " + "; ".join(cleanup_failures)
                )
                raise RuntimeError(
                    "VPM forward repair required after the schema-migration candidate failed. "
                    f"{cleanup_status} The previous VPM image and timers were not restarted. "
                    f"Original candidate failure: {error}"
                ) from error
            try:
                if candidate_started:
                    self._run(self._compose_prefix() + ["stop"])
                    if spec.credential_mode == "systemd-encrypted":
                        self._run(["systemctl", "stop", "vast-price-manager-container.service"])
                if snapshot_ready:
                    self._data_recovery(spec, recovery, "restore")
            except Exception:
                self._hold_candidate_for_forward_repair()
                raise RuntimeError("VPM update recovery is unverified; old image and timers held for forward repair") from None
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
            try:
                self._run(["systemctl", "daemon-reload"])
                self._verify_loaded_product_units(VPMRenderedFiles(old_compose or "", old_units))
            except Exception:
                self._hold_candidate_for_forward_repair()
                raise RuntimeError("VPM rollback loaded ownership is unverified; forward repair required and stop requests must be verified") from None
            if old_compose is not None:
                self._launch(spec)
                if before is not None and self._continuity() != before:
                    self._hold_candidate_for_forward_repair()
                    raise RuntimeError("VPM restored state could not be verified; timers held for forward repair") from None
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
