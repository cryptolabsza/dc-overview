"""Render, install, and reload DC Overview's Grafana fleet alerts."""

from __future__ import annotations

import copy
import json
import logging
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests
import yaml

logger = logging.getLogger(__name__)

ALERT_RULES_FILENAME = "fleet-gpu-health.yml"
NOTIFICATION_TEMPLATE_FILENAME = "dc-overview-notifications.yml"
NOTIFICATION_TEMPLATE_NAME = "cryptolabs.telegram.message"
MANAGED_ALERT_UIDS = frozenset(
    {
        "fleet-gpu-hardware-failure",
        "fleet-gpu-inventory-mismatch",
        "fleet-gpu-thermal-slowdown",
    }
)
_THERMAL_EXPRESSION = "__DC_OVERVIEW_THERMAL_EXPRESSION__"
_HARDWARE_USABLE_EXPRESSION = "__DC_OVERVIEW_HARDWARE_USABLE_EXPRESSION__"
_HARDWARE_TOTAL_EXPRESSION = "__DC_OVERVIEW_HARDWARE_TOTAL_EXPRESSION__"
_INVENTORY_USABLE_EXPRESSION = "__DC_OVERVIEW_INVENTORY_USABLE_EXPRESSION__"
_INVENTORY_TOTAL_EXPRESSION = "__DC_OVERVIEW_INVENTORY_TOTAL_EXPRESSION__"
ROLLBACK_RELOAD_ATTEMPTS = 2
_RECEIVER_UNSET = object()


class DuplicateManagedAlertError(RuntimeError):
    """Raised when another provisioning file owns a DC Overview alert UID."""

    def __init__(self, duplicates: Dict[Path, set[str]]):
        self.duplicates = duplicates
        details = ", ".join(
            f"{path.name}: {', '.join(sorted(uids))}"
            for path, uids in sorted(duplicates.items(), key=lambda item: str(item[0]))
        )
        super().__init__(f"Managed Grafana alert UID already exists in {details}")


class GrafanaReceiverError(RuntimeError):
    """Raised when a named Grafana receiver cannot be safely configured."""

    def __init__(self, message: str, *, rollback_complete: bool = True):
        self.rollback_complete = rollback_complete
        super().__init__(message)


@dataclass(frozen=True)
class GrafanaReceiverConfigurationResult:
    """Safe contact-point update outcome; never contains receiver secrets."""

    configured: bool
    receiver: str
    updated_uids: Tuple[str, ...]


@dataclass(frozen=True)
class GrafanaAlertSyncResult:
    """Outcome and recovery evidence for one host-side alert sync."""

    success: bool
    canonical_path: Path
    backup_dir: Path
    migrated_files: Tuple[Path, ...]
    notification_template_path: Optional[Path] = None
    restored: bool = False
    rollback_complete: bool = True
    status: str = "synchronized"
    failure_reason: str = ""
    receiver: Optional[str] = None
    notification_template_configured: bool = False


@dataclass(frozen=True)
class _FileSnapshot:
    existed: bool
    content: bytes
    mode: int
    uid: Optional[int]
    gid: Optional[int]


def _template_path(filename: str):
    return (
        resources.files("dc_overview")
        .joinpath("templates")
        .joinpath("grafana")
        .joinpath("provisioning")
        .joinpath("alerting")
        .joinpath(filename)
    )


def _template_document() -> Dict[str, Any]:
    return yaml.safe_load(_template_path(ALERT_RULES_FILENAME).read_text(encoding="utf-8"))


def _notification_template_content() -> bytes:
    return _template_path(NOTIFICATION_TEMPLATE_FILENAME).read_bytes()


def _promql_string(value: str) -> str:
    """Quote an operator-supplied regex as a PromQL string literal."""
    return json.dumps(value)


def _managed_uids(document: Any) -> set[str]:
    if not isinstance(document, dict):
        return set()
    return {
        rule.get("uid")
        for group in document.get("groups", [])
        if isinstance(group, dict)
        for rule in group.get("rules", [])
        if isinstance(rule, dict) and rule.get("uid") in MANAGED_ALERT_UIDS
    }


def find_duplicate_managed_uids(
    alerting_dir: Path,
    *,
    canonical_path: Optional[Path] = None,
) -> Dict[Path, set[str]]:
    """Return managed UIDs found outside the canonical provisioning file."""
    alerting_dir = Path(alerting_dir)
    if not alerting_dir.exists():
        return {}

    canonical = canonical_path.resolve() if canonical_path else None
    duplicates: Dict[Path, set[str]] = {}
    candidates = sorted(
        {*alerting_dir.rglob("*.yml"), *alerting_dir.rglob("*.yaml")},
        key=str,
    )
    for path in candidates:
        if canonical and path.resolve() == canonical:
            continue
        uids = _managed_uids(yaml.safe_load(path.read_text(encoding="utf-8")))
        if uids:
            duplicates[path] = uids
    return duplicates


def _atomic_write(
    path: Path,
    content: bytes,
    mode: int = 0o644,
    *,
    owner: Optional[Tuple[int, int]] = None,
) -> None:
    """Atomically replace a file while retaining requested access metadata."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temp_path = Path(temporary.name)
        os.chmod(temp_path, mode)
        if owner is not None:
            try:
                os.chown(temp_path, owner[0], owner[1])
            except (AttributeError, PermissionError):
                current = temp_path.stat()
                if (current.st_uid, current.st_gid) != owner:
                    raise
        os.replace(temp_path, path)
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink()


def _existing_owner(path: Path) -> Optional[Tuple[int, int]]:
    if not path.exists():
        return None
    metadata = path.stat()
    return metadata.st_uid, metadata.st_gid


def _thermal_expression(instance_matcher: str) -> str:
    selector = f"instance=~{_promql_string(instance_matcher)}"
    identity = "instance, gpu, UUID, pci_bus_id"
    return f"""(
  (
    DCGM_FI_DEV_CLOCKS_THROTTLE_REASON{{{selector},reason=~\"HwThermalSlowdown|SwThermalSlowdown\"}} == 1
  )
  * on({identity}) group_left()
  DCGM_FI_DEV_GPU_TEMP{{{selector}}}
)
and on({identity})
(
  DCXP_GPU_STATE{{{selector}}} == 1
)
and on({identity})
(
  DCXP_GPU_HW_FAILURE{{{selector}}} == 0
)"""


def _hardware_count_expression(instance_matcher: str, count_type: str) -> str:
    selector = f"instance=~{_promql_string(instance_matcher)}"
    return f"""(
  DCXP_GPU_HW_FAILURE{{{selector}}} == 1
)
* on(instance, Hostname) group_left()
  DCXP_GPU_COUNT{{type=\"{count_type}\"}}"""


def _inventory_mismatch_count_expression(
    instance_matcher: str,
    count_type: str,
) -> str:
    selector = f"instance=~{_promql_string(instance_matcher)}"
    return f"""(
  (
    (DCXP_GPU_STATE{{{selector},UUID="DRIVER-ERROR"}} == 2) / 2
  )
  and on(instance, Hostname)
  (
    (DCXP_GPU_COUNT{{type=\"nvml\"}} > 0)
    and on(instance, Hostname)
    (
      DCXP_GPU_COUNT{{type=\"nvml\"}}
      < on(instance, Hostname)
      DCXP_GPU_COUNT{{type=\"pcie\"}}
    )
  )
)
* on(instance, Hostname) group_left()
  DCXP_GPU_COUNT{{type=\"{count_type}\"}}"""


def _default_notification_settings(receiver: str) -> Dict[str, Any]:
    return {
        "receiver": receiver,
        "group_by": ["alertname", "instance", "gpu"],
        "group_wait": "0s",
        "group_interval": "5m",
        "repeat_interval": "1h",
    }


def render_grafana_alerts(
    *,
    instance_matcher: str = ".+",
    receiver: Optional[str] = None,
    _notification_settings: Optional[Dict[str, Dict[str, Any]]] = None,
) -> str:
    """Render reusable GPU-health alerts for one DC Overview installation."""
    if not instance_matcher:
        raise ValueError("instance_matcher must not be empty")

    document = _template_document()
    expressions = {
        _THERMAL_EXPRESSION: _thermal_expression(instance_matcher),
        _HARDWARE_USABLE_EXPRESSION: _hardware_count_expression(
            instance_matcher, "usable"
        ),
        _HARDWARE_TOTAL_EXPRESSION: _hardware_count_expression(instance_matcher, "pcie"),
        _INVENTORY_USABLE_EXPRESSION: _inventory_mismatch_count_expression(
            instance_matcher, "usable"
        ),
        _INVENTORY_TOTAL_EXPRESSION: _inventory_mismatch_count_expression(
            instance_matcher, "pcie"
        ),
    }

    for group in document["groups"]:
        for rule in group["rules"]:
            for query in rule["data"]:
                expression = query.get("model", {}).get("expr")
                if expression in expressions:
                    query["model"]["expr"] = expressions[expression]

            if receiver:
                rule["notification_settings"] = _default_notification_settings(receiver)
            elif _notification_settings and rule["uid"] in _notification_settings:
                rule["notification_settings"] = copy.deepcopy(
                    _notification_settings[rule["uid"]]
                )

    return yaml.safe_dump(document, sort_keys=False, allow_unicode=True)


def install_grafana_alerts(
    config_dir: Path,
    *,
    instance_matcher: str = ".+",
    receiver: Optional[str] = None,
    _notification_settings: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Path:
    """Atomically install canonical alert and notification-template files."""
    alerting_dir = Path(config_dir) / "grafana" / "provisioning" / "alerting"
    alerting_dir.mkdir(parents=True, exist_ok=True)
    target = alerting_dir / ALERT_RULES_FILENAME
    template_target = alerting_dir / NOTIFICATION_TEMPLATE_FILENAME
    duplicates = find_duplicate_managed_uids(
        alerting_dir,
        canonical_path=target,
    )
    if duplicates:
        raise DuplicateManagedAlertError(duplicates)
    rendered = render_grafana_alerts(
        instance_matcher=instance_matcher,
        receiver=receiver,
        _notification_settings=_notification_settings,
    )

    _atomic_write(
        template_target,
        _notification_template_content(),
        owner=_existing_owner(template_target),
    )
    _atomic_write(
        target,
        rendered.encode("utf-8"),
        owner=_existing_owner(target),
    )

    return target


def reload_grafana_alerts(
    grafana_url: str,
    admin_password: str,
    *,
    admin_user: str = "admin",
    timeout: int = 10,
) -> bool:
    """Ask Grafana to reload provisioned alerts without restarting a container."""
    endpoint = f"{grafana_url.rstrip('/')}/api/admin/provisioning/alerting/reload"
    try:
        response = requests.post(
            endpoint,
            auth=(admin_user, admin_password),
            timeout=timeout,
        )
        response.raise_for_status()
        return True
    except requests.RequestException as error:
        logger.warning("Grafana alert provisioning reload failed: %s", error)
        return False


def _contact_point_payload(contact_point: Any) -> Dict[str, Any]:
    if not isinstance(contact_point, dict):
        raise GrafanaReceiverError("Grafana returned an invalid contact point")
    required = ("uid", "name", "type", "settings")
    if any(field not in contact_point for field in required):
        raise GrafanaReceiverError("Grafana returned an incomplete contact point")
    if not isinstance(contact_point["settings"], dict):
        raise GrafanaReceiverError("Grafana returned invalid contact point settings")

    payload = {field: copy.deepcopy(contact_point[field]) for field in required}
    if "disableResolveMessage" in contact_point:
        payload["disableResolveMessage"] = contact_point["disableResolveMessage"]
    return payload


def _get_telegram_contact_points(
    grafana_url: str,
    admin_password: str,
    *,
    receiver: str,
    admin_user: str,
    timeout: int,
) -> Tuple[Dict[str, Any], ...]:
    endpoint = f"{grafana_url.rstrip('/')}/api/v1/provisioning/contact-points"
    try:
        response = requests.get(
            endpoint,
            params={"name": receiver},
            auth=(admin_user, admin_password),
            timeout=timeout,
        )
        response.raise_for_status()
        document = response.json()
    except (requests.RequestException, ValueError) as error:
        raise GrafanaReceiverError(
            f"Could not validate Grafana receiver {receiver!r}: {error}"
        ) from error

    if not isinstance(document, list):
        raise GrafanaReceiverError("Grafana returned an invalid contact point list")
    if any(not isinstance(point, dict) for point in document):
        raise GrafanaReceiverError("Grafana returned an invalid contact point")
    named = [point for point in document if point.get("name") == receiver]
    telegram = [
        point
        for point in named
        if str(point.get("type", "")).lower() == "telegram"
    ]
    if not named:
        raise GrafanaReceiverError(f"Grafana receiver {receiver!r} was not found")
    if not telegram:
        raise GrafanaReceiverError(
            f"Grafana receiver {receiver!r} is not a Telegram receiver"
        )
    return tuple(_contact_point_payload(point) for point in telegram)


def _put_contact_point(
    grafana_url: str,
    admin_password: str,
    payload: Dict[str, Any],
    *,
    admin_user: str,
    timeout: int,
) -> None:
    endpoint = (
        f"{grafana_url.rstrip('/')}/api/v1/provisioning/contact-points/"
        f"{payload['uid']}"
    )
    response = requests.put(
        endpoint,
        json=payload,
        auth=(admin_user, admin_password),
        timeout=timeout,
    )
    response.raise_for_status()


def configure_grafana_telegram_receiver(
    grafana_url: str,
    admin_password: str,
    *,
    receiver: str,
    admin_user: str = "admin",
    timeout: int = 10,
) -> GrafanaReceiverConfigurationResult:
    """Wire a Telegram receiver to the concise template without exposing secrets.

    Grafana returns secure settings as a redacted sentinel. Sending that sentinel
    back unchanged on PUT tells Grafana to retain the existing encrypted value;
    only the non-secret ``message`` field is changed here.
    """
    originals = _get_telegram_contact_points(
        grafana_url,
        admin_password,
        receiver=receiver,
        admin_user=admin_user,
        timeout=timeout,
    )
    attempted: list[Dict[str, Any]] = []
    try:
        for original in originals:
            updated = copy.deepcopy(original)
            updated["settings"]["message"] = (
                f'{{{{ template "{NOTIFICATION_TEMPLATE_NAME}" . }}}}'
            )
            attempted.append(original)
            _put_contact_point(
                grafana_url,
                admin_password,
                updated,
                admin_user=admin_user,
                timeout=timeout,
            )
    except Exception as error:
        rollback_complete = True
        for original in reversed(attempted):
            try:
                _put_contact_point(
                    grafana_url,
                    admin_password,
                    original,
                    admin_user=admin_user,
                    timeout=timeout,
                )
            except Exception:
                rollback_complete = False
        raise GrafanaReceiverError(
            f"Could not configure Telegram receiver {receiver!r}: {error}",
            rollback_complete=rollback_complete,
        ) from error

    return GrafanaReceiverConfigurationResult(
        configured=True,
        receiver=receiver,
        updated_uids=tuple(str(point["uid"]) for point in originals),
    )


def _remove_managed_uids(path: Path) -> None:
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    groups = []
    for group in document.get("groups", []):
        remaining_rules = [
            rule
            for rule in group.get("rules", [])
            if rule.get("uid") not in MANAGED_ALERT_UIDS
        ]
        if remaining_rules:
            group["rules"] = remaining_rules
            groups.append(group)
    document["groups"] = groups
    metadata = path.stat()
    rendered = yaml.safe_dump(document, sort_keys=False, allow_unicode=True)
    _atomic_write(
        path,
        rendered.encode("utf-8"),
        mode=metadata.st_mode & 0o777,
        owner=(metadata.st_uid, metadata.st_gid),
    )


def _new_backup_dir(config_dir: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = (
        config_dir
        / "backups"
        / "grafana-alerts"
        / f"{timestamp}-{uuid.uuid4().hex[:8]}"
    )
    backup_dir.mkdir(parents=True, exist_ok=False)
    return backup_dir


def _snapshot(path: Path) -> _FileSnapshot:
    if not path.exists():
        return _FileSnapshot(False, b"", 0o644, None, None)
    metadata = path.stat()
    return _FileSnapshot(
        True,
        path.read_bytes(),
        metadata.st_mode & 0o777,
        metadata.st_uid,
        metadata.st_gid,
    )


def _notification_settings_from_paths(
    paths: Tuple[Path, ...],
) -> Dict[str, Dict[str, Any]]:
    settings: Dict[str, Dict[str, Any]] = {}
    for path in paths:
        if not path.exists():
            continue
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for group in document.get("groups", []):
            for rule in group.get("rules", []):
                uid = rule.get("uid")
                notification_settings = rule.get("notification_settings")
                if (
                    uid in MANAGED_ALERT_UIDS
                    and uid not in settings
                    and isinstance(notification_settings, dict)
                ):
                    settings[uid] = copy.deepcopy(notification_settings)
    return settings


def _managed_uids_from_paths(paths: Tuple[Path, ...]) -> set[str]:
    uids: set[str] = set()
    for path in paths:
        if path.exists():
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            uids.update(_managed_uids(document))
    return uids


def _receiver_from_settings(settings: Dict[str, Dict[str, Any]]) -> Optional[str]:
    receivers = {
        value.get("receiver")
        for value in settings.values()
        if isinstance(value.get("receiver"), str) and value.get("receiver")
    }
    if len(receivers) > 1:
        raise GrafanaReceiverError(
            "Managed Grafana alerts use multiple receivers; choose one with --receiver"
        )
    return next(iter(receivers), None)


def _restore_snapshots(
    snapshots: Dict[Path, _FileSnapshot],
) -> Tuple[bool, Tuple[str, ...]]:
    errors = []
    for path, snapshot in snapshots.items():
        try:
            if snapshot.existed:
                owner = None
                if snapshot.uid is not None and snapshot.gid is not None:
                    owner = (snapshot.uid, snapshot.gid)
                _atomic_write(path, snapshot.content, mode=snapshot.mode, owner=owner)
            elif path.exists():
                path.unlink()
        except Exception as error:
            errors.append(f"{path.name}: {error}")
    return not errors, tuple(errors)


def _reload_after_rollback(
    grafana_url: str,
    admin_password: str,
    *,
    admin_user: str,
    timeout: int,
) -> Tuple[bool, Tuple[str, ...]]:
    errors = []
    for attempt in range(1, ROLLBACK_RELOAD_ATTEMPTS + 1):
        try:
            if reload_grafana_alerts(
                grafana_url,
                admin_password,
                admin_user=admin_user,
                timeout=timeout,
            ):
                return True, tuple(errors)
            errors.append(f"rollback reload attempt {attempt} was rejected")
        except Exception as error:
            errors.append(f"rollback reload attempt {attempt} failed: {error}")
    return False, tuple(errors)


def sync_grafana_alerts(
    config_dir: Path,
    *,
    grafana_url: str,
    admin_password: str,
    admin_user: str = "admin",
    instance_matcher: str = ".+",
    receiver: Any = _RECEIVER_UNSET,
    clear_receiver: bool = False,
    migrate_duplicates: bool = False,
    timeout: int = 10,
) -> GrafanaAlertSyncResult:
    """Transactionally sync file-provisioned alerts on an existing host."""
    if clear_receiver and receiver is not _RECEIVER_UNSET:
        raise ValueError("receiver and clear_receiver cannot be used together")
    if receiver is not _RECEIVER_UNSET and (
        not isinstance(receiver, str) or not receiver
    ):
        raise ValueError("receiver must be a non-empty string")

    config_dir = Path(config_dir)
    alerting_dir = config_dir / "grafana" / "provisioning" / "alerting"
    alerting_dir.mkdir(parents=True, exist_ok=True)
    canonical_path = alerting_dir / ALERT_RULES_FILENAME
    notification_template_path = alerting_dir / NOTIFICATION_TEMPLATE_FILENAME
    duplicates = find_duplicate_managed_uids(
        alerting_dir,
        canonical_path=canonical_path,
    )
    if duplicates and not migrate_duplicates:
        raise DuplicateManagedAlertError(duplicates)

    existing_settings: Dict[str, Dict[str, Any]] = {}
    effective_receiver: Optional[str] = None
    if receiver is _RECEIVER_UNSET and not clear_receiver:
        existing_paths = (canonical_path, *tuple(duplicates))
        existing_settings = _notification_settings_from_paths(existing_paths)
        effective_receiver = _receiver_from_settings(existing_settings)
        if effective_receiver:
            existing_uids = _managed_uids_from_paths(existing_paths)
            for uid in MANAGED_ALERT_UIDS - existing_uids:
                existing_settings[uid] = _default_notification_settings(
                    effective_receiver
                )
    elif receiver is not _RECEIVER_UNSET:
        effective_receiver = receiver

    backup_dir = _new_backup_dir(config_dir)
    touched_paths = [*duplicates, canonical_path, notification_template_path]
    snapshots = {path: _snapshot(path) for path in touched_paths}
    migrated_files = tuple(duplicates)

    try:
        for path, snapshot in snapshots.items():
            if snapshot.existed:
                relative_path = path.relative_to(alerting_dir)
                backup_path = backup_dir / relative_path
                backup_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, backup_path)

        for path in duplicates:
            _remove_managed_uids(path)

        install_grafana_alerts(
            config_dir,
            instance_matcher=instance_matcher,
            receiver=(
                effective_receiver if receiver is not _RECEIVER_UNSET else None
            ),
            _notification_settings=(
                existing_settings
                if receiver is _RECEIVER_UNSET and not clear_receiver
                else None
            ),
        )

        if not reload_grafana_alerts(
            grafana_url,
            admin_password,
            admin_user=admin_user,
            timeout=timeout,
        ):
            raise RuntimeError("Grafana rejected the alert provisioning reload")

        notification_configured = False
        if effective_receiver:
            receiver_result = configure_grafana_telegram_receiver(
                grafana_url,
                admin_password,
                receiver=effective_receiver,
                admin_user=admin_user,
                timeout=timeout,
            )
            notification_configured = receiver_result.configured

        return GrafanaAlertSyncResult(
            success=True,
            canonical_path=canonical_path,
            notification_template_path=notification_template_path,
            backup_dir=backup_dir,
            migrated_files=migrated_files,
            receiver=effective_receiver,
            notification_template_configured=notification_configured,
        )
    except Exception as error:
        files_restored, restore_errors = _restore_snapshots(snapshots)
        reload_restored, reload_errors = _reload_after_rollback(
            grafana_url,
            admin_password,
            admin_user=admin_user,
            timeout=timeout,
        )
        receiver_rollback_complete = getattr(error, "rollback_complete", True)
        rollback_complete = (
            files_restored and reload_restored and receiver_rollback_complete
        )
        details = [str(error), *restore_errors, *reload_errors]
        if not receiver_rollback_complete:
            details.append("Telegram receiver rollback was incomplete")
        return GrafanaAlertSyncResult(
            success=False,
            canonical_path=canonical_path,
            notification_template_path=notification_template_path,
            backup_dir=backup_dir,
            migrated_files=migrated_files,
            restored=files_restored,
            rollback_complete=rollback_complete,
            status="rolled_back" if rollback_complete else "rollback_incomplete",
            failure_reason="; ".join(detail for detail in details if detail),
            receiver=effective_receiver,
        )
