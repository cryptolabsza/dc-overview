"""Durable, credential-free RunPod observations for operational alerting."""

import copy
import datetime
import json
import logging
import math
import os
import tempfile
from pathlib import Path

LOGGER = logging.getLogger(__name__)

HEALTH_QUERY = """query {
  myself { machines {
    id name listed note maintenanceNote maintenanceMode lastSyncAt
    latestTelemetry { time }
  } }
}"""


def escape_label(value):
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def timestamp(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        number = parsed.timestamp()
        return number if math.isfinite(number) and number > 0 else None
    except (TypeError, ValueError, OverflowError):
        return None


def new_machine(hostname):
    return {
        "hostname": hostname, "known": False, "present": None, "listed": None,
        "last_success": 0, "note_present": None, "network_outage_note": None,
        "maintenance_note_present": None, "maintenance_mode": None, "last_sync": None,
        "last_sync_known": False, "telemetry": None, "telemetry_known": False,
    }


class HealthState:
    """Persist only explicit provider records across exporter restarts."""

    def __init__(self, accounts=(), path="/data/health-state.json"):
        self.path = Path(path) if path else None
        self.accounts = {}
        self.storage_success = 1
        self._load()
        for account in accounts:
            self._account(account)

    def _account(self, name):
        if name not in self.accounts:
            self.accounts[name] = {
                "poll_success": 0, "last_attempt": 0, "last_success": 0, "machines": {}
            }
        return self.accounts[name]

    def _load(self):
        if self.path is None or not self.path.exists():
            return
        try:
            document = json.loads(self.path.read_text())
            if document.get("version") != 1 or not isinstance(document.get("accounts"), dict):
                raise ValueError("invalid health-state envelope")
            for name, saved in document["accounts"].items():
                if not isinstance(name, str) or not isinstance(saved, dict):
                    raise ValueError("invalid account state")
                account = {"poll_success": 0, "last_attempt": 0, "last_success": 0, "machines": {}}
                for key in ("last_attempt", "last_success"):
                    value = saved.get(key, 0)
                    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                        raise ValueError("invalid state timestamp")
                    account[key] = value
                for machine_id, record in saved.get("machines", {}).items():
                    if not isinstance(machine_id, str) or not isinstance(record, dict):
                        raise ValueError("invalid machine state")
                    hostname = record.get("hostname")
                    if not isinstance(hostname, str) or not hostname:
                        raise ValueError("invalid stable hostname")
                    clean = new_machine(hostname)
                    for key in clean:
                        if key not in record or key == "hostname":
                            continue
                        value = record[key]
                        if key in ("last_success", "last_sync", "telemetry"):
                            if value is not None and (
                                type(value) not in (int, float) or not math.isfinite(value) or value < 0
                            ):
                                raise ValueError("invalid saved timestamp")
                        elif value is not None and type(value) is not bool:
                            raise ValueError("invalid saved boolean")
                        clean[key] = value
                    account["machines"][machine_id] = clean
                self.accounts[name] = account
        except (OSError, ValueError, TypeError, AttributeError):
            self.accounts = {}
            self.storage_success = 0
            LOGGER.error("RunPod health state could not be loaded; state is unknown until a valid API poll")

    def _save(self, accounts):
        """Atomically save a candidate snapshot and report whether it committed."""
        if self.path is None:
            return True
        temp_name = None
        committed = False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(prefix=".health-state-", dir=self.path.parent)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as target:
                json.dump({"version": 1, "accounts": accounts}, target, separators=(",", ":"))
                target.flush()
                os.fsync(target.fileno())
            os.replace(temp_name, self.path)
            committed = True
            temp_name = None
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            self.storage_success = 1
        except OSError:
            self.storage_success = 0
            LOGGER.error("RunPod health state save failed")
        finally:
            if temp_name is not None:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
        return committed

    def clear_account(self, name):
        """Forget observations when an account identity is removed or replaced."""
        candidate = copy.deepcopy(self.accounts)
        candidate.pop(name, None)
        if self._save(candidate):
            self.accounts = candidate
            return True
        return False

    def failure(self, name, now):
        account = self._account(name)
        account["last_attempt"] = now
        account["poll_success"] = 0
        self._save(self.accounts)

    @staticmethod
    def _valid_machine(machine, seen_ids):
        return (
            isinstance(machine, dict)
            and isinstance(machine.get("id"), str) and bool(machine["id"])
            and machine["id"] not in seen_ids
            and isinstance(machine.get("name"), str) and bool(machine["name"].strip())
            and type(machine.get("listed")) is bool
            and "note" in machine and (machine["note"] is None or isinstance(machine["note"], str))
            and "maintenanceNote" in machine
            and (machine["maintenanceNote"] is None or isinstance(machine["maintenanceNote"], str))
            and type(machine.get("maintenanceMode")) is bool
            and "lastSyncAt" in machine and "latestTelemetry" in machine
        )

    def success(self, name, machines, now):
        """Commit listing state only after a complete, explicit provider inventory."""
        valid = isinstance(machines, list)
        ids = set()
        for machine in machines if valid else []:
            if not self._valid_machine(machine, ids):
                valid = False
                break
            ids.add(machine["id"])
        if not valid:
            self.failure(name, now)
            return False

        account = self._account(name)
        account.update(poll_success=1, last_attempt=now, last_success=now)
        candidate = copy.deepcopy(self.accounts)
        account = candidate[name]
        for saved in account["machines"].values():
            saved["present"] = False
        for machine in machines:
            machine_id = machine["id"]
            record = account["machines"].setdefault(
                machine_id, new_machine(machine["name"].strip().lower())
            )
            note = machine["note"] or ""
            record.update(
                known=True, present=True, listed=machine["listed"], last_success=now,
                note_present=bool(note.strip()),
                network_outage_note="network outage" in note.casefold(),
                maintenance_note_present=bool((machine["maintenanceNote"] or "").strip()),
                maintenance_mode=machine["maintenanceMode"],
            )
            last_sync = timestamp(machine["lastSyncAt"])
            telemetry = machine["latestTelemetry"]
            telemetry_time = timestamp(telemetry.get("time")) if isinstance(telemetry, dict) else None
            record["last_sync_known"] = last_sync is not None
            record["telemetry_known"] = telemetry_time is not None
            if last_sync is not None:
                record["last_sync"] = last_sync
            if telemetry_time is not None:
                record["telemetry"] = telemetry_time
        committed = self._save(candidate)
        if committed:
            self.accounts = candidate
        return committed

    def format_metrics(self, active_accounts):
        definitions = {
            "runpod_health_state_schema_version": "Version of the RunPod health metric contract",
            "runpod_api_poll_success": "Whether the latest health API poll returned a complete valid inventory",
            "runpod_api_last_attempt_timestamp_seconds": "Unix time of the latest completed health API poll attempt",
            "runpod_api_last_success_timestamp_seconds": "Unix time of the latest complete valid health inventory",
            "runpod_health_state_persist_success": "Whether state loaded or last saved with successful file and directory sync",
            "runpod_machine_health_known": "Whether an explicit valid API record has been committed",
            "runpod_machine_health_last_success_timestamp_seconds": "Unix time this machine last appeared in a committed valid inventory",
            "runpod_machine_present": "Whether this machine appeared in the latest committed account inventory",
            "runpod_machine_health_listed": "Last committed explicit API listed boolean",
            "runpod_machine_api_note_present": "Whether the last valid API note contained non-whitespace text",
            "runpod_machine_network_outage_note": "Whether the last valid API note explicitly contained network outage",
            "runpod_machine_maintenance_note_present": "Whether the last valid API maintenance note contained text",
            "runpod_machine_maintenance_mode": "Last explicit API maintenanceMode boolean",
            "runpod_machine_last_sync_known": "Whether lastSyncAt was a usable timestamp in the latest valid machine record",
            "runpod_machine_last_sync_timestamp_seconds": "Last usable provider lastSyncAt Unix timestamp",
            "runpod_machine_telemetry_known": "Whether latestTelemetry.time was usable in the latest valid machine record",
            "runpod_machine_telemetry_timestamp_seconds": "Last usable provider latestTelemetry.time Unix timestamp",
        }
        lines = []
        for metric, help_text in definitions.items():
            lines.extend((f"# HELP {metric} {help_text}", f"# TYPE {metric} gauge"))
        lines.append("runpod_health_state_schema_version 1")
        lines.append(f"runpod_health_state_persist_success {self.storage_success}")
        fields = {
            "health_known": "known", "health_last_success_timestamp_seconds": "last_success",
            "present": "present", "health_listed": "listed", "api_note_present": "note_present",
            "network_outage_note": "network_outage_note",
            "maintenance_note_present": "maintenance_note_present",
            "maintenance_mode": "maintenance_mode", "last_sync_known": "last_sync_known",
            "last_sync_timestamp_seconds": "last_sync", "telemetry_known": "telemetry_known",
            "telemetry_timestamp_seconds": "telemetry",
        }
        for name in sorted(set(active_accounts)):
            account = self._account(name)
            label = 'account="' + escape_label(name) + '"'
            for metric, field in (
                ("poll_success", "poll_success"),
                ("last_attempt_timestamp_seconds", "last_attempt"),
                ("last_success_timestamp_seconds", "last_success"),
            ):
                lines.append(f"runpod_api_{metric}{{{label}}} {account[field]}")
            for machine_id, machine in sorted(account["machines"].items()):
                labels = label + ',machine_id="' + escape_label(machine_id) + '",hostname="' + escape_label(machine["hostname"]) + '"'
                for suffix, field in fields.items():
                    value = machine[field]
                    if value is None:
                        continue
                    if type(value) is bool:
                        value = int(value)
                    lines.append(f"runpod_machine_{suffix}{{{labels}}} {value}")
        return "\n".join(lines) + "\n"
