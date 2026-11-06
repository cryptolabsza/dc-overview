# TRACEWEAVER: file-role=stable-release-policy; req=REQ-AUTOADVANCE-003; trace=TRACE-AUTOADVANCE-003; ver=VER-AUTOADVANCE-003
"""Explicit pin/follow intent; candidate selection never installs software."""
import re
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from . import release_catalog as catalog
from .release_catalog import COMPONENTS, artifact_identity
from .release_candidates import require_compatible, verify_candidate
from .release_broker import BrokerError, canonical, private_write, sha


def guard_publication(config, operation_id=None):
    path = config.config_dir / 'releases' / 'broker' / 'policy-publication.json'
    if os.path.lexists(path):
        from .release_broker import _private
        _private(path)
        value = catalog._json(path.read_bytes())
        if operation_id is None or value.get('operation_id') != operation_id:
            raise BrokerError('recovery-required', 'Reconcile the pending update policy before another release change')


def remove_journal(path):
    path.unlink()
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

_VERSION = re.compile(r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z")


def stable_version(value):
    if not isinstance(value, str) or len(value) > 128:
        return None
    match = _VERSION.fullmatch(value)
    return tuple(int(v) for v in match.groups()) if match else None


def supported(name):
    return name in COMPONENTS and COMPONENTS[name][0] == "proxy-updater" and name != "cryptolabs-proxy"


# TRACEWEAVER: entrypoint=choose_candidate; req=REQ-AUTOADVANCE-003; trace=TRACE-AUTOADVANCE-003; ver=VER-AUTOADVANCE-003
def choose_candidate(name, selected_release, major, candidates, capabilities, platform):
    """Choose only one unambiguous, compatible, admitted stable advancement.

    The broker supplies candidates after signature/revocation/high-water checks.
    The selected version is the floor, including a not-yet-installed target.
    """
    floor = stable_version(selected_release)
    if not supported(name) or type(major) is not int or not floor or floor[0] != major:
        return None
    eligible = []
    for candidate in candidates:
        try:
            component = candidate.manifest.data["components"][name]
            version = stable_version(component["release"])
            if not version or version[0] != major or version <= floor:
                continue
            entries = require_compatible([candidate], [name], capabilities, platform, "services-update")
            entry = entries[name]
            artifact = component["artifacts"].get(platform, component["artifacts"].get("any"))
            if (component["owner"] != COMPONENTS[name][0] or entry["channel"] != "main"
                    or artifact is None or artifact_identity(artifact) != entry["identity"]):
                continue
            eligible.append((version, entry["identity"], candidate))
        except (KeyError, ValueError, TypeError):
            continue
    if not eligible:
        return None
    newest = max(value[0] for value in eligible)
    choices = [value for value in eligible if value[0] == newest]
    if len({value[1] for value in choices}) != 1:
        return None
    return choices[0][2]


def installed_component(current, name, store, inspect):
    """Bind a running immutable image to retained, root-custodied release bytes."""
    if not supported(name):
        return None
    try:
        live = inspect(name)
        if live.get("State", {}).get("Running") is not True:
            return None
        image = inspect(live["Image"])
        if image.get("Id") != live["Image"] or image.get("Os", "") + "/" + image.get("Architecture", "") != current.platform:
            return None
        references = image.get("RepoDigests")
        if not isinstance(references, list):
            return None
        known = [current.manifest]
        paths = list((store.root / "manifests").glob("*.json"))
        if len(paths) > 1024:
            return None
        for path in paths:
            if not catalog.HEX.fullmatch(path.stem):
                continue
            catalog._check_root_path(path)
            if path.stat().st_size > 1024 * 1024:
                return None
            raw = path.read_bytes()
            if sha(raw) != path.stem:
                return None
            known.append(catalog.Manifest.from_bytes(raw))
        matches = []
        for manifest in known:
            item = manifest.data["components"].get(name)
            if not item or item["owner"] != COMPONENTS[name][0] or not stable_version(item["release"]):
                continue
            artifact = item["artifacts"].get(current.platform)
            if artifact and artifact_identity(artifact) in references:
                matches.append(item)
        if not matches or len({stable_version(item["release"]) for item in matches}) != 1:
            return None
        item = matches[0]
        labels = image.get("Config", {}).get("Labels") or {}
        declared = labels.get("org.opencontainers.image.version")
        if declared and stable_version(declared) and stable_version(declared) != stable_version(item["release"]):
            return None
        again = inspect(name)
        if any(again.get(k) != live.get(k) for k in ("Id", "Image")) or again.get("State", {}).get("Running") is not True:
            return None
        return copy.deepcopy(item)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        return None


class PolicyManager:
    """Selection-only operations under the broker's dispatch lock.

    Every mode mutation also changes selection identity. A private forward
    recovery record joins policy intent to the existing selection/public-config
    transaction. No method submits an update or creates/restarts a container.
    """
    def __init__(self, broker):
        self.broker = broker
        self.store = broker.store
        self.path = broker.root / "policy-state.json"
        self.journal = broker.root / "policy-publication.json"

    def _state(self):
        value = self.broker._read(self.path) if self.path.exists() else {"schema_version": 1, "components": {}}
        if not isinstance(value, dict) or set(value) != {"schema_version", "components"} or type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise BrokerError("policy-unavailable", "Installed update policy is invalid", 503)
        if not isinstance(value["components"], dict) or len(value["components"]) > len(COMPONENTS):
            raise BrokerError("policy-unavailable", "Installed update policy is invalid", 503)
        for name, item in value["components"].items():
            if (not supported(name) or not isinstance(item, dict) or set(item) != {"mode", "major"}
                    or item["mode"] not in ("pinned", "follow-stable")
                    or (item["mode"] == "pinned" and item["major"] is not None)
                    or (item["mode"] == "follow-stable" and (type(item["major"]) is not int or item["major"] < 0))):
                raise BrokerError("policy-unavailable", "Installed update policy is invalid", 503)
        return value

    def _recover(self):
        if not self.journal.exists():
            return
        if self.broker.policy.get("writes_enabled") is not True:
            raise BrokerError("recovery-required", "Update policy publication needs its installed owner", 503)
        record = self.broker._read(self.journal)
        if (not isinstance(record, dict) or set(record) != {"before_selection", "after_selection", "before_policy", "after_policy", "operation_id"}
                or any(not isinstance(record[k], str) or not catalog.HEX.fullmatch(record[k]) for k in ("before_selection", "after_selection"))):
            raise BrokerError("recovery-required", "Update policy recovery record is invalid", 503)
        from .fleet_upgrade import reconcile_release_operation
        reconcile_release_operation(self.broker.config, record["operation_id"])
        current = self.store.load()
        policy = self._state()
        if policy not in (record["before_policy"], record["after_policy"]):
            raise BrokerError("recovery-required", "Update policy changed during publication", 409)
        if current.selection_sha256 == record["after_selection"]:
            import yaml
            public = yaml.safe_load((self.broker.config.config_dir / "fleet-config.yaml").read_bytes())
            if public.get("release_selection", {}).get("selection_sha256") != current.selection_sha256:
                raise BrokerError("recovery-required", "Release public reference must be reconciled first", 409)
            private_write(self.path, record["after_policy"])
        elif current.selection_sha256 == record["before_selection"] and policy == record["before_policy"]:
            pass
        else:
            raise BrokerError("recovery-required", "Release selection changed during policy publication", 409)
        remove_journal(self.journal)

    def _mutable(self):
        if self.broker.policy.get("writes_enabled") is not True:
            raise BrokerError("disabled", "Release writes are disabled", 503)
        for path in (self.broker.root / "operations").glob("*.json"):
            from .release_broker import TERMINAL
            if self.broker._read(path)["state"] not in TERMINAL:
                raise BrokerError("busy", "Reconcile the existing release operation first")

    def listing(self, current=None, state=None):
        current = current or self.store.load()
        state = state or self._state()
        components = {}
        for name, selected in current.selection["components"].items():
            enabled = supported(name) and selected["enabled"] and name in current.targets
            installed = self.broker.owner.installed_component(current, name) if enabled else None
            intent = state["components"].get(name, {"mode": "pinned", "major": None})
            components[name] = {**intent, "supported": bool(enabled and installed),
                "installed_release": installed["release"] if installed else None,
                "selected_release": current.manifest.data["components"][name]["release"],
                "reason": None if enabled and installed else "Installed release identity unavailable" if enabled else "Managed by its existing lifecycle owner"}
        return {"selection_id": current.selection["selection_id"], "selection_sha256": current.selection_sha256,
                "components": components, "writes_enabled": self.broker.policy.get("writes_enabled") is True}

# TRACEWEAVER: entrypoint=dispatch; req=REQ-AUTOADVANCE-002; trace=TRACE-AUTOADVANCE-002; ver=VER-AUTOADVANCE-002
    def dispatch(self, action, params):
        self._recover()
        current = self.store.load()
        state = self._state()
        if action == "policy-list":
            return self.listing(current, state)
        self._mutable()
        self.broker._check_expected(current, params)
        if action == "policy-set":
            name = params["component"]
            if not supported(name) or name not in current.targets:
                raise BrokerError("unsupported", "This service retains its existing lifecycle owner", 400)
            installed = self.broker.owner.installed_component(current, name)
            if installed is None or stable_version(installed["release"]) is None:
                raise BrokerError("installed-unverified", "Installed immutable release identity is unavailable", 409)
            after = copy.deepcopy(state)
            mode = params["mode"]
            after["components"][name] = {"mode": mode, "major": stable_version(installed["release"])[0] if mode == "follow-stable" else None}
            component = installed if mode == "pinned" else current.manifest.data["components"][name]
            policy = {"origin": "customer-pin" if mode == "pinned" else "baseline", "enabled": True}
            if mode == "pinned":
                policy["pin"] = artifact_identity(component["artifacts"][current.platform])
            self._publish(current, state, after, {name: component}, {name: policy}, installed_proofs={name: installed})
            return self.listing()
        following = {n: item for n, item in state["components"].items() if item["mode"] == "follow-stable" and n in current.targets}
        if not following:
            return {**self.listing(current, state), "advanced": [], "reasons": {}}
        try:
            candidates = list(self.broker._candidates().values())
            capabilities = self.broker.owner.capabilities(max(c.manifest.data["selection_contract"] for c in candidates))
        except (ValueError, OSError, RuntimeError) as error:
            if isinstance(error, BrokerError):
                raise
            raise BrokerError("unavailable", "Verified stable discovery is unavailable", 503) from None
        changes, reasons, proofs, installed_proofs = {}, {}, [], {}
        after = copy.deepcopy(state)
        for name, intent in following.items():
            installed = self.broker.owner.installed_component(current, name)
            version = stable_version(installed['release']) if installed else None
            if version is None:
                reasons[name] = 'Installed immutable release identity is unavailable'
                continue
            installed_proofs[name] = installed
            major = version[0]
            after['components'][name]['major'] = major
            chosen = choose_candidate(name, current.manifest.data["components"][name]["release"], major, candidates, capabilities, current.platform)
            if chosen is None:
                reasons[name] = "No newer compatible stable release within the installed major version"
            else:
                changes[name] = chosen.manifest.data["components"][name]
                proofs.append(chosen)
        advanced = sorted(changes)
        for name in following:
            if after['components'][name] != state['components'][name] and name not in changes:
                changes[name] = current.manifest.data['components'][name]
        if changes:
            self._publish(current, state, after, changes, {n: {"origin": "baseline", "enabled": True} for n in changes}, proofs=proofs, installed_proofs=installed_proofs)
        return {**self.listing(), "advanced": advanced, "reasons": reasons}

    def _publish(self, current, before, after, changes, policies, proofs=(), installed_proofs=None):
        data = copy.deepcopy(current.manifest.data)
        data["baseline_id"] = "policy-" + uuid.uuid4().hex
        for name, component in changes.items():
            data["components"][name] = copy.deepcopy(component)
            if name in data.get('component_channels', {}):
                data['component_channels'][name] = 'main'
        manifest = catalog.Manifest.from_bytes(canonical(data))
        chosen = copy.deepcopy(current.selection["components"])
        chosen.update(policies)
        selection = {"schema_version": 1, "selection_id": data["baseline_id"], "manifest_sha256": manifest.sha256, "components": chosen}
        raw = canonical(selection) + b"\n"
        operation = str(uuid.uuid4())
        record = {"before_selection": current.selection_sha256, "after_selection": sha(raw),
                  "before_policy": before, "after_policy": after, "operation_id": operation}
        path = self.broker.root / "policy-candidate.json"
        private_write(path, data)
        from .fleet_upgrade import select_release_components
        def precommit():
            self.broker._reload_policy()
            self._mutable()
            if self._state() != before:
                raise BrokerError('policy-conflict', 'Update policy changed before release publication')
            for name, installed in (installed_proofs or {}).items():
                if self.broker.owner.installed_component(current, name) != installed:
                    raise BrokerError('installed-unverified', 'Installed release changed before policy publication')
            if proofs:
                watermark = self.broker._read(self.broker.root / 'high-water.json')
                for candidate in proofs:
                    verified = verify_candidate(candidate.manifest_raw, candidate.admission_raw, candidate.signature,
                        candidate.index_raw, candidate.index_signature, self.broker.policy,
                        highest_generation=max(watermark['generation'], self.broker.policy['minimum_generation']))
                    if verified.index_raw != candidate.index_raw:
                        raise BrokerError('unavailable', 'Admission changed before release publication', 503)
            # The native lifecycle and updater locks are held here. A losing
            # CAS never creates an orphan policy journal, and a supported native
            # writer cannot replace the installed image across this boundary.
            private_write(self.journal, record)
        def finish():
            private_write(self.path, after)
            remove_journal(self.journal)
        try:
            select_release_components(self.broker.config, path, tuple(changes), platform=current.platform,
                expected_selection_id=current.selection["selection_id"], expected_selection_sha256=current.selection_sha256,
                operation_id=operation, policy_updates=policies, precommit_check=precommit, postcommit=finish)
        except BaseException as error:
            # A native preflight/compensated failure may leave the prior state.
            # A committed candidate retains this record for forward recovery.
            if (self.store.root / "selection.json").read_bytes() == current.selection_raw and self._state() == before:
                if self.journal.exists():
                    remove_journal(self.journal)
            if isinstance(error, RuntimeError) and not isinstance(error, BrokerError):
                raise BrokerError("busy", "Release publication is held; reconcile before retry") from None
            raise


SYSTEMD_DIR = Path("/etc/systemd/system")


def release_cli():
    path = Path(sys.executable).parent / "dc-overview"
    if not re.fullmatch(r"/[A-Za-z0-9/_.-]+", str(path)):
        raise PermissionError("installed release CLI path is unsupported")
    for entry in (path, *path.parents):
        info = entry.lstat()
        if entry.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError("release timer requires a root-custodied installed CLI")
    return str(path)


# TRACEWEAVER: entrypoint=install_timer; req=REQ-AUTOADVANCE-004; trace=TRACE-AUTOADVANCE-004; ver=VER-AUTOADVANCE-004
def install_timer():
    """Install the fixed packaged selection-refresh timer from the installed CLI."""
    catalog._require_root()
    cli = release_cli()
    SYSTEMD_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    catalog._check_root_path(SYSTEMD_DIR, directory=True)
    templates = Path(__file__).parent / "templates" / "systemd"
    for suffix in ("service", "timer"):
        name = "dc-overview-release-refresh." + suffix
        raw = (templates / name).read_text().replace("@RELEASE_CLI@", cli).encode()
        catalog._atomic_write(SYSTEMD_DIR / name, raw)
    subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=30)
    subprocess.run(["systemctl", "enable", "--now", "dc-overview-release-refresh.timer"], check=True, timeout=30)
