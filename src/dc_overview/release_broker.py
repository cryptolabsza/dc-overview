# TRACEWEAVER: file-role=release-owner; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
"""Fixed release dispatcher with durable previews, CAS and owner operation identity."""

import base64
import copy
import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

from . import release_catalog as catalog
from .release_candidates import GitHubDiscovery, require_compatible, verify_candidate

SOCKET_PATH = "/run/dc-overview-release-broker.sock"
POLICY_PATH = Path("/etc/dc-overview/releases/broker-policy.json")
MAX_REQUEST = 65536
MAX_RESPONSE = 1048576
TERMINAL = {"completed", "failed-restored", "selection-conflict"}


class BrokerError(RuntimeError):
    def __init__(self, code, message, status=409):
        super().__init__(message)
        self.code = code
        self.status = status


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _id(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value)


def _uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except ValueError:
        return False


def validate_actor(actor):
    if not isinstance(actor, dict):
        raise ValueError("invalid authenticated actor")
    if actor.get("kind") == "fleet-admin":
        if set(actor) != {"kind", "username", "subject"} or not all(
            isinstance(actor[k], str)
            and 1 <= len(actor[k]) <= 128
            and all(ord(c) >= 32 for c in actor[k])
            for k in ("username", "subject")
        ):
            raise ValueError("invalid authenticated actor")
    elif actor.get("kind") == "host-peer":
        if set(actor) != {"kind", "uid"} or type(actor["uid"]) is not int or actor["uid"] < 0:
            raise ValueError("invalid native actor")
    else:
        raise ValueError("invalid authenticated actor")


def validate_params(action, params):
    fields = {
        "list": {"channel"},
        "preview": {
            "candidate_ids",
            "components",
            "expected_selection_id",
            "expected_selection_sha256",
            "operation_kind",
        },
        "apply": {
            "operation_id",
            "preview_id",
            "preview_sha256",
            "expected_selection_id",
            "expected_selection_sha256",
        },
        "status": {"operation_id"},
        "recover": {"operation_id"},
    }
    if action not in fields or not isinstance(params, dict) or set(params) != fields[action]:
        raise ValueError("invalid release request fields")
    for key, value in params.items():
        if key in ("components", "candidate_ids"):
            if (
                not isinstance(value, list)
                or not 1 <= len(value) <= 32
                or not all(_id(v) for v in value)
                or len(value) != len(set(value))
                or key == "components"
                and any(n not in catalog.COMPONENTS for n in value)
            ):
                raise ValueError("invalid explicit release scope")
        elif key == "operation_id":
            if not _uuid(value):
                raise ValueError("canonical operation UUID required")
        elif key in ("preview_sha256", "expected_selection_sha256"):
            if not isinstance(value, str) or not catalog.HEX.fullmatch(value):
                raise ValueError("invalid release hash")
        elif key == "operation_kind":
            if value not in ("services-update", "proxy-adopt"):
                raise ValueError("invalid release operation")
        elif key == "channel":
            if value not in ("main", "dev"):
                raise ValueError("invalid release channel")
        elif not _id(value):
            raise ValueError("invalid release identifier")


def parse_request(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_REQUEST or not raw.endswith(b"\n"):
        raise ValueError("invalid release frame")
    value = catalog._json(raw)
    catalog._keys(value, {"schema_version", "action", "params", "actor"})
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("unsupported release request schema")
    validate_actor(value["actor"])
    validate_params(value["action"], value["params"])
    return value


def authorize_peer(uid, allowed_uids):
    if (
        not isinstance(allowed_uids, list)
        or not all(type(v) is int and v >= 0 for v in allowed_uids)
        or uid not in allowed_uids
    ):
        raise PermissionError("release peer is not authorized")


def _private(path, *, directory=False):
    path = Path(path)
    if (
        not path.is_absolute()
        or ".." in path.parts
        or any(p.is_symlink() for p in (path, *path.parents))
    ):
        raise PermissionError("unsafe broker custody")
    info = path.lstat()
    if (
        info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
        or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        or not directory
        and info.st_nlink != 1
    ):
        raise PermissionError("broker records require private root custody")


def private_write(path, value):
    path = Path(path)
    _private(path.parent, directory=True)
    if path.exists() or path.is_symlink():
        _private(path)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".broker-")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o600)
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_policy(path=POLICY_PATH):
    _private(path)
    policy = catalog._json(Path(path).read_bytes())
    if not isinstance(policy, dict) or type(policy.get("writes_enabled", False)) is not bool:
        raise ValueError("invalid installed broker policy")
    return policy


class InstalledOwner:
    """Only fixed installed APIs; paths originate in root policy and runtime mounts."""

    def __init__(self, config, policy):
        self.config = config
        self.policy = policy

    def capabilities(self, contract):
        from cryptolabs_proxy import updates

        from .fleet_upgrade import _scoped_proxy, _scoped_updater_directory, proxy_capabilities

        self.directory = _scoped_updater_directory(_scoped_proxy(self.config))
        host, live = updates.get_capabilities(), proxy_capabilities()
        for capabilities in (host, live):
            supported = capabilities.get(
                "supported_selection_contracts", [capabilities.get("selection_contract")]
            )
            if (
                not isinstance(supported, list)
                or any(type(v) is not int for v in supported)
                or contract not in supported
            ):
                raise BrokerError(
                    "owner-maintenance", "Installed and running owner capability upgrade required"
                )
            for name in ("release_components", "release_idempotency"):
                if type(capabilities.get(name)) is not int or capabilities[name] != 1:
                    raise BrokerError(
                        "owner-maintenance",
                        "Installed and running owner capability upgrade required",
                    )
        return {k: v for k, v in host.items() if live.get(k) == v}

    def identity(self):
        from .fleet_upgrade import _scoped_private

        value = _scoped_private(self.directory, directory=True)
        return {
            "updater_directory": str(self.directory),
            "device": value.st_dev,
            "inode": value.st_ino,
            "proxy_config_dir": self.policy.get("proxy_config_dir"),
            "declaration_path": self.policy.get("declaration_path"),
        }

    def submit(self, operation):
        from cryptolabs_proxy import updates

        try:
            return updates.submit_job(
                operation["components"][0],
                operation["channel"],
                "update",
                directory=self.directory,
                components=operation["components"],
                operation_id=operation["operation_id"],
                request_fingerprint=operation["request_fingerprint"],
                selection_id=operation["selection_id"],
                selection_sha256=operation["selection_sha256"],
                selection_directory=self.config.config_dir / "releases",
            )
        except updates.UpdateError as error:
            if str(error) == "selection_changed":
                raise BrokerError(
                    "selection-conflict", "Selected release changed before owner submission"
                ) from None
            raise

    def status(self, operation):
        from cryptolabs_proxy import updates

        try:
            return updates.operation_status(operation["operation_id"], directory=self.directory)
        except updates.UpdateError as error:
            if str(error) == "operation_not_found":
                return None
            raise

    def adoption(self):
        from cryptolabs_proxy.standard_adoption import StandardAdoption

        path = self.policy.get("declaration_path")
        config_dir = self.policy.get("proxy_config_dir")
        if not isinstance(path, str) or not isinstance(config_dir, str):
            raise BrokerError(
                "owner-maintenance", "Installed recoverable owner declaration required"
            )
        _private(path)
        settings = catalog._json(Path(path).read_bytes())
        return StandardAdoption(config_dir), settings

    def plan(self, proposed):
        from cryptolabs_proxy.release_selection import validate

        owner, settings = self.adoption()
        snapshot = validate(proposed.selection_raw, proposed.manifest.raw)
        result = owner.plan(settings, proposed_selection=snapshot)
        declaration = canonical(settings)
        self._planned_declaration = {
            "canonical_json_base64": base64.b64encode(declaration).decode(),
            "sha256": sha(declaration),
        }
        return result

    def declaration_evidence(self):
        return self._planned_declaration

    def adopt(self, plan):
        owner, settings = self.adoption()
        if owner.plan(settings) != plan:
            raise BrokerError(
                "source-conflict", "Proxy source or declaration changed after preview"
            )
        return owner.adopt(settings, plan["plan_id"])

    def recover(self, operation):
        if any(
            self.policy.get(k) != operation["owner_identity"].get(k)
            for k in ("proxy_config_dir", "declaration_path")
        ):
            raise BrokerError(
                "owner-maintenance",
                "Retained proxy owner policy changed; reconcile before recovery",
            )
        owner, settings = self.adoption()
        return owner.recover_adoption(operation["owner_plan"]["plan_id"])


class ReleaseBroker:
    def __init__(
        self, config, policy, *, discovery=None, owner=None, schedule=None, policy_loader=None
    ):
        self.config = config
        self.policy = policy
        self.policy_loader = policy_loader
        self.store = catalog.ReleaseStore(config.config_dir / "releases")
        self.root = self.store.root / "broker"
        self.discovery = discovery or GitHubDiscovery().discover
        self.owner = owner or InstalledOwner(config, policy)
        self.executor = None
        if schedule is None:
            self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="release-owner")
            self.schedule = self.executor.submit
        else:
            self.schedule = schedule

    def _ensure(self):
        catalog._require_root()
        catalog._check_root_path(self.store.root, directory=True)
        for path in (self.root, self.root / "previews", self.root / "operations"):
            if not path.exists():
                path.mkdir(mode=0o700)
            _private(path, directory=True)

    @contextmanager
    def _lock(self, name="dispatch"):
        self._ensure()
        path = self.root / (name + ".lock")
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            _private(path)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        except BlockingIOError:
            raise BrokerError("busy", "A release operation is already active") from None
        finally:
            os.close(descriptor)

    def _read(self, path):
        _private(path)
        return catalog._json(path.read_bytes())

    def _current(self):
        return self.store.load()

    def _candidates(self):
        with self._lock("admission"):
            return self._candidates_locked()

    def _candidates_locked(self):
        self._ensure()
        path = self.root / "high-water.json"
        watermark = self._read(path) if path.exists() else None
        # First installed trust acceptance starts at an explicit operator generation.
        minimum = self.policy.get("minimum_generation")
        if type(minimum) is not int or minimum < 1:
            raise BrokerError("unavailable", "Installed admission generation policy required", 503)
        if path.exists() and (
            not isinstance(watermark, dict)
            or set(watermark) != {"generation", "index_sha256"}
            or type(watermark["generation"]) is not int
            or watermark["generation"] < 1
            or not isinstance(watermark["index_sha256"], str)
            or not catalog.HEX.fullmatch(watermark["index_sha256"])
        ):
            raise BrokerError(
                "unavailable", "Installed admission high-water record is invalid", 503
            )
        highest = max(minimum, watermark["generation"] if watermark is not None else minimum)
        from datetime import datetime, timezone

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        from .release_candidates import _signed, _validity

        try:
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.policy["public_key_hex"]))
            maximum = self.policy["max_validity_seconds"]
            if type(maximum) is not int or maximum <= 0:
                raise ValueError()
        except (KeyError, ValueError, TypeError):
            raise BrokerError(
                "unavailable", "Installed release trust policy required", 503
            ) from None
        bundles = self.discovery()
        proofs = []
        indexes = []
        for bundle in bundles:
            if hasattr(bundle, "admission_raw"):
                values = (
                    bundle.manifest_raw,
                    bundle.admission_raw,
                    bundle.signature,
                    bundle.index_raw,
                    bundle.index_signature,
                )
            else:
                values = tuple(
                    bundle[n]
                    for n in (
                        "suite-release.json",
                        "suite-admission.json",
                        "suite-admission.sig",
                        "admission-index.json",
                        "admission-index.sig",
                    )
                )
            proofs.append(values)
            try:
                index = _signed(values[3], values[4], key)
                catalog._keys(
                    index,
                    {
                        "schema_version",
                        "generation",
                        "issued_at",
                        "expires_at",
                        "candidates",
                        "revoked",
                    },
                )
                _validity(index, datetime.now(timezone.utc), maximum)
                if (
                    not isinstance(index["candidates"], dict)
                    or len(index["candidates"]) > 1024
                    or any(
                        not isinstance(k, str)
                        or not catalog.HEX.fullmatch(k)
                        or not isinstance(v, str)
                        or not catalog.HEX.fullmatch(v)
                        for k, v in index["candidates"].items()
                    )
                    or not isinstance(index["revoked"], list)
                    or len(index["revoked"]) > 1024
                    or any(
                        not isinstance(v, str) or not catalog.HEX.fullmatch(v)
                        for v in index["revoked"]
                    )
                    or len(set(index["revoked"])) != len(index["revoked"])
                ):
                    raise ValueError("invalid signed index")
                if index["generation"] >= highest:
                    indexes.append((index, values[3], values[4]))
            except (ValueError, KeyError, TypeError):
                continue
        if not indexes:
            raise BrokerError("unavailable", "Fresh current admission index unavailable", 503)
        newest_index, index_raw, index_signature = max(
            indexes, key=lambda item: item[0]["generation"]
        )
        if any(
            index["generation"] == newest_index["generation"] and raw != index_raw
            for index, raw, _ in indexes
        ):
            raise BrokerError("unavailable", "Admission index generation is inconsistent", 503)
        if (
            watermark
            and newest_index["generation"] == watermark["generation"]
            and sha(index_raw) != watermark["index_sha256"]
        ):
            raise BrokerError("unavailable", "Admission index generation is inconsistent", 503)
        # A valid all-revoked index also advances durable replay protection.
        private_write(
            path, {"generation": newest_index["generation"], "index_sha256": sha(index_raw)}
        )
        result = []
        for values in proofs:
            try:
                result.append(
                    verify_candidate(
                        *values[:3],
                        index_raw,
                        index_signature,
                        self.policy,
                        highest_generation=highest,
                    )
                )
            except ValueError:
                continue
        if not result:
            raise BrokerError("unavailable", "No fresh admitted releases are available", 503)
        newest = max(result, key=lambda c: c.index["generation"])
        result = [c for c in result if c.index_raw == newest.index_raw]
        private_write(
            path, {"generation": newest.index["generation"], "index_sha256": sha(newest.index_raw)}
        )
        return {c.candidate_id: c for c in result}

    # TRACEWEAVER: entrypoint=dispatch; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
    def _reload_policy(self):
        if self.policy_loader is not None:
            self.policy = self.policy_loader()
            if isinstance(self.owner, InstalledOwner):
                self.owner.policy = self.policy

    def dispatch(self, action, params, *, actor):
        self._reload_policy()
        validate_actor(actor)
        validate_params(action, params)
        if action == "list":
            with self._lock():
                candidates = self._candidates()
                current = self._current()
                selected = {
                    "selection_id": current.selection["selection_id"],
                    "selection_sha256": current.selection_sha256,
                    "manifest_sha256": current.manifest.sha256,
                    "components": {
                        name: {
                            **policy,
                            "owner": current.manifest.data["components"][name]["owner"],
                            "release": current.manifest.data["components"][name]["release"],
                            "channel": current.manifest.data.get("component_channels", {}).get(
                                name, "main"
                            ),
                            "identity": (
                                catalog.artifact_identity(
                                    current.manifest.data["components"][name]["artifacts"].get(
                                        current.platform,
                                        current.manifest.data["components"][name]["artifacts"].get(
                                            "any", {}
                                        ),
                                    )
                                )
                                if current.platform
                                in current.manifest.data["components"][name]["artifacts"]
                                or "any" in current.manifest.data["components"][name]["artifacts"]
                                else None
                            ),
                        }
                        for name, policy in current.selection["components"].items()
                    },
                }
                return {
                    "channel": params["channel"],
                    "writes_enabled": self.policy.get("writes_enabled") is True,
                    "selected": selected,
                    "candidates": [
                        {
                            "candidate_id": c.candidate_id,
                            "manifest_sha256": c.manifest.sha256,
                            "generation": c.index["generation"],
                            "components": [
                                {
                                    **a,
                                    "release": c.manifest.data["components"][a["component"]][
                                        "release"
                                    ],
                                }
                                for a in c.admission["component_admissions"]
                                if a["channel"] == params["channel"]
                            ],
                        }
                        for c in candidates.values()
                        if any(
                            a["channel"] == params["channel"]
                            for a in c.admission["component_admissions"]
                        )
                    ],
                }
        if action == "preview":
            with self._lock():
                return self._preview(params, actor)
        if action == "apply":
            with self._lock():
                return self._apply(params, actor)
        self._ensure()
        path = self.root / "operations" / (params["operation_id"] + ".json")
        if not path.exists():
            raise BrokerError("not-found", "Release operation not found", 404)
        operation = self._read(path)
        if action == "status" and operation["state"] not in TERMINAL:
            self.schedule(self.run_operation, operation["operation_id"])
        if action == "recover":
            if self.policy.get("writes_enabled") is not True:
                raise BrokerError("disabled", "Release writes are disabled", 503)
            self.schedule(self.run_operation, operation["operation_id"])
        return self._public(operation)

    def _check_expected(self, current, params):
        if (
            current.selection["selection_id"] != params["expected_selection_id"]
            or current.selection_sha256 != params["expected_selection_sha256"]
        ):
            raise BrokerError("selection-conflict", "Selection changed after release preview")

    def _preview(self, params, actor):
        current = self._current()
        self._check_expected(current, params)
        available = self._candidates()
        try:
            candidates = [available[n] for n in params["candidate_ids"]]
        except KeyError:
            raise BrokerError("unavailable", "Candidate is unavailable", 503) from None
        data = copy.deepcopy(current.manifest.data)
        data["baseline_id"] = "release-" + uuid.uuid4().hex
        caps = self.owner.capabilities(
            max(c.manifest.data["selection_contract"] for c in candidates)
        )
        entries = require_compatible(
            candidates, params["components"], caps, current.platform, params["operation_kind"]
        )
        policy = copy.deepcopy(current.selection["components"])
        channels = data.get("component_channels", {}).copy()
        for name, entry in entries.items():
            if name not in current.targets:
                raise BrokerError(
                    "scope-unavailable", "Scoped component must already be managed and enabled"
                )
            source = next(c for c in candidates if entry in c.admission["component_admissions"])
            data["components"][name] = copy.deepcopy(source.manifest.data["components"][name])
            if entry["channel"] == "dev" or data["schema_version"] == 2:
                channels[name] = entry["channel"]
            if policy[name]["origin"] == "customer-pin":
                policy[name]["pin"] = entry["identity"]
        if channels:
            data.update(schema_version=2, selection_contract=2, component_channels=channels)
            self.owner.capabilities(2)
        manifest = catalog.Manifest.from_bytes(canonical(data))
        selection = {
            "schema_version": 1,
            "selection_id": data["baseline_id"],
            "manifest_sha256": manifest.sha256,
            "components": policy,
        }
        selection_raw = (
            json.dumps(selection, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        proposed = catalog.PreparedSelection(
            manifest,
            selection,
            selection_raw,
            sha(selection_raw),
            catalog.resolve(manifest, selection, current.platform),
            current.platform,
        )
        owner_plan = None
        owner_declaration = None
        if params["operation_kind"] == "proxy-adopt":
            if caps.get("proxy_selection_preview") != 1 or caps.get("proxy_adoption_recovery") != 1:
                raise BrokerError("owner-maintenance", "Installed recoverable proxy owner required")
            owner_plan = self.owner.plan(proposed)
            owner_declaration = self.owner.declaration_evidence()
        preview_id = str(uuid.uuid4())
        value = {
            "preview_id": preview_id,
            "actor": actor,
            "request": params,
            "manifest": base64.b64encode(manifest.raw).decode(),
            "selection_sha256": proposed.selection_sha256,
            "selection_id": selection["selection_id"],
            "manifest_sha256": manifest.sha256,
            "generation": max(c.index["generation"] for c in candidates),
            "owner_plan": owner_plan,
            "owner_declaration": owner_declaration,
            "public_sha256": sha((self.config.config_dir / "fleet-config.yaml").read_bytes()),
            "owner_identity": self.owner.identity(),
            "policy_sha256": sha(canonical(self.policy)),
            "channel": next(iter(entries.values()))["channel"],
        }
        if len(canonical(value)) > 900000:
            raise BrokerError("unavailable", "Release preview exceeds retained record limit", 503)
        digest = sha(canonical(value))
        value["preview_sha256"] = digest
        private_write(self.root / "previews" / (preview_id + ".json"), value)
        return {
            k: value[k]
            for k in (
                "preview_id",
                "preview_sha256",
                "selection_id",
                "selection_sha256",
                "manifest_sha256",
                "generation",
                "owner_plan",
            )
        } | {
            "components": params["components"],
            "operation_kind": params["operation_kind"],
            "disconnect_expected": params["operation_kind"] == "proxy-adopt",
        }

    def _apply(self, params, actor):
        fingerprint = sha(canonical({"params": params, "actor": actor}))
        path = self.root / "operations" / (params["operation_id"] + ".json")
        if path.exists():
            previous = self._read(path)
            if previous["request_fingerprint"] != fingerprint:
                raise BrokerError("id-conflict", "Operation ID is bound to a different request")
            return self._public(previous)
        if self.policy.get("writes_enabled") is not True:
            raise BrokerError("disabled", "Release writes are disabled", 503)
        for existing in (self.root / "operations").glob("*.json"):
            if self._read(existing)["state"] not in TERMINAL:
                raise BrokerError("busy", "Reconcile the existing release operation first")
        preview = self._preview_record(params["preview_id"])
        if preview["preview_sha256"] != params["preview_sha256"] or preview["actor"] != actor:
            raise BrokerError("preview-conflict", "Preview does not match authenticated request")
        self._check_expected(self._current(), params)
        if any(
            params[k] != preview["request"][k]
            for k in ("expected_selection_id", "expected_selection_sha256")
        ):
            raise BrokerError("preview-conflict", "Preview selection identity differs")
        self._fresh(preview)
        operation = {
            **preview,
            **params,
            "request_fingerprint": fingerprint,
            "state": "prepared",
            "components": preview["request"]["components"],
            "operation_kind": preview["request"]["operation_kind"],
            "phase": "selection",
        }
        private_write(path, operation)
        self.schedule(self.run_operation, params["operation_id"])
        return self._public(operation)

    def _preview_record(self, preview_id):
        value = self._read(self.root / "previews" / (preview_id + ".json"))
        content = {k: v for k, v in value.items() if k != "preview_sha256"}
        if sha(canonical(content)) != value.get("preview_sha256"):
            raise BrokerError("preview-conflict", "Preview content integrity check failed")
        return value

    def _fresh(self, operation):
        if operation["policy_sha256"] != sha(canonical(self.policy)):
            raise BrokerError("preview-conflict", "Installed release policy changed after preview")
        available = self._candidates()
        try:
            candidates = [available[n] for n in operation["request"]["candidate_ids"]]
        except KeyError:
            raise BrokerError(
                "unavailable", "Candidate revoked or no longer admitted", 503
            ) from None
        caps = self.owner.capabilities(
            max(c.manifest.data["selection_contract"] for c in candidates)
        )
        self._check_owner(operation)
        require_compatible(
            candidates,
            operation["request"]["components"],
            caps,
            self._current().platform,
            operation["request"]["operation_kind"],
        )
        if operation["request"]["operation_kind"] == "proxy-adopt" and (
            caps.get("proxy_selection_preview") != 1 or caps.get("proxy_adoption_recovery") != 1
        ):
            raise BrokerError("owner-maintenance", "Installed recoverable proxy owner required")

    def _check_owner(self, operation):
        if self.owner.identity() != operation["owner_identity"]:
            raise BrokerError(
                "owner-maintenance",
                "Updater store identity changed; reconcile retained owner operation",
            )

    def _public(self, value):
        keys = (
            "operation_id",
            "state",
            "components",
            "operation_kind",
            "selection_id",
            "selection_sha256",
            "manifest_sha256",
            "preview_id",
            "preview_sha256",
            "job_id",
            "reason",
            "observed_selection_id",
            "observed_selection_sha256",
        )
        return {k: value[k] for k in keys if k in value}

    def run_operation(self, operation_id):
        """Restart-safe progression: uncertain adoption goes only to fixed recovery."""
        with self._lock(operation_id):
            self._reload_policy()
            path = self.root / "operations" / (operation_id + ".json")
            operation = self._read(path)
            if operation["state"] in TERMINAL:
                return

            def save(**updates):
                operation.update(updates)
                private_write(path, operation)

            try:
                bound = self._preview_record(operation["preview_id"])
                if any(operation.get(k) != v for k, v in bound.items()):
                    raise BrokerError(
                        "preview-conflict", "Preview and retained operation identities differ"
                    )
                if operation["phase"] == "owner":
                    if operation["operation_kind"] == "proxy-adopt" and operation["state"] in (
                        "adopting",
                        "recovery-required",
                    ):
                        result = self.owner.recover(operation)
                        recovered = result.get("state") if isinstance(result, dict) else None
                        save(
                            state=(
                                recovered
                                if recovered in ("completed", "failed-restored")
                                else "recovery-required"
                            )
                        )
                        return
                    if operation["operation_kind"] == "services-update":
                        self.owner.capabilities(
                            catalog.Manifest.from_bytes(
                                base64.b64decode(operation["manifest"], validate=True)
                            ).data["selection_contract"]
                        )
                        self._check_owner(operation)
                        known = self.owner.status(operation)
                        if isinstance(known, dict):
                            state = known.get("state")
                            job_id = known.get("id", known.get("job_id"))
                            save(
                                state=(
                                    (
                                        "completed"
                                        if known.get("success") is True
                                        else "recovery-required"
                                    )
                                    if state == "completed"
                                    else (
                                        "updating"
                                        if state in ("queued", "running")
                                        else "recovery-required"
                                    )
                                ),
                                **({"job_id": job_id} if job_id else {}),
                            )
                            return
                if self.policy.get("writes_enabled") is not True:
                    return
                self._fresh(operation)
                if operation["phase"] == "selection":
                    from .fleet_upgrade import reconcile_release_operation

                    reconcile_release_operation(self.config, operation_id)
                current = self._current()
                if current.selection_sha256 != operation["selection_sha256"]:
                    if operation["phase"] != "selection":
                        save(
                            state="selection-conflict",
                            reason="Selected release changed before owner dispatch",
                        )
                        return
                    self._check_expected(current, operation["request"])
                    if (
                        sha((self.config.config_dir / "fleet-config.yaml").read_bytes())
                        != operation["public_sha256"]
                    ):
                        raise BrokerError(
                            "selection-conflict", "Configuration changed after preview"
                        )
                    save(state="selecting")
                    manifest_path = (
                        self.root / "previews" / (operation["preview_id"] + ".manifest.json")
                    )
                    # Bytes remain private; selector uses the same strict manifest parser.
                    private_write(
                        manifest_path,
                        catalog._json(base64.b64decode(operation["manifest"], validate=True)),
                    )
                    from .fleet_upgrade import select_release_components

                    select_release_components(
                        self.config,
                        manifest_path,
                        operation["components"],
                        platform=current.platform,
                        expected_selection_id=current.selection["selection_id"],
                        expected_selection_sha256=current.selection_sha256,
                        operation_id=operation_id,
                    )
                    if self._current().selection_sha256 != operation["selection_sha256"]:
                        save(
                            state="selection-conflict",
                            reason="Resulting selection differs from preview",
                        )
                        return
                save(
                    phase="owner",
                    state=(
                        "pending-submit"
                        if operation["operation_kind"] == "services-update"
                        else operation["state"]
                    ),
                )
                if operation["operation_kind"] == "services-update":
                    result = self.owner.status(operation)
                    if result is None:
                        self._fresh(operation)
                        result = self.owner.submit(operation)
                    if not isinstance(result, dict):
                        raise RuntimeError("owner result unavailable")
                    job_id = result.get("id", result.get("job_id"))
                    if job_id is not None:
                        save(job_id=job_id)
                    state = result.get("state")
                    if state == "completed":
                        save(
                            state=(
                                "completed"
                                if result.get("success") is True
                                else "recovery-required"
                            )
                        )
                    elif state in ("failed", "blocked"):
                        save(
                            state="recovery-required",
                            reason="Owner update did not verify; inspect retained owner result",
                        )
                    else:
                        save(state="updating")
                else:
                    if operation["state"] in ("adopting", "recovery-required"):
                        result = self.owner.recover(operation)
                    else:
                        self._fresh(operation)
                        save(state="adopting")
                        result = self.owner.adopt(operation["owner_plan"])
                    state = result.get("state") if isinstance(result, dict) else None
                    if state in ("completed", "adopted", "already_adopted"):
                        save(state="completed")
                    elif state == "failed-restored":
                        save(state="failed-restored")
                    else:
                        save(
                            state="recovery-required",
                            reason="Installed owner recovery verification required",
                        )
            except BrokerError as error:
                if error.code == "selection-conflict":
                    observed = self._current()
                    save(
                        observed_selection_id=observed.selection["selection_id"],
                        observed_selection_sha256=observed.selection_sha256,
                    )
                save(
                    state=(
                        "selection-conflict"
                        if error.code == "selection-conflict"
                        else "recovery-required"
                    ),
                    reason=str(error),
                )
            except (OSError, ValueError, RuntimeError, ImportError, TypeError, KeyError):
                save(
                    state="recovery-required",
                    reason="Owner operation interrupted; reconcile retained operation before retry",
                )

    def reconcile(self):
        self._ensure()
        for path in (self.root / "operations").glob("*.json"):
            operation = self._read(path)
            if operation["state"] not in TERMINAL:
                self.schedule(self.run_operation, operation["operation_id"])
