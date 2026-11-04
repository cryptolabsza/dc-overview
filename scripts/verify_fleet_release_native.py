#!/usr/bin/env python3
# TRACEWEAVER: file-role=native-verification; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
"""One sequential, guest-only integration proof. This is never a production installer."""

import argparse
import contextlib
import selectors
import threading
import dis
import hashlib
import importlib
import importlib.metadata
import json
import os
import platform
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
import tomllib
import types
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path

REGISTRY_IMAGE = "registry@sha256:1290056e2357eceb0c047cb60ae9abb370305a218e2df650eb8d3ea021b1c151"
NGINX_BASE = "nginx@sha256:2db7d28517d1fba17c2da3210395f7be11a11b419246ad0da2edf782af72f367"
IPMI_OLD = "ghcr.io/cryptolabsza/ipmi-monitor@sha256:738f11f7b432c4d9d8409154c9ca3f531a1e069999eb639a9d86433e84ac279d"
IPMI_NEW = "ghcr.io/cryptolabsza/ipmi-monitor@sha256:1d616479a3842f5101615b6d97552f732de73fd424fcb844a9c643e92abc8bb1"
ROOT = Path("/var/lib/fleet-native-qa")
CONFIG = Path("/etc/dc-overview")
PROXY_CONFIG = Path("/etc/cryptolabs-proxy")
POLICY = CONFIG / "releases/broker-policy.json"
REGISTRY_CA_DIR = Path("/etc/docker/certs.d/ghcr.io")
REGISTRY_HOSTS_SHA256 = "5b44770a4caca465e8991cbbaaa6a50eae52bc5d349700f4ca2c240ca0458629"
SOCKET = "/run/dc-overview-release-broker.sock"
SERVICE = "dc-overview-release-broker.service"
SOCKET_UNIT = "dc-overview-release-broker.socket"
ORIGIN = "https://127.0.0.1:18443"
# Filled from the accepted frozen source manifests, never from an untrusted runtime response.
FROZEN_PRODUCT_HASHES = {
    "dc": {
        "src/dc_overview/cli.py": "89490e41d09233df8ed05a67b2248377a8907a7bca3913a9138ab60b9431b71a",
        "src/dc_overview/fleet_upgrade.py": "c5a462957d94aae2fcc28634d046460c7bc7107b67369979cedc2dddfda0b48d",
        "src/dc_overview/release_broker.py": "137c990c00ba4d59ade7c8490b9fd9b574709f73c0d072466bbc41e253fbb33b",
        "src/dc_overview/release_broker_service.py": "92dbdf0d83c2aa3ef74a518947599102077c58ee85a95589690087052d115d08",
        "src/dc_overview/release_candidates.py": "bf8bd9145005901817cb4bbaa24726dbee20e7555e782e7383722e24df1d41a3",
        "src/dc_overview/release_catalog.py": "21d4cf4731226c4ca9498cd4999bec1ec90bb9d3628faa615e13f20ccd9a29f6",
        "src/dc_overview/templates/systemd/dc-overview-release-broker.service": "6128bf4553bd87458c680377e1b4490fc157b6f092072271bc77bd21b18c4612",
        "src/dc_overview/templates/systemd/dc-overview-release-broker.socket": "67994e4c1d4b2ac9fa4b44de9e8ba60db2b087424993fce77656c0618272c559",
    },
    "proxy": {
        "src/cryptolabs_proxy/update_recovery.py": "0063848821dd41d8f600e936a432bee10c80f9851ce0b99a00aea8aa43f29316",
        "src/cryptolabs_proxy/account_link.py": "c9f921e25ee0341c3b191064f1a57c94919310d5d4e08ec2c2c3030b964ea634",
        "landing-page/index.html": "20061e8140c5132b68f0bdc5a7ebfd48023534cf6f1ea7f2921ea6d04530ff37",
        "nginx/nginx.conf": "5a6f8bbd6c9121fb0b1a2fd4884205b996f52c332ae2e0ea9b026fc5a748ed7d",
        "scripts/health-api.py": "cc70687058e964b1afce202fed0117f8fee511cdece637f853eee2f25684e6d3",
        "src/cryptolabs_proxy/auth.py": "e9bda16030012f4045364ea4fa6929c6d42e6da5d4e1392259298fbcff3fb679",
        "src/cryptolabs_proxy/config.py": "cb921e11d4cf316df013c53bd36c7de89b0a8e5cb66df6dd3131f7425d15cf3f",
        "src/cryptolabs_proxy/release_client.py": "d3ed1dd31ea3a54f07a17772fefdbbb1bc9105880ab7b0d563f17d73a4332c25",
        "src/cryptolabs_proxy/release_selection.py": "b56a4dac88c8ef0c03500430ab1054bcf142e4bfaeef7edce67fce0f27f5b5d4",
        "src/cryptolabs_proxy/standard_adoption.py": "db2d257341c186fd8fc74c6a141854c9c46d19640964aa34b8799e0820971511",
        "src/cryptolabs_proxy/templates/docker-compose.yml.j2": "ec923fb17e99c649bb0aacd95eb8aeee465cfc9dbc6c65b721461cbf094a8856",
        "src/cryptolabs_proxy/templates/nginx.conf.j2": "d14273f48d5370f480870068b8bcf1ebb2a84a868979079ff97549ef8fcdd7ed",
        "src/cryptolabs_proxy/templates/previous-standard-nginx-444d7c0.conf.j2": "f12e2b9800cbaa0e49e685506cfaad38eb7e568fa6d239fa15277af59073d8de",
        "src/cryptolabs_proxy/templates/previous-standard-nginx-8e2b421.conf.j2": "05828b78143c5d6cd7cbe60700cfc54b627cb4efff9a7af43439fdb56e25edab",
        "src/cryptolabs_proxy/updates.py": "34735d28a4c9a91dbb33386060b2e0f5721c295a92951b9298e29fb1c9287bc9",
    },
}


def check_source_pin(value):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{40}", value):
        raise RuntimeError("Root must supply the exact published reviewed proxy source SHA")
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def fixture_hosts_bytes(original, certificate_path):
    """Add only default-server CA trust to the exact approved external recipe."""
    if digest(original) != REGISTRY_HOSTS_SHA256:
        raise RuntimeError("unsupported registry trust baseline; native gate held")
    parsed = tomllib.loads(original.decode())
    expected = {
        "server": "https://ghcr.io",
        "host": {
            "https://192.168.1.101:5444": {
                "capabilities": ["pull", "resolve"],
                "ca": "/etc/docker/certs.d/192.168.1.101:5444/ca.crt",
            }
        },
    }
    if parsed != expected:
        raise RuntimeError("unsupported registry trust semantics; native gate held")
    field = b"ca = [" + json.dumps(str(certificate_path)).encode() + b"]\n"
    offset = original.index(b"[host.")
    augmented = original[:offset] + field + original[offset:]
    after = tomllib.loads(augmented.decode())
    if after.pop("ca") != [str(certificate_path)] or after != parsed:
        raise RuntimeError("fixture trust augmentation is invalid; native gate held")
    if augmented[:offset] + augmented[offset + len(field) :] != original:
        raise RuntimeError("fixture trust preimage differs; native gate held")
    return augmented


def trust_identity(info):
    return info.st_dev, info.st_ino


def trust_metadata(info):
    return info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_mtime_ns


def trust_directories(path):
    """Compare-before-rename guards assume one exclusive fresh single-job guest."""
    identities = []
    for directory in (*reversed(path.parents), path):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("registry trust directory custody is invalid; native gate held")
        identities.append((str(directory), trust_identity(info)))
    return identities


def trust_read(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NOATIME", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or info.st_nlink != 1
            or info.st_size > 16384
            or os.listxattr(path, follow_symlinks=False)
        ):
            raise RuntimeError("registry trust file custody is invalid; native gate held")
        content = stream.read(16385)
        after = os.fstat(stream.fileno())
        if (
            len(content) > 16384
            or trust_identity(path.lstat()) != trust_identity(info)
            or trust_metadata(after) != trust_metadata(info)
            or after.st_size != info.st_size
        ):
            raise RuntimeError("registry trust file changed; native gate held")
    return content, info


def write(path, value, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    temporary.write_bytes(value if isinstance(value, bytes) else encoded(value))
    temporary.chmod(mode)
    os.replace(temporary, path)


# Whole child-output observations only; repeated literals never identify an executed guard.
SCOPED_SELECT_MESSAGES = (
    (b'Error: requires_cli_upgrade: install the verified exact wheel from the selected manifest using the documented package-manager step, then rerun this command\n', 'cli-provenance-rejected'),
    (b'Error: native_service_recovery_required\n', 'recovery-required'),
    (b'Error: updater is busy; retry scoped selection after it finishes\n', 'updater-busy'),
    (b'Error: updater custody changed during scoped selection\n', 'updater-custody-changed'),
    (b'Error: updater store changed during scoped selection\n', 'updater-store-changed'),
    (b'Error: updater lock changed during scoped selection\n', 'updater-lock-changed'),
    (b'Error: public configuration/selection snapshot is stale\n', 'public-reference-stale'),
    (b'Error: public configuration changed after release preflight\n', 'public-reference-changed'),
    (b'Error: running proxy identity is required for scoped selection\n', 'proxy-identity-required'),
    (b'Error: proxy changed during scoped selection\n', 'proxy-identity-changed'),
    (b'Error: proxy read-only release mount prerequisite\n', 'proxy-release-mount-required'),
    (b'Error: updater mount changed during scoped selection\n', 'updater-mount-changed'),
    (b'Error: manifest changed during scoped preparation\n', 'manifest-changed'),
    (b'Error: scoped runtime changed during selection\n', 'runtime-changed'),
    (b'Error: Proxy updater authority prerequisite: install the compatible published cryptolabs-proxy package, then use cryptolabs-proxy configuration plan and cryptolabs-proxy configuration adopt to migrate the existing proxy before retrying. The running updater must advertise selection contract 1 and proxy_replacement_policy=host-adoption-required-v1; no update was submitted or release changes applied.\n', 'proxy-authority-required'),
)


def scoped_select_category(value, categories=tuple(category for _, category in SCOPED_SELECT_MESSAGES)):
    if type(value) is not str:
        return "unknown"
    return next((category for category in categories if value == category), "unknown")


def classify_scoped_select_output(returncode, stdout, stderr, messages=SCOPED_SELECT_MESSAGES):
    """Project exact bounded built-in buffers into one fixed public category."""
    if (type(returncode) is not int or returncode != 1 or type(stdout) is not bytes
            or stdout != b"" or type(stderr) is not bytes or len(stderr) > 512):
        return "unknown"
    return next((category for literal, category in messages if stderr == literal), "unknown")


INNER_GUARDS = {
    "proxy-updates": ("service_recovery_dependency", "_validate_predecessor", "observe_original",
                      "_require_terminated_helper", "_require_recovery_capability",
                      "_needs_service_receipt", "_retains_predecessor"),
    "proxy-recovery": ("hold", "require", "strict_json", "_pairs", "_finite_float", "_pattern",
                       "validate_continuity", "validate_receipt", "_private", "open_existing_directory",
                       "read_private", "validate_job", "load_bound_job", "validate_original_restored",
                       "runtime_fingerprints", "_timestamp"),
}
_SCOPED_SELECT_DISPATCH_FRAME = None
_SCOPED_SELECT_TRACEBACK = None


CONTINUITY_FIELDS = (
    "runtime_config_sha256", "host_config_sha256", "mounts_sha256", "network_sha256",
    "schema_sha256", "settings_sha256", "stable_cloud_sha256", "stable_inventory_sha256",
    "saved_identity_sha256", "declared_config_sha256", "database_device", "database_inode",
)
_OBSERVATION_FIELDS = ("container_id", "image_id", "helper_terminated", "healthy", "continuity")


@dataclass(frozen=True)
class _ContinuityObservationShape:
    container_id: str
    image_id: str
    helper_terminated: bool
    healthy: bool
    continuity: dict


@dataclass(frozen=True, slots=True)
class _InnerTrustedContext:
    codes: tuple
    recovery_globals: dict
    observation_class: type

    def __iter__(self):
        return iter(self.codes)

    def __bool__(self):
        return bool(self.codes)


def bind_inner_trusted_context(codes, recovery):
    """Capture class identity after source qualification, before original execution."""
    if type(codes) is not tuple or type(recovery) is not types.ModuleType:
        return ()
    namespace = vars(recovery)
    cls = namespace.get("OriginalObservation")
    if not continuity_class_valid(namespace, cls):
        return codes  # Guard coordinates remain useful; field facts stay unbound.
    return _InnerTrustedContext(codes, namespace, cls)


def inner_unknown():
    return {"guards": [], "condition": "unknown", "require_capability": "unknown",
            "continuity_equal": "unknown"}


def continuity_equal_record(value):
    if (type(value) is not dict or any(type(k) is not str for k in value)
            or set(value) != set(CONTINUITY_FIELDS)
            or any(type(v) is not bool for v in value.values()) or all(value.values())):
        return "unknown"
    return {key: value[key] for key in CONTINUITY_FIELDS}


def continuity_values_valid(value):
    """Check primitives before comparing; never invoke a foreign equality method."""
    fixed = {"projection", "saved_identity_field_count", "stored_key_digest_matches", "sync_enabled"}
    if (type(value) is not dict or any(type(k) is not str for k in value)
            or set(value) != set(CONTINUITY_FIELDS) | fixed):
        return False
    for key in CONTINUITY_FIELDS[:10]:
        if type(value[key]) is not str or re.fullmatch("[0-9a-f]{64}", value[key]) is None:
            return False
    return (type(value["projection"]) is str and value["projection"] == "ipmi-original-continuity-v1"
            and type(value["database_device"]) is int and value["database_device"] >= 0
            and type(value["database_inode"]) is int and value["database_inode"] > 0
            and type(value["saved_identity_field_count"]) is int and value["saved_identity_field_count"] == 5
            and value["stored_key_digest_matches"] is True and value["sync_enabled"] is False)


def continuity_class_valid(namespace, cls):
    if type(cls) is not type:
        return False
    attributes = vars(cls)
    if (type(attributes.get("__module__")) is not str or type(namespace.get("__name__")) is not str
            or attributes["__module__"] != namespace["__name__"]
            or cls.__name__ != "OriginalObservation" or cls.__qualname__ != "OriginalObservation"
            or type(attributes.get("__match_args__")) is not tuple
            or any(type(k) is not str for k in attributes["__match_args__"])
            or attributes["__match_args__"] != _OBSERVATION_FIELDS
            or "__getattribute__" in attributes or "__getattr__" in attributes
            or any(name in attributes for name in _OBSERVATION_FIELDS)):
        return False
    for name in ("__init__", "__eq__", "__setattr__", "__delattr__", "__hash__"):
        method = attributes.get(name)
        if (type(method) is not types.FunctionType or method.__globals__ is not namespace
                or len(method.__code__.co_consts) > 16
                or any(not (type(c) in (str, int, bool, type(None)) or
                            (type(c) in (tuple, frozenset) and len(c) <= 8
                             and all(type(k) is str for k in c))) for c in method.__code__.co_consts)
                or not helper_code_matches(method.__code__, vars(_ContinuityObservationShape)[name].__code__)):
            return False
    descriptor = attributes.get("__dict__")
    if type(descriptor) is not types.GetSetDescriptorType or descriptor.__objclass__ is not cls:
        return False
    return True


def project_continuity_frame(frame, trusted):
    """Use the already captured exact guard frame, never rerun any observer/validator."""
    namespace, local = frame.f_globals, frame.f_locals
    if type(trusted) is not _InnerTrustedContext or trusted.recovery_globals is not namespace:
        return "unknown"
    observation, receipt = local.get("observation"), local.get("value")
    cls = trusted.observation_class
    if (namespace.get("OriginalObservation") is not cls or type(observation) is not cls
            or not continuity_class_valid(namespace, cls)):
        return "unknown"
    for name in ("validate_original_restored", "validate_receipt", "validate_job", "validate_continuity", "require", "hold", "_pattern"):
        function = namespace.get(name)
        if (type(function) is not types.FunctionType or function.__globals__ is not namespace
                or not any(code is function.__code__ and source == "proxy-recovery" and guard == name
                           for code, source, guard in trusted)):
            return "unknown"
    hashes, keys = namespace.get("HASH_KEYS"), namespace.get("CONTINUITY_KEYS")
    if (type(hashes) is not set or any(type(k) is not str for k in hashes)
            or hashes != set(CONTINUITY_FIELDS[:10]) or type(keys) is not set
            or any(type(k) is not str for k in keys)
            or keys != set(CONTINUITY_FIELDS) | {"projection", "saved_identity_field_count", "stored_key_digest_matches", "sync_enabled"}):
        return "unknown"
    descriptor = vars(cls)["__dict__"]
    state = descriptor.__get__(observation, cls)
    if (type(state) is not dict or any(type(k) is not str for k in state)
            or set(state) != set(_OBSERVATION_FIELDS)
            or state["helper_terminated"] is not True or state["healthy"] is not True
            or type(state["container_id"]) is not str or re.fullmatch("[0-9a-f]{64}", state["container_id"]) is None
            or type(state["image_id"]) is not str or re.fullmatch("sha256:[0-9a-f]{64}", state["image_id"]) is None
            or type(receipt) is not dict or any(type(k) is not str for k in receipt)
            or "continuity" not in receipt):
        return "unknown"
    before, after = receipt["continuity"], state["continuity"]
    if not continuity_values_valid(before) or not continuity_values_valid(after):
        return "unknown"
    return continuity_equal_record({key: before[key] == after[key] for key in CONTINUITY_FIELDS})


def inner_record(value):
    """Closed value schema; never coerce foreign objects or retain mutable input."""
    unknown = inner_unknown()
    if (type(value) is not dict or any(type(k) is not str for k in value)
            or set(value) != set(unknown)):
        return unknown
    guards = value["guards"]
    if type(guards) is not list or len(guards) > 256:
        return unknown
    result = inner_unknown()
    for row in guards:
        if (type(row) is not dict or any(type(k) is not str for k in row)
                or set(row) != {"source", "guard", "line"}):
            return unknown
        source, guard, line = row["source"], row["guard"], row["line"]
        if (type(source) is not str or source not in INNER_GUARDS or type(guard) is not str
                or guard not in INNER_GUARDS[source] or type(line) is not int or not 0 < line < 65536):
            return unknown
        result["guards"].append({"source": source, "guard": guard, "line": line})
    for key in ("condition", "require_capability"):
        fact = value[key]
        if type(fact) is not bool and not (type(fact) is str and fact == "unknown"):
            return unknown
        result[key] = fact
    equality = value["continuity_equal"]
    result["continuity_equal"] = continuity_equal_record(equality)
    if result["continuity_equal"] != "unknown" and (result["condition"] is not False
            or sum(g == {"source": "proxy-recovery", "guard": "validate_original_restored", "line": 228}
                   for g in result["guards"]) != 1):
        return unknown
    if result["continuity_equal"] == "unknown" and not (type(equality) is str and equality == "unknown"):
        return unknown
    if not guards and result != unknown:
        return unknown
    return result


def inner_contexts(error):
    contexts, seen = [], set()
    while error is not None:
        if id(error) in seen or len(contexts) == 8:
            return None
        seen.add(id(error))
        contexts.append(error)
        error = BaseException.__context__.__get__(error, type(error))
    return contexts


def project_inner_failure(error, trusted):
    """Read selected strict booleans only after exact loaded-code qualification."""
    contexts = inner_contexts(error)
    if contexts is None:
        return inner_unknown()
    result = inner_unknown()
    facts = {"condition": set(), "require_capability": set()}
    seen = set()
    continuity = []
    for context in contexts:
        if type(context) not in (ValueError, RuntimeError, TypeError, KeyError, OSError,
                                 FileNotFoundError, PermissionError):
            return inner_unknown()
        trace = BaseException.__traceback__.__get__(context, type(context))
        count, leaf = 0, None
        while trace is not None:
            if count == 32:
                return inner_unknown()
            count += 1
            code, line = trace.tb_frame.f_code, trace.tb_lineno
            leaf = next((row for row in trusted if row[0] is code), None)
            if leaf is not None:
                if type(line) is not int or line not in {n for _, _, n in code.co_lines()}:
                    return inner_unknown()
                _, source, guard = leaf
                coordinate = (source, guard, line)
                if coordinate not in seen:
                    result["guards"].append(dict(source=source, guard=guard, line=line))
                    seen.add(coordinate)
                key = ("condition" if (source, guard) == ("proxy-recovery", "require") else
                       "require_capability" if (source, guard) == ("proxy-updates", "service_recovery_dependency") else None)
                if key is not None:
                    value = trace.tb_frame.f_locals.get(key)
                    facts[key].add(value if type(value) is bool else "unknown")
                if (source, guard, line) == ("proxy-recovery", "validate_original_restored", 228):
                    try:
                        actual_line = next((n for start, end, n in code.co_lines()
                                            if start <= trace.tb_lasti < end), None)
                        continuity.append(project_continuity_frame(trace.tb_frame, trusted)
                                          if actual_line == 228 else "unknown")
                    except BaseException:
                        continuity.append("unknown")
            trace = trace.tb_next
        # An untrusted raise site cannot become a qualified failure merely
        # because an outer frame happened to be a recognized caller.
        if leaf is None:
            return inner_unknown()
    for key, values in facts.items():
        if len(values) == 1:
            result[key] = next(iter(values))
    if len(contexts) == 1 and len(continuity) == 1 and result["condition"] is False:
        result["continuity_equal"] = continuity[0]
    value = inner_record(result)
    return value if len(encoded(value)) <= 8192 else inner_unknown()


def inner_trusted_codes(wheels):
    """Bind installed functions to exact wheel bytes and frozen source bytes."""
    if type(wheels) is not list or len(wheels) != 2:
        return ()
    wheel_members = {}
    for row in wheels:
        if type(row) is not list or len(row) != 3 or any(type(v) is not str for v in row):
            return ()
        name, path, checksum = row
        if name not in ("dc-overview", "cryptolabs-proxy") or name in wheel_members:
            return ()
        raw = Path(path).read_bytes()
        if type(checksum) is not str or digest(raw) != checksum:
            return ()
        with zipfile.ZipFile(__import__("io").BytesIO(raw)) as archive:
            wheel_members[name] = {n: archive.read(n) for n in archive.namelist() if n.endswith(".py")}
    trusted = []
    for module_name, distribution, product, source_id in (
        ("dc_overview.fleet_upgrade", "dc-overview", "dc", None),
        ("cryptolabs_proxy.updates", "cryptolabs-proxy", "proxy", "proxy-updates"),
        ("cryptolabs_proxy.update_recovery", "cryptolabs-proxy", "proxy", "proxy-recovery"),
    ):
        module = importlib.import_module(module_name)
        member = module_name.replace(".", "/") + ".py"
        source = wheel_members[distribution][member]
        expected = FROZEN_PRODUCT_HASHES[product]["src/" + member]
        installed = importlib.metadata.distribution(distribution).locate_file(member).resolve()
        if (Path(module.__file__).resolve() != installed or digest(source) != expected
                or installed.read_bytes() != source):
            return ()
        compiled = compile(source, str(installed), "exec")
        definitions = {c.co_name: c for c in compiled.co_consts if type(c) is types.CodeType}
        for name in INNER_GUARDS.get(source_id, ()):
            function = vars(module).get(name)
            if name == "open_existing_directory" and type(function) is types.FunctionType:
                function = function.__dict__.get("__wrapped__")
            if (type(function) is not types.FunctionType
                    or not helper_code_matches(function.__code__, definitions[name])):
                return ()
            trusted.append((function.__code__, source_id, name))
    return bind_inner_trusted_context(tuple(trusted), module)


def scoped_select_child(descriptor, wheels, argv):
    """Execute the original console once under a bounded observation binding."""
    global _SCOPED_SELECT_TRACEBACK
    import runpy
    _SCOPED_SELECT_TRACEBACK = None
    invocation = sys._getframe()
    caller = invocation.f_back
    dispatch = (_SCOPED_SELECT_DISPATCH_FRAME, caller, invocation)
    runpy_codes = tuple(f.__code__ if type(f) is types.FunctionType else None
                        for f in (runpy.run_path, runpy._run_module_code, runpy._run_code))
    original, module, failures, trusted = None, None, [], ()
    try:
        trusted = inner_trusted_codes(wheels)
        if trusted:
            module = importlib.import_module("cryptolabs_proxy.updates")
            original = module.service_recovery_dependency
    except BaseException:
        pass  # Diagnostic setup never substitutes for the original console.
    def observed(*args, **kwargs):
        observer_invocation = sys._getframe()
        try:
            return original(*args, **kwargs)
        except BaseException as error:
            try:
                value = project_inner_failure(error, trusted)
            except BaseException:
                value = inner_unknown()
            # Multiple recovered failures cannot uniquely bind this observation.
            if len(failures) < 2:
                failures.append((error, value))
            try:
                trace = BaseException.__traceback__.__get__(error, type(error))
                if (trace is not None and trace.tb_frame is observer_invocation
                        and trace.tb_frame.f_code is observer_code):
                    # Remove our one invocation before the original caller can
                    # catch/contextualize it. Preserve every original node.
                    BaseException.__traceback__.__set__(error, trace.tb_next)
            except BaseException:
                pass  # A filtering fault must never replace the exception.
            raise
    observer_code = observed.__code__
    if original is not None:
        module.service_recovery_dependency = observed
    previous_argv, previous_path = sys.argv, sys.path[:]
    value = inner_unknown()
    try:
        sys.argv = argv
        sys.path[0] = str(Path(argv[0]).parent)
        runpy.run_path(argv[0], run_name="__main__")
    except BaseException as error:
        try:
            contexts = inner_contexts(error)
            if contexts is not None and len(failures) == 1 and any(e is failures[0][0] for e in contexts):
                value = failures[0][1]
        except BaseException:
            pass
        try:
            trace = BaseException.__traceback__.__get__(error, type(error))
            if (dispatch[0] is not None and caller.f_code is main.__code__
                    and caller.f_back is dispatch[0] and trace is not None
                    and trace.tb_frame is invocation):
                trace = trace.tb_next
                previous, scaffold = invocation, []
                for code in runpy_codes:
                    if (code is None or trace is None or trace.tb_frame.f_code is not code
                            or trace.tb_frame.f_back is not previous):
                        break
                    scaffold.append(trace.tb_frame)
                    previous, trace = trace.tb_frame, trace.tb_next
                else:
                    if trace is not None and trace.tb_frame.f_back is previous:
                        # Actual frame identities bind this single invocation
                        # prefix. Application-owned runpy calls follow it and
                        # are never searched or removed.
                        _SCOPED_SELECT_TRACEBACK = (error, (*dispatch, *scaffold), trace)
        except BaseException:
            pass
        raise
    finally:
        if original is not None:
            module.service_recovery_dependency = original
        sys.argv, sys.path[:] = previous_argv, previous_path
        try:
            raw = encoded(inner_record(value))
            if len(raw) <= 8192:
                os.write(descriptor, raw)  # One nonblocking write; partial means unknown.
        except BaseException:
            pass
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass


def scoped_select_subprocess(command, kwargs, wheels):
    """Private pipe only; no output readback extension or extra CLI invocation."""
    descriptors = []
    try:
        configuration = [[name, str(value[0]), value[2]] for name, value in wheels.items()]
        reader, writer = os.pipe()
        descriptors.extend((reader, writer))
        os.set_blocking(reader, False)
        os.set_blocking(writer, False)
        child = [str(Path(command[0]).parent / "python"), "-B", str(Path(__file__).resolve()),
                 "--scoped-select-child", str(writer), json.dumps(configuration), *command]
    except BaseException:
        for fd in descriptors:
            try:
                os.close(fd)
            except OSError:
                pass
        return subprocess.run(command, **kwargs), inner_unknown()
    try:
        result = subprocess.run(child, pass_fds=(writer,), **kwargs)
        try:
            os.close(writer)
            descriptors.remove(writer)
        except OSError:
            pass
        raw = b""
        try:
            while len(raw) <= 8192:
                chunk = os.read(reader, 8193 - len(raw))
                if not chunk:
                    break
                raw += chunk
            def unique(pairs):
                result = {}
                for key, item in pairs:
                    if key in result:
                        raise ValueError()
                    result[key] = item
                return result
            value = inner_record(json.loads(raw, object_pairs_hook=unique)) if 0 < len(raw) <= 8192 else inner_unknown()
        except BaseException:
            value = inner_unknown()
        return result, value
    finally:
        for fd in descriptors:
            try:
                os.close(fd)
            except OSError:
                pass


class NativeCommandFailure(RuntimeError):
    """Owned, bounded command facts; never retain arguments or captured output."""
    __slots__ = ("_command_outcome", "_command_returncode", "_scoped_select_diagnostic", "_scoped_select_inner_diagnostic")

    def __init__(self, outcome, returncode=None, scoped_select_diagnostic="unknown", inner=None):
        if hasattr(self, "_command_outcome") or hasattr(self, "_command_returncode"):
            raise AttributeError("command diagnostics are immutable")
        outcomes = {"nonzero-exit": "nonzero-exit", "timeout": "timeout", "spawn-error": "spawn-error"}
        outcome = outcomes.get(outcome, "unknown") if type(outcome) is str else "unknown"
        returncode = returncode if type(returncode) is int and -255 <= returncode <= 255 else None
        object.__setattr__(self, "_command_outcome", outcome)
        object.__setattr__(self, "_command_returncode", returncode)
        object.__setattr__(self, "_scoped_select_diagnostic", scoped_select_category(scoped_select_diagnostic))
        value = inner_record(inner)
        object.__setattr__(self, "_scoped_select_inner_diagnostic",
                           (tuple((g['source'], g['guard'], g['line']) for g in value['guards']),
                            value['condition'], value['require_capability'],
                            tuple(value['continuity_equal'].items()) if type(value['continuity_equal']) is dict else 'unknown'))
        message = "native command timed out; native gate held" if outcome == "timeout" else "native command failed; native gate held"
        RuntimeError.__init__(self, message)

    def __setattr__(self, name, value):
        if name in NativeCommandFailure.__slots__:
            raise AttributeError("command diagnostics are immutable")
        # Exception propagation/context managers must still manage traceback
        # and chaining attributes. Only the owned command facts are immutable.
        BaseException.__setattr__(self, name, value)

    def __delattr__(self, name):
        if name in NativeCommandFailure.__slots__:
            raise AttributeError("command diagnostics are immutable")
        BaseException.__delattr__(self, name)


def command_failure_facts(
    error,
    command_type=NativeCommandFailure,
    outcome_slot=NativeCommandFailure.__dict__["_command_outcome"],
    returncode_slot=NativeCommandFailure.__dict__["_command_returncode"],
):
    if type(error) is not command_type:
        return "unknown", None
    outcome = outcome_slot.__get__(error, command_type)
    returncode = returncode_slot.__get__(error, command_type)
    outcomes = {"nonzero-exit": "nonzero-exit", "timeout": "timeout", "spawn-error": "spawn-error"}
    return (outcomes.get(outcome, "unknown") if type(outcome) is str else "unknown",
            returncode if type(returncode) is int and -255 <= returncode <= 255 else None)


def scoped_select_failure_fact(
    error,
    command_type=NativeCommandFailure,
    diagnostic_slot=NativeCommandFailure.__dict__["_scoped_select_diagnostic"],
):
    if type(error) is not command_type:
        return "unknown"
    try:
        return scoped_select_category(diagnostic_slot.__get__(error, command_type))
    except AttributeError:
        return "unknown"


def scoped_select_inner_fact(error, command_type=NativeCommandFailure,
                            slot=NativeCommandFailure.__dict__["_scoped_select_inner_diagnostic"]):
    if type(error) is not command_type:
        return inner_unknown()
    try:
        guards, condition, capability, equality = slot.__get__(error, command_type)
        if type(guards) is not tuple or any(type(g) is not tuple or len(g) != 3 for g in guards):
            return inner_unknown()
        if type(equality) is tuple:
            if (len(equality) != len(CONTINUITY_FIELDS)
                    or any(type(row) is not tuple or len(row) != 2 or type(row[0]) is not str
                           or type(row[1]) is not bool for row in equality)
                    or set(key for key, _ in equality) != set(CONTINUITY_FIELDS)):
                return inner_unknown()
            equality = dict(equality)
        return inner_record({'guards': [dict(source=s, guard=g, line=n) for s, g, n in guards],
                             'condition': condition, 'require_capability': capability,
                             'continuity_equal': equality})
    except BaseException:
        return inner_unknown()


def run(*args, input_bytes=None, timeout=180, check=True, env=None, scoped_select_diagnostic=False,
        scoped_select_wheels=None):
    inner = inner_unknown()
    try:
        command = [str(a) for a in args]
        kwargs = dict(input=input_bytes, capture_output=True, timeout=timeout, env=env)
        if scoped_select_diagnostic is True and scoped_select_wheels is not None:
            result, inner = scoped_select_subprocess(command, kwargs, scoped_select_wheels)
        else:
            result = subprocess.run(command, **kwargs)
    except subprocess.TimeoutExpired:
        raise NativeCommandFailure("timeout") from None
    except OSError:
        raise NativeCommandFailure("spawn-error") from None
    if check and result.returncode:
        # Never expose inspected environments, auth files, command arguments or private snapshots.
        diagnostic = "unknown"
        if scoped_select_diagnostic is True:
            try:
                diagnostic = classify_scoped_select_output(result.returncode, result.stdout, result.stderr)
            except Exception:
                pass  # Collection must never replace the original checked command failure.
        raise NativeCommandFailure("nonzero-exit", result.returncode, diagnostic,
                                   inner if diagnostic == 'recovery-required' else None) from None
    return result


def docker(*args, **kwargs):
    return run("docker", *args, **kwargs)


def registry_push_signals(*outputs):
    # Match bytes in memory; only these literal observations may enter evidence.
    markers = (
        ("certificate-untrusted", (b"x509: certificate signed by unknown authority",)),
        (
            "certificate-name-or-time",
            (
                b"x509: certificate has expired or is not yet valid",
                b"x509: certificate is valid for",
                b"x509: cannot validate certificate for",
            ),
        ),
        ("client-certificate-configuration", (b"CA certificates should use the extension .crt.",)),
        (
            "tls-protocol",
            (
                b"server gave HTTP response to HTTPS client",
                b"tls: first record does not look like a TLS handshake",
            ),
        ),
        ("name-resolution", (b"no such host", b"Temporary failure in name resolution")),
        ("connection-refused", (b"connect: connection refused",)),
        ("timeout", (b"context deadline exceeded", b"i/o timeout", b"Client.Timeout exceeded")),
        (
            "registry-denied-or-auth",
            (
                b"unauthorized: authentication required",
                b"denied: requested access to the resource is denied",
            ),
        ),
        ("registry-http-error", (b"received unexpected HTTP status:", b"unexpected HTTP status")),
        (
            "manifest-or-blob-invalid",
            (
                b"manifest invalid",
                b"manifest unknown",
                b"blob unknown",
                b"blob upload invalid",
                b"unsupported manifest media type",
            ),
        ),
        ("storage-error", (b"no space left on device", b"read-only file system")),
    )
    return [
        signal
        for signal, values in markers
        if any(marker in output for marker in values for output in outputs)
    ] or ["unknown"]


def inspect(name, *, image=False):
    args = ("image", "inspect", name) if image else ("inspect", name)
    return json.loads(docker(*args).stdout)[0]


def wait(predicate, *, timeout=180, message="native condition timed out"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = predicate()
        except OSError:
            value = None
        if value:
            return value
        time.sleep(0.25)
    raise RuntimeError(message)


def raw_request(action="list", params=None, *, actor=None, payload=None):
    if payload is None:
        payload = encoded(
            {
                "schema_version": 1,
                "action": action,
                "params": params or {"channel": "main"},
                "actor": actor or {"kind": "host-peer", "uid": os.geteuid()},
            }
        )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(15)
        connection.connect(SOCKET)
        connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)
        data = bytearray()
        while True:
            part = connection.recv(65536)
            if not part:
                break
            data.extend(part)
            if len(data) > 1048576:
                raise RuntimeError("native response exceeded bound")
    return json.loads(data)


# TRACEWEAVER: diagnostic-boundary=broker-child; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
BROKER_CODE_LABELS = (
    "broker-serve", "broker-connection", "broker-response", "broker-init",
    "broker-policy", "broker-dispatch", "broker-reconcile", "broker-operation",
    "installed-owner-capabilities", "installed-owner-identity", "installed-owner-submit", "installed-owner-status",
    "proxy-submit-job", "proxy-submit-locked", "proxy-helper-request", "proxy-write-json",
    "proxy-installed-selection", "proxy-selection-plan", "proxy-require-selected-updater",
)
ERROR_KINDS = (
    "assertion-error", "file-not-found", "permission-error", "os-error", "runtime-error", "unknown",
)
SERVICE_ENUMS = {
    "ActiveState": ("active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing"),
    "SubState": ("dead", "condition", "start-pre", "start", "start-post", "running", "exited", "reload", "reload-signal", "reload-notify", "stop", "stop-watchdog", "stop-sigterm", "stop-sigkill", "stop-post", "final-watchdog", "final-sigterm", "final-sigkill", "failed", "auto-restart", "auto-restart-queued", "cleaning"),
    "Result": ("success", "resources", "protocol", "timeout", "exit-code", "signal", "core-dump", "watchdog", "start-limit-hit", "oom-kill", "exec-condition"),
}


def service_state(raw):
    """Project only a closed set of systemd properties; never copy unknown output."""
    result = {**dict.fromkeys(SERVICE_ENUMS, "unknown"), "MainPID": None, "ExecMainStatus": None}
    if not isinstance(raw, bytes) or len(raw) > 4096:
        return result
    fields = {}
    for line in raw.splitlines():
        key, _, value = line.partition(b"=")
        fields.setdefault(key, []).append(value)
    for key in result:
        values = fields.get(key.encode(), [])
        if len(values) != 1:
            continue
        value = values[0]
        if key in SERVICE_ENUMS:
            result[key] = next((item for item in SERVICE_ENUMS[key] if value == item.encode()), "unknown")
        elif re.fullmatch(rb"[0-9]{1,10}", value):
            number = int(value)
            if number <= (4194304 if key == "MainPID" else 255):
                result[key] = number
    return result


def parse_process_stat(raw, pid):
    """Read only kernel identity fields; the comm field is never exported."""
    if not isinstance(raw, bytes) or len(raw) > 4096:
        raise RuntimeError("process identity unavailable; native gate held")
    prefix = str(pid).encode() + b" ("
    close = raw.rfind(b") ")
    fields = raw[close + 2:].split() if close >= len(prefix) else []
    if (not raw.startswith(prefix) or not 20 <= len(fields) <= 64
            or fields[0] not in (b"R", b"S", b"D", b"Z", b"T", b"t", b"X", b"x", b"K", b"W", b"P", b"I", b"N")
            or any(not re.fullmatch(rb"-?[0-9]{1,20}", value) for value in fields[1:])
            or not re.fullmatch(rb"[0-9]{1,20}", fields[19])):
        raise RuntimeError("process identity unavailable; native gate held")
    start = int(fields[19])
    if not 1 <= start <= 18446744073709551615:
        raise RuntimeError("process identity unavailable; native gate held")
    return start, fields[0].decode("ascii")


def process_identity(pid):
    if type(pid) is not int or not 1 <= pid <= 4194304:
        raise RuntimeError("process identity unavailable; native gate held")
    try:
        descriptor = os.open(f"/proc/{pid}/stat", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as stream:
            raw = stream.read(4097)
    except FileNotFoundError:
        return None
    except OSError:
        raise RuntimeError("process identity unavailable; native gate held") from None
    return parse_process_stat(raw, pid)


def broker_failure_metadata(error, code_objects):
    result = {"code_label": None, "source_line": None, "error_kind": "unknown"}
    frame = error.__traceback__
    while frame is not None:
        for label, code in code_objects:
            if label in BROKER_CODE_LABELS and frame.tb_frame.f_code is code:
                metadata = fixture_failure_metadata(error, fixture_code=code)
                if metadata["fixture_line"] is not None:
                    result = {"code_label": label, "source_line": metadata["fixture_line"],
                              "error_kind": metadata["fixture_error_kind"]}
        frame = frame.tb_next
    return result


def child_failure_file(flags):
    """Only the fixture's private regular file; callers retain/check inode custody."""
    parent = ROOT.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) != 0o700):
        raise RuntimeError("child diagnostic directory custody held")
    descriptor = os.open(ROOT / "broker-child-failure.json", flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise RuntimeError("child diagnostic file custody held")
        return descriptor, info
    except Exception:
        os.close(descriptor)
        raise


def write_broker_failure(value):
    descriptor, _ = child_failure_file(os.O_WRONLY)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded(value))
        stream.truncate()


def inspect_owner_mounts_bounded():
    """One owned pipe, 1 MiB capture, four-second capture/five-second cleanup budget."""
    child = selector = None
    data = bytearray()
    captured = cleaned = False
    start = time.monotonic()
    try:
        child = subprocess.Popen(
            ["docker", "inspect", "cryptolabs-proxy"], shell=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            bufsize=0, close_fds=True,
        )
        descriptor = child.stdout.fileno()
        os.set_blocking(descriptor, False)
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ)
        while len(data) <= 1048576:
            remaining = start + 4 - time.monotonic()
            if remaining <= 0:
                break
            if not selector.select(remaining):
                continue
            if time.monotonic() >= start + 4:
                break
            try:
                chunk = os.read(descriptor, min(65536, 1048577 - len(data)))
            except BlockingIOError:
                continue
            data.extend(chunk)
            if len(data) > 1048576:
                break
            if not chunk:
                remaining = start + 4 - time.monotonic()
                if remaining > 0:
                    captured = child.wait(timeout=remaining) == 0
                break
    except Exception:
        captured = False
    finally:
        resources_closed = True
        if selector is not None:
            try:
                if child is not None:
                    selector.unregister(child.stdout)
            except Exception:
                pass
            try:
                selector.close()
            except Exception:
                resources_closed = False
        if child is not None:
            try:
                child.stdout.close()
            except Exception:
                resources_closed = False
            try:
                if child.poll() is None:
                    child.kill()
                remaining = start + 5 - time.monotonic()
                if remaining > 0:
                    child.wait(timeout=remaining)
                    cleaned = resources_closed
            except Exception:
                cleaned = False
    if captured and cleaned:
        try:
            return json.loads(data)
        except Exception:
            pass
    return None


def observation_uuid(value):
    return type(value) is str and str(uuid.UUID(value)) == value


def observation_directories(path, *, private=True):
    """No-follow ancestry plus exact producer custody at the selected directory."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError()
    identities = []
    for parent in (*reversed(path.parents), path):
        info = parent.lstat()
        # macOS exposes its OS-owned temporary tree through this fixed alias.
        # This portable fixture accommodation is never active in the Linux lane.
        if (platform.system() == 'Darwin' and parent == Path('/var')
                and stat.S_ISLNK(info.st_mode) and info.st_uid == 0
                and os.readlink(parent) == 'private/var'):
            info = Path('/private/var').lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()):
            raise ValueError()
        # Portable local tests use the OS temporary ancestor. The native Linux
        # fixture never allows writable ancestry, including sticky directories.
        if info.st_mode & 0o022 and not (platform.system() != 'Linux' and info.st_mode & stat.S_ISVTX):
            raise ValueError()
        identities.append((parent, trust_identity(info)))
    info = path.lstat()
    if private and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError()
    return identities


class ObservationAbsent(FileNotFoundError):
    """Initial open found no file under the same verified parent directories."""


def observation_read(path, limit, *, identity=None):
    """At most limit+1 returned bytes; reject replacement rather than infer absence."""
    path = Path(path)
    parents = observation_directories(path.parent)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if observation_directories(path.parent) != parents:
            raise ValueError() from None
        raise ObservationAbsent() from None
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > limit or (identity is not None and trust_identity(info) != identity)
                or trust_identity(path.lstat()) != trust_identity(info)):
            raise ValueError()
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - len(raw)))
            raw.extend(chunk)
            if not chunk or len(raw) > limit:
                break
        after = os.fstat(descriptor)
        if (len(raw) > limit or trust_identity(path.lstat()) != trust_identity(info)
                or trust_metadata(after) != trust_metadata(info) or after.st_size != info.st_size
                or observation_directories(path.parent) != parents):
            raise ValueError()
        return json.loads(raw)
    except FileNotFoundError:
        # Once opened, a lost pathname or ancestor is a custody race, not absence.
        raise ValueError() from None
    finally:
        os.close(descriptor)


def observation_failure_valid(value):
    if (type(value) is not dict or set(value) != {'code_label', 'source_line', 'error_kind'}
            or type(value['error_kind']) is not str or value['error_kind'] not in ERROR_KINDS):
        return False
    if value['code_label'] is None:
        return value == {'code_label': None, 'source_line': None, 'error_kind': 'unknown'}
    return (type(value['code_label']) is str and value['code_label'] in BROKER_CODE_LABELS
            and type(value['source_line']) is int and 1 <= value['source_line'] <= 1000000)


_owner_observation_lock = threading.Lock()
_owner_observation_identity = None


def owner_observation_file(flags):
    observation_directories(ROOT)
    path = ROOT / 'broker-owner-observation.json'
    descriptor = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or trust_identity(path.lstat()) != trust_identity(info)):
            raise ValueError()
        return descriptor, info
    except Exception:
        os.close(descriptor)
        raise


def write_owner_observation(operation_id, failure):
    if not _owner_observation_lock.acquire(blocking=False):
        return
    try:
        if not observation_uuid(operation_id) or not observation_failure_valid(failure):
            return
        raw = encoded({'schema_version': 1, 'operation_id': operation_id, 'failure': failure})
        if len(raw) > 4096 or _owner_observation_identity is None:
            return
        descriptor, info = owner_observation_file(os.O_WRONLY)
        try:
            if trust_identity(info) != _owner_observation_identity:
                return
            # A partial/interrupted diagnostic is unavailable; no journal/fsync.
            os.ftruncate(descriptor, 0)
            if os.write(descriptor, raw) != len(raw):
                return
        finally:
            os.close(descriptor)
    except Exception:
        pass
    finally:
        _owner_observation_lock.release()


def naturally_loaded_proxy_codes():
    """Only the naturally loaded, installed pinned module; no import or discovery."""
    module = sys.modules.get('cryptolabs_proxy.updates')
    if type(module) is not types.ModuleType:
        return ()
    path = Path(module.__file__)
    if (not path.is_relative_to(Path(sys.prefix)) or path.parts[-2:] != ('cryptolabs_proxy', 'updates.py')):
        return ()
    observation_directories(path.parent, private=False)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > 1048576:
            return ()
        raw = bytearray()
        while len(raw) <= 1048576:
            chunk = os.read(descriptor, min(65536, 1048577 - len(raw)))
            raw.extend(chunk)
            if not chunk or len(raw) > 1048576:
                break
        if (len(raw) > 1048576 or trust_identity(path.lstat()) != trust_identity(info)
                or trust_metadata(os.fstat(descriptor)) != trust_metadata(info)
                or digest(raw) != FROZEN_PRODUCT_HASHES['proxy']['src/cryptolabs_proxy/updates.py']):
            return ()
    finally:
        os.close(descriptor)
    return tuple((label, function.__code__) for label, function in (
        ('proxy-submit-job', module.submit_job), ('proxy-submit-locked', module._submit_job_locked),
        ('proxy-helper-request', module.helper_request), ('proxy-write-json', module._write_json),
        ('proxy-installed-selection', module.installed_selection), ('proxy-selection-plan', module._selection_plan),
        ('proxy-require-selected-updater', module._require_selected_updater),
    ) if type(function) is types.FunctionType)


@contextlib.contextmanager
def observe_broker_owner_failures(broker_module, operation_root, code_objects):
    original = broker_module.private_write
    codes = tuple(code_objects)
    proxy_codes = None
    def observed(*args, **kwargs):
        nonlocal proxy_codes
        result = original(*args, **kwargs)
        # Nothing diagnostic executes before a successful original write.
        try:
            error = sys.exception()
            if error is None or not args or type(args[0]) is not type(Path()):
                return result
            path = args[0]
            identity = path.stem
            if path != Path(operation_root) / (identity + '.json') or not observation_uuid(identity):
                return result
            frame = error.__traceback__
            eligible = False
            while frame is not None:
                if any(label == 'broker-operation' and frame.tb_frame.f_code is code for label, code in codes):
                    eligible = True
                frame = frame.tb_next
            if eligible:
                if proxy_codes is None:
                    found = naturally_loaded_proxy_codes()
                    if found:
                        proxy_codes = found
                write_owner_observation(identity, broker_failure_metadata(error, codes + (proxy_codes or ())))
        except Exception:
            pass
        return result
    broker_module.private_write = observed
    try:
        yield
    finally:
        broker_module.private_write = original


def broker_child():
    """Test discovery adapter plus handled-save observation; installed source bytes retained."""
    if os.geteuid() or platform.system() != "Linux":
        raise RuntimeError("fixture broker child is only for the disposable Linux guest")
    from dc_overview.fleet_config import FleetConfig
    from dc_overview.release_broker import ReleaseBroker, load_policy
    from dc_overview.release_broker_service import response, serve, serve_connection

    def fixture_assets():
        assets = ROOT / "admission"
        names = (
            "suite-release.json",
            "suite-admission.json",
            "suite-admission.sig",
            "admission-index.json",
            "admission-index.sig",
        )
        return [{name: (assets / name).read_bytes() for name in names}]

    # Freeze original installed function identities before executing any owner code.
    codes = tuple((label, function.__code__) for label, function in (
        ("broker-serve", serve), ("broker-connection", serve_connection),
        ("broker-response", response), ("broker-init", ReleaseBroker.__init__),
        ("broker-policy", ReleaseBroker._reload_policy), ("broker-dispatch", ReleaseBroker.dispatch),
        ("broker-reconcile", ReleaseBroker.reconcile), ("broker-operation", ReleaseBroker.run_operation),
    ))
    broker_module = sys.modules['dc_overview.release_broker']
    observer = contextlib.nullcontext()
    if type(broker_module) is types.ModuleType:
        owner = broker_module.InstalledOwner
        codes += tuple((label, function.__code__) for label, function in (
            ('installed-owner-capabilities', owner.capabilities), ('installed-owner-identity', owner.identity),
            ('installed-owner-submit', owner.submit), ('installed-owner-status', owner.status),
        ))
        try:
            global _owner_observation_identity
            descriptor, info = owner_observation_file(os.O_WRONLY)
            _owner_observation_identity = trust_identity(info)
            os.close(descriptor)
        except Exception:
            pass
        observer = observe_broker_owner_failures(broker_module, CONFIG / 'releases/broker/operations', codes)
    try:
        with observer:
            serve(
                ReleaseBroker(
                    FleetConfig.load(CONFIG),
                    load_policy(),
                    discovery=fixture_assets,
                    policy_loader=load_policy,
                )
            )
    except Exception as error:
        try:
            write_broker_failure(broker_failure_metadata(error, codes))
        except Exception:
            pass  # Preserve the original child failure even if collection fails.
        raise


def certificate(directory, hostname):
    import ipaddress
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    directory.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=4))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(hostname), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    write(directory / "server.crt", cert.public_bytes(serialization.Encoding.PEM), 0o644)
    write(
        directory / "server.key",
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )



"""Guest-only additions to the retained NativeQA lane. Never a host installer.

This file is composed into a COPY of the exact retained verifier. It does not
import source checkouts as product code and never edits package provenance.
"""
import contextlib
import http.server
import io
import ssl
import threading
import zipfile

LEGACY_PROXY = "ghcr.io/cryptolabsza/cryptolabs-proxy@sha256:bff38744e774875287e60e1e14995b19c7eb3afbe531d07f5921d06d9b76a1fd"
LEGACY_DESIRED = "ghcr.io/cryptolabsza/ipmi-monitor@sha256:dfa8a56159aab545d128b14bfb7d91cad17cac7de4f706307de508086fc56db9"
LEGACY_WHEELS = {
    "dc-overview": ("1.8.0", "72fcf2fde1d765cdfebfd2e4071261e3ff28d202f7ffb1975340e9d362969304"),
    "cryptolabs-proxy": ("1.5.4", "5e64f0ae59d38ebcf4885d8aa60822bc3187d5a63f9abb8bdd11927d1ffd2b47"),
}
PROTECTION_SHA = "c1bb469da0e7eaa1d733c6904f685e82aa9f33a5fd2cb7df947af67198697102"
RECOVERY_INPUTS_FROZEN = True  # root fills only after final exact source/pin review


def check_recovery_inputs(proxy_sha):
    check_source_pin(proxy_sha)
    if RECOVERY_INPUTS_FROZEN is not True:
        raise RuntimeError('reviewed final recovery inputs are unresolved; native gate held')


def recovery_store_snapshot(directory):
    return {path.name: (path.read_bytes(), path.stat().st_ino)
            for path in directory.iterdir() if path.is_file()}


def verify_recovery_store(directory, before, job_id, original_id):
    receipt_name = 'service-recovery-' + job_id + '.json'
    assert {p.name for p in directory.iterdir()} == set(before) | {receipt_name}
    for name, (raw, inode) in before.items():
        path = directory / name
        assert path.read_bytes() == raw and path.stat().st_ino == inode
    receipt_path = directory / receipt_name
    info = receipt_path.lstat()
    assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_uid == os.geteuid() and info.st_nlink == 1
    receipt = receipt_path.read_bytes()
    assert len(receipt) <= 16384
    parsed = json.loads(receipt)
    assert parsed['job_sha256'] == digest(before[job_id + '.json'][0])
    assert parsed['active_sha256'] == digest(before['active.json'][0])
    assert parsed['original_container_id'] == original_id
    return receipt


def wheel_info(path):
    from email.parser import BytesParser
    with zipfile.ZipFile(path) as archive:
        names = [n for n in archive.namelist() if n.endswith('.dist-info/METADATA')]
        if len(names) != 1:
            raise RuntimeError('wheel metadata ambiguity')
        info = BytesParser().parsebytes(archive.read(names[0]))
        return info['Name'].replace('_', '-'), info['Version']


class LegacyRecoveryFixture:
    def __init__(self, qa):
        self.qa = qa
        self.server = None
        self.thread = None
        self.github_hosts = None
        self.host_env = ROOT / 'legacy-host-venv'
        self.backup_root = Path('/var/backups/cryptolabs/ipmi132')
        self.backup_root_identity = None
        self.backups = []
        self.legacy = {}
        self.current = {}

    def validate_inputs(self):
        for directory, destination in ((self.qa.args.legacy_wheel_dir, self.legacy),
                                       (self.qa.args.wheel_dir, self.current)):
            for path in directory.glob('*.whl'):
                name, version = wheel_info(path)
                if name not in LEGACY_WHEELS:
                    continue
                if name in destination:
                    raise RuntimeError('duplicate fixture product wheel')
                destination[name] = (path.resolve(), version, digest(path.read_bytes()))
        if set(self.legacy) != set(LEGACY_WHEELS) or set(self.current) != set(LEGACY_WHEELS):
            raise RuntimeError('exact legacy and compatible wheel pairs required')
        for name, (version, checksum) in LEGACY_WHEELS.items():
            if self.legacy[name][1:] != (version, checksum):
                raise RuntimeError('legacy immutable wheel differs')
        if digest(self.qa.args.protection_helper.read_bytes()) != PROTECTION_SHA:
            raise RuntimeError('retained synthetic protection helper differs')
        for path in (self.host_env, self.backup_root):
            if path.exists() or path.is_symlink():
                raise RuntimeError('fresh disposable guest fixture path occupied')

    def install_old_host(self):
        self.validate_inputs()
        run(sys.executable, '-m', 'venv', '--system-site-packages', self.host_env)
        run(self.host_env / 'bin/python', '-m', 'pip', 'install', '--disable-pip-version-check',
            *[str(value[0]) for value in self.legacy.values()], timeout=300)
        self.assert_host_versions({name: v[0] for name, v in LEGACY_WHEELS.items()})
        help_text = run(self.host_env / 'bin/dc-overview', 'release', '--help').stdout
        assert b'reconcile-service' not in help_text
        run(self.host_env / 'bin/python', '-I', '-c',
            'import dc_overview, cryptolabs_proxy; from cryptolabs_proxy.updates import submit_job')
        self.qa.record('actual-legacy-host-pair', result='passed',
                       installed_versions={name: v[0] for name, v in LEGACY_WHEELS.items()},
                       wheel_sha256={name: value[2] for name, value in self.legacy.items()})

    def assert_host_versions(self, expected):
        source = 'import importlib.metadata as m,json;print(json.dumps({n:m.version(n) for n in ' + repr(list(expected)) + '}))'
        found = json.loads(run(self.host_env / 'bin/python', '-I', '-c', source).stdout)
        assert found == expected

    def wheel_mirror(self):
        """Actual pip HTTPS provenance in the isolated guest; no dist-info editing.

        github.com is guest-loopback only, as ghcr.io already is in this lane.
        This is explicitly synthetic transport, never public release acceptance.
        """
        certificate(ROOT / 'wheel-certs', 'github.com')
        routes = {}
        self.urls = {}
        for name, (path, version, checksum) in self.current.items():
            route = '/cryptolabsza/' + name + '/releases/download/native-fixture/' + path.name
            routes[route] = path.read_bytes()
            self.urls[name] = 'https://github.com' + route
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                payload = routes.get(self.path)
                if payload is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            def log_message(self, *args):
                pass
        hosts = Path('/etc/hosts').read_bytes()
        if any('github.com' in line.split('#')[0].split()[1:] for line in hosts.decode().splitlines()):
            raise RuntimeError('github fixture host mapping occupied')
        self.server = http.server.ThreadingHTTPServer(('127.0.0.2', 443), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(ROOT / 'wheel-certs/server.crt', ROOT / 'wheel-certs/server.key')
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.github_hosts = hosts
        Path('/etc/hosts').write_bytes(self.github_hosts + b'\n127.0.0.2 github.com # fleet-native-owned-wheel-mirror\n')
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def install_compatible_host(self):
        self.wheel_mirror()
        env = {k: v for k, v in os.environ.items() if k not in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
               'http_proxy', 'https_proxy', 'all_proxy', 'PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL')}
        env['NO_PROXY'] = 'github.com,127.0.0.2'
        run(self.host_env / 'bin/python', '-m', 'pip', 'install', '--no-deps', '--force-reinstall',
            '--cert', ROOT / 'wheel-certs/server.crt',
            *[self.urls[name] + '#sha256=' + value[2] for name, value in self.current.items()],
            env=env, timeout=180)
        self.assert_host_versions({name: value[1] for name, value in self.current.items()})
        # Full import checks the actual proxy __init__/setup/Jinja2 dependency closure.
        run(self.host_env / 'bin/python', '-I', '-c',
            'import dc_overview, cryptolabs_proxy; from dc_overview.fleet_upgrade import reconcile_service')
        link = Path('/usr/local/bin/dc-overview')
        assert link.is_symlink() and link.resolve() == Path(sys.executable).parent / 'dc-overview'
        link.unlink()
        link.symlink_to(self.host_env / 'bin/dc-overview')

    def seed_synthetic_selected_state(self):
        """Only owned synthetic DB. No network credentials or real collection claim."""
        _bootstrap_step = "synthetic-runtime-inspect"
        qa = self.qa
        original = inspect('ipmi-monitor')
        mounts = [m for m in original['Mounts'] if m['Destination'] == '/app/data']
        assert len(mounts) == 1
        assert mounts[0]['Type'] == 'volume' and mounts[0].get('Name') in qa.volumes
        database = Path(mounts[0]['Source']) / 'ipmi_events.db'
        import sqlite3
        from datetime import datetime, timezone
        _bootstrap_step = "synthetic-db-seed"
        with sqlite3.connect(database) as db:
            credential = 'SYNTHETIC-NONSECRET-NOT-A-CREDENTIAL'
            fields = {'ai_link_email': 'fixture@example.invalid', 'ai_link_user_id': 'fixture-user',
                      'ai_link_customer_id': 'fixture-customer', 'ai_link_linked_at': '2026-11-02T00:00:00Z',
                      'ai_link_key_digest': digest(credential.encode())}
            for key, value in fields.items():
                db.execute('DELETE FROM system_settings WHERE key=?', (key,))
                db.execute('INSERT INTO system_settings(key,value) VALUES (?,?)', (key, value))
            count = db.execute('SELECT count(*) FROM cloud_sync').fetchone()[0]
            assert count <= 1
            if not count:
                db.execute('INSERT INTO cloud_sync(id) VALUES (1)')
            db.execute('UPDATE cloud_sync SET license_key=?,sync_enabled=0,subscription_valid=1', (credential,))
            sampled_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
            db.execute("INSERT OR REPLACE INTO server_status(bmc_ip,server_name,last_check) VALUES ('192.0.2.254','SYNTHETIC-no-collector',?)", (sampled_at,))
        # Import only retained verification code, never product checkout modules.
        _bootstrap_step = "synthetic-read-aggregate"
        import importlib.util
        spec = importlib.util.spec_from_file_location('synthetic_protection', qa.args.protection_helper)
        helper = importlib.util.module_from_spec(spec)
        try:
            helper_source = qa.args.protection_helper.read_bytes()
        except Exception:
            helper_source = None  # Diagnostics never add a new bootstrap gate.
        spec.loader.exec_module(helper)
        try:
            capture_helper_diagnostics(helper, helper_source, str(qa.args.protection_helper))
        except Exception:
            pass  # Unavailable diagnostic identity must not alter the helper.
        deadline = time.monotonic() + 30
        ro = helper.open_ro(database, deadline)
        try:
            names = {row[0] for row in ro.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            state = helper.table_snapshot(ro, names & set(helper.SELECTED))
            baseline = helper.state_aggregate(state, 'ltx')
            schema = helper.fingerprint(ro.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name').fetchall())
        finally:
            ro.close()
        declared = {}
        for name in ('/app/config/servers.yaml', '/app/data/servers.json'):
            path = (Path(next(m['Source'] for m in original['Mounts'] if m['Destination'] == name))
                    if name.endswith('servers.yaml') else database.parent / 'servers.json')
            declared[name] = {'present': path.exists()}
            if path.exists():
                declared[name]['sha256'] = digest(path.read_bytes())
        with database.open('rb') as file:
            header = list(file.read(20)[18:20])
        helper.PINS = {'ltx': {'synthetic_fixture_only': True, 'data_volume_name': mounts[0]['Name'],
            'hostname': socket.gethostname(), 'container_id': original['Id'],
            'image_id': original['Image'], 'mounts': original['Mounts'],
            'database_device': database.stat().st_dev, 'database_inode': database.stat().st_ino,
            'journal_header_bytes': header, 'table_names': sorted(names), 'secret_mount_metadata': [],
            'declared_config': declared,
            'link_baseline': {key: baseline[key] for key in ('saved_identity_sha256', 'saved_identity_field_count',
                'saved_identity_complete', 'identity_mode', 'credential_present', 'credential_sha256',
                'stored_key_digest_matches', 'expected_email_matches', 'sync_enabled')},
            'schema_sha256': schema,
            'protection_baseline': {key: baseline[key] for key in ('stable_cloud_sha256', 'settings_sha256',
                 'stable_inventory_sha256', 'cached_subscription_valid')},
            'selected_count_bounds': {key: [value, value] for key, value in baseline['counts'].items()}}}
        capture = io.StringIO()
        _bootstrap_step = "synthetic-root-custody"
        self.backup_root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        helper.safe_chain(self.backup_root.parent)
        self.claim_backup_root()
        _bootstrap_step = "synthetic-protection-helper"
        with contextlib.redirect_stdout(capture):
            helper.main('ltx')
        result = json.loads(capture.getvalue())
        self.backups.append(Path(result['operation_dir']))
        qa.record('synthetic-continuity-baseline', result='passed',
                  receipt_sha256=result['receipt']['sha256'],
                  synthetic_health_timestamp=True, actual_collector_acceptance=False,
                  full_database_snapshot=False)

    def seed_failed_job(self):
        """Use real old submit constructor, intercept helper launch only.

        The terminal result is intentional fixture state; no historical phases
        are supplied, no real update is claimed to have failed in this setup.
        """
        code = '''
import json
from pathlib import Path
from cryptolabs_proxy import updates as u
class SeedEngine(u.UpdateEngine):
    def create(self, name, request):
        assert name.startswith('cryptolabs-update-')
        assert request['Config']['Image'] == self.inspect('cryptolabs-proxy')['Image']
    def start(self, name):
        assert name.startswith('cryptolabs-update-')
d=Path('/data/auth/update-jobs')
j=u.submit_job('ipmi-monitor','main','update',directory=d,engine=SeedEngine(),selection_directory='/etc/cryptolabs/releases')
assert {'id','helper','sources','targets','selection_snapshot','selection_sha256','manifest_sha256'} <= set(j)
j.update(state='failed',success=False,results={'ipmi-monitor':{'state':'recovery_required','success':False,'reason':'replacement_failed','desired':j['targets']['ipmi-monitor']['reference'],'observed':None,'owner':'proxy-updater','origin':j['targets']['ipmi-monitor']['origin'],'rollback_container':'ipmi-monitor'}})
u.write_job(d,j)
print(json.dumps({'id':j['id']}))
'''
        result = docker('exec', 'cryptolabs-proxy', 'python3', '-c', code)
        return json.loads(result.stdout)['id']

    def bootstrap(self):
        _bootstrap_step = "legacy-runtime-inspect"
        qa = self.qa
        old_proxy = inspect('cryptolabs-proxy')
        assert old_proxy['Image'] == inspect(LEGACY_PROXY, image=True)['Id']
        # Released images copy source; their stale OCI/__version__ strings are
        # not installed wheel metadata. Compare real updater bytes to old wheel.
        _bootstrap_step = "legacy-updater-probe"
        with zipfile.ZipFile(self.legacy['cryptolabs-proxy'][0]) as archive:
            expected_updater = digest(archive.read('cryptolabs_proxy/updates.py'))
        observed_updater = docker('exec', 'cryptolabs-proxy', 'python3', '-c',
            'import hashlib,pathlib;from cryptolabs_proxy import updates;print(hashlib.sha256(pathlib.Path(updates.__file__).read_bytes()).hexdigest())').stdout.decode().strip()
        assert observed_updater == expected_updater
        _bootstrap_step = "legacy-capabilities-probe"
        caps = json.loads(docker('exec', 'cryptolabs-proxy', 'python3', '-m',
                                'cryptolabs_proxy.updates', 'capabilities').stdout)
        assert caps.get('release_components') != 1 and caps.get('native_service_recovery') != 1
        _bootstrap_step = "synthetic-runtime-inspect"
        self.seed_synthetic_selected_state()
        _bootstrap_step = "legacy-job-seed"
        job_id = self.seed_failed_job()
        qa.legacy_job_id = job_id
        before = recovery_store_snapshot(qa.jobs)
        self.failed_job_raw = before[job_id + '.json'][0]
        selected_before = (qa.store.root / 'selection.json').read_bytes()
        public_before = (CONFIG / 'fleet-config.yaml').read_bytes()
        _bootstrap_step = "compatible-wheel-install"
        self.install_compatible_host()
        assert (qa.store.root / 'selection.json').read_bytes() == selected_before
        assert (CONFIG / 'fleet-config.yaml').read_bytes() == public_before
        # New broker owner must refuse actual legacy capabilities, even with
        # compatible host packages and valid synthetic admission installed.
        _bootstrap_step = "legacy-owner-rejection"
        from dc_overview.release_broker import InstalledOwner
        from dc_overview.fleet_config import FleetConfig
        try:
            InstalledOwner(FleetConfig.load(CONFIG), qa.policy).capabilities(1)
        except Exception as error:
            assert getattr(error, 'code', None) == 'owner-maintenance'
        else:
            raise AssertionError('legacy live owner unexpectedly accepted')
        cli = self.host_env / 'bin/dc-overview'
        arguments = ('release', 'reconcile-service', '--service', 'ipmi-monitor', '--job', job_id)
        _bootstrap_step = "legacy-reconcile"
        first = run(cli, *arguments, timeout=130)
        reply = json.loads(first.stdout)
        assert set(reply) == {'job_id', 'service', 'outcome', 'resolution_available', 'reason'}
        assert reply['job_id'] == job_id and reply['service'] == 'ipmi-monitor'
        assert reply['outcome'] == 'original_restored'
        receipt_name = 'service-recovery-' + job_id + '.json'
        receipt = verify_recovery_store(qa.jobs, before, job_id, inspect('ipmi-monitor')['Id'])
        parsed = json.loads(receipt)
        assert inspect('cryptolabs-proxy')['Id'] == old_proxy['Id']
        # Simulated lost CLI acknowledgement: disregard first reply, retry
        # the actual command; exact durable receipt and timestamp must survive.
        _bootstrap_step = "legacy-reconcile-replay"
        run(cli, *arguments, timeout=130)
        assert verify_recovery_store(qa.jobs, before, job_id, parsed['original_container_id']) == receipt
        assert (qa.store.root / 'selection.json').read_bytes() == selected_before
        assert (CONFIG / 'fleet-config.yaml').read_bytes() == public_before
        qa.record('legacy-reconcile-before-selection', result='passed', job_id=job_id,
                  proxy_image=LEGACY_PROXY, failed_job_sha256=parsed['job_sha256'],
                  active_sha256=parsed['active_sha256'], receipt_sha256=digest(receipt),
                  only_new_durable_file=receipt_name, lost_cli_ack_replay='same receipt bytes',
                  historical_phase_evidence='not fabricated')
        _bootstrap_step = "scoped-select"
        manifest = json.loads(qa.store.load(platform='linux/amd64').manifest.raw)
        manifest['baseline_id'] = 'native-compatible-bootstrap'
        manifest['components']['cryptolabs-proxy'] = qa.component('proxy-a')
        path, version, checksum = self.current['dc-overview']
        manifest['components']['dc-overview-cli'] = {'owner': 'host-cli', 'release': version,
            'artifacts': {'any': {'kind': 'wheel', 'url': self.urls['dc-overview'], 'sha256': checksum}}}
        candidate = qa.data / 'compatible-bootstrap.json'
        write(candidate, manifest)
        run(cli, 'release', 'select', '--release-manifest', candidate,
            '--component', 'cryptolabs-proxy', '--record-cli', scoped_select_diagnostic=True,
            scoped_select_wheels=self.current)
        assert (qa.jobs / (job_id + '.json')).read_bytes() == self.failed_job_raw
        assert (qa.jobs / 'active.json').read_bytes() == before['active.json'][0]
        _bootstrap_step = "proxy-plan"
        from cryptolabs_proxy.standard_adoption import StandardAdoption
        owner = StandardAdoption(PROXY_CONFIG)
        plan = owner.plan(qa.declaration)
        qa.owner_plans.add(plan['plan_id'])
        _bootstrap_step = "proxy-adopt"
        result = owner.adopt(qa.declaration, plan['plan_id'])
        assert result['state'] == 'adopted'
        assert inspect('cryptolabs-proxy')['Id'] != old_proxy['Id']
        assert inspect('cryptolabs-proxy')['Image'] == inspect(qa.refs['proxy-a'], image=True)['Id']
        assert (qa.jobs / (job_id + '.json')).read_bytes() == self.failed_job_raw
        assert (qa.jobs / 'active.json').read_bytes() == before['active.json'][0]
        assert any(m['Destination'] == SOCKET and not m['RW'] for m in inspect('cryptolabs-proxy')['Mounts'])
        assert qa.policy['writes_enabled'] is False
        _bootstrap_step = "proxy-health"
        qa.wait_healthy('cryptolabs-proxy')
        qa.record('legacy-host-select-socket-adopt', result='passed', old_proxy_id=old_proxy['Id'],
                  new_proxy_id=inspect('cryptolabs-proxy')['Id'], writes_enabled=False,
                  old_job_still_failed=True, new_durable_receipt_retained=True)

    def verify_successor(self, job_id):
        qa = self.qa
        successor = json.loads((qa.jobs / (job_id + '.json')).read_bytes())
        predecessor = successor['recovery_predecessor']
        assert predecessor['job_id'] == qa.legacy_job_id
        assert (qa.jobs / (qa.legacy_job_id + '.json')).read_bytes() == self.failed_job_raw
        receipt = (qa.jobs / ('service-recovery-' + qa.legacy_job_id + '.json')).read_bytes()
        assert predecessor['receipt_sha256'] == digest(receipt)
        qa.record('legacy-recovery-scoped-successor', result='passed', job_id=job_id,
                  predecessor_id=qa.legacy_job_id, original_failed_history_retained=True)

    def claim_backup_root(self):
        parent = self.backup_root.parent.lstat()
        assert stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and not parent.st_mode & 0o022
        self.backup_root.mkdir(mode=0o700)  # exclusive; never adopt a preexisting root
        info = self.backup_root.lstat()
        assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid()
        self.backup_root_identity = (info.st_dev, info.st_ino, info.st_uid)

    def reset(self):
        # Called after normal owned containers quiesce; retain on custody doubt.
        if self.backup_root_identity is not None:
            info = self.backup_root.lstat()
            assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
            assert (info.st_dev, info.st_ino, info.st_uid) == self.backup_root_identity and info.st_uid == os.geteuid()
            for directory in self.backups:
                assert directory.parent == self.backup_root and directory.is_dir() and not directory.is_symlink()
                shutil.rmtree(directory)
            self.backups.clear()
            self.backup_root.rmdir()
            self.backup_root_identity = None
        else:
            assert not self.backups
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=5)
            assert not self.thread.is_alive()
            self.server = None
        if self.github_hosts is not None:
            expected = self.github_hosts + b'\n127.0.0.2 github.com # fleet-native-owned-wheel-mirror\n'
            assert Path('/etc/hosts').read_bytes() == expected
            Path('/etc/hosts').write_bytes(self.github_hosts)
            self.github_hosts = None
        link = Path('/usr/local/bin/dc-overview')
        if link.is_symlink() and link.resolve() == self.host_env / 'bin/dc-overview':
            link.unlink()
            link.symlink_to(Path(sys.executable).parent / 'dc-overview')


class NativeQA:
    def __init__(self, args):
        self.args = args
        self.evidence = args.evidence_dir.resolve()
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.events = []
        self.label = "io.cryptolabs.native-qa.run=" + os.environ.get("FLEET_NATIVE_RUN_ID", "")
        self.hosts = None
        self.units = []
        self.volumes = []
        self.networks = []
        self.session = None
        self.cookie = None
        self.issuer = None
        self.assets = None
        self.generation = 0
        self.refs = {}
        self.policy = None
        self.owner_plans = set()
        self.job_ids = set()
        self.registry_ca_file = None
        self.registry_ca_identity = None
        self.registry_ca_created = False
        self.registry_baseline = None
        self.registry_trust = None
        self.fixture_owned = False
        self.child_failure_identity = None
        self.owner_observation_identity = None
        self.recovery = LegacyRecoveryFixture(self)

    def reset_owner_observation(self):
        global _owner_observation_identity
        flags = os.O_RDWR
        if self.owner_observation_identity is None:
            flags |= os.O_CREAT | os.O_EXCL
        descriptor, info = owner_observation_file(flags)
        try:
            if (self.owner_observation_identity is not None
                    and trust_identity(info) != self.owner_observation_identity):
                raise ValueError('owner observation custody held')
            os.ftruncate(descriptor, 0)
            self.owner_observation_identity = trust_identity(info)
            _owner_observation_identity = self.owner_observation_identity
        finally:
            os.close(descriptor)

    def read_owner_observation(self, operation_id):
        try:
            if self.owner_observation_identity is None or not observation_uuid(operation_id):
                return None
            value = observation_read(ROOT / 'broker-owner-observation.json', 4096,
                                     identity=self.owner_observation_identity)
            if (type(value) is dict and set(value) == {'schema_version', 'operation_id', 'failure'}
                    and type(value['schema_version']) is int and value['schema_version'] == 1
                    and value['operation_id'] == operation_id and observation_failure_valid(value['failure'])):
                return value['failure']
        except Exception:
            pass
        return None

    def owner_mapping_observation(self, operation_id):
        unknown = {'observation': 'unknown', 'job_id_present': None}
        result = {'operation': {**unknown, 'state': 'unknown', 'phase': 'unknown', 'reason_category': 'unknown'},
                  'fixture_mapping': dict(unknown), 'current_mapping': dict(unknown),
                  'owner_store': {'observation': 'unknown', 'mount_type': 'unknown',
                                  'auth_equal': None, 'jobs_equal': None}, 'failure': None}
        try:
            if not observation_uuid(operation_id):
                return result
        except Exception:
            return result

        try:
            result['failure'] = self.read_owner_observation(operation_id)
        except Exception:
            pass

        def project(directory, operation=False):
            value = dict(result['operation'] if operation else unknown)
            try:
                observation_directories(directory)
                try:
                    record = observation_read(directory / (operation_id + '.json'), 1048576)
                except ObservationAbsent:
                    # Absence only follows a trusted, still present parent lookup.
                    observation_directories(directory)
                    value['observation'] = 'absent'
                    return value
                if type(record) is not dict or record.get('operation_id') != operation_id:
                    return value
                if operation and (type(record.get('schema_version')) is not int or record['schema_version'] != 1):
                    return value
                value['observation'] = 'present'
                job = record.get('job_id')
                value['job_id_present'] = (False if 'job_id' not in record else
                    True if type(job) is str and re.fullmatch('[0-9a-f]{32}', job) else None)
                if operation:
                    states = ('prepared', 'selecting', 'pending-submit', 'updating', 'adopting',
                              'recovery-required', 'selection-conflict', 'completed', 'failed-restored')
                    state, phase = record.get('state'), record.get('phase')
                    value['state'] = state if type(state) is str and state in states else 'unknown'
                    value['phase'] = phase if type(phase) is str and phase in ('selection', 'owner') else 'unknown'
                    reasons = {
                        'Owner operation interrupted; reconcile retained operation before retry': 'owner-interrupted',
                        'Owner update did not verify; inspect retained owner result': 'owner-unverified',
                        'Installed owner recovery verification required': 'owner-recovery-required',
                        'Selected release changed before owner dispatch': 'selection-conflict',
                        'Resulting selection differs from preview': 'selection-conflict',
                    }
                    reason = record.get('reason')
                    value['reason_category'] = reasons.get(reason, 'unknown') if type(reason) is str else 'unknown'
                return value
            except Exception:
                return value

        try:
            result['operation'] = project(self.store.root / 'broker/operations', operation=True)
            # Verify the independently constructed fixture store before using any
            # mount-derived source. Never authorize a new path from inspect alone.
            fixture_auth = observation_directories(self.auth)
            fixture_jobs = observation_directories(self.jobs)
            if self.jobs != self.auth / 'update-jobs':
                return result
            result['fixture_mapping'] = project(self.jobs / 'operations')
            inspected = inspect_owner_mounts_bounded()
            if type(inspected) is not list or len(inspected) != 1 or type(inspected[0]) is not dict:
                return result
            mounts = inspected[0].get('Mounts')
            if type(mounts) is not list or any(type(m) is not dict for m in mounts):
                return result
            auth = [m for m in mounts if m.get('Destination') == '/data/auth']
            if (len(auth) != 1 or auth[0].get('RW') is not True
                    or auth[0].get('Type') not in ('bind', 'volume')
                    or any(type(m.get('Destination')) is not str or m['Destination'].startswith('/data/auth/') for m in mounts)):
                return result
            mount = auth[0]
            if type(mount.get('Source')) is not str:
                return result
            source = Path(mount['Source'])
            if not source.is_absolute() or '..' in source.parts or source != self.auth:
                result['owner_store']['observation'] = 'foreign'
                return result
            if observation_directories(self.auth) != fixture_auth or observation_directories(self.jobs) != fixture_jobs:
                return result
            auth_info, jobs_info = self.auth.lstat(), self.jobs.lstat()
            result['owner_store'] = {'observation': 'same', 'mount_type': mount['Type'],
                                     'auth_equal': True, 'jobs_equal': True,
                                     'auth_device': auth_info.st_dev, 'auth_inode': auth_info.st_ino,
                                     'jobs_device': jobs_info.st_dev, 'jobs_inode': jobs_info.st_ino}
            result['current_mapping'] = dict(result['fixture_mapping'])
        except Exception:
            pass
        return result

    def reset_child_failure(self):
        try:
            if self.child_failure_identity is None:
                descriptor, info = child_failure_file(os.O_RDWR | os.O_CREAT | os.O_EXCL)
            else:
                descriptor, info = child_failure_file(os.O_RDWR)
            with os.fdopen(descriptor, "r+b") as stream:
                if self.child_failure_identity is not None and trust_identity(info) != self.child_failure_identity:
                    raise RuntimeError("child diagnostic identity changed")
                stream.truncate(0)
                self.child_failure_identity = trust_identity(info)
        except OSError:
            raise RuntimeError("child diagnostic reset custody held") from None

    def consume_child_failure(self):
        if self.child_failure_identity is None:
            return
        try:
            descriptor, info = child_failure_file(os.O_RDWR)
            with os.fdopen(descriptor, "r+b") as stream:
                if trust_identity(info) != self.child_failure_identity:
                    return
                raw = stream.read(4097)
                stream.truncate(0)
            if not raw or len(raw) > 4096:
                return
            value = json.loads(raw)
            if (not isinstance(value, dict)
                    or set(value) != {"code_label", "source_line", "error_kind"}
                    or value["error_kind"] not in ERROR_KINDS):
                return
            if value["code_label"] is None:
                if value != {"code_label": None, "source_line": None, "error_kind": "unknown"}:
                    return
            elif (value["code_label"] not in BROKER_CODE_LABELS
                    or type(value["source_line"]) is not int
                    or not 1 <= value["source_line"] <= 1000000):
                return
            if self.layout not in ("named-volume", "bind"):
                return
            self.record("broker-child-failure", layout=self.layout, failure=value)
        except Exception:
            pass  # Best effort only; never override lifecycle or cleanup failure.

    def broker_state(self, timeout=10):
        try:
            result = run("systemctl", "show", "--property=ActiveState,SubState,Result,MainPID,ExecMainStatus", SERVICE, check=False, timeout=timeout)
            return service_state(result.stdout if result.returncode == 0 else b"")
        except Exception:
            return service_state(b"")

    def wait_broker_identity(self, old_main, *, fresh):
        """At most 30 seconds for one observation barrier; never repeat the signal."""
        deadline = time.monotonic() + 30
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                message = "fresh broker identity unavailable" if fresh else "old broker death unobserved"
                raise RuntimeError(message + "; native gate held")
            state = self.broker_state(timeout=min(1, remaining))
            pid = state["MainPID"]
            running = state["ActiveState"] == "active" and state["SubState"] == "running"
            # Read the old PID even if MainPID changed. Manager metadata alone cannot prove death.
            old = process_identity(old_main[0])
            retired = old is None or old[0] != old_main[1] or old[1] in ("Z", "X", "x")
            # Unknown fields cannot corroborate a transition or a zombie's retirement.
            transition = (state["ActiveState"] != "unknown" and state["SubState"] != "unknown"
                          and type(pid) is int and (pid != old_main[0] or not running))
            if retired and transition:
                if not running and not fresh:
                    return state
                if running and type(pid) is int and pid > 1:
                    current = process_identity(pid)
                    if (current is not None and current[1] not in ("Z", "X", "x")
                            and (pid, current[0]) != old_main):
                        return (pid, current[0]) if fresh else state
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.25, remaining))

    def wait_fresh_broker(self, old_main):
        fresh = self.wait_broker_identity(old_main, fresh=True)
        try:
            self.record("broker-fresh-running", layout=self.layout,
                        old_main_retired=True, main_pid=fresh[0], main_starttime=fresh[1])
        except Exception:
            pass
        return fresh

    # TRACEWEAVER: diagnostic-boundary=service-kill; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
    def kill_broker(self, phase):
        if phase not in ("service_update", "interrupted_adoption"):
            raise RuntimeError("unknown broker kill boundary")
        before = service_state(b"")
        result, old_main, supported, retired = None, None, False, False
        try:
            capability = run("systemctl", "--help", check=False, timeout=10)
            supported = (capability.returncode == 0 and len(capability.stdout) <= 65536
                         and b"--kill-whom=" in capability.stdout)
            if not supported:
                raise RuntimeError("main-only systemctl capability unavailable; native gate held")
            before = self.broker_state()
            pid = before["MainPID"]
            if (before["ActiveState"] != "active" or before["SubState"] != "running"
                    or type(pid) is not int or pid <= 1):
                raise RuntimeError("live broker identity unavailable; native gate held")
            identity = process_identity(pid)
            if identity is None or identity[1] in ("Z", "X", "x"):
                raise RuntimeError("live broker identity unavailable; native gate held")
            old_main = pid, identity[0]
            result = run("systemctl", "kill", "--kill-whom=main", "--signal=KILL", SERVICE, check=False)
            if result.returncode:
                raise RuntimeError(f"systemctl failed (exit {result.returncode}); native gate held")
            self.wait_broker_identity(old_main, fresh=False)
            retired = True
            return old_main
        finally:
            try:
                after = self.broker_state()
                code = result.returncode if result is not None else None
                code = code if type(code) is int and -255 <= code <= 255 else None
                self.record("broker-kill", phase=phase,
                            layout=self.layout if self.layout in ("named-volume", "bind") else "unknown",
                            before=before, after=after, kill_exit_code=code,
                            main_scope_supported=supported, old_main_retired=retired,
                            old_main_pid=old_main[0] if old_main else None,
                            old_main_starttime=old_main[1] if old_main else None)
            except Exception:
                pass  # Evidence failures must leave the original kill verdict intact.

    def attest_registry_trust(self, engine):
        version = "29.1.3" if engine.get("ServerVersion") == "29.1.3" else "unsupported"
        store = (
            "containerd-snapshotter"
            if isinstance(engine.get("DriverStatus"), list)
            and ["driver-type", "io.containerd.snapshotter.v1"] in engine["DriverStatus"]
            else "unsupported"
        )
        security = engine.get("SecurityOptions")
        rootless = (
            "rootful"
            if isinstance(security, list)
            and all(isinstance(value, str) for value in security)
            and not any(value.split(",")[0] == "name=rootless" for value in security)
            else "unsupported"
        )
        observed = None
        try:
            if version != "29.1.3" or store != "containerd-snapshotter" or rootless != "rootful":
                raise RuntimeError("unsupported guest trust context")
            parents = trust_directories(REGISTRY_CA_DIR)
            content, info = trust_read(REGISTRY_CA_DIR / "hosts.toml")
            observed = digest(content)
            fixture_hosts_bytes(content, "/unused-public-fixture.crt")
            self.registry_baseline = (content, info, parents)
        except Exception:
            self.record(
                "fixture-registry-trust-context",
                result="failed",
                reason="unsupported-context-or-custody",
                engine_version=version,
                image_store=store,
                rootless=rootless,
                hosts_sha256=observed,
            )
            raise RuntimeError("unsupported guest registry trust; native gate held") from None
        self.record(
            "fixture-registry-trust-context",
            result="passed",
            engine_version=version,
            image_store=store,
            rootless=rootless,
            hosts_sha256=observed,
        )

    def install_registry_trust(self):
        try:
            original, info, parents = self.registry_baseline
            path = REGISTRY_CA_DIR / "hosts.toml"
            current, current_info = trust_read(path)
            if (
                trust_directories(REGISTRY_CA_DIR) != parents
                or current != original
                or trust_identity(current_info) != trust_identity(info)
                or trust_metadata(current_info) != trust_metadata(info)
            ):
                raise RuntimeError("registry trust preimage drift")
            ca_info = self.registry_ca_file.lstat()
            if trust_identity(ca_info) != self.registry_ca_identity or not stat.S_ISREG(
                ca_info.st_mode
            ):
                raise RuntimeError("fixture CA custody drift")
            augmented = fixture_hosts_bytes(original, self.registry_ca_file)
            custody = ROOT / "registry-trust"
            custody.mkdir(mode=0o700)
            state = {
                "parents": parents,
                "custody": custody,
                "custody_identity": trust_identity(custody.lstat()),
                "custody_parents": trust_directories(custody),
                "backup": custody / "original",
                "temporary": REGISTRY_CA_DIR / (".native-fleet-qa-" + uuid.uuid4().hex),
                "replacement_identity": None,
                "replacement_metadata": None,
                "replacement_sha256": digest(augmented),
            }
            # Register before any owned partial write or baseline rename can fail.
            self.registry_trust = state
            descriptor = os.open(
                state["temporary"], os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            state["replacement_identity"] = trust_identity(os.fstat(descriptor))
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(augmented)
                stream.flush()
                os.fsync(stream.fileno())
                if (os.fstat(stream.fileno()).st_uid, os.fstat(stream.fileno()).st_gid) != (
                    info.st_uid,
                    info.st_gid,
                ):
                    os.fchown(stream.fileno(), info.st_uid, info.st_gid)
                os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
                state["replacement_metadata"] = trust_metadata(os.fstat(stream.fileno()))
            current, current_info = trust_read(path)
            if (
                trust_directories(REGISTRY_CA_DIR) != parents
                or trust_directories(state["custody"]) != state["custody_parents"]
                or current != original
                or trust_identity(current_info) != trust_identity(info)
                or trust_metadata(current_info) != trust_metadata(info)
            ):
                raise RuntimeError("registry trust preimage drift")
            # Retain the actual original inode; userspace cannot preserve its ctime.
            os.rename(path, state["backup"])
            os.replace(state["temporary"], path)
            self.record("fixture-registry-trust", result="installed", hosts_sha256=digest(original))
        except Exception:
            raise RuntimeError(
                "fixture registry trust preparation failed; native gate held"
            ) from None

    def restore_registry_trust(self):
        state = self.registry_trust
        if state is None:
            return
        try:
            original, info, parents = self.registry_baseline
            path = REGISTRY_CA_DIR / "hosts.toml"
            if (
                trust_directories(REGISTRY_CA_DIR) != parents
                or trust_identity(state["custody"].lstat()) != state["custody_identity"]
                or stat.S_IMODE(state["custody"].lstat().st_mode) != 0o700
                or state["custody"].lstat().st_uid != 0
            ):
                raise RuntimeError("registry trust directory drift")
            backup_exists = state["backup"].exists() or state["backup"].is_symlink()
            if backup_exists:
                saved, saved_info = trust_read(state["backup"])
                if (
                    saved != original
                    or trust_identity(saved_info) != trust_identity(info)
                    or trust_metadata(saved_info) != trust_metadata(info)
                ):
                    raise RuntimeError("registry trust preimage custody drift")
                if path.exists() or path.is_symlink():
                    changed, changed_info = trust_read(path)
                    if (
                        trust_identity(changed_info) != state["replacement_identity"]
                        or trust_metadata(changed_info) != state["replacement_metadata"]
                        or digest(changed) != state["replacement_sha256"]
                    ):
                        raise RuntimeError("registry trust replacement custody drift")
                elif trust_identity(state["temporary"].lstat()) != state["replacement_identity"]:
                    raise RuntimeError("registry trust replacement missing")
                os.utime(state["backup"], ns=(info.st_atime_ns, info.st_mtime_ns))
                os.replace(state["backup"], path)
            restored, restored_info = trust_read(path)
            if (
                restored != original
                or trust_identity(restored_info) != trust_identity(info)
                or trust_metadata(restored_info) != trust_metadata(info)
            ):
                raise RuntimeError("registry trust restoration differs")
            # NOATIME preserves timestamps on Linux; reset after read for local checks too.
            os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
            final_info = path.lstat()
            if (
                trust_identity(final_info) != trust_identity(info)
                or trust_metadata(final_info) != trust_metadata(info)
                or final_info.st_atime_ns != info.st_atime_ns
            ):
                raise RuntimeError("registry trust restored metadata differs")
            if state["temporary"].exists() or state["temporary"].is_symlink():
                temporary_info = state["temporary"].lstat()
                if trust_identity(temporary_info) != state[
                    "replacement_identity"
                ] or not stat.S_ISREG(temporary_info.st_mode):
                    raise RuntimeError("registry trust temporary custody drift")
                state["temporary"].unlink()
            state["custody"].rmdir()
            self.registry_trust = None
            self.record(
                "fixture-registry-trust",
                result="restored",
                hosts_sha256=digest(original),
                original_inode=True,
                ctime_restored=False,
            )
        except Exception:
            self.record("fixture-registry-trust", result="held", reason="cleanup-custody-held")
            raise RuntimeError(
                "fixture registry trust restoration held; native gate held"
            ) from None

    def verify_registry_ca_directory(self):
        info = REGISTRY_CA_DIR.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("registry CA directory custody is invalid; native gate held")

    def install_registry_ca(self, certificate_path):
        if self.registry_baseline is not None:
            original, info, parents = self.registry_baseline
            current, observed = trust_read(REGISTRY_CA_DIR / "hosts.toml")
            if (
                current != original
                or trust_identity(observed) != trust_identity(info)
                or trust_metadata(observed) != trust_metadata(info)
                or trust_directories(REGISTRY_CA_DIR) != parents
            ):
                raise RuntimeError("registry trust preimage drift; native gate held")
        try:
            REGISTRY_CA_DIR.lstat()
        except FileNotFoundError:
            REGISTRY_CA_DIR.mkdir(parents=True, mode=0o755)
            self.registry_ca_created = True
        self.verify_registry_ca_directory()
        path = REGISTRY_CA_DIR / ("native-fleet-qa-" + uuid.uuid4().hex + ".crt")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        self.registry_ca_file = path
        info = os.fstat(descriptor)
        self.registry_ca_identity = (info.st_dev, info.st_ino)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(certificate_path.read_bytes())
            stream.flush()
            os.fsync(stream.fileno())

    def remove_registry_ca(self):
        if self.registry_ca_file is not None:
            try:
                info = self.registry_ca_file.lstat()
            except FileNotFoundError:
                pass
            else:
                if (info.st_dev, info.st_ino) != self.registry_ca_identity or not stat.S_ISREG(
                    info.st_mode
                ):
                    raise RuntimeError("owned fixture CA identity changed; cleanup held")
                self.registry_ca_file.unlink()
            self.registry_ca_file = None
        if self.registry_ca_created:
            try:
                REGISTRY_CA_DIR.rmdir()
            except OSError:
                pass  # Preserve any entry added since creation; external destruction remains required.
            self.registry_ca_created = False

    def record(self, case, **details):
        self._record_event({"case": case, "utc": time.time(), **details})

    def _record_event(self, event):
        self.events.append(event)
        write(
            self.evidence / "results.json",
            {
                "schema_version": 1,
                "native_results": self.events,
                "release_ready": False,
                "holds": [
                    "production issuer/current real admission",
                    "default live GitHub discovery",
                    "genuine future version migration",
                    "desktop/mobile pointer acceptance",
                    "any unobserved exact crash micro-window",
                    "full release environment-dependent checks and external VM destruction receipt",
                ],
            },
            0o644,
        )

    def preflight(self):
        check_recovery_inputs(self.args.proxy_sha)
        check_source_pin(self.args.proxy_sha)
        if not re.fullmatch("[0-9a-f]{40}", self.args.dc_sha or ""):
            raise RuntimeError("exact reviewed DC event head required")
        if (
            platform.system() != "Linux"
            or os.geteuid() != 0
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("FLEET_NATIVE_REPOSITORY_ID") != "1133295682"
            or not re.fullmatch("[1-9][0-9]*", os.environ.get("FLEET_NATIVE_RUN_ID", ""))
        ):
            raise RuntimeError(
                "native execution requires the admitted Linux job guest and root child"
            )
        virtualization = run("systemd-detect-virt", "--vm", check=False)
        if virtualization.returncode or virtualization.stdout.strip() in (b"", b"none"):
            raise RuntimeError("VM execution context unavailable; no runner fallback")
        if not hasattr(socket, "SO_PEERCRED") or run(
            "systemctl", "is-system-running", check=False
        ).stdout.strip() not in (b"running", b"degraded"):
            raise RuntimeError("real Linux peer/systemd capability unavailable")
        endpoint = json.loads(
            docker("context", "inspect", "--format", "{{json .Endpoints.docker.Host}}").stdout
        )
        if endpoint not in ("unix:///var/run/docker.sock", "unix:///run/docker.sock"):
            raise RuntimeError("only this guest local Docker Engine is allowed")
        if os.environ.get("DOCKER_HOST") or os.environ.get("DOCKER_CONTEXT"):
            raise RuntimeError("Docker endpoint overrides are forbidden")
        engine = json.loads(docker("info", "--format", "{{json .}}").stdout)
        if engine.get("HTTPProxy") or engine.get("HTTPSProxy"):
            raise RuntimeError(
                "guest registry fixture requires an Engine without an outbound proxy"
            )
        self.attest_registry_trust(engine)
        for source, expected, product in (
            (self.args.dc_source, self.args.dc_sha, "dc"),
            (self.args.proxy_source, self.args.proxy_sha, "proxy"),
        ):
            if run("git", "-C", source, "rev-parse", "HEAD").stdout.decode().strip() != expected:
                raise RuntimeError("checked-out exact source SHA mismatch")
            for name, wanted in FROZEN_PRODUCT_HASHES[product].items():
                if digest((source / name).read_bytes()) != wanted:
                    raise RuntimeError("frozen product source hash mismatch: " + name)
        for module_name in ("dc_overview", "cryptolabs_proxy"):
            module = importlib.import_module(module_name)
            installed = Path(module.__file__).resolve().parent
            if not installed.is_relative_to(Path(sys.prefix).resolve()):
                raise RuntimeError("source import bypasses installed wheel")
            for name, expected in FROZEN_PRODUCT_HASHES[
                "dc" if module_name == "dc_overview" else "proxy"
            ].items():
                if name.startswith("src/" + module_name + "/"):
                    relative = Path(name).relative_to("src/" + module_name)
                    if digest((installed / relative).read_bytes()) != expected:
                        raise RuntimeError("installed wheel product file differs")
        for path in (
            ROOT,
            CONFIG,
            PROXY_CONFIG,
            Path("/usr/local/bin/dc-overview"),
        ):
            if path.exists() or path.is_symlink():
                raise RuntimeError("fresh guest fixture path is already occupied: " + str(path))
        if REGISTRY_CA_DIR.exists() or REGISTRY_CA_DIR.is_symlink():
            self.verify_registry_ca_directory()
        for name in ("cryptolabs-proxy", "ipmi-monitor", "native-fleet-registry"):
            if docker("inspect", name, check=False).returncode == 0:
                raise RuntimeError("fixture container name already occupied")
        ROOT.mkdir(mode=0o700)
        self.fixture_owned = True
        self.recovery.install_old_host()
        (ROOT / "docker-client").mkdir(mode=0o700)
        os.environ["DOCKER_CONFIG"] = str(ROOT / "docker-client")
        write(ROOT / "docker-client/config.json", {"auths": {}})
        self.record(
            "preflight",
            result="passed",
            dc_sha=self.args.dc_sha,
            proxy_sha=self.args.proxy_sha,
            run_id=os.environ["FLEET_NATIVE_RUN_ID"],
            wheels={p.name: digest(p.read_bytes()) for p in self.args.wheel_dir.glob("*.whl")},
        )

    def push_fixture(self, key, tag):
        if key not in ("proxy-a", "proxy-b", "ipmi-old", "ipmi-new", "ipmi-bad"):
            raise RuntimeError("unknown registry fixture key; native gate held")
        try:
            result = docker("push", tag, timeout=900, check=False)
        except RuntimeError:
            # run() already sanitizes timeouts; never inspect the original exception.
            self._record_event(
                {
                    "case": "fixture-registry-push",
                    "fixture_key": key,
                    "result": "failed",
                    "exit_code": None,
                    "diagnostic_signals": ["timeout"],
                    "diagnostic_version": 1,
                }
            )
            raise RuntimeError("fixture registry push timed out; native gate held") from None
        if result.returncode:
            self._record_event(
                {
                    "case": "fixture-registry-push",
                    "fixture_key": key,
                    "result": "failed",
                    "exit_code": max(-255, min(255, result.returncode)),
                    "diagnostic_signals": registry_push_signals(result.stdout, result.stderr),
                    "diagnostic_version": 1,
                }
            )
            raise RuntimeError("fixture registry push failed; native gate held") from None
        return result

    def images(self):
        docker("pull", "--platform", "linux/amd64", LEGACY_PROXY, timeout=900)
        assert LEGACY_PROXY in inspect(LEGACY_PROXY, image=True)["RepoDigests"]
        for ref in (REGISTRY_IMAGE, NGINX_BASE, IPMI_OLD, IPMI_NEW):
            docker("pull", "--platform", "linux/amd64", ref, timeout=900)
            data = inspect(ref, image=True)
            if (
                ref not in data.get("RepoDigests", [])
                or data.get("Os") != "linux"
                or data.get("Architecture") != "amd64"
            ):
                raise RuntimeError("official pinned image identity/platform mismatch")
        dockerfile = (self.args.proxy_source / "Dockerfile").read_text()
        if not dockerfile.startswith("#") or dockerfile.count("FROM nginx:alpine") != 1:
            raise RuntimeError("reviewed proxy base is not the expected single nginx stage")
        pinned = dockerfile.replace("FROM nginx:alpine", "FROM " + NGINX_BASE)
        for slot in ("a", "b"):
            docker(
                "build",
                "--platform",
                "linux/amd64",
                "-f",
                "-",
                "--label",
                self.label,
                "--label",
                "io.cryptolabs.native-qa.slot=" + slot,
                "--build-arg",
                "BUILD_COMMIT=" + self.args.proxy_sha,
                "-t",
                "native-fleet-proxy-" + slot,
                str(self.args.proxy_source),
                input_bytes=pinned.encode(),
                timeout=1200,
            )
        # One unhealthy test-only image derivative; product Python bytes stay unchanged.
        docker("tag", IPMI_NEW, "native-fleet-ipmi-healthy")
        bad = b"FROM native-fleet-ipmi-healthy\nHEALTHCHECK --interval=1s --timeout=1s --start-period=0s --retries=1 CMD exit 1\n"
        docker(
            "build",
            "--platform",
            "linux/amd64",
            "-f",
            "-",
            "-t",
            "native-fleet-ipmi-unhealthy",
            str(ROOT),
            input_bytes=bad,
            timeout=300,
        )
        certificate(ROOT / "registry-certs", "ghcr.io")
        self.install_registry_ca(ROOT / "registry-certs/server.crt")
        self.install_registry_trust()
        self.hosts = Path("/etc/hosts").read_bytes()
        Path("/etc/hosts").write_bytes(self.hosts + b"\n127.0.0.1 ghcr.io\n")
        if any(
            address[4][0] != "127.0.0.1"
            for address in socket.getaddrinfo("ghcr.io", 443, type=socket.SOCK_STREAM)
        ):
            raise RuntimeError(
                "fixture GHCR resolution is not entirely guest loopback; push forbidden"
            )
        docker(
            "run",
            "-d",
            "--name",
            "native-fleet-registry",
            "--label",
            self.label,
            "--user",
            "0:0",
            "-p",
            "127.0.0.1:443:5000",
            "--mount",
            f"type=bind,src={ROOT}/registry-certs,dst=/certs,readonly",
            "-e",
            "REGISTRY_HTTP_TLS_CERTIFICATE=/certs/server.crt",
            "-e",
            "REGISTRY_HTTP_TLS_KEY=/certs/server.key",
            REGISTRY_IMAGE,
        )
        import requests

        wait(
            lambda: requests.get(
                "https://ghcr.io/v2/", verify=str(ROOT / "registry-certs/server.crt"), timeout=3
            ).status_code
            == 200,
            message="guest-only registry unavailable",
        )
        for key, source, repository in (
            ("proxy-a", "native-fleet-proxy-a", "cryptolabs-proxy"),
            ("proxy-b", "native-fleet-proxy-b", "cryptolabs-proxy"),
            ("ipmi-old", IPMI_OLD, "ipmi-monitor"),
            ("ipmi-new", IPMI_NEW, "ipmi-monitor"),
            ("ipmi-bad", "native-fleet-ipmi-unhealthy", "ipmi-monitor"),
        ):
            image_id = inspect(source, image=True)["Id"]
            tag = "ghcr.io/cryptolabsza/" + repository + ":native-" + key
            docker("tag", source, tag)
            result = self.push_fixture(key, tag)
            found = re.search(rb"digest: (sha256:[0-9a-f]{64})", result.stdout + result.stderr)
            if not found:
                raise RuntimeError("registry push did not return actual digest")
            ref = tag.rsplit(":", 1)[0] + "@" + found[1].decode()
            docker("pull", ref, timeout=300)
            actual = inspect(ref, image=True)
            if actual["Id"] != image_id or ref not in actual.get("RepoDigests", []):
                raise RuntimeError("guest mirror changed actual image config identity")
            self.refs[key] = ref
        if (
            inspect(self.refs["proxy-a"], image=True)["Id"]
            == inspect(self.refs["proxy-b"], image=True)["Id"]
        ):
            raise RuntimeError("proxy A/B must have distinct real image identities")
        self.record(
            "images",
            result="passed",
            inputs={
                "registry": REGISTRY_IMAGE,
                "nginx": NGINX_BASE,
                "ipmi_old_public": IPMI_OLD,
                "ipmi_new_public": IPMI_NEW,
            },
            qa_refs=self.refs,
            note="Proxy A/B code bytes identical; metadata distinguishes actual runtime replacement",
        )

    def units_install(self):
        import dc_overview

        package = Path(dc_overview.__file__).parent
        for name in (SERVICE, SOCKET_UNIT):
            destination = Path("/etc/systemd/system") / name
            if destination.exists():
                raise RuntimeError("systemd fixture destination is occupied")
            shutil.copyfile(package / "templates/systemd" / name, destination)
            destination.chmod(0o644)
            self.units.append(destination)
        Path("/usr/local/bin/dc-overview").symlink_to(Path(sys.executable).parent / "dc-overview")
        shutil.copyfile(Path(__file__), Path("/opt/fleet-native-qa/verify_fleet_release_native.py"))
        run("systemd-analyze", "verify", *self.units)
        run("systemctl", "daemon-reload")

    def fixture(self, layout):
        import yaml
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from cryptolabs_proxy.standard_adoption import _declaration, render_standard

        from dc_overview.fleet_config import FleetConfig
        from dc_overview.release_catalog import ReleaseStore

        self.layout = layout
        CONFIG.mkdir(mode=0o755)
        write(CONFIG / ".lifecycle-config.lock", b"")
        PROXY_CONFIG.mkdir(mode=0o700)
        network = "native-fleet-" + layout + "-" + os.environ["FLEET_NATIVE_RUN_ID"]
        docker("network", "create", "--label", self.label, network)
        self.networks.append(network)
        self.network = network
        self.data = ROOT / layout
        self.data.mkdir(mode=0o700)
        if layout == "named-volume":
            auth_name = network + "-auth"
            docker("volume", "create", "--label", self.label, auth_name)
            self.volumes.append(auth_name)
            auth_mount = f"type=volume,src={auth_name},dst=/data/auth"
            self.auth = Path(inspect_volume(auth_name)["Mountpoint"])
        else:
            self.auth = self.data / "auth"
            self.auth.mkdir(mode=0o700)
            auth_mount = f"type=bind,src={self.auth},dst=/data/auth"
        self.auth.chmod(0o700)
        jobs = self.auth / "update-jobs"
        jobs.mkdir(mode=0o700)
        for name in ("dispatch.lock", "operation.lock"):
            write(jobs / name, b"")
        self.jobs = jobs
        self.password = secrets.token_urlsafe(24)
        self.auth_secret = secrets.token_urlsafe(48)
        env = {
            **os.environ,
            "AUTH_DATA_DIR": str(self.auth),
            "AUTH_SECRET_KEY": self.auth_secret,
            "QA_USER_PASS": self.password,
        }
        run(
            self.recovery.host_env / 'bin/python' if layout == 'named-volume' else sys.executable,
            "-c",
            "from cryptolabs_proxy.auth import create_user; import os; assert create_user('native-admin',os.environ['QA_USER_PASS'],'admin')",
            env=env,
        )
        manifest = {
            "schema_version": 1,
            "selection_contract": 1,
            "baseline_id": "native-baseline",
            "components": {
                "cryptolabs-proxy": ({"owner": "proxy-updater", "release": "1.5.4", "artifacts": {"linux/amd64": {"kind": "oci", "reference": LEGACY_PROXY}}} if layout == 'named-volume' else self.component("proxy-a")),
                "ipmi-monitor": ({"owner": "proxy-updater", "release": "1.3.2", "artifacts": {"linux/amd64": {"kind": "oci", "reference": LEGACY_DESIRED}}} if layout == 'named-volume' else self.component("ipmi-old")),
                "grafana": {
                    "owner": "proxy-updater",
                    "release": "untouched-pin",
                    "artifacts": {
                        "linux/amd64": {
                            "kind": "oci",
                            "reference": "grafana/grafana@sha256:" + "c" * 64,
                        }
                    },
                },
                "vast-price-manager": {
                    "owner": "dc-vpm",
                    "release": "untouched-owner",
                    "artifacts": {
                        "linux/amd64": {
                            "kind": "oci",
                            "reference": "ghcr.io/cryptolabsza/vast-price-manager@sha256:"
                            + "d" * 64,
                        }
                    },
                },
            },
        }
        source = self.data / "baseline.json"
        write(source, manifest)
        policies = {
            "cryptolabs-proxy": {"origin": "baseline", "enabled": True},
            "ipmi-monitor": {"origin": "baseline", "enabled": True},
            "grafana": {
                "origin": "customer-pin",
                "enabled": False,
                "pin": "grafana/grafana@sha256:" + "c" * 64,
            },
            "vast-price-manager": {"origin": "unmanaged", "enabled": False},
        }
        self.store = ReleaseStore(CONFIG / "releases")
        prepared = self.store.prepare(source, platform="linux/amd64", policies=policies)
        self.store.commit(prepared)
        config = FleetConfig(config_dir=CONFIG)
        config.release_selection.selection_id = prepared.selection["selection_id"]
        config.release_selection.selection_sha256 = prepared.selection_sha256
        config.release_selection.components = prepared.selection["components"]
        public = config._to_dict(include_secrets=False)
        public["native_opaque"] = {"preserve": True, "layout": layout}
        write(CONFIG / "fleet-config.yaml", yaml.safe_dump(public).encode(), 0o644)
        self.declaration = {
            "schema_version": 1,
            "domain": "native-fleet.invalid",
            "tls": "self-signed",
            "release_selection_dir": str(self.store.root),
            "services": {
                "ipmi-monitor": {"container_name": "ipmi-monitor", "path": "/ipmi/", "port": 5000}
            },
            "obsolete_overlays": [],
            "obsolete_owner_labels": [],
            "release_broker_enabled": True,
        }
        write(PROXY_CONFIG / "native-declaration.json", self.declaration)
        write(PROXY_CONFIG / "nginx.conf", render_standard(_declaration(self.declaration)), 0o644)
        certificate(self.data / "ssl", "native-fleet.invalid")
        self.policy = {
            "writes_enabled": False,
            "allowed_uids": [0],
            "minimum_generation": 1,
            "declaration_path": str(PROXY_CONFIG / "native-declaration.json"),
            "proxy_config_dir": str(PROXY_CONFIG),
        }
        write(POLICY, self.policy)
        self.reset_child_failure()
        self.reset_owner_observation()
        run("systemctl", "start", SOCKET_UNIT)
        denied = raw_request()
        assert denied["ok"] is False and denied["error"]["status"] == 503
        self.policy["allowed_uids"] = [65534]
        write(POLICY, self.policy)
        peer_denied = raw_request(payload=b"")
        assert peer_denied["ok"] is False and peer_denied["error"]["status"] == 403
        self.policy["allowed_uids"] = [0]
        write(POLICY, self.policy)
        malformed = raw_request(payload=b'{"schema_version":1,"schema_version":1}\n')
        assert malformed["ok"] is False and malformed["error"]["status"] == 400
        mode = Path(SOCKET).stat()
        assert mode.st_uid == mode.st_gid == 0 and mode.st_mode & 0o777 == 0o600
        unpriv = run(
            "runuser",
            "-u",
            "nobody",
            "--",
            sys.executable,
            "-c",
            "import socket,sys; s=socket.socket(socket.AF_UNIX);\ntry: s.connect('/run/dc-overview-release-broker.sock')\nexcept PermissionError: sys.exit(73)\nraise RuntimeError('unauthorized socket connection succeeded')",
            check=False,
        )
        assert unpriv.returncode == 73
        run("systemctl", "stop", SERVICE)
        dropin = Path("/etc/systemd/system") / (SERVICE + ".d") / "native-fixture.conf"
        write(
            dropin,
            (
                "[Service]\nExecStart=\nExecStart="
                + sys.executable
                + " /opt/fleet-native-qa/verify_fleet_release_native.py --broker-child\n"
            ).encode(),
            0o644,
        )
        run("systemctl", "daemon-reload")
        self.issuer = Ed25519PrivateKey.generate()
        self.policy.update(
            public_key_hex=self.issuer.public_key()
            .public_bytes(Encoding.Raw, PublicFormat.Raw)
            .hex(),
            allowed_producer={
                "repository_id": 1133295682,
                "workflow": "test-only/native-qa",
                "ref": "refs/heads/native-fixture",
            },
            max_validity_seconds=3600,
        )
        write(POLICY, self.policy)
        self.generation = 0
        self.admit("ipmi-new")
        empty = self.data / "servers.yaml"
        write(empty, b"servers: []\n", 0o644)
        ipmi_data = network + "-data"
        docker("volume", "create", "--label", self.label, ipmi_data)
        self.volumes.append(ipmi_data)
        docker(
            "run",
            "-d",
            "--name",
            "ipmi-monitor",
            "--label",
            self.label,
            "--network",
            network,
            "--mount",
            f"type=volume,src={ipmi_data},dst=/app/data",
            "--mount",
            f"type=bind,src={empty},dst=/app/config/servers.yaml,readonly",
            self.refs["ipmi-old"],
        )
        socket_mount = ("--mount", f"type=bind,src={SOCKET},dst={SOCKET},readonly") if layout == 'bind' else ()
        docker(
            "run",
            "-d",
            "--name",
            "cryptolabs-proxy",
            "--label",
            self.label,
            "--network",
            network,
            "-p",
            "127.0.0.1:18080:80",
            "-p",
            "127.0.0.1:18443:443",
            "--mount",
            auth_mount,
            "--mount",
            f"type=bind,src={PROXY_CONFIG}/nginx.conf,dst=/etc/nginx/nginx.conf,readonly",
            "--mount",
            f"type=bind,src={self.data}/ssl,dst=/etc/nginx/ssl,readonly",
            "--mount",
            f"type=bind,src={self.store.root},dst=/etc/cryptolabs/releases,readonly",
            *socket_mount,
            "--mount",
            "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock",
            "-e",
            "AUTH_SECRET_KEY=" + self.auth_secret,
            "-e",
            "FLEET_ADMIN_PASS=",
            "-e",
            "PYTHONPATH=/app/src",
            "-e",
            "FLEET_PUBLIC_ORIGIN=" + ORIGIN,
            "-e",
            "RELEASE_SELECTION_REQUIRED=true",
            LEGACY_PROXY if layout == 'named-volume' else self.refs["proxy-a"],
        )
        self.wait_healthy("ipmi-monitor")
        self.wait_healthy("cryptolabs-proxy")
        if layout == 'named-volume':
            self.recovery.bootstrap()
        for name in ("ipmi-monitor", "cryptolabs-proxy"):
            for mount in inspect(name).get("Mounts", []):
                if mount.get("Type") == "volume" and mount.get("Name") not in self.volumes:
                    self.volumes.append(mount["Name"])
        self.login()
        time.sleep(1.2)  # Exercise ordinary permanent-cookie renewal, never pin an obsolete cookie.
        session = self.http("GET", "/api/releases/session")
        assert session.status_code == 200
        self.csrf = session.json()["csrf_token"]
        assert (
            self.http(
                "POST",
                "/api/releases/preview",
                body={},
                headers={"Origin": "https://wrong.invalid"},
            ).status_code
            == 403
        )
        assert (
            self.http(
                "POST", "/api/update", body={"service": "ipmi-monitor", "branch": "main"}
            ).status_code
            == 409
        )
        selected = self.selection()
        fake_uid_request = {
            "candidate_ids": [self.candidate_id],
            "components": ["ipmi-monitor"],
            "expected_selection_id": selected.selection["selection_id"],
            "expected_selection_sha256": selected.selection_sha256,
            "operation_kind": "services-update",
        }
        peer_preview = raw_request(
            "preview", fake_uid_request, actor={"kind": "host-peer", "uid": 65534}
        )
        assert peer_preview["ok"] is True
        peer_record = json.loads(
            (
                self.store.root
                / "broker/previews"
                / (peer_preview["result"]["preview_id"] + ".json")
            ).read_bytes()
        )
        assert peer_record["actor"] == {"kind": "host-peer", "uid": 0}
        native = run(
            Path(sys.executable).parent / "dc-overview",
            "release",
            "candidates",
            "--channel",
            "main",
        )
        assert json.loads(native.stdout)["channel"] == "main"
        self.record(
            "bootstrap-" + layout,
            result="passed",
            auth_backing={"device": self.auth.stat().st_dev, "inode": self.auth.stat().st_ino},
            socket_mode="root:root0600",
            vanilla="disabled/unavailable",
            fixture_discovery_adapter=True,
            kernel_peer="root allowed then excluded by reloaded UID policy; nobody denied by socket mode",
        )

    def component(self, key):
        return {
            "owner": "proxy-updater",
            "release": "native-" + key,
            "artifacts": {"linux/amd64": {"kind": "oci", "reference": self.refs[key]}},
        }

    def admit(self, key, *, revoked=False):
        from datetime import datetime, timedelta, timezone

        self.generation += 1
        name = "cryptolabs-proxy" if key.startswith("proxy") else "ipmi-monitor"
        manifest = {
            "schema_version": 1,
            "selection_contract": 1,
            "baseline_id": "native-candidate-" + str(self.generation),
            "components": {name: self.component(key)},
        }
        now = datetime.now(timezone.utc)
        times = {
            "issued_at": (now - timedelta(seconds=2)).isoformat(),
            "expires_at": (now + timedelta(minutes=50)).isoformat(),
        }
        admission = {
            "schema_version": 1,
            "manifest_sha256": digest(encoded(manifest)),
            "component_admissions": [
                {
                    "component": name,
                    "channel": "main",
                    "platform": "linux/amd64",
                    "identity": self.refs[key],
                    "required_capabilities": {"release_components": 1, "release_idempotency": 1},
                    "independently_replaceable": True,
                    "dependency_group": [],
                }
            ],
            "producer": {
                "repository_id": 1133295682,
                "workflow": "test-only/native-qa",
                "ref": "refs/heads/native-fixture",
                "source_sha": self.args.proxy_sha if name == "cryptolabs-proxy" else "a" * 40,
                "run_id": 1,
                "attempt": 1,
            },
            "owner_approval_receipt": "SYNTHETIC-GUEST-ONLY-NOT-PRODUCTION",
            "generation": self.generation,
            **times,
        }
        a = encoded(admission)
        identity = digest(a)
        index = encoded(
            {
                "schema_version": 1,
                "generation": self.generation,
                **times,
                "candidates": {identity: identity},
                "revoked": [identity] if revoked else [],
            }
        )
        assets = {
            "suite-release.json": encoded(manifest),
            "suite-admission.json": a,
            "suite-admission.sig": self.issuer.sign(a),
            "admission-index.json": index,
            "admission-index.sig": self.issuer.sign(index),
        }
        for filename, data in assets.items():
            write(ROOT / "admission" / filename, data, 0o644)
        self.candidate_id = identity
        return name

    def wait_healthy(self, name):
        def healthy():
            value = inspect(name)
            state = value["State"]
            if not state.get("Running"):
                return False
            health = state.get("Health", {}).get("Status")
            if health == "unhealthy":
                raise RuntimeError("real container is unhealthy: " + name)
            if health == "healthy":
                return True
            if health is None and name == "ipmi-monitor":
                # Both approved IPMI images lack HEALTHCHECK. Probe the actual
                # application inside that exact container; Running alone is insufficient.
                probe = docker(
                    "exec",
                    name,
                    "curl",
                    "--silent",
                    "--show-error",
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{http_code}",
                    "--max-time",
                    "3",
                    "http://127.0.0.1:5000/health",
                    check=False,
                    timeout=5,
                )
                return probe.returncode == 0 and probe.stdout.strip() == b"200"
            return False

        wait(healthy, timeout=240, message="real container health did not verify: " + name)

    def login(self):
        import requests

        self.session = requests.Session()
        self.session.verify = str(self.data / "ssl/server.crt")
        result = self.session.post(
            ORIGIN + "/auth/login",
            data={"username": "native-admin", "password": self.password},
            allow_redirects=False,
            timeout=15,
        )
        assert result.status_code == 302
        self.cookie = dict(self.session.cookies)

    def http(self, method, path, *, body=None, headers=None):
        if method == "POST":
            current = self.session.get(ORIGIN + "/api/releases/session", timeout=15)
            if current.status_code != 200:
                raise RuntimeError("current live administrator/session authorization unavailable")
            self.csrf = current.json()["csrf_token"]
        supplied = {"Origin": ORIGIN, "X-CSRF-Token": getattr(self, "csrf", "")}
        supplied.update(headers or {})
        return self.session.request(method, ORIGIN + path, json=body, headers=supplied, timeout=15)

    def selection(self):
        return self.store.load(platform="linux/amd64")

    def preview(self, key):
        name = self.admit(key)
        current = self.selection()
        params = {
            "candidate_ids": [self.candidate_id],
            "components": [name],
            "expected_selection_id": current.selection["selection_id"],
            "expected_selection_sha256": current.selection_sha256,
            "operation_kind": "proxy-adopt" if name == "cryptolabs-proxy" else "services-update",
        }
        response = self.http("POST", "/api/releases/preview", body=params)
        if response.status_code != 200:
            raise RuntimeError("real HTTP preview refused: " + str(response.status_code))
        return params, response.json()

    def apply(self, params, preview, *, lose_reply=False):
        identity = str(uuid.uuid4())
        if preview.get("owner_plan"):
            self.owner_plans.add(preview["owner_plan"]["plan_id"])
        body = {
            "operation_id": identity,
            "preview_id": preview["preview_id"],
            "preview_sha256": preview["preview_sha256"],
            "expected_selection_id": params["expected_selection_id"],
            "expected_selection_sha256": params["expected_selection_sha256"],
        }
        path = self.store.root / "broker/operations" / (identity + ".json")
        if lose_reply:
            import ssl

            # Observe durable acceptance before dropping the unread HTTPS reply.
            payload = encoded(body)
            cookie = "; ".join(k + "=" + v for k, v in self.session.cookies.items())
            request = (
                f"POST /api/releases/apply HTTP/1.1\r\nHost: 127.0.0.1:18443\r\nOrigin: {ORIGIN}\r\n"
                f"X-CSRF-Token: {self.csrf}\r\nCookie: {cookie}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
            ).encode() + payload
            context = ssl.create_default_context(cafile=str(self.data / "ssl/server.crt"))
            with socket.create_connection(("127.0.0.1", 18443), timeout=15) as raw:
                with context.wrap_socket(raw, server_hostname="127.0.0.1") as connection:
                    connection.sendall(request)
                    wait(path.exists, message="apply was not durably received")
        else:
            result = self.http("POST", "/api/releases/apply", body=body)
            if result.status_code != 200:
                raise RuntimeError("real HTTP apply refused: " + str(result.status_code))
            wait(path.exists, message="apply was not durably received")
        return identity, body

    def status(self, identity):
        value = raw_request("status", {"operation_id": identity})
        if not value.get("ok"):
            raise RuntimeError("installed status unavailable")
        return value["result"]

    def finish(self, identity, states=("completed",)):
        def final():
            value = self.status(identity)
            if value["state"] in (
                "completed",
                "failed-restored",
                "recovery-required",
                "selection-conflict",
            ):
                if value["state"] not in states:
                    raise RuntimeError("owner operation held: " + value["state"])
                return value
            return None

        return wait(final, timeout=420, message="actual owner operation did not finish")

    def wait_mapped_worker(self, mapped):
        job_id = mapped["job_id"]
        helper = "cryptolabs-update-" + job_id

        def launched():
            path = self.jobs / (job_id + ".json")
            if not path.exists():
                return None
            job = json.loads(path.read_bytes())
            if (
                job.get("id") != job_id
                or job.get("helper") != helper
                or job.get("operation_id") != mapped["operation_id"]
            ):
                raise RuntimeError("mapped worker journal identity differs; native gate held")
            if job.get("state") in (
                "completed",
                "failed",
                "blocked",
                "interrupted",
                "recovery-required",
            ):
                return "job-" + job["state"]
            observed = docker("inspect", helper, check=False)
            if observed.returncode:
                return None
            value = json.loads(observed.stdout)[0]
            if (
                value.get("State", {}).get("Running") is True
                and value.get("Config", {}).get("Labels", {}).get("io.cryptolabs.update.worker")
                == job_id
            ):
                return "helper-running"
            return None

        return wait(
            launched, timeout=90, message="mapped worker did not start or reach a terminal job"
        )

    def service_update(self):
        before_proxy = inspect("cryptolabs-proxy")["Id"]
        old = self.selection()
        self.policy["writes_enabled"] = True
        write(POLICY, self.policy)
        params, p = self.preview("ipmi-new")
        identity, body = self.apply(params, p, lose_reply=True)
        mapping = self.jobs / "operations" / (identity + ".json")
        try:
            wait(mapping.exists, timeout=90, message="actual owner mapping was not created")
        except Exception:
            try:
                self.record('owner-mapping-observation', layout=self.layout,
                            operation_id=identity, **self.owner_mapping_observation(identity))
            except Exception:
                pass
            raise
        mapped = json.loads(mapping.read_bytes())
        job_id = mapped["job_id"]
        self.job_ids.add(job_id)
        continuation = self.wait_mapped_worker(mapped)
        old_main = self.kill_broker("service_update")
        run("systemctl", "start", SERVICE)
        self.wait_fresh_broker(old_main)
        final = self.finish(identity)
        if self.layout == 'named-volume':
            self.recovery.verify_successor(job_id)
        replay = self.http("POST", "/api/releases/apply", body=body)
        assert replay.status_code == 200 and replay.json()["operation_id"] == identity
        after = json.loads(mapping.read_bytes())
        assert after["job_id"] == job_id and final["job_id"] == job_id
        assert json.loads((self.jobs / (job_id + ".json")).read_bytes())["components"] == [
            "ipmi-monitor"
        ]
        names = docker("ps", "-a", "--format", "{{.Names}}").stdout.decode().splitlines()
        assert names.count("cryptolabs-update-" + job_id) == 1
        assert inspect("cryptolabs-proxy")["Id"] == before_proxy
        current = self.selection()
        for name in ("cryptolabs-proxy", "grafana", "vast-price-manager"):
            assert (
                current.manifest.data["components"][name] == old.manifest.data["components"][name]
            )
            assert current.selection["components"][name] == old.selection["components"][name]
        container = inspect("cryptolabs-proxy")
        mount = next(m for m in container["Mounts"] if m["Destination"] == "/data/auth")
        assert Path(mount["Source"]) == self.auth
        # Actual helper's retained job file is the same host backing path/inode, not /data/auth on the host.
        assert (
            final["state"] == "completed"
            and inspect("ipmi-monitor")["Config"]["Image"]
            == inspect(self.refs["ipmi-new"], image=True)["Id"]
        )
        self.record(
            "scoped-update-" + self.layout,
            result="passed",
            operation_id=identity,
            job_id=job_id,
            continuation_observed=continuation,
            helper="cryptolabs-update-" + job_id,
            auth_store_inode=self.auth.stat().st_ino,
            job_inode=(self.jobs / (job_id + ".json")).stat().st_ino,
            unscoped_proxy_id=before_proxy,
            replay="same terminal mapping after dropped HTTPS response and broker restart",
        )
        # New root floor and live policy disable must prevent a fresh old-generation preview.
        self.policy["minimum_generation"] = self.generation + 1
        write(POLICY, self.policy)
        blocked = self.http("GET", "/api/releases/candidates?channel=main")
        assert blocked.status_code == 503
        self.admit("ipmi-new")
        assert self.http("GET", "/api/releases/candidates?channel=main").status_code == 200
        self.policy["writes_enabled"] = False
        write(POLICY, self.policy)
        params, p = self.preview("ipmi-new")
        rejected = self.http(
            "POST",
            "/api/releases/apply",
            body={
                "operation_id": str(uuid.uuid4()),
                "preview_id": p["preview_id"],
                "preview_sha256": p["preview_sha256"],
                "expected_selection_id": params["expected_selection_id"],
                "expected_selection_sha256": params["expected_selection_sha256"],
            },
        )
        assert rejected.status_code == 503
        self.policy["writes_enabled"] = True
        write(POLICY, self.policy)
        self.record(
            "fresh-policy-" + self.layout,
            result="passed",
            raised_generation=True,
            disabled_apply=True,
        )

    def proxy_adopt(self):
        from cryptolabs_proxy.standard_adoption import StandardAdoption

        before_service = inspect("ipmi-monitor")["Id"]
        before = inspect("cryptolabs-proxy")
        users = digest((self.auth / "users.json").read_bytes())
        params, p = self.preview("proxy-b")
        assert p["disconnect_expected"] is True
        identity, _ = self.apply(params, p)
        final = self.finish(identity)
        assert final["state"] == "completed"
        after = inspect("cryptolabs-proxy")
        assert (
            after["Id"] != before["Id"]
            and after["Image"] == inspect(self.refs["proxy-b"], image=True)["Id"]
        )
        assert after["HostConfig"]["PortBindings"] == before["HostConfig"]["PortBindings"]
        assert inspect("ipmi-monitor")["Id"] == before_service
        assert digest((self.auth / "users.json").read_bytes()) == users
        # Same cookie, no re-login: actual Nginx/auth server must accept it after replacement.
        response = self.http("GET", "/api/releases/session")
        assert response.status_code == 200 and response.json()["authenticated"] is True
        operation = json.loads(
            (self.store.root / "broker/operations" / (identity + ".json")).read_bytes()
        )
        recovered = StandardAdoption(PROXY_CONFIG).recover_adoption(
            operation["owner_plan"]["plan_id"]
        )
        assert recovered["state"] == "completed"
        self.record(
            "proxy-adopt-" + self.layout,
            result="passed",
            operation_id=identity,
            plan_id=operation["owner_plan"]["plan_id"],
            before_id=before["Id"],
            after_id=after["Id"],
            session_reconnect=True,
            owner_recovery=recovered["state"],
            unscoped_service_id=before_service,
            note="actual A/B replacement from identical reviewed application bytes, not future-version acceptance",
        )

    def rollback(self):
        original = inspect("ipmi-monitor")
        users = digest((self.auth / "users.json").read_bytes())
        params, p = self.preview("ipmi-bad")
        identity, _ = self.apply(params, p)
        final = self.finish(identity, states=("recovery-required", "failed-restored"))
        after = inspect("ipmi-monitor")
        assert after["Id"] == original["Id"] and after["Image"] == original["Image"]
        self.wait_healthy("ipmi-monitor")
        self.job_ids.add(final["job_id"])
        job = json.loads((self.jobs / (final["job_id"] + ".json")).read_bytes())
        assert job["results"]["ipmi-monitor"]["state"] == "rolled_back"
        assert digest((self.auth / "users.json").read_bytes()) == users
        self.record(
            "failed-health-rollback",
            result="passed",
            operation_id=identity,
            job_id=job["id"],
            original_id=after["Id"],
            original_image=after["Image"],
            owner_result="rolled_back",
            broker_state=final["state"],
        )

    def interrupted_adoption(self):
        params, p = self.preview("proxy-a")
        identity, _ = self.apply(params, p, lose_reply=True)
        path = self.store.root / "broker/operations" / (identity + ".json")

        def owner_started():
            value = json.loads(path.read_bytes())
            plan = value.get("owner_plan", {})
            return (
                value
                if plan
                and (PROXY_CONFIG / "standard-adoptions" / plan["plan_id"] / "plan.json").exists()
                else None
            )

        before = wait(
            owner_started, timeout=120, message="actual adoption private plan was not retained"
        )
        old_main = self.kill_broker("interrupted_adoption")
        run("systemctl", "start", SERVICE)
        self.wait_fresh_broker(old_main)
        final = self.finish(identity, states=("completed", "failed-restored", "recovery-required"))
        first = self.status(identity)
        raw_request("recover", {"operation_id": identity})
        time.sleep(1)
        second = self.status(identity)
        assert second["operation_id"] == first["operation_id"]
        self.record(
            "interrupted-adoption",
            result="passed",
            operation_id=identity,
            observed_before_kill=before["state"],
            after_restart=final["state"],
            after_fixed_recover=second["state"],
            precise_crash_window="held: scheduler race not claimed as exact mid-stop timing",
            note="real owner retained plan; completed/restored or visible uncertainty, never fabricated operation outcome",
        )

    def reset_fixture(self):
        self.consume_child_failure()
        run("systemctl", "stop", SERVICE, check=False)
        run("systemctl", "stop", SOCKET_UNIT, check=False)
        # Only exact helpers created by this fixture's retained operation IDs.
        for key in self.job_ids:
            name = "cryptolabs-update-" + key
            found = docker("inspect", name, check=False)
            if found.returncode == 0:
                value = json.loads(found.stdout)[0]
                assert (
                    value.get("Config", {}).get("Labels", {}).get("io.cryptolabs.update.worker")
                    == key
                )
                docker("rm", "-f", name)
        for key in self.owner_plans:
            for prefix in (
                "cryptolabs-adoption-lock-",
                "cryptolabs-proof-",
                "cryptolabs-recovery-proof-",
            ):
                name = prefix + key
                if docker("inspect", name, check=False).returncode == 0:
                    docker("rm", "-f", name)
        self.job_ids.clear()
        self.owner_plans.clear()
        owned = docker("ps", "-aq", "--filter", "label=" + self.label).stdout.decode().split()
        for identity in owned:
            value = inspect(identity)
            if value.get("Name") != "/native-fleet-registry":
                docker("rm", "-f", identity)
        for name in self.volumes:
            docker("volume", "rm", name, check=False)
        self.volumes = []
        for name in self.networks:
            docker("network", "rm", name, check=False)
        self.networks = []
        self.recovery.reset()
        shutil.rmtree(CONFIG, ignore_errors=True)
        shutil.rmtree(PROXY_CONFIG, ignore_errors=True)
        shutil.rmtree(Path("/etc/systemd/system") / (SERVICE + ".d"), ignore_errors=True)
        run("systemctl", "daemon-reload", check=False)

    def cleanup(self):
        failed = False
        quiesced = True

        def stop_registry():
            if docker("ps", "-aq", "--filter", "name=^/native-fleet-registry$").stdout.strip():
                docker("rm", "-f", "native-fleet-registry")

        def verify_quiesced():
            if docker("ps", "-aq", "--filter", "label=" + self.label).stdout.strip():
                raise RuntimeError("fixture consumers remain; cleanup held")
            if self.units:
                for name in (SERVICE, SOCKET_UNIT):
                    if run("systemctl", "is-active", name, check=False).stdout.strip() not in (
                        b"inactive",
                        b"failed",
                        b"unknown",
                    ):
                        raise RuntimeError("fixture units remain; cleanup held")

        for operation in (
            self.reset_fixture,
            stop_registry,
            verify_quiesced,
        ):
            try:
                operation()
            except Exception:
                failed = True
                quiesced = False
        try:
            if self.hosts is not None:
                Path("/etc/hosts").write_bytes(self.hosts)
        except Exception:
            failed = True
        trust_restored = False
        if quiesced:
            try:
                self.restore_registry_trust()
                trust_restored = True
                self.remove_registry_ca()
            except Exception:
                failed = True
        else:
            failed = True
        # Independent fixture cleanup continues. Preserve private custody and referenced
        # CA on uncertainty, pending the separately required external VM destruction.
        for unit in self.units:
            try:
                unit.unlink(missing_ok=True)
            except Exception:
                failed = True
        try:
            link = Path("/usr/local/bin/dc-overview")
            if link.is_symlink() and link.resolve() == Path(sys.executable).parent / "dc-overview":
                link.unlink()
            run("systemctl", "daemon-reload")
        except Exception:
            failed = True
        if trust_restored and self.registry_ca_file is None:
            try:
                if ROOT.exists():
                    shutil.rmtree(ROOT)
            except Exception:
                failed = True
        if failed:
            raise RuntimeError("fixture cleanup held; native gate held") from None
        self.record("native-cleanup", result="passed", external_vm_destruction="unverified")

    def execute(self):
        prepared = False
        failed = False
        message = "native verification failed; native gate held"
        phase = "preflight"
        try:
            self.preflight()
            prepared = True
            phase = "images"
            self.images()
            phase = "units_install"
            self.units_install()
            for layout in ("named-volume", "bind"):
                phase = "fixture"
                self.fixture(layout)
                phase = "service_update"
                self.service_update()
                phase = "proxy_adopt"
                self.proxy_adopt()
                if layout == "named-volume":
                    phase = "rollback"
                    self.rollback()
                else:
                    phase = "interrupted_adoption"
                    self.interrupted_adoption()
                phase = "reset_fixture"
                self.reset_fixture()
            self.record(
                "native-flow",
                result="passed",
                legacy_bootstrap_layout="named-volume",
                old_dc_service_oci=False,
                actual_collector_proof=False,
                engine_reply_loss_proof=False,
                production_enablement=False,
                external_vm_cleanup="parent must independently retain coordinator destruction receipt",
            )
        except Exception as error:
            failed = True
            # Only owned numeric command facts or exact builtin fixed messages;
            # arbitrary exceptions must never supply text or properties here.
            try:
                command_outcome, _ = command_failure_facts(error)
            except Exception:
                command_outcome = "unknown"
            if command_outcome == "timeout":
                message = "native command timed out; native gate held"
            elif type(error) is RuntimeError:
                arguments = BaseException.args.__get__(error, type(error))
                if (len(arguments) == 1 and type(arguments[0]) is str and arguments[0] in (
                    "native command timed out; native gate held",
                    "fixture registry push timed out; native gate held",
                )):
                    message = arguments[0]
            diagnostics = {"source_line": None, "error_kind": "unknown"}
            try:
                diagnostics = native_phase_failure_metadata(error, phase)
            except Exception:
                pass  # Diagnostic collection must preserve the original failure and cleanup.
            if phase == "fixture":
                diagnostics.update(
                    fixture_line=diagnostics["source_line"],
                    fixture_error_kind=diagnostics["error_kind"],
                )
            self.record(
                "native-flow",
                result="failed",
                phase=phase,
                reason="observable-native-gate-failed",
                message=message,
                **diagnostics,
            )
        finally:
            try:
                self.consume_child_failure()
            except Exception:
                pass  # A failed child collector must never skip existing cleanup.
            if prepared or self.fixture_owned:
                try:
                    self.cleanup()
                except Exception as error:
                    failed = True
                    message = "fixture cleanup held; native gate held"
                    diagnostics = {"source_line": None, "error_kind": "unknown"}
                    try:
                        diagnostics = native_phase_failure_metadata(error, "cleanup")
                    except Exception:
                        pass  # A diagnostic error must not replace terminal cleanup failure.
                    self.record("native-cleanup", result="failed", reason="cleanup-custody-held")
                    self.record(
                        "native-flow",
                        result="failed",
                        phase="cleanup",
                        reason="cleanup-custody-held",
                        **diagnostics,
                    )
        if failed:
            raise RuntimeError(message) from None


def fixture_failure_metadata(error, fixture_code=NativeQA.fixture.__code__):
    line = None
    frame = error.__traceback__
    while frame is not None:
        if frame.tb_frame.f_code is fixture_code:
            line = frame.tb_lineno
        frame = frame.tb_next
    if type(line) is not int or line not in {value for _, _, value in fixture_code.co_lines()}:
        return {"fixture_line": None, "fixture_error_kind": "unknown"}
    kind = "unknown"
    for error_type, label in (
        (AssertionError, "assertion-error"),
        (FileNotFoundError, "file-not-found"),
        (PermissionError, "permission-error"),
        (OSError, "os-error"),
        (RuntimeError, "runtime-error"),
    ):
        if isinstance(error, error_type):
            kind = label
            break
    return {"fixture_line": line, "fixture_error_kind": kind}


BOOTSTRAP_STEPS = (
    "legacy-runtime-inspect", "legacy-updater-probe", "legacy-capabilities-probe",
    "synthetic-runtime-inspect", "synthetic-db-seed", "synthetic-read-aggregate",
    "synthetic-root-custody", "synthetic-protection-helper", "legacy-job-seed",
    "compatible-wheel-install", "legacy-owner-rejection", "legacy-reconcile",
    "legacy-reconcile-replay", "scoped-select", "proxy-plan", "proxy-adopt", "proxy-health",
)
HELPER_DIAGNOSTIC_CODES = ()


def bootstrap_step_offsets(code):
    """Read fixed lexical markers from original bytecode, never frame locals."""
    markers = []
    previous = None
    for instruction in dis.get_instructions(code):
        if (instruction.opname == "STORE_FAST" and instruction.argval == "_bootstrap_step"
                and previous is not None and previous.opname == "LOAD_CONST"
                and type(previous.argval) is str and previous.argval in BOOTSTRAP_STEPS):
            markers.append((instruction.offset, previous.argval))
        previous = instruction
    return tuple(markers)


def helper_code_matches(actual, expected):
    if type(actual) is not types.CodeType or type(expected) is not types.CodeType:
        return False
    for field in ("co_argcount", "co_posonlyargcount", "co_kwonlyargcount", "co_nlocals",
                  "co_stacksize", "co_flags", "co_code", "co_names", "co_varnames",
                  "co_filename", "co_name", "co_qualname", "co_firstlineno", "co_linetable",
                  "co_exceptiontable", "co_freevars", "co_cellvars"):
        if getattr(actual, field) != getattr(expected, field):
            return False
    if len(actual.co_consts) != len(expected.co_consts):
        return False
    for observed, wanted in zip(actual.co_consts, expected.co_consts):
        if type(wanted) is types.CodeType:
            if not helper_code_matches(observed, wanted):
                return False
        elif type(observed) is not type(wanted) or observed != wanted:
            return False
    return True


def capture_helper_diagnostics(helper, source, filename):
    """Bind loaded helper code to the exact retained bytes before trusting it."""
    global HELPER_DIAGNOSTIC_CODES
    if type(source) is not bytes or digest(source) != PROTECTION_SHA:
        return
    expected = compile(source, filename, "exec")
    entries = []
    def capture(code, need=False):
        entries.append((code, need))
        for constant in code.co_consts:
            if type(constant) is types.CodeType:
                capture(constant)
    for code in expected.co_consts:
        if type(code) is not types.CodeType:
            continue
        function = vars(helper).get(code.co_name)
        if type(function) is types.FunctionType:
            actual = function.__code__
            # Full compiled structure, including nested bodies and coordinates;
            # after capture every traceback comparison uses exact `is`.
            if helper_code_matches(actual, code):
                capture(actual, code.co_name == "need")
    HELPER_DIAGNOSTIC_CODES = (*HELPER_DIAGNOSTIC_CODES, *entries)[-128:]


def bootstrap_failure_metadata(
    error,
    codes=tuple(
        (function.__code__, label, bootstrap_step_offsets(function.__code__))
        for function, label in (
            (LegacyRecoveryFixture.bootstrap, "legacy-bootstrap"),
            (LegacyRecoveryFixture.seed_synthetic_selected_state, "synthetic-seed"),
            (LegacyRecoveryFixture.seed_failed_job, "legacy-bootstrap"),
            (LegacyRecoveryFixture.install_compatible_host, "legacy-bootstrap"),
            (LegacyRecoveryFixture.wheel_mirror, "legacy-bootstrap"),
            (LegacyRecoveryFixture.assert_host_versions, "legacy-bootstrap"),
            (run, "native-command"), (docker, "native-command"), (inspect, "native-command"),
        )
    ),
    bootstrap_codes=(LegacyRecoveryFixture.bootstrap.__code__, LegacyRecoveryFixture.seed_synthetic_selected_state.__code__),
    command_code=run.__code__,
    command_type=NativeCommandFailure,
):
    result = {"bootstrap_step": "unknown", "code_label": "unknown", "source_line": None,
              "guard_line": None, "error_kind": "unknown", "command_outcome": "unknown", "command_returncode": None,
              "scoped_select_diagnostic": "unknown", "scoped_select_inner_diagnostic": inner_unknown()}
    frames = []
    frame = BaseException.__traceback__.__get__(error, type(error))
    while frame is not None:
        frames.append(frame)
        frame = frame.tb_next
    if not any(any(frame.tb_frame.f_code is code for code in bootstrap_codes) for frame in frames):
        return result
    result["command_outcome"] = "none"
    helper_line = None
    need_seen = False
    for frame in frames:
        code = frame.tb_frame.f_code
        line = frame.tb_lineno
        if type(line) is not int or line not in {value for _, _, value in code.co_lines()}:
            continue
        trusted = next((entry for entry in codes if code is entry[0]), None)
        helper = next((entry for entry in HELPER_DIAGNOSTIC_CODES if code is entry[0]), None)
        if trusted is not None:
            _, label, markers = trusted
            for offset, step in markers:
                if offset <= frame.tb_lasti:
                    result["bootstrap_step"] = step
            result.update(code_label=label, source_line=line,
                          error_kind=fixture_failure_metadata(error, code)["fixture_error_kind"])
        elif helper is not None:
            if helper[1]:
                need_seen = True  # Skip need() trampoline; retain its trusted caller.
                continue
            helper_line = line
            result.update(code_label="synthetic-helper", source_line=line,
                          error_kind=fixture_failure_metadata(error, code)["fixture_error_kind"])
    if need_seen:
        result["guard_line"] = helper_line
    if type(error) is command_type and any(frame.tb_frame.f_code is command_code for frame in frames):
        result["command_outcome"], result["command_returncode"] = command_failure_facts(error)
        if result["bootstrap_step"] == "scoped-select":
            result["scoped_select_diagnostic"] = scoped_select_failure_fact(error)
            result["scoped_select_inner_diagnostic"] = scoped_select_inner_fact(error)
    return result


def native_phase_failure_metadata(
    error,
    phase,
    phase_codes=(
        ("preflight", NativeQA.preflight.__code__),
        ("images", NativeQA.images.__code__),
        ("units_install", NativeQA.units_install.__code__),
        ("fixture", NativeQA.fixture.__code__),
        ("service_update", NativeQA.service_update.__code__),
        ("proxy_adopt", NativeQA.proxy_adopt.__code__),
        ("rollback", NativeQA.rollback.__code__),
        ("interrupted_adoption", NativeQA.interrupted_adoption.__code__),
        ("reset_fixture", NativeQA.reset_fixture.__code__),
        ("cleanup", NativeQA.cleanup.__code__),
    ),
):
    # Capture original code objects at module load; runtime names/files grant no identity.
    code = next((code for name, code in phase_codes if name == phase), None)
    if code is None:
        return {"source_line": None, "error_kind": "unknown"}
    metadata = fixture_failure_metadata(error, fixture_code=code)
    result = {"source_line": metadata["fixture_line"], "error_kind": metadata["fixture_error_kind"]}
    if phase == "fixture":
        try:
            result["bootstrap_failure"] = bootstrap_failure_metadata(error)
        except Exception:
            pass  # Keep original phase evidence and lifecycle even without inner facts.
    return result


def inspect_volume(name):
    return json.loads(docker("volume", "inspect", name).stdout)[0]


# TRACEWEAVER: entrypoint=main; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
def main():
    if len(sys.argv) >= 5 and sys.argv[1] == '--scoped-select-child':
        scoped_select_child(int(sys.argv[2]), json.loads(sys.argv[3]), sys.argv[4:])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-inputs-only", action="store_true")
    parser.add_argument("--broker-child", action="store_true")
    parser.add_argument("--dc-source", type=Path)
    parser.add_argument("--dc-sha")
    parser.add_argument("--proxy-source", type=Path)
    parser.add_argument("--proxy-sha")
    parser.add_argument("--wheel-dir", type=Path)
    parser.add_argument("--legacy-wheel-dir", type=Path)
    parser.add_argument("--protection-helper", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    if args.broker_child:
        broker_child()
        return
    check_source_pin(args.proxy_sha)
    if args.check_inputs_only:
        check_recovery_inputs(args.proxy_sha)
        return
    if any(
        getattr(args, key) is None
        for key in ("dc_source", "dc_sha", "proxy_source", "wheel_dir", "evidence_dir", "legacy_wheel_dir", "protection_helper")
    ):
        parser.error("exact sources, SHAs, wheel and evidence directories are required")
    NativeQA(args).execute()


if __name__ == "__main__":
    _SCOPED_SELECT_DISPATCH_FRAME = sys._getframe()
    try:
        main()
    except BaseException as error:
        try:
            captured = _SCOPED_SELECT_TRACEBACK
            if captured is not None and captured[0] is error:
                trace = BaseException.__traceback__.__get__(error, type(error))
                for frame in captured[1]:
                    if trace is None or trace.tb_frame is not frame:
                        break
                    trace = trace.tb_next
                else:
                    if trace is captured[2]:
                        BaseException.__traceback__.__set__(error, trace)
        except BaseException:
            pass
        raise  # The same exception, rendered by the interpreter's current hook.
