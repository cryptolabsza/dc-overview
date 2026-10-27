#!/usr/bin/env python3
# TRACEWEAVER: file-role=native-verification; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
"""One sequential, guest-only integration proof. This is never a production installer."""

import argparse
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
import uuid
from pathlib import Path

REGISTRY_IMAGE = "registry@sha256:1290056e2357eceb0c047cb60ae9abb370305a218e2df650eb8d3ea021b1c151"
NGINX_BASE = "nginx@sha256:2db7d28517d1fba17c2da3210395f7be11a11b419246ad0da2edf782af72f367"
IPMI_OLD = "ghcr.io/cryptolabsza/ipmi-monitor@sha256:14774a0784787d95b32a6c94e28de84accc88f0c28f17e3b30e984f2c2f17fa5"
IPMI_NEW = "ghcr.io/cryptolabsza/ipmi-monitor@sha256:84563cf838bd34c12cc83239c06c44f9a69c01b9dfff570e35ca913ef1825dac"
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
        "src/dc_overview/cli.py": "39ec1edbf04d91293eed13a63f7fd8cc7d6f1a3f2d4f83017829cfe3b7c83b7f",
        "src/dc_overview/fleet_upgrade.py": "5f4504f38f64c59d00ca90b13cf94eb905c5fe3fe5ebd3fa49b28561f0d8cc14",
        "src/dc_overview/release_broker.py": "137c990c00ba4d59ade7c8490b9fd9b574709f73c0d072466bbc41e253fbb33b",
        "src/dc_overview/release_broker_service.py": "92dbdf0d83c2aa3ef74a518947599102077c58ee85a95589690087052d115d08",
        "src/dc_overview/release_candidates.py": "1dd829c1441d7bfb703122ac1ada4e6ecf40568df449ebb442cf597458b756bd",
        "src/dc_overview/release_catalog.py": "21d4cf4731226c4ca9498cd4999bec1ec90bb9d3628faa615e13f20ccd9a29f6",
        "src/dc_overview/templates/systemd/dc-overview-release-broker.service": "6128bf4553bd87458c680377e1b4490fc157b6f092072271bc77bd21b18c4612",
        "src/dc_overview/templates/systemd/dc-overview-release-broker.socket": "67994e4c1d4b2ac9fa4b44de9e8ba60db2b087424993fce77656c0618272c559",
    },
    "proxy": {
        "landing-page/index.html": "20061e8140c5132b68f0bdc5a7ebfd48023534cf6f1ea7f2921ea6d04530ff37",
        "nginx/nginx.conf": "7993c9adc7b90f9c79cc569470008a124bb31763ecbc3cf12105cd906c930fbb",
        "scripts/health-api.py": "cc70687058e964b1afce202fed0117f8fee511cdece637f853eee2f25684e6d3",
        "src/cryptolabs_proxy/auth.py": "b37585f4356459e69d0e3aabf79b3cf093a99ab0bb50a0212373934ca579ec72",
        "src/cryptolabs_proxy/config.py": "cb921e11d4cf316df013c53bd36c7de89b0a8e5cb66df6dd3131f7425d15cf3f",
        "src/cryptolabs_proxy/release_client.py": "d3ed1dd31ea3a54f07a17772fefdbbb1bc9105880ab7b0d563f17d73a4332c25",
        "src/cryptolabs_proxy/release_selection.py": "b56a4dac88c8ef0c03500430ab1054bcf142e4bfaeef7edce67fce0f27f5b5d4",
        "src/cryptolabs_proxy/standard_adoption.py": "1d608c6b25b41a1f2eca4c0b3e6034eb567db48c7212b00c72c1028e36ad6f17",
        "src/cryptolabs_proxy/templates/docker-compose.yml.j2": "ec923fb17e99c649bb0aacd95eb8aeee465cfc9dbc6c65b721461cbf094a8856",
        "src/cryptolabs_proxy/templates/nginx.conf.j2": "6b40f203f6331d6610e558e7a42655f8917fa87ce8ada5edc6f844ffab274377",
        "src/cryptolabs_proxy/templates/previous-standard-nginx-444d7c0.conf.j2": "f12e2b9800cbaa0e49e685506cfaad38eb7e568fa6d239fa15277af59073d8de",
        "src/cryptolabs_proxy/updates.py": "cdb0958893eb6a11dc2764c4384ea784bf4b9632418a0871c3cee35bde3d00b6",
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


def run(*args, input_bytes=None, timeout=180, check=True, env=None):
    try:
        result = subprocess.run(
            [str(a) for a in args], input=input_bytes, capture_output=True, timeout=timeout, env=env
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("native command timed out; native gate held") from None
    if check and result.returncode:
        # Never expose inspected environments, auth files, command arguments or private snapshots.
        raise RuntimeError(
            f"{Path(str(args[0])).name} failed (exit {result.returncode}); native gate held"
        )
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


def broker_child():
    """Accepted test-input adapter: replace discovery data only, preserve installed owners."""
    if os.geteuid() or platform.system() != "Linux":
        raise RuntimeError("fixture broker child is only for the disposable Linux guest")
    from dc_overview.fleet_config import FleetConfig
    from dc_overview.release_broker import ReleaseBroker, load_policy
    from dc_overview.release_broker_service import serve

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

    serve(
        ReleaseBroker(
            FleetConfig.load(CONFIG),
            load_policy(),
            discovery=fixture_assets,
            policy_loader=load_policy,
        )
    )


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
            sys.executable,
            "-c",
            "from cryptolabs_proxy.auth import create_user; import os; assert create_user('native-admin',os.environ['QA_USER_PASS'],'admin')",
            env=env,
        )
        manifest = {
            "schema_version": 1,
            "selection_contract": 1,
            "baseline_id": "native-baseline",
            "components": {
                "cryptolabs-proxy": self.component("proxy-a"),
                "ipmi-monitor": self.component("ipmi-old"),
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
        run("systemctl", "start", SOCKET_UNIT)
        denied = raw_request()
        assert denied["ok"] is False and denied["error"]["status"] == 503
        self.policy["allowed_uids"] = [65534]
        write(POLICY, self.policy)
        peer_denied = raw_request()
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
            "--mount",
            f"type=bind,src={SOCKET},dst={SOCKET},readonly",
            "--mount",
            "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock",
            "-e",
            "AUTH_SECRET_KEY=" + self.auth_secret,
            "-e",
            "FLEET_ADMIN_PASS=",
            "-e",
            "FLEET_PUBLIC_ORIGIN=" + ORIGIN,
            "-e",
            "RELEASE_SELECTION_REQUIRED=true",
            self.refs["proxy-a"],
        )
        self.wait_healthy("ipmi-monitor")
        self.wait_healthy("cryptolabs-proxy")
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
        if lose_reply:
            import ssl

            # Send real authenticated HTTPS request, close before reading any response.
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
        else:
            result = self.http("POST", "/api/releases/apply", body=body)
            if result.status_code != 200:
                raise RuntimeError("real HTTP apply refused: " + str(result.status_code))
        path = self.store.root / "broker/operations" / (identity + ".json")
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
        wait(mapping.exists, timeout=90, message="actual owner mapping was not created")
        mapped = json.loads(mapping.read_bytes())
        job_id = mapped["job_id"]
        self.job_ids.add(job_id)
        continuation = self.wait_mapped_worker(mapped)
        run("systemctl", "kill", "--signal=KILL", SERVICE)
        run("systemctl", "start", SERVICE)
        final = self.finish(identity)
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
        run("systemctl", "kill", "--signal=KILL", SERVICE)
        run("systemctl", "start", SERVICE)
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
                production_enablement=False,
                external_vm_cleanup="parent must independently retain coordinator destruction receipt",
            )
        except Exception as error:
            failed = True
            if isinstance(error, RuntimeError) and str(error) in (
                "native command timed out; native gate held",
                "fixture registry push timed out; native gate held",
            ):
                message = str(error)
            diagnostics = {}
            if phase == "fixture":
                diagnostics = {"fixture_line": None, "fixture_error_kind": "unknown"}
                try:
                    diagnostics = fixture_failure_metadata(error)
                except Exception:
                    pass  # Diagnostic collection must preserve the original failure and cleanup.
            self.record(
                "native-flow",
                result="failed",
                phase=phase,
                reason="observable-native-gate-failed",
                message=message,
                **diagnostics,
            )
        finally:
            if prepared or self.fixture_owned:
                try:
                    self.cleanup()
                except Exception:
                    failed = True
                    message = "fixture cleanup held; native gate held"
                    self.record("native-cleanup", result="failed", reason="cleanup-custody-held")
                    self.record(
                        "native-flow",
                        result="failed",
                        phase="cleanup",
                        reason="cleanup-custody-held",
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


def inspect_volume(name):
    return json.loads(docker("volume", "inspect", name).stdout)[0]


# TRACEWEAVER: entrypoint=main; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-inputs-only", action="store_true")
    parser.add_argument("--broker-child", action="store_true")
    parser.add_argument("--dc-source", type=Path)
    parser.add_argument("--dc-sha")
    parser.add_argument("--proxy-source", type=Path)
    parser.add_argument("--proxy-sha")
    parser.add_argument("--wheel-dir", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    if args.broker_child:
        broker_child()
        return
    check_source_pin(args.proxy_sha)
    if args.check_inputs_only:
        return
    if any(
        getattr(args, key) is None
        for key in ("dc_source", "dc_sha", "proxy_source", "wheel_dir", "evidence_dir")
    ):
        parser.error("exact sources, SHAs, wheel and evidence directories are required")
    NativeQA(args).execute()


if __name__ == "__main__":
    main()
