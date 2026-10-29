# TRACEWEAVER: file-role=release-owner; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
"""Verify exact publisher bytes against installed trust; discovery confers no trust."""

import base64
import binascii
import hashlib
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .release_catalog import (
    COMPONENTS,
    HEX,
    Manifest,
    _json,
    _keys,
    _object_pairs,
    artifact_identity,
)

REPOSITORY_ID = 1133295682
ASSETS = (
    "suite-release.json",
    "suite-admission.json",
    "suite-admission.sig",
    "admission-index.json",
    "admission-index.sig",
)
MAX_BYTES = 1024 * 1024
PACK_URL = (
    "https://api.github.com/repositories/1133295682/contents/current-pack.json"
    "?ref=fleet-suite-current"
)
PACK_MAX_BYTES = 8 * MAX_BYTES
PACK_MAX_DECODED_BYTES = 5 * MAX_BYTES
DISCOVERY_MAX_SUITE_ENVELOPES = 32
DISCOVERY_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class Candidate:
    candidate_id: str
    manifest: Manifest
    admission: dict
    index: dict
    # Exact proof retained for freshness/revocation revalidation at application.
    manifest_raw: bytes
    admission_raw: bytes
    signature: bytes
    index_raw: bytes
    index_signature: bytes


def _timestamp(value):
    if not isinstance(value, str):
        raise ValueError("invalid admission timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
            raise ValueError()
        return parsed
    except (ValueError, TypeError):
        raise ValueError("invalid admission timestamp") from None


def _validity(document, now, maximum):
    issued, expires = _timestamp(document["issued_at"]), _timestamp(document["expires_at"])
    if not issued <= now < expires or not 0 < (expires - issued).total_seconds() <= maximum:
        raise ValueError("admission is expired or outside installed validity policy")
    if type(document["generation"]) is not int or document["generation"] < 1:
        raise ValueError("invalid admission generation")


def _signed(raw, signature, key):
    if (
        not isinstance(raw, bytes)
        or not 0 < len(raw) <= MAX_BYTES
        or not isinstance(signature, bytes)
        or len(signature) != 64
    ):
        raise ValueError("invalid signed release document")
    try:
        key.verify(signature, raw)
    except InvalidSignature:
        raise ValueError("release signature verification failed") from None
    value = _json(raw)
    if (
        not isinstance(value, dict)
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
    ):
        raise ValueError("unsupported admission schema")
    return value


# TRACEWEAVER: entrypoint=verify_candidate; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
def verify_candidate(
    manifest_raw,
    admission_raw,
    signature,
    index_raw,
    index_signature,
    policy,
    *,
    now=None,
    highest_generation=0,
):
    """Trust and producer policy are mandatory installed inputs, never defaults."""
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(policy["public_key_hex"]))
        maximum = policy["max_validity_seconds"]
        producer_policy = policy["allowed_producer"]
        if (
            type(maximum) is not int
            or maximum <= 0
            or producer_policy["repository_id"] != REPOSITORY_ID
        ):
            raise ValueError()
        if set(producer_policy) != {"repository_id", "workflow", "ref"} or not all(
            isinstance(producer_policy[k], str) and producer_policy[k] for k in ("workflow", "ref")
        ):
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise RuntimeError("release trust policy is unavailable") from None
    admission = _signed(admission_raw, signature, key)
    index = _signed(index_raw, index_signature, key)
    _keys(
        admission,
        {
            "schema_version",
            "manifest_sha256",
            "component_admissions",
            "producer",
            "owner_approval_receipt",
            "generation",
            "issued_at",
            "expires_at",
        },
    )
    _keys(
        index, {"schema_version", "generation", "issued_at", "expires_at", "candidates", "revoked"}
    )
    now = now or datetime.now(timezone.utc)
    _validity(admission, now, maximum)
    _validity(index, now, maximum)
    if (
        type(highest_generation) is not int
        or index["generation"] < highest_generation
        or admission["generation"] > index["generation"]
    ):
        raise ValueError("admission generation rollback")
    identity = hashlib.sha256(admission_raw).hexdigest()
    if (
        not isinstance(index["candidates"], dict)
        or len(index["candidates"]) > 1024
        or any(
            not isinstance(k, str)
            or not HEX.fullmatch(k)
            or not isinstance(v, str)
            or not HEX.fullmatch(v)
            for k, v in index["candidates"].items()
        )
        or not isinstance(index["revoked"], list)
        or len(index["revoked"]) > 1024
        or any(not isinstance(v, str) or not HEX.fullmatch(v) for v in index["revoked"])
        or len(set(index["revoked"])) != len(index["revoked"])
        or index["candidates"].get(identity) != identity
        or identity in index["revoked"]
    ):
        raise ValueError("candidate is absent from current index or revoked")
    producer = admission["producer"]
    _keys(producer, {"repository_id", "workflow", "ref", "source_sha", "run_id", "attempt"})
    if (
        any(
            producer.get(k) != v or type(producer.get(k)) is not type(v)
            for k, v in producer_policy.items()
        )
        or not isinstance(producer["source_sha"], str)
        or not re.fullmatch("[0-9a-f]{40}", producer["source_sha"])
        or any(type(producer[k]) is not int or producer[k] <= 0 for k in ("run_id", "attempt"))
        or not isinstance(admission["owner_approval_receipt"], str)
        or not 1 <= len(admission["owner_approval_receipt"]) <= 1024
    ):
        raise ValueError("unapproved release producer or approval receipt")
    manifest = Manifest.from_bytes(manifest_raw)
    if admission["manifest_sha256"] != manifest.sha256:
        raise ValueError("admitted manifest hash mismatch")
    entries = admission["component_admissions"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 32:
        raise ValueError("invalid component admissions")
    seen = set()
    for item in entries:
        _keys(
            item,
            {
                "component",
                "channel",
                "platform",
                "identity",
                "required_capabilities",
                "independently_replaceable",
                "dependency_group",
            },
        )
        name = item["component"]
        if not isinstance(name, str) or name not in manifest.data["components"] or name in seen:
            raise ValueError("invalid admitted component")
        seen.add(name)
        component = manifest.data["components"][name]
        if item["channel"] not in ("main", "dev") or item["channel"] != manifest.data.get(
            "component_channels", {}
        ).get(name, "main"):
            raise ValueError("admitted channel mismatch")
        artifact = (
            component["artifacts"].get(item["platform"])
            if isinstance(item["platform"], str)
            else None
        )
        if artifact is None or artifact_identity(artifact) != item["identity"]:
            raise ValueError("admitted artifact/platform mismatch")
        required, group = item["required_capabilities"], item["dependency_group"]
        if (
            not isinstance(required, dict)
            or len(required) > 32
            or any(
                not isinstance(k, str) or not 1 <= len(k) <= 80 or type(v) is not int or v < 1
                for k, v in required.items()
            )
            or type(item["independently_replaceable"]) is not bool
            or not isinstance(group, list)
            or not all(isinstance(n, str) and n in COMPONENTS for n in group)
            or len(group) != len(set(group))
            or len(group) > 32
            or (not item["independently_replaceable"] and name not in group)
        ):
            raise ValueError("invalid compatibility admission")
    return Candidate(
        identity,
        manifest,
        admission,
        index,
        manifest_raw,
        admission_raw,
        signature,
        index_raw,
        index_signature,
    )


def require_compatible(candidates, components, capabilities, platform, operation_kind):
    entries = {}
    for candidate in candidates:
        for entry in candidate.admission["component_admissions"]:
            if entry["component"] in components and entry["platform"] in (platform, "any"):
                if entry["component"] in entries:
                    raise ValueError("ambiguous admitted component")
                entries[entry["component"]] = entry
    if set(entries) != set(components):
        raise ValueError("exact scoped component admission required")
    if operation_kind == "proxy-adopt":
        if (
            set(components) != {"cryptolabs-proxy"}
            or not entries["cryptolabs-proxy"]["independently_replaceable"]
        ):
            raise ValueError("proxy adoption requires independently replaceable proxy alone")
    elif "cryptolabs-proxy" in components or any(
        COMPONENTS[n][0] != "proxy-updater" for n in components
    ):
        raise ValueError("service update scope is not owned by service updater")
    for entry in entries.values():
        if any(
            type(capabilities.get(k)) is not int or capabilities[k] < v
            for k, v in entry["required_capabilities"].items()
        ):
            raise ValueError("installed owner maintenance required")
        if not entry["independently_replaceable"] and not set(entry["dependency_group"]) <= set(
            components
        ):
            raise ValueError("complete admitted dependency group required")
    if len({entry["channel"] for entry in entries.values()}) != 1:
        raise ValueError("mixed scoped channels unsupported")
    return entries


class GitHubDiscovery:
    """Read one bounded public pack; the wrapper is never signing authority."""

    def __init__(self, session=None):
        import requests

        if session is None:
            session = requests.Session()
            session.trust_env = False
            session.auth = None
            session.headers.pop("Authorization", None)
        self.session = session
        self._next_allowed = 0.0

    @staticmethod
    def _retry_delay(headers):
        retry = headers.get("Retry-After")
        if retry is not None:
            try:
                delay = int(retry)
                if delay >= 0:
                    return min(delay, 3600)
            except (TypeError, ValueError):
                try:
                    reset_at = parsedate_to_datetime(retry)
                    delay = (reset_at - datetime.now(timezone.utc)).total_seconds()
                    return min(3600, max(0, delay))
                except (TypeError, ValueError, OverflowError):
                    pass
        reset = headers.get("X-RateLimit-Reset")
        if reset is not None:
            try:
                return min(3600, max(0, int(reset) - time.time()))
            except (TypeError, ValueError, OverflowError):
                pass
        return 60

    def _get_pack(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("release discovery timed out")
        response = self.session.get(
            PACK_URL,
            timeout=(min(3, remaining), remaining),
            stream=True,
            allow_redirects=False,
            headers={
                "Accept": "application/vnd.github.raw+json",
                "Cache-Control": "no-cache, no-store",
                "Pragma": "no-cache",
            },
        )
        try:
            if response.status_code in (403, 429):
                self._next_allowed = time.monotonic() + self._retry_delay(response.headers)
            if response.status_code != 200:
                raise RuntimeError("release discovery unavailable")
            parts = []
            size = 0
            for part in response.iter_content(65536):
                if not isinstance(part, (bytes, bytearray)):
                    raise ValueError("invalid pack response chunk")
                size += len(part)
                if size > PACK_MAX_BYTES:
                    raise ValueError("release pack exceeds body limit")
                if time.monotonic() > deadline:
                    raise RuntimeError("release discovery timed out")
                parts.append(part)
            if time.monotonic() > deadline:
                raise RuntimeError("release discovery timed out")
            return b"".join(parts)
        finally:
            response.close()

    @staticmethod
    def _parse_pack(body):
        try:
            pack = json.loads(
                body.decode("utf-8"),
                object_pairs_hook=_object_pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON constant")),
            )
        except (UnicodeError, json.JSONDecodeError):
            raise ValueError("invalid release pack JSON") from None
        _keys(
            pack,
            {"schema_version", "admission_index_b64", "admission_index_signature_b64", "families"},
        )
        if type(pack["schema_version"]) is not int or pack["schema_version"] != 1:
            raise ValueError("invalid release pack schema")
        families = pack["families"]
        if (
            not isinstance(families, list)
            or not 1 <= len(families) <= DISCOVERY_MAX_SUITE_ENVELOPES
        ):
            raise ValueError("invalid release pack family count")

        total_decoded = 0

        def decode(value, limit):
            nonlocal total_decoded
            if type(value) is not str or not 1 <= len(value) <= 4 * ((limit + 2) // 3):
                raise ValueError("invalid release pack base64 length")
            try:
                decoded = base64.b64decode(value.encode("ascii"), validate=True)
            except (UnicodeError, binascii.Error, ValueError):
                raise ValueError("invalid release pack base64") from None
            if len(decoded) > limit or base64.b64encode(decoded).decode("ascii") != value:
                raise ValueError("invalid release pack canonical base64")
            total_decoded += len(decoded)
            if total_decoded > PACK_MAX_DECODED_BYTES:
                raise ValueError("release pack decoded byte limit exceeded")
            return decoded

        index = decode(pack["admission_index_b64"], MAX_BYTES)
        index_signature = decode(pack["admission_index_signature_b64"], 64)
        if len(index_signature) != 64:
            raise ValueError("invalid release pack index signature length")
        bundles = []
        seen = set()
        for family in families:
            _keys(family, {"manifest_b64", "admission_b64", "admission_signature_b64"})
            manifest = decode(family["manifest_b64"], MAX_BYTES)
            admission = decode(family["admission_b64"], MAX_BYTES)
            signature = decode(family["admission_signature_b64"], 64)
            if len(signature) != 64:
                raise ValueError("invalid release pack admission signature length")
            identity = hashlib.sha256(admission).digest()
            if identity in seen:
                raise ValueError("duplicate release pack admission")
            seen.add(identity)
            bundles.append({
                "suite-release.json": manifest,
                "suite-admission.json": admission,
                "suite-admission.sig": signature,
                "admission-index.json": index,
                "admission-index.sig": index_signature,
            })
        return bundles

    # TRACEWEAVER: entrypoint=discover; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
    def discover(self):
        try:
            if time.monotonic() < self._next_allowed:
                raise RuntimeError("release discovery cooldown")
            deadline = time.monotonic() + DISCOVERY_TIMEOUT_SECONDS
            body = self._get_pack(deadline)
            bundles = self._parse_pack(body)
            if time.monotonic() > deadline:
                raise RuntimeError("release discovery timed out")
            return bundles
        except (ValueError, OSError, RuntimeError, TypeError, KeyError):
            raise RuntimeError("release discovery unavailable") from None
