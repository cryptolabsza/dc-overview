# TRACEWEAVER: file-role=release-owner; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
"""Verify exact publisher bytes against installed trust; discovery confers no trust."""

import hashlib
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .release_catalog import COMPONENTS, HEX, Manifest, _json, _keys, artifact_identity

REPOSITORY_ID = 1133295682
ASSETS = (
    "suite-release.json",
    "suite-admission.json",
    "suite-admission.sig",
    "admission-index.json",
    "admission-index.sig",
)
MAX_BYTES = 1024 * 1024


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
    """Only numeric fixed repository and exact release asset family may be fetched."""

    def __init__(self, session=None):
        import requests

        self.session = session or requests.Session()

    def _get(self, url, *, api=False):
        deadline = getattr(self, "_deadline", time.monotonic() + 10)
        for _redirect in range(4):
            parsed = urlsplit(url)
            if (
                parsed.scheme != "https"
                or parsed.hostname
                not in (
                    "api.github.com",
                    "release-assets.githubusercontent.com",
                    "objects.githubusercontent.com",
                )
                or parsed.username
                or parsed.password
                or parsed.port not in (None, 443)
                or parsed.fragment
            ):
                raise ValueError("release discovery redirect is outside fixed GitHub hosts")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("release discovery timed out")
            response = self.session.get(
                url,
                timeout=(min(3, remaining), remaining),
                stream=True,
                allow_redirects=False,
                headers={
                    "Accept": "application/vnd.github+json" if api else "application/octet-stream"
                },
            )
            try:
                response.raise_for_status()
                if response.status_code in (301, 302, 303, 307, 308):
                    url = response.headers.get("Location", "")
                    continue
                if response.status_code != 200:
                    raise RuntimeError("release discovery unavailable")
                parts = []
                size = 0
                for part in response.iter_content(65536):
                    size += len(part)
                    if size > MAX_BYTES:
                        raise ValueError("release discovery document too large")
                    if time.monotonic() > deadline:
                        raise RuntimeError("release discovery timed out")
                    parts.append(part)
                return b"".join(parts)
            finally:
                response.close()
        raise RuntimeError("release discovery redirect limit exceeded")

    def discover(self):
        self._deadline = time.monotonic() + 10
        values = _json(
            self._get(
                f"https://api.github.com/repositories/{REPOSITORY_ID}/releases?per_page=10",
                api=True,
            )
        )
        if not isinstance(values, list) or len(values) > 10:
            raise ValueError("invalid release discovery list")
        bundles = []
        for release in values:
            if not isinstance(release, dict) or release.get("draft") is not False:
                continue
            assets = release.get("assets", [])
            if not isinstance(assets, list):
                raise ValueError("invalid release assets")
            chosen = {}
            for asset in assets:
                if not isinstance(asset, dict) or asset.get("name") not in ASSETS:
                    continue
                name = asset["name"]
                url = asset.get("url", "")
                if (
                    name in chosen
                    or not isinstance(url, str)
                    or not re.fullmatch(
                        r"https://api\.github\.com/repos/cryptolabsza/dc-overview/releases/assets/[1-9][0-9]*",
                        url,
                    )
                ):
                    raise ValueError("invalid fixed release asset URL")
                chosen[name] = url
            if set(chosen) == set(ASSETS):
                bundles.append({name: self._get(url) for name, url in chosen.items()})
        return bundles
