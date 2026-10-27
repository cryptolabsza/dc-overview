# TRACEWEAVER: file-role=release-verification; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
# TRACEWEAVER: verifies=VER-FLEETUPDATE-001; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001
# TRACEWEAVER: file-role=release-verification; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
"""Admission must prove signature, producer, freshness and exact component identity."""

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from dc_overview import release_candidates as candidates


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@pytest.fixture
def admitted():
    key = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    times = {
        "issued_at": (now - timedelta(seconds=10)).isoformat(),
        "expires_at": (now + timedelta(seconds=120)).isoformat(),
    }
    manifest = raw(
        {
            "schema_version": 1,
            "selection_contract": 1,
            "baseline_id": "candidate",
            "components": {
                "grafana": {
                    "owner": "proxy-updater",
                    "release": "new",
                    "artifacts": {
                        "linux/amd64": {
                            "kind": "oci",
                            "reference": "grafana/grafana@sha256:" + "a" * 64,
                        }
                    },
                }
            },
        }
    )
    producer = {
        "repository_id": 1133295682,
        "workflow": ".github/workflows/release.yml",
        "ref": "refs/heads/main",
        "source_sha": "b" * 40,
        "run_id": 123,
        "attempt": 1,
    }
    envelope = {
        "schema_version": 1,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "component_admissions": [
            {
                "component": "grafana",
                "channel": "main",
                "platform": "linux/amd64",
                "identity": "grafana/grafana@sha256:" + "a" * 64,
                "required_capabilities": {"release_components": 1},
                "independently_replaceable": True,
                "dependency_group": [],
            }
        ],
        "producer": producer,
        "owner_approval_receipt": "fixture-only",
        "generation": 5,
        **times,
    }
    admission = raw(envelope)
    identity = hashlib.sha256(admission).hexdigest()
    index = {
        "schema_version": 1,
        "generation": 5,
        **times,
        "candidates": {identity: identity},
        "revoked": [],
    }
    policy = {
        "public_key_hex": key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        "allowed_producer": {k: producer[k] for k in ("repository_id", "workflow", "ref")},
        "max_validity_seconds": 300,
    }

    def verify(**changes):
        env = changes.pop("envelope", envelope)
        idx = changes.pop("index", index)
        a = raw(env)
        if a != admission:
            idx = {
                **idx,
                "candidates": {hashlib.sha256(a).hexdigest(): hashlib.sha256(a).hexdigest()},
            }
        i = raw(idx)
        return candidates.verify_candidate(
            manifest,
            a,
            changes.pop("signature", key.sign(a)),
            i,
            key.sign(i),
            changes.pop("policy", policy),
            now=now,
            highest_generation=changes.pop("highest_generation", 0),
            **changes,
        )

    return locals()


def test_signed_candidate_exact_boundary(admitted):
    result = admitted["verify"]()
    assert result.candidate_id == admitted["identity"]
    assert result.manifest.raw == admitted["manifest"]


@pytest.mark.parametrize(
    "fault",
    [
        "signature",
        "producer",
        "manifest",
        "expired",
        "replay",
        "revoked",
        "identity",
        "missing-trust",
    ],
)
def test_admission_failures_are_unavailable(admitted, fault):
    import copy

    f = admitted
    changes = {}
    envelope = copy.deepcopy(f["envelope"])
    index = copy.deepcopy(f["index"])
    if fault == "signature":
        changes["signature"] = bytes(64)
    if fault == "producer":
        envelope["producer"]["repository_id"] = 1
    if fault == "manifest":
        envelope["manifest_sha256"] = "f" * 64
    if fault == "expired":
        index["expires_at"] = (f["now"] - timedelta(seconds=1)).isoformat()
    if fault == "replay":
        changes["highest_generation"] = 6
    if fault == "revoked":
        index["revoked"] = [f["identity"]]
    if fault == "identity":
        envelope["component_admissions"][0]["identity"] = "grafana/grafana@sha256:" + "f" * 64
    if fault == "missing-trust":
        changes["policy"] = {}
    changes.update(envelope=envelope, index=index)
    with pytest.raises((ValueError, RuntimeError)):
        f["verify"](**changes)


def test_compatibility_refuses_incomplete_group_and_capability(admitted):
    candidate = admitted["verify"]()
    candidates.require_compatible(
        [candidate], ["grafana"], {"release_components": 1}, "linux/amd64", "services-update"
    )
    with pytest.raises(ValueError):
        candidates.require_compatible(
            [candidate], ["grafana"], {}, "linux/amd64", "services-update"
        )
    candidate.admission["component_admissions"][0].update(
        independently_replaceable=False, dependency_group=["grafana", "prometheus"]
    )
    with pytest.raises(ValueError):
        candidates.require_compatible(
            [candidate], ["grafana"], {"release_components": 1}, "linux/amd64", "services-update"
        )


def test_discovery_follows_only_fixed_github_asset_hosts():
    class Response:
        def __init__(self, status, content=b"", location=None):
            self.status_code = status
            self.content = content
            self.headers = {"Location": location} if location else {}

        def raise_for_status(self):
            pass

        def iter_content(self, size):
            yield self.content

        def close(self):
            pass

    class Session:
        def __init__(self, target):
            self.target = target
            self.urls = []

        def get(self, url, **kwargs):
            self.urls.append(url)
            return (
                Response(302, location=self.target)
                if len(self.urls) == 1
                else Response(200, b"signed-bytes")
            )

    good = Session("https://release-assets.githubusercontent.com/fixed/artifact?opaque=signature")
    assert (
        candidates.GitHubDiscovery(good)._get(
            "https://api.github.com/repos/cryptolabsza/dc-overview/releases/assets/1"
        )
        == b"signed-bytes"
    )
    bad = Session("http://127.0.0.1/private")
    with pytest.raises((ValueError, RuntimeError)):
        candidates.GitHubDiscovery(bad)._get(
            "https://api.github.com/repos/cryptolabsza/dc-overview/releases/assets/1"
        )
    assert len(bad.urls) == 1
