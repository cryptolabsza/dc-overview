# TRACEWEAVER: file-role=release-verification; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
# TRACEWEAVER: verifies=VER-FLEETUPDATE-001; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001
# TRACEWEAVER: file-role=release-verification; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
"""Admission must prove signature, producer, freshness and exact component identity."""

import base64
import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

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


class Response:
    def __init__(self, status, content=b"", location=None, headers=None):
        self.status_code = status
        self.content = content
        self.headers = dict(headers or {})
        if location:
            self.headers["Location"] = location

    def raise_for_status(self):
        pass

    def iter_content(self, size):
        for offset in range(0, len(self.content), size):
            yield self.content[offset : offset + size]

    def close(self):
        pass


def signed_bundle(f, *, platform="linux/amd64", generation=5, index=None, expired=False):
    manifest = json.loads(f["manifest"])
    component = manifest["components"]["grafana"]
    component["artifacts"] = {platform: next(iter(component["artifacts"].values()))}
    manifest_raw = raw(manifest)
    envelope = copy.deepcopy(f["envelope"])
    envelope.update(generation=generation, manifest_sha256=hashlib.sha256(manifest_raw).hexdigest())
    envelope["component_admissions"][0]["platform"] = platform
    if expired:
        envelope["expires_at"] = (f["now"] - timedelta(seconds=1)).isoformat()
    admission_raw = raw(envelope)
    identity = hashlib.sha256(admission_raw).hexdigest()
    index = index or {**f["index"], "generation": generation, "candidates": {identity: identity}}
    index_raw = raw(index)
    return {
        "suite-release.json": manifest_raw,
        "suite-admission.json": admission_raw,
        "suite-admission.sig": f["key"].sign(admission_raw),
        "admission-index.json": index_raw,
        "admission-index.sig": f["key"].sign(index_raw),
    }


PACK_URL = (
    "https://api.github.com/repositories/1133295682/contents/current-pack.json"
    "?ref=fleet-suite-current"
)


class PackSession:
    """One fixed response; any legacy release or asset request is a test failure."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.urls = []
        self.requests = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        self.requests.append(kwargs)
        if url != PACK_URL:
            raise RuntimeError("legacy release listing or asset request")
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def pack_bytes(index_bundle, families):
    encode = lambda value: base64.b64encode(value).decode("ascii")
    return raw({
        "schema_version": 1,
        "admission_index_b64": encode(index_bundle["admission-index.json"]),
        "admission_index_signature_b64": encode(index_bundle["admission-index.sig"]),
        "families": [
            {
                "manifest_b64": encode(bundle["suite-release.json"]),
                "admission_b64": encode(bundle["suite-admission.json"]),
                "admission_signature_b64": encode(bundle["suite-admission.sig"]),
            }
            for bundle in families
        ],
    })


def current_families(admitted, *, all_revoked=False):
    first = signed_bundle(admitted)
    second = signed_bundle(admitted, platform="linux/arm64")
    identities = [hashlib.sha256(b["suite-admission.json"]).hexdigest() for b in (first, second)]
    index = {
        **admitted["index"],
        "generation": 6,
        "candidates": {identity: identity for identity in identities},
        "revoked": identities if all_revoked else [],
    }
    carrier = signed_bundle(admitted, generation=4, index=index, expired=True)
    return first, second, carrier, identities, index


def test_one_fixed_pack_snapshot_survives_ordinary_release_churn(admitted):
    first, second, carrier, _, _ = current_families(admitted)

    def release_record(number, bundle=None):
        return {"id": number, "draft": False, "published_at": datetime.now(timezone.utc).isoformat(),
                "assets": [{"name": name, "url": f"https://api.github.com/repos/cryptolabsza/dc-overview/releases/assets/{number * 10 + i}"}
                           for i, name in enumerate(bundle or {}, 1)]}

    class ChurnSession(PackSession):
        def __init__(self):
            super().__init__(Response(200, pack_bytes(carrier, [first, second])))
            self.legacy = [release_record(1), release_record(2, first)] + [
                release_record(n) for n in range(3, 101)
            ] + [release_record(101, carrier), release_record(102)]
            self.assets = {asset["url"]: bundle[asset["name"]]
                           for record, bundle in ((self.legacy[1], first), (self.legacy[-2], carrier))
                           for asset in record["assets"]}

        def get(self, url, **kwargs):
            if url == PACK_URL:
                return super().get(url, **kwargs)
            self.urls.append(url)
            self.requests.append(kwargs)
            parsed = urlsplit(url)
            if parsed.path == f"/repositories/{candidates.REPOSITORY_ID}/releases":
                query = parse_qs(parsed.query)
                page = int(query.get("page", ["1"])[0])
                size = int(query["per_page"][0])
                if page == 2:
                    self.legacy.pop(0)  # Ordinary deletion moves carrier before offset 100.
                return Response(200, raw(self.legacy[(page - 1) * size:page * size]))
            return Response(200, self.assets[url])

    session = ChurnSession()
    found = candidates.GitHubDiscovery(session).discover()
    assert found == [
        {**family, "admission-index.json": carrier["admission-index.json"],
         "admission-index.sig": carrier["admission-index.sig"]}
        for family in (first, second)
    ]
    assert session.urls == [PACK_URL]
    assert session.requests[0]["allow_redirects"] is False
    assert session.requests[0]["headers"] == {
        "Accept": "application/vnd.github.raw+json",
        "Cache-Control": "no-cache, no-store",
        "Pragma": "no-cache",
    }
    assert "Authorization" not in session.requests[0]["headers"]
    assert {candidates.verify_candidate(*[bundle[name] for name in candidates.ASSETS],
                                       admitted["policy"]).admission["component_admissions"][0]["platform"]
            for bundle in found} == {"linux/amd64", "linux/arm64"}


def test_all_revoked_pack_advances_real_broker_highwater_and_rejects_old_pack(
    admitted, tmp_path, monkeypatch
):
    from types import SimpleNamespace
    from dc_overview import release_broker as broker

    first, second, carrier, _, index = current_families(admitted, all_revoked=True)
    old = signed_bundle(admitted)
    session = PackSession(
        Response(200, pack_bytes(carrier, [first, second, carrier])),
        Response(200, pack_bytes(old, [old])),
    )
    monkeypatch.setattr(broker, "_private", lambda p, **k: None)
    monkeypatch.setattr(broker.catalog, "_require_root", lambda: None)
    monkeypatch.setattr(broker.catalog, "_check_root_path", lambda p, **k: None)
    (tmp_path / "releases").mkdir(mode=0o700)
    service = broker.ReleaseBroker(
        SimpleNamespace(config_dir=tmp_path),
        {**admitted["policy"], "minimum_generation": 5},
        discovery=candidates.GitHubDiscovery(session).discover,
        schedule=lambda *args: None,
    )
    with pytest.raises(broker.BrokerError, match="No fresh admitted releases"):
        service._candidates()
    expected = {"generation": 6, "index_sha256": hashlib.sha256(raw(index)).hexdigest()}
    assert json.loads((service.root / "high-water.json").read_bytes()) == expected
    with pytest.raises(broker.BrokerError, match="Fresh current admission index unavailable"):
        service._candidates()
    assert json.loads((service.root / "high-water.json").read_bytes()) == expected
    assert session.urls == [PACK_URL, PACK_URL]


def test_concurrent_pointer_reads_are_whole_old_or_new_packs(admitted):
    old = signed_bundle(admitted)
    first, second, carrier, _, _ = current_families(admitted)
    session = PackSession(
        Response(200, pack_bytes(old, [old])),
        Response(200, pack_bytes(carrier, [first, second])),
    )
    discovery = candidates.GitHubDiscovery(session)
    assert discovery.discover() == [old]
    newer = discovery.discover()
    assert len(newer) == 2
    assert {bundle["admission-index.json"] for bundle in newer} == {carrier["admission-index.json"]}
    assert session.urls == [PACK_URL, PACK_URL]


def test_owned_session_disables_ambient_credentials(monkeypatch):
    import requests

    class OwnedSession:
        trust_env = True
        headers = {"Authorization": "ambient"}

    session = OwnedSession()
    monkeypatch.setattr(requests, "Session", lambda: session)
    assert candidates.GitHubDiscovery().session is session
    assert session.trust_env is False
    assert "Authorization" not in session.headers


@pytest.mark.parametrize("fault", [
    "bool-schema", "unknown-field", "family-extra", "duplicate-json-key", "nan",
    "bad-base64", "noncanonical-base64",
    "empty-families", "duplicate-family", "short-signature", "large-document",
    "family-overflow", "body-overflow", "decoded-overflow", "truncated",
])
def test_pack_rejects_malformed_or_unbounded_snapshot(admitted, fault):
    bundle = signed_bundle(admitted)
    body = json.loads(pack_bytes(bundle, [bundle]))
    if fault == "bool-schema":
        body["schema_version"] = True
    elif fault == "unknown-field":
        body["download_url"] = "https://example.invalid"
    elif fault == "family-extra":
        body["families"][0]["url"] = "https://example.invalid"
    elif fault == "duplicate-json-key":
        body = b'{"schema_version":1,"schema_version":1}'
    elif fault == "nan":
        body = b'{"schema_version":NaN}'
    elif fault == "bad-base64":
        body["admission_index_b64"] = "!"
    elif fault == "noncanonical-base64":
        body["admission_index_b64"] = "YR=="
    elif fault == "empty-families":
        body["families"] = []
    elif fault == "duplicate-family":
        body["families"].append(body["families"][0])
    elif fault == "short-signature":
        body["families"][0]["admission_signature_b64"] = base64.b64encode(b"x" * 63).decode()
    elif fault == "large-document":
        body["families"][0]["manifest_b64"] = base64.b64encode(b"x" * (1048576 + 1)).decode()
    elif fault == "family-overflow":
        body["families"] = [
            {**body["families"][0], "admission_b64": base64.b64encode(str(i).encode()).decode()}
            for i in range(33)
        ]
    elif fault == "body-overflow":
        body = b" " * (8388608 + 1)
    elif fault == "decoded-overflow":
        families = []
        for i in range(3):
            family = dict(body["families"][0])
            family["manifest_b64"] = base64.b64encode(b"m" * 850000).decode()
            family["admission_b64"] = base64.b64encode(b"a" * 849999 + bytes([i])).decode()
            families.append(family)
        body["admission_index_b64"] = base64.b64encode(b"i" * 200000).decode()
        body["families"] = families
    else:
        body = b'{"schema_version":1'
    wire = body if isinstance(body, bytes) else raw(body)
    session = PackSession(Response(200, wire))
    with pytest.raises(RuntimeError, match="^release discovery unavailable$"):
        candidates.GitHubDiscovery(session).discover()
    assert session.urls == [PACK_URL]


@pytest.mark.parametrize("boundary", ["body", "decoded", "document", "families"])
def test_pack_accepts_exact_inclusive_limits(admitted, boundary):
    bundle = signed_bundle(admitted)
    index = dict(bundle)
    families = [bundle]
    if boundary == "decoded":
        index["admission-index.json"] = b"i" * (1048576 - 192)
        families = [
            {**bundle, "suite-release.json": b"m" * 1048576,
             "suite-admission.json": b"a" * 1048575 + bytes([i])}
            for i in range(2)
        ]
    elif boundary == "document":
        families = [{**bundle, "suite-release.json": b"m" * 1048576}]
    elif boundary == "families":
        families = [
            {**bundle, "suite-admission.json": bundle["suite-admission.json"] + str(i).encode()}
            for i in range(32)
        ]
    wire = pack_bytes(index, families)
    if boundary == "body":
        wire += b" " * (8388608 - len(wire))
        assert len(wire) == 8388608
    if boundary == "decoded":
        assert sum(len(value) for value in (
            index["admission-index.json"], index["admission-index.sig"],
            *(family[name] for family in families
              for name in ("suite-release.json", "suite-admission.json", "suite-admission.sig")),
        )) == 5242880
    session = PackSession(Response(200, wire))
    found = candidates.GitHubDiscovery(session).discover()
    assert found == [
        {**family, "admission-index.json": index["admission-index.json"],
         "admission-index.sig": index["admission-index.sig"]}
        for family in families
    ]
    assert session.urls == [PACK_URL]


def test_pack_streaming_deadline_refuses_without_second_request(admitted, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(candidates.time, "monotonic", lambda: clock[0])
    wire = pack_bytes(signed_bundle(admitted), [signed_bundle(admitted)])

    class SlowResponse(Response):
        def iter_content(self, size):
            yield wire[:1]
            clock[0] = 10.01
            yield wire[1:]

    session = PackSession(SlowResponse(200))
    with pytest.raises(RuntimeError, match="^release discovery unavailable$"):
        candidates.GitHubDiscovery(session).discover()
    assert session.urls == [PACK_URL]


@pytest.mark.parametrize("status", [302, 304, 403, 404, 429, "timeout", "chunk"])
def test_valid_service_list_maps_pack_transport_failure_to_503(admitted, tmp_path, monkeypatch, status):
    from types import SimpleNamespace
    from dc_overview import release_broker as broker
    from dc_overview.release_broker_service import response

    if status == "timeout":
        upstream = TimeoutError("upstream timeout")
    elif status == "chunk":
        class BrokenResponse(Response):
            def iter_content(self, size):
                yield b"{"
                raise TimeoutError("stream interrupted")
        upstream = BrokenResponse(200)
    else:
        upstream = Response(status, b"upstream failure", location="https://example.invalid")
    session = PackSession(upstream)
    monkeypatch.setattr(broker, "_private", lambda p, **k: None)
    monkeypatch.setattr(broker.catalog, "_require_root", lambda: None)
    monkeypatch.setattr(broker.catalog, "_check_root_path", lambda p, **k: None)
    (tmp_path / "releases").mkdir(mode=0o700)
    service = broker.ReleaseBroker(
        SimpleNamespace(config_dir=tmp_path),
        {**admitted["policy"], "minimum_generation": 5, "allowed_uids": [0]},
        discovery=candidates.GitHubDiscovery(session).discover,
        schedule=lambda *args: None,
    )
    valid = broker.canonical({"schema_version": 1, "action": "list", "params": {"channel": "main"},
                              "actor": {"kind": "host-peer", "uid": 0}}) + b"\n"
    result = json.loads(response(service, valid, 0))
    assert result["error"] == {"code": "unavailable", "message": "Installed release owner is unavailable", "status": 503}
    assert session.urls == [PACK_URL]
    invalid = broker.canonical({"schema_version": 1, "action": "list", "params": {"channel": "unknown"},
                                "actor": {"kind": "host-peer", "uid": 0}}) + b"\n"
    assert json.loads(response(service, invalid, 0))["error"]["status"] == 400


def test_rate_limit_cooldown_uses_no_extra_request(admitted, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(candidates.time, "monotonic", lambda: clock[0])
    bundle = signed_bundle(admitted)
    session = PackSession(
        Response(429, headers={"Retry-After": "60"}),
        Response(200, pack_bytes(bundle, [bundle])),
    )
    discovery = candidates.GitHubDiscovery(session)
    with pytest.raises(RuntimeError, match="^release discovery unavailable$"):
        discovery.discover()
    with pytest.raises(RuntimeError, match="^release discovery unavailable$"):
        discovery.discover()
    assert session.urls == [PACK_URL]
    clock[0] = 61.0
    assert discovery.discover() == [bundle]
    assert session.urls == [PACK_URL, PACK_URL]
