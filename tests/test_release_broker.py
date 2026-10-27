# TRACEWEAVER: file-role=release-verification; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
# TRACEWEAVER: verifies=VER-FLEETUPDATE-001; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001
# TRACEWEAVER: file-role=release-verification; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
"""Exercise strict requests and durable operation replay against real selection store."""

import copy
import json
import uuid

import pytest
from test_release_candidates import admitted as _admitted
from test_scoped_release_selection import selected_host as _selected_host

from dc_overview import release_broker as broker

selected_host = _selected_host
admitted = _admitted


@pytest.mark.parametrize(
    "change",
    [
        {"extra": "/tmp/command"},
        {"schema_version": True},
        {"params": {"channel": "main", "url": "https://example.invalid"}},
        {"actor": ""},
        {"action": "shell"},
    ],
)
def test_strict_request_refuses_untrusted_fields(change):
    request = {
        "schema_version": 1,
        "action": "list",
        "params": {"channel": "main"},
        "actor": {"kind": "fleet-admin", "username": "fixture", "subject": "test-session"},
    }
    request.update(change)
    with pytest.raises(ValueError):
        broker.parse_request(json.dumps(request).encode() + b"\n")


def test_peer_authorization_and_extra_frames():
    assert broker.authorize_peer(0, [0]) is None
    with pytest.raises(PermissionError):
        broker.authorize_peer(1000, [0])
    with pytest.raises(ValueError):
        broker.parse_request(
            b'{"schema_version":1,"action":"list","params":{"channel":"main"},"actor":"x"}\n{}\n'
        )
    with pytest.raises(ValueError):
        broker.parse_request(b'{"schema_version":1,"schema_version":1}\n')


class Owner:
    def __init__(self):
        self.calls = []
        self.mapping = {}
        self.fail_response = False

    def capabilities(self, contract):
        return {
            "release_components": 1,
            "release_idempotency": 1,
            "proxy_selection_preview": 1,
            "proxy_adoption_recovery": 1,
            "supported_selection_contracts": [1, 2],
        }

    def declaration_evidence(self):
        return None  # Installed declaration validation is covered by the actual owner package.

    def identity(self):
        return {"store": "fixture-updater"}

    def submit(self, operation):
        self.calls.append(operation["operation_id"])
        value = self.mapping.setdefault(
            operation["operation_id"], {"id": "f" * 32, "state": "completed", "success": True}
        )
        if self.fail_response:
            self.fail_response = False
            raise OSError("lost reply after durable updater submit")
        return value

    def status(self, operation):
        return self.mapping.get(operation["operation_id"])


@pytest.fixture
def product(selected_host, admitted, monkeypatch):
    # Same root-custody adapter used by existing publication/CAS tests.
    monkeypatch.setattr(broker, "_private", lambda p, **k: None)
    from types import SimpleNamespace

    from dc_overview import fleet_upgrade

    original_docker = fleet_upgrade.subprocess.run

    def docker(command, **kwargs):
        result = original_docker(command, **kwargs)
        if command[2].startswith("sha256:"):
            value = json.loads(result.stdout)
            value["RepoDigests"].append("grafana/grafana@sha256:" + "a" * 64)
            result = SimpleNamespace(returncode=0, stdout=json.dumps(value), stderr="")
        return result

    monkeypatch.setattr(fleet_upgrade.subprocess, "run", docker)
    host = selected_host
    candidate = admitted["verify"]()
    owner = Owner()
    service = broker.ReleaseBroker(
        host.config,
        {**admitted["policy"], "writes_enabled": True, "minimum_generation": 5},
        discovery=lambda: [candidate],
        owner=owner,
        schedule=lambda *args: None,
    )
    return host, service, owner, candidate


def preview(product):
    host, service, owner, candidate = product
    return service.dispatch(
        "preview",
        {
            "candidate_ids": [candidate.candidate_id],
            "components": ["grafana"],
            "expected_selection_id": host.previous.selection["selection_id"],
            "expected_selection_sha256": host.previous.selection_sha256,
            "operation_kind": "services-update",
        },
        actor={"kind": "fleet-admin", "username": "fixture", "subject": "test-session"},
    )


def apply(product, p, operation_id=None):
    host, service, *_ = product
    return service.dispatch(
        "apply",
        {
            "operation_id": operation_id or str(uuid.uuid4()),
            "preview_id": p["preview_id"],
            "preview_sha256": p["preview_sha256"],
            "expected_selection_id": host.previous.selection["selection_id"],
            "expected_selection_sha256": host.previous.selection_sha256,
        },
        actor={"kind": "fleet-admin", "username": "fixture", "subject": "test-session"},
    )


def test_durable_lost_response_and_terminal_replay(product):
    host, service, owner, _ = product
    p = preview(product)
    result = apply(product, p)
    assert result["state"] == "prepared"
    operation_id = result["operation_id"]
    owner.fail_response = True
    service.run_operation(operation_id)
    assert (
        service.dispatch(
            "status",
            {"operation_id": operation_id},
            actor={"kind": "fleet-admin", "username": "fixture", "subject": "test-session"},
        )["state"]
        == "recovery-required"
    )
    # Restart reads the same persisted selection, preview and operation; updater maps UUID.
    service = broker.ReleaseBroker(
        host.config,
        service.policy,
        discovery=service.discovery,
        owner=owner,
        schedule=lambda *a: None,
    )
    service.dispatch(
        "recover",
        {"operation_id": operation_id},
        actor={"kind": "fleet-admin", "username": "fixture", "subject": "test-session"},
    )
    service.run_operation(operation_id)
    assert (
        service.dispatch(
            "status",
            {"operation_id": operation_id},
            actor={"kind": "fleet-admin", "username": "fixture", "subject": "test-session"},
        )["state"]
        == "completed"
    )
    assert len(owner.mapping) == 1
    assert apply((host, service, owner, product[3]), p, operation_id)["state"] == "completed"
    current = host.store.load(platform="linux/amd64")
    for name in host.previous.manifest.data["components"]:
        if name != "grafana":
            assert (
                current.manifest.data["components"][name]
                == host.previous.manifest.data["components"][name]
            )
            assert (
                current.selection["components"][name] == host.previous.selection["components"][name]
            )


def test_selection_cas_and_id_conflict(product):
    host, service, *_ = product
    p = preview(product)
    result = apply(product, p)
    params = {
        "operation_id": result["operation_id"],
        "preview_id": p["preview_id"],
        "preview_sha256": "f" * 64,
        "expected_selection_id": "old",
        "expected_selection_sha256": host.previous.selection_sha256,
    }
    with pytest.raises(broker.BrokerError, match="different request"):
        service.dispatch(
            "apply",
            params,
            actor={"kind": "fleet-admin", "username": "fixture", "subject": "test-session"},
        )
    path = host.store.root / "selection.json"
    path.write_bytes(path.read_bytes() + b"\n")
    service.run_operation(result["operation_id"])
    assert (
        service.dispatch(
            "status",
            {"operation_id": result["operation_id"]},
            actor={"kind": "fleet-admin", "username": "fixture", "subject": "test-session"},
        )["state"]
        == "selection-conflict"
    )


def test_disabled_apply_and_missing_production_trust(product):
    host, service, *_ = product
    p = preview(product)
    service.policy["writes_enabled"] = False
    with pytest.raises(broker.BrokerError, match="disabled"):
        apply(product, p)
    service.policy = {}
    with pytest.raises((RuntimeError, broker.BrokerError)):
        preview(product)


def test_disabled_restart_cannot_dispatch_retained_prepared_operation(product):
    _, service, owner, _ = product
    p = preview(product)
    result = apply(product, p)
    service.policy["writes_enabled"] = False
    service.run_operation(result["operation_id"])
    assert owner.calls == []
    assert service._current().selection_sha256 == p.get(
        "expected_selection_sha256", product[0].previous.selection_sha256
    )


def test_status_reconciles_existing_job_after_admission_expiry(product):
    _, service, owner, _ = product
    p = preview(product)
    result = apply(product, p)
    service.run_operation(result["operation_id"])
    # A terminal retained result remains inspectable independently of new admission availability.
    service.discovery = lambda: []
    assert (
        service.dispatch(
            "status",
            {"operation_id": result["operation_id"]},
            actor={"kind": "host-peer", "uid": 0},
        )["state"]
        == "completed"
    )


def test_committed_selection_with_unfinished_publication_reconciles_before_owner(product):
    host, service, owner, _ = product
    p = preview(product)
    result = apply(product, p)
    operation_path = service.root / "operations" / (result["operation_id"] + ".json")
    operation = json.loads(operation_path.read_bytes())
    import base64

    source = service.root / "previews" / "interrupted.manifest.json"
    source.write_bytes(base64.b64decode(operation["manifest"]))
    policy = copy.deepcopy(host.previous.selection["components"])
    policy["grafana"]["pin"] = "grafana/grafana@sha256:" + "a" * 64
    plan = host.store.prepare(source, platform="linux/amd64", policies=policy)
    host.store.begin_publication(
        plan,
        (host.config.config_dir / "fleet-config.yaml").read_bytes(),
        operation_id=result["operation_id"],
    )
    host.store.commit(plan)
    service.run_operation(result["operation_id"])
    assert not (host.store.root / ".lifecycle-publication.json").exists()
    assert (
        service.dispatch(
            "status",
            {"operation_id": result["operation_id"]},
            actor={"kind": "host-peer", "uid": 0},
        )["state"]
        == "completed"
    )
    assert len(owner.mapping) == 1


def test_discovery_uses_one_current_signed_index_for_older_candidates(product, admitted):
    import hashlib
    from dataclasses import replace

    from dc_overview.release_candidates import verify_candidate

    _, service, _, current = product
    from test_release_candidates import raw

    envelope = copy.deepcopy(admitted["envelope"])
    envelope.update(generation=4, owner_approval_receipt="older-fixture")
    old_raw = raw(envelope)
    old_id = hashlib.sha256(old_raw).hexdigest()
    old_index = copy.deepcopy(admitted["index"])
    old_index.update(generation=4, candidates={old_id: old_id})
    key = admitted["key"]
    old = verify_candidate(
        admitted["manifest"],
        old_raw,
        key.sign(old_raw),
        raw(old_index),
        key.sign(raw(old_index)),
        admitted["policy"],
        now=admitted["now"],
    )
    newest_index = copy.deepcopy(current.index)
    newest_index["candidates"][old_id] = old_id
    current = replace(
        current,
        index=newest_index,
        index_raw=raw(newest_index),
        index_signature=key.sign(raw(newest_index)),
    )
    service.discovery = lambda: [old, current]
    result = service.dispatch("list", {"channel": "main"}, actor={"kind": "host-peer", "uid": 0})
    assert {c["candidate_id"] for c in result["candidates"]} == {old_id, current.candidate_id}
    assert {c["generation"] for c in result["candidates"]} == {5}


def test_all_revoked_index_still_advances_replay_highwater(product, admitted):
    from dataclasses import replace

    from test_release_candidates import raw

    _, service, _, candidate = product
    old = candidate
    index = copy.deepcopy(candidate.index)
    index["generation"] = 6
    index["revoked"] = [candidate.candidate_id]
    data = raw(index)
    candidate = replace(
        candidate, index=index, index_raw=data, index_signature=admitted["key"].sign(data)
    )
    service.discovery = lambda: [candidate]
    with pytest.raises(broker.BrokerError):
        service.dispatch("list", {"channel": "main"}, actor={"kind": "host-peer", "uid": 0})
    service.discovery = lambda: [old]
    with pytest.raises(broker.BrokerError):
        service.dispatch("list", {"channel": "main"}, actor={"kind": "host-peer", "uid": 0})


def proxy_candidate(admitted):
    import hashlib

    from test_release_candidates import raw

    from dc_overview.release_candidates import verify_candidate

    manifest = json.loads(admitted["manifest"])
    item = manifest["components"].pop("grafana")
    item["artifacts"]["linux/amd64"]["reference"] = (
        "ghcr.io/cryptolabsza/cryptolabs-proxy@sha256:" + "b" * 64
    )
    manifest["components"]["cryptolabs-proxy"] = item
    data = raw(manifest)
    envelope = copy.deepcopy(admitted["envelope"])
    envelope["manifest_sha256"] = hashlib.sha256(data).hexdigest()
    envelope["component_admissions"][0].update(
        component="cryptolabs-proxy", identity=item["artifacts"]["linux/amd64"]["reference"]
    )
    a = raw(envelope)
    identity = hashlib.sha256(a).hexdigest()
    index = copy.deepcopy(admitted["index"])
    index["candidates"] = {identity: identity}
    i = raw(index)
    key = admitted["key"]
    return verify_candidate(
        data, a, key.sign(a), i, key.sign(i), admitted["policy"], now=admitted["now"]
    )


def test_proxy_adoption_recovers_lost_reply_without_rerun(product, admitted):
    host, service, owner, _ = product
    candidate = proxy_candidate(admitted)
    service.discovery = lambda: [candidate]
    plans = []
    adopts = []
    recoveries = []

    def plan(proposed):
        result = {
            "plan_id": "a" * 24,
            "image": proposed.targets["cryptolabs-proxy"]["reference"],
            "selection_sha256": proposed.selection_sha256,
        }
        plans.append(result)
        return result

    def adopt(plan):
        adopts.append(plan)
        raise OSError("lost response after owner retained outcome")

    def recover(operation):
        recoveries.append(operation["owner_plan"])
        return {"state": "completed", "plan_id": "a" * 24}

    owner.plan = plan
    owner.adopt = adopt
    owner.recover = recover
    p = service.dispatch(
        "preview",
        {
            "candidate_ids": [candidate.candidate_id],
            "components": ["cryptolabs-proxy"],
            "expected_selection_id": host.previous.selection["selection_id"],
            "expected_selection_sha256": host.previous.selection_sha256,
            "operation_kind": "proxy-adopt",
        },
        actor={"kind": "host-peer", "uid": 0},
    )
    result = service.dispatch(
        "apply",
        {
            "operation_id": str(uuid.uuid4()),
            "preview_id": p["preview_id"],
            "preview_sha256": p["preview_sha256"],
            "expected_selection_id": host.previous.selection["selection_id"],
            "expected_selection_sha256": host.previous.selection_sha256,
        },
        actor={"kind": "host-peer", "uid": 0},
    )
    service.run_operation(result["operation_id"])
    assert len(adopts) == 1
    service.policy["writes_enabled"] = False
    service.discovery = lambda: []
    service.run_operation(result["operation_id"])
    assert (
        service.dispatch(
            "status",
            {"operation_id": result["operation_id"]},
            actor={"kind": "host-peer", "uid": 0},
        )["state"]
        == "completed"
    )
    assert len(adopts) == len(recoveries) == 1
    assert plans[0] == recoveries[0]


def test_native_cli_routes_same_dispatcher(monkeypatch):
    from click.testing import CliRunner

    from dc_overview import cli, release_broker_service

    calls = []
    monkeypatch.setattr(
        release_broker_service,
        "request",
        lambda action, params: calls.append((action, params))
        or {"channel": "dev", "candidates": []},
    )
    result = CliRunner().invoke(cli.main, ["release", "candidates", "--channel", "dev"])
    assert result.exit_code == 0
    assert json.loads(result.output) == {"channel": "dev", "candidates": []}
    assert calls == [("list", {"channel": "dev"})]


def test_changed_updater_store_cannot_allocate_second_owner_job(product):
    _, service, owner, _ = product
    owner.identity = lambda: {"store": "original"}
    p = preview(product)
    result = apply(product, p)
    owner.fail_response = True
    service.run_operation(result["operation_id"])
    owner.identity = lambda: {"store": "replacement"}
    owner.mapping = {}  # New mount cannot reveal the old mapping; never resubmit here.
    service.run_operation(result["operation_id"])
    assert len(owner.calls) == 1
    assert (
        service.dispatch(
            "status",
            {"operation_id": result["operation_id"]},
            actor={"kind": "host-peer", "uid": 0},
        )["state"]
        == "recovery-required"
    )


def test_preview_content_hash_is_verified_before_apply(product):
    _, service, owner, _ = product
    p = preview(product)
    path = service.root / "previews" / (p["preview_id"] + ".json")
    value = json.loads(path.read_bytes())
    value["channel"] = "dev"
    broker.private_write(path, value)
    with pytest.raises(broker.BrokerError, match="Preview"):
        apply(product, p)
    assert owner.calls == []


def test_installed_policy_disable_is_reloaded_before_new_dispatch(product):
    host, service, owner, _ = product
    p = preview(product)
    service.policy_loader = lambda: {**service.policy, "writes_enabled": False}
    with pytest.raises(broker.BrokerError, match="disabled"):
        apply(product, p)
    assert owner.calls == []
    assert (
        host.store.load(platform="linux/amd64").selection_sha256 == host.previous.selection_sha256
    )


def test_changed_trust_policy_requires_new_preview(product):
    _, service, owner, _ = product
    p = preview(product)
    service.policy["max_validity_seconds"] *= 2
    with pytest.raises(broker.BrokerError, match="policy"):
        apply(product, p)
    assert owner.calls == []


def test_peer_revocation_is_checked_against_reloaded_policy(product):
    _, service, _, _ = product
    from dc_overview.release_broker_service import response

    service.policy["allowed_uids"] = [0]
    service.policy_loader = lambda: {**service.policy, "allowed_uids": [1000]}
    request = (
        broker.canonical(
            {
                "schema_version": 1,
                "action": "list",
                "params": {"channel": "main"},
                "actor": {"kind": "host-peer", "uid": 0},
            }
        )
        + b"\n"
    )
    result = json.loads(response(service, request, 0))
    assert result["ok"] is False
    assert result["error"]["status"] == 403


@pytest.mark.parametrize("existing_highwater", [False, True])
def test_minimum_generation_blocks_new_preview_before_owner_dispatch(product, existing_highwater):
    host, service, owner, _ = product
    if existing_highwater:
        service._candidates()
    service.policy = {**service.policy, "minimum_generation": 6}
    with pytest.raises(broker.BrokerError, match="Fresh current admission index unavailable"):
        preview(product)
    assert owner.calls == []
    assert list((service.root / "operations").glob("*.json")) == []
    assert (
        host.store.load(platform="linux/amd64").selection_sha256 == host.previous.selection_sha256
    )


@pytest.mark.parametrize(
    "watermark",
    [
        None,
        {"generation": True, "index_sha256": "a" * 64},
        {"generation": 5},
        {"generation": 5, "index_sha256": "invalid"},
    ],
)
def test_invalid_highwater_is_unavailable(product, watermark):
    _, service, _, _ = product
    service._ensure()
    broker.private_write(service.root / "high-water.json", watermark)
    with pytest.raises(broker.BrokerError, match="high-water"):
        service._candidates()
