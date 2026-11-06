# TRACEWEAVER: file-role=policy-regression; req=REQ-AUTOADVANCE-008; trace=TRACE-AUTOADVANCE-008; ver=VER-AUTOADVANCE-008
# TRACEWEAVER: verifies=VER-AUTOADVANCE-008; req=REQ-AUTOADVANCE-008; trace=TRACE-AUTOADVANCE-008
# TRACEWEAVER: file-role=policy-regression; req=REQ-AUTOADVANCE-008; trace=TRACE-AUTOADVANCE-008; ver=VER-AUTOADVANCE-008
"""Approved C1-C8: policy-only pin/follow changes against the real selection store."""
import copy
import importlib
import json
from types import SimpleNamespace

import pytest
import yaml

from test_release_broker import admitted, product, selected_host
from dc_overview import release_catalog as catalog
from dc_overview import release_candidates

ACTOR = {"kind": "fleet-admin", "username": "fixture", "subject": "policy-session"}


def policy_module():
    return importlib.import_module("dc_overview.release_policy")


def candidate(version, *, identity="b", channel="main", platform="linux/amd64"):
    component = {"owner": "proxy-updater", "release": version, "artifacts": {
        platform: {"kind": "oci", "reference": "grafana/grafana@sha256:" + identity * 64}}}
    return SimpleNamespace(candidate_id=version + identity, manifest=SimpleNamespace(data={
        "schema_version": 1, "selection_contract": 1, "baseline_id": "fixture",
        "components": {"grafana": component}}), admission={"component_admissions": [{
            "component": "grafana", "channel": channel, "platform": platform,
            "identity": component["artifacts"][platform]["reference"],
            "required_capabilities": {"release_components": 1},
            "independently_replaceable": True, "dependency_group": []}]})


@pytest.mark.parametrize("version", ["latest", "dev", "1.5.0-rc.1", "01.5.0", "1.5", "2.0.0", "1.3.9"])
def test_follow_never_chooses_unstable_major_or_downgrade(version):
    chosen = policy_module().choose_candidate("grafana", "1.4.0", 1,
        [candidate(version)], {"release_components": 1}, "linux/amd64")
    assert chosen is None


def test_stable_order_is_numeric_not_lexical_and_ignores_dev():
    older, newest = candidate("1.9.0"), candidate("1.10.0")
    assert policy_module().choose_candidate("grafana", "1.4.0", 1,
        [newest, candidate("1.99.0", channel="dev"), older],
        {"release_components": 1}, "linux/amd64") is newest


@pytest.mark.parametrize("fault", ["platform", "capability", "dependency", "ambiguous"])
def test_follow_requires_compatible_unambiguous_independent_admission(fault):
    c = candidate("1.5.0", platform="linux/arm64" if fault == "platform" else "linux/amd64")
    values = [c]
    caps = {"release_components": 0 if fault == "capability" else 1}
    if fault == "dependency":
        c.admission["component_admissions"][0].update(independently_replaceable=False, dependency_group=["grafana", "prometheus"])
    if fault == "ambiguous":
        values.append(candidate("1.5.0", identity="c"))
    assert policy_module().choose_candidate("grafana", "1.4.0", 1, values, caps, "linux/amd64") is None


@pytest.fixture
def policy_product(product):
    host, service, owner, _ = product
    data = copy.deepcopy(host.previous.manifest.data)
    data["components"]["grafana"]["release"] = "1.4.0"
    path = host.config.config_dir / "test-current.json"
    path.write_text(json.dumps(data))
    host.previous = host.store.prepare(path, policies=host.previous.selection["components"], platform="linux/amd64")
    host.store.commit(host.previous)
    host.config.release_selection.selection_id = host.previous.selection["selection_id"]
    host.config.release_selection.selection_sha256 = host.previous.selection_sha256
    host.config.release_selection.components = host.previous.selection["components"]
    public = yaml.safe_load((host.config.config_dir / "fleet-config.yaml").read_bytes())
    public["release_selection"] = host.config._to_dict(include_secrets=False)["release_selection"]
    (host.config.config_dir / "fleet-config.yaml").write_text(yaml.safe_dump(public))
    installed = copy.deepcopy(data["components"]["grafana"])
    owner.installed_component = lambda current, name: copy.deepcopy(installed) if name == "grafana" else None
    return host, service, owner


def expected(service):
    current = service.store.load()
    return {"expected_selection_id": current.selection["selection_id"],
            "expected_selection_sha256": current.selection_sha256}


def set_mode(service, mode):
    return service.dispatch("policy-set", {"component": "grafana", "mode": mode, **expected(service)}, actor=ACTOR)


def admitted_version(admitted, version, identity="b", generation=5):
    manifest = json.loads(admitted["manifest"])
    component = manifest["components"]["grafana"]
    component["release"] = version
    component["artifacts"]["linux/amd64"]["reference"] = "grafana/grafana@sha256:" + identity * 64
    raw = catalog._canonical(manifest) if hasattr(catalog, "_canonical") else json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    envelope = copy.deepcopy(admitted["envelope"])
    envelope['generation'] = generation
    envelope["manifest_sha256"] = __import__("hashlib").sha256(raw).hexdigest()
    envelope["component_admissions"][0]["identity"] = component["artifacts"]["linux/amd64"]["reference"]
    admission = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    digest = __import__("hashlib").sha256(admission).hexdigest()
    index = {**admitted["index"], "generation":generation, "candidates": {digest: digest}}
    index_raw = json.dumps(index, sort_keys=True, separators=(",", ":")).encode()
    return release_candidates.verify_candidate(raw, admission, admitted["key"].sign(admission),
        index_raw, admitted["key"].sign(index_raw), admitted["policy"], now=admitted["now"])


def test_existing_components_default_pinned_with_no_implicit_follow(policy_product):
    host, service, owner = policy_product
    before = host.store.load().selection_raw
    listing = service.dispatch("policy-list", {}, actor=ACTOR)
    assert all(c["mode"] == "pinned" for c in listing["components"].values())
    assert listing["components"]["vast-price-manager"]["supported"] is False
    assert host.store.load().selection_raw == before
    assert owner.calls == []


def test_unpin_survives_restart_and_changes_only_one_policy_without_install(policy_product):
    host, service, owner = policy_product
    before = host.store.load()
    result = set_mode(service, "follow-stable")
    assert result["components"]["grafana"]["mode"] == "follow-stable"
    current = host.store.load()
    assert current.selection["components"]["grafana"] == {"origin": "baseline", "enabled": True}
    for name in before.selection["components"]:
        if name != "grafana":
            assert current.selection["components"][name] == before.selection["components"][name]
            assert current.manifest.data["components"][name] == before.manifest.data["components"][name]
    restarted = type(service)(host.config, service.policy, discovery=service.discovery, owner=owner, schedule=lambda *a: None)
    assert restarted.dispatch("policy-list", {}, actor=ACTOR)["components"]["grafana"]["mode"] == "follow-stable"
    assert owner.calls == []


def test_refresh_only_advances_opted_in_service_and_repin_installed_freezes_it(policy_product, admitted):
    host, service, owner = policy_product
    set_mode(service, "follow-stable")
    c = admitted_version(admitted, "1.5.0")
    service.discovery = lambda: [c]
    result = service.dispatch("policy-refresh", expected(service), actor=ACTOR)
    assert result["advanced"] == ["grafana"]
    assert host.store.load().manifest.data["components"]["grafana"]["release"] == "1.5.0"
    set_mode(service, "pinned")
    frozen = host.store.load()
    assert frozen.manifest.data["components"]["grafana"]["release"] == "1.4.0"
    assert frozen.selection["components"]["grafana"]["origin"] == "customer-pin"
    result = service.dispatch("policy-refresh", expected(service), actor=ACTOR)
    assert result["advanced"] == [] and host.store.load().selection_raw == frozen.selection_raw
    assert owner.calls == []


@pytest.mark.parametrize("fault", ["stale", "busy", "disabled", "unproven-installed"])
def test_mode_failure_has_no_partial_policy_or_selection_change(policy_product, fault):
    host, service, owner = policy_product
    from dc_overview.release_broker import BrokerError
    set_mode(service, "follow-stable")
    before = snapshot(host, service)
    params = {"component": "grafana", "mode": "pinned", **expected(service)}
    if fault == "stale": params["expected_selection_sha256"] = "0" * 64
    if fault == "busy":
        for path,value in [(host.jobs/'active.json',{'id':'e'*32}),(host.jobs/('e'*32+'.json'),{'id':'e'*32,'state':'running'})]:
            path.write_text(json.dumps(value));path.chmod(0o600)
    if fault == "disabled": service.policy["writes_enabled"] = False
    if fault == "unproven-installed": owner.installed_component = lambda *a: None
    codes = {'stale':'selection-conflict', 'busy':'busy', 'disabled':'disabled', 'unproven-installed':'installed-unverified'}
    with pytest.raises(BrokerError) as error:
        service.dispatch("policy-set", params, actor=ACTOR)
    assert error.value.code == codes[fault]
    assert snapshot(host, service) == before
    assert owner.calls == []


def snapshot(host, service):
    mode = service.root / 'policy-state.json'
    current = host.store.load()
    return (current.selection_raw, current.manifest.raw,
            (host.config.config_dir / 'fleet-config.yaml').read_bytes(),
            mode.read_bytes() if mode.exists() else None)


@pytest.mark.parametrize('fault', ['signature','expired','revoked','replay','digest','unavailable'])
def test_refresh_uses_actual_signed_admission_and_preserves_policy_on_failure(policy_product, admitted, fault):
    from dataclasses import replace
    from dc_overview.release_broker import BrokerError, canonical, sha
    from datetime import timedelta
    host, service, owner = policy_product
    set_mode(service, 'follow-stable')
    before = snapshot(host, service)
    c = admitted_version(admitted, '1.5.0')
    if fault == 'signature': c = replace(c, signature=b'0'*64)
    elif fault == 'digest': c = replace(c, manifest_raw=c.manifest_raw+b' ')
    elif fault in ('expired','revoked','replay'):
        index = copy.deepcopy(c.index)
        if fault == 'expired': index['expires_at'] = (admitted['now']-timedelta(seconds=1)).isoformat()
        elif fault == 'revoked': index['revoked'] = [c.candidate_id]
        else: index['generation'] = 4
        raw = canonical(index)
        c = replace(c,index_raw=raw,index_signature=admitted['key'].sign(raw))
    def discover():
        if fault == 'unavailable': raise OSError('offline fixture')
        return [c]
    service.discovery = discover
    with pytest.raises(BrokerError) as error:
        service.dispatch('policy-refresh',expected(service),actor=ACTOR)
    assert error.value.code == 'unavailable'
    assert snapshot(host,service) == before and owner.calls == []


def test_repeated_check_never_downgrades_an_already_pending_target(policy_product, admitted):
    host, service, owner = policy_product
    set_mode(service,'follow-stable')
    service.discovery = lambda:[admitted_version(admitted,'1.8.0')]
    service.dispatch('policy-refresh',expected(service),actor=ACTOR)
    before = snapshot(host,service)
    service.discovery = lambda:[admitted_version(admitted,'1.5.0',generation=6)]
    result = service.dispatch('policy-refresh',expected(service),actor=ACTOR)
    assert result['advanced'] == [] and result['reasons']['grafana']
    assert snapshot(host,service) == before and owner.calls == []


@pytest.mark.parametrize('boundary', ['journal','selection','public','policy','finish'])
def test_interrupted_policy_publication_restarts_to_a_coherent_state(policy_product, monkeypatch, boundary):
    import dc_overview.release_policy as policy
    from dc_overview.release_broker import ReleaseBroker
    from dc_overview.fleet_config import FleetConfig
    from pathlib import Path
    host, service, owner = policy_product
    before = snapshot(host, service)
    original_write = policy.private_write
    original_atomic = catalog._atomic_write
    original_unlink = Path.unlink
    fired = []
    def write(path, value):
        if not fired and ((boundary=='journal' and path.name=='policy-publication.json') or
                          (boundary=='policy' and path.name=='policy-state.json')):
            fired.append(True); raise OSError('fixture publication interruption')
        return original_write(path,value)
    def atomic(path,*args,**kwargs):
        if boundary=='selection' and path.name=='selection.json' and not fired:
            fired.append(True); raise OSError('fixture selection interruption')
        return original_atomic(path,*args,**kwargs)
    def unlink(path,*args,**kwargs):
        if boundary=='finish' and path.name=='policy-publication.json' and not fired:
            fired.append(True); raise OSError('fixture cleanup interruption')
        return original_unlink(path,*args,**kwargs)
    with monkeypatch.context() as change:
        change.setattr(policy,'private_write',write)
        change.setattr(catalog,'_atomic_write',atomic)
        change.setattr(Path,'unlink',unlink)
        if boundary=='public':
            def fail_public(**kw):
                fired.append(True);raise OSError('public interruption')
            change.setattr(host.config,'persist_lifecycle',fail_public)
        with pytest.raises((OSError,RuntimeError,ValueError)):
            set_mode(service,'follow-stable')
    assert fired, 'test never reached its intended publication boundary'
    # Recreate configuration from persisted public data, not the original Python object.
    config = FleetConfig.load(host.config.config_dir)
    restarted = ReleaseBroker(config,service.policy,discovery=service.discovery,owner=owner,schedule=lambda *a:None)
    listing = restarted.dispatch('policy-list',{},actor=ACTOR)
    current = host.store.load()
    if boundary in ('journal','selection','public'):
        assert snapshot(host,service)==before
        assert listing['components']['grafana']['mode']=='pinned'
    else:
        assert current.selection['components']['grafana']['origin']=='baseline'
        assert listing['components']['grafana']['mode']=='follow-stable'
    public = yaml.safe_load((host.config.config_dir/'fleet-config.yaml').read_bytes())
    assert public['release_selection']['selection_sha256']==current.selection_sha256
    assert not (service.root/'policy-publication.json').exists() and owner.calls==[]


def test_refresh_and_repin_are_serialized_and_stale_refresh_cannot_win(policy_product, admitted):
    import threading
    from dc_overview.release_broker import ReleaseBroker,BrokerError
    from dc_overview.fleet_config import FleetConfig
    host, service, owner = policy_product
    set_mode(service,'follow-stable')
    started, resume = threading.Event(),threading.Event()
    def discovery():
        started.set(); assert resume.wait(5)
        return [admitted_version(admitted,'1.5.0')]
    service.discovery=discovery
    prior=expected(service); failures=[]
    def refresh():
        try: service.dispatch('policy-refresh',prior,actor=ACTOR)
        except BaseException as e: failures.append(e)
    thread=threading.Thread(target=refresh);thread.start();assert started.wait(5)
    try:
        config=FleetConfig.load(host.config.config_dir)
        peer=ReleaseBroker(config,service.policy,owner=owner,schedule=lambda *a:None)
        with pytest.raises(BrokerError) as error: set_mode(peer,'pinned')
        assert error.value.code=='busy'
    finally: resume.set();thread.join(5)
    assert not thread.is_alive() and not failures
    set_mode(service,'pinned'); frozen=snapshot(host,service)
    with pytest.raises(BrokerError) as error: service.dispatch('policy-refresh',prior,actor=ACTOR)
    assert error.value.code=='selection-conflict' and snapshot(host,service)==frozen
    assert owner.calls==[]


@pytest.mark.parametrize('fault',[None,'missing','wrong-component','version-conflict','unregistered-image'])
def test_installed_pin_requires_exact_known_component_artifact(policy_product,fault):
    host,service,owner=policy_product
    current=host.store.load();reference=current.targets['grafana']['reference']
    image={'Id':'sha256:'+'e'*64,'Os':'linux','Architecture':'amd64',
           'RepoDigests':[reference], 'Config':{'Labels':{'org.opencontainers.image.version':'1.4.0'}}}
    live={'Id':'d'*64,'Image':image['Id'],'State':{'Running':True},'Config':{'Image':reference}}
    if fault=='missing': live['State']['Running']=False
    if fault=='wrong-component': image['RepoDigests']=['prom/prometheus@sha256:'+'a'*64]
    if fault=='version-conflict': image['Config']['Labels']['org.opencontainers.image.version']='1.9.0'
    if fault=='unregistered-image': image['RepoDigests']=['grafana/grafana@sha256:'+'f'*64]
    inspect=lambda name:live if name=='grafana' else image
    result=policy_module().installed_component(current,'grafana',host.store,inspect)
    assert result == (current.manifest.data['components']['grafana'] if fault is None else None)


def test_policy_only_change_advances_cas_even_when_digest_is_unchanged(policy_product):
    from dc_overview.release_broker import BrokerError
    host,service,owner=policy_product;prior=expected(service);target=host.store.load().targets['grafana']['reference']
    set_mode(service,'follow-stable')
    assert host.store.load().targets['grafana']['reference']==target
    assert expected(service)!=prior
    with pytest.raises(BrokerError) as error:
        service.dispatch('policy-set',{'component':'grafana','mode':'pinned',**prior},actor=ACTOR)
    assert error.value.code=='selection-conflict' and owner.calls==[]


def test_native_policy_cli_uses_the_same_owner_contract(policy_product,monkeypatch):
    from click.testing import CliRunner
    from dc_overview.cli import main
    from dc_overview import release_broker_service
    host,service,owner=policy_product;calls=[]
    monkeypatch.setattr(release_broker_service,'request',lambda action,params:calls.append((action,params)) or {'components':{}})
    runner=CliRunner()
    result=runner.invoke(main,['release','policy-set','--component','grafana','--mode','follow-stable',
        '--expected-selection-id','fixture','--expected-selection-sha256','a'*64])
    assert result.exit_code==0,result.output
    assert calls[-1]==('policy-set',{'component':'grafana','mode':'follow-stable','expected_selection_id':'fixture','expected_selection_sha256':'a'*64})


@pytest.mark.parametrize('change',[{'mode':True},{'mode':'latest'},{'component':'../ipmi-monitor'},
    {'expected_selection_sha256':'a'}, {'path':'/etc/passwd'}, {'actor':{'kind':'host-peer','uid':0}}])
def test_broker_policy_params_are_strict_supported_actions(change):
    from dc_overview.release_broker import validate_params
    body={'component':'grafana','mode':'follow-stable','expected_selection_id':'fixture','expected_selection_sha256':'a'*64}
    validate_params('policy-set',body)  # Positive control prevents an unknown-action false pass.
    body.update(change)
    with pytest.raises(ValueError):validate_params('policy-set',body)


@pytest.mark.parametrize('kind',['fleet-admin','host-peer'])
def test_policy_socket_does_not_trust_an_unapproved_peer_claim(policy_product,kind):
    from dc_overview.release_broker_service import response
    host,service,owner=policy_product;service.policy['allowed_uids']=[0]
    actor=ACTOR if kind=='fleet-admin' else {'kind':'host-peer','uid':0}
    raw=json.dumps({'schema_version':1,'action':'policy-set','params':{
        'component':'grafana','mode':'follow-stable',**expected(service)},'actor':actor}).encode()+b'\n'
    result=json.loads(response(service,raw,1001))
    assert result['ok'] is False and result['error']['code']=='forbidden' and owner.calls==[]


def test_daily_timer_install_uses_only_fixed_packaged_units(policy_product,tmp_path,monkeypatch):
    from pathlib import Path
    policy=policy_module();calls=[]
    monkeypatch.setattr(policy,'SYSTEMD_DIR',tmp_path/'units')
    monkeypatch.setattr(policy,'release_cli',lambda:'/opt/verified/bin/dc-overview')
    monkeypatch.setattr(policy.subprocess,'run',lambda args,**kw:calls.append(args) or SimpleNamespace(returncode=0))
    policy.install_timer()
    assert calls==[['systemctl','daemon-reload'],['systemctl','enable','--now','dc-overview-release-refresh.timer']]
    service=(tmp_path/'units/dc-overview-release-refresh.service').read_text()
    assert '/opt/verified/bin/dc-overview release policy-refresh' in service
    assert (tmp_path/'units/dc-overview-release-refresh.timer').exists()


def test_policy_refresh_revalidates_admission_at_native_precommit(policy_product,admitted,monkeypatch):
    import dc_overview.release_policy as policy
    from dc_overview import fleet_upgrade
    host,service,owner=policy_product
    set_mode(service,'follow-stable');before=snapshot(host,service)
    service.discovery=lambda:[admitted_version(admitted,'1.5.0')]
    original=fleet_upgrade.select_release_components;verified=[]
    def expire_at_precommit(*args,**kwargs):
        check=kwargs.get('precommit_check')
        assert callable(check), 'publication must carry a freshness and policy-intent check'
        def expired(*args,**kwargs):
            verified.append(True);raise ValueError('admission expired before publication')
        with monkeypatch.context() as m:
            m.setattr(policy,'verify_candidate',expired)
            return original(*args,**kwargs)
    monkeypatch.setattr(fleet_upgrade,'select_release_components',expire_at_precommit)
    with pytest.raises(ValueError): service.dispatch('policy-refresh',expected(service),actor=ACTOR)
    assert verified and snapshot(host,service)==before and owner.calls==[]


def test_unfinished_policy_publication_blocks_other_release_paths(policy_product,monkeypatch):
    import dc_overview.release_policy as policy
    from dc_overview import fleet_upgrade
    from dc_overview.release_broker import BrokerError
    host,service,owner=policy_product;write=policy.private_write
    def fail(path,value):
        if path.name=='policy-state.json':raise OSError('interrupted policy write')
        return write(path,value)
    with monkeypatch.context() as m:
        m.setattr(policy,'private_write',fail)
        with pytest.raises(OSError):set_mode(service,'follow-stable')
    before=host.store.load().selection_raw
    with pytest.raises(BrokerError) as error:
        service.dispatch('preview',{'candidate_ids':['fixture'],'components':['grafana'],
            'operation_kind':'services-update',**expected(service)},actor=ACTOR)
    assert error.value.code=='recovery-required'
    with pytest.raises((RuntimeError,ValueError)):
        fleet_upgrade.select_release_components(host.config,host.manifest,['grafana'],platform='linux/amd64')
    assert host.store.load().selection_raw==before


def test_retained_installed_provenance_is_found_when_newer_selection_is_pending(policy_product,admitted):
    host,service,owner=policy_product;old=host.store.load();component=old.manifest.data['components']['grafana']
    reference=old.targets['grafana']['reference']
    set_mode(service,'follow-stable');service.discovery=lambda:[admitted_version(admitted,'1.5.0')]
    service.dispatch('policy-refresh',expected(service),actor=ACTOR)
    image={'Id':'sha256:'+'e'*64,'Os':'linux','Architecture':'amd64','RepoDigests':[reference],
           'Config':{'Labels':{'org.opencontainers.image.version':'1.4.0'}}}
    live={'Id':'d'*64,'Image':image['Id'],'State':{'Running':True},'Config':{'Image':reference}}
    assert policy_module().installed_component(host.store.load(),'grafana',host.store,
        lambda name:live if name=='grafana' else image)==component


def test_native_writer_wins_before_journal_without_orphaning_policy(policy_product,monkeypatch):
    from dc_overview import fleet_upgrade
    from dc_overview.release_broker import BrokerError
    policy=policy_module();host,service,owner=policy_product;write=policy.private_write;fired=[]
    data=copy.deepcopy(host.store.load().manifest.data);data['baseline_id']='competing-native-writer'
    path=host.config.config_dir/'competing.json';path.write_text(json.dumps(data))
    def competing_write(target,value):
        if target.name=='policy-candidate.json' and not fired:
            fired.append(True)
            fleet_upgrade.select_release_components(host.config,path,['grafana'],platform='linux/amd64')
        return write(target,value)
    with monkeypatch.context() as change:
        change.setattr(policy,'private_write',competing_write)
        with pytest.raises((BrokerError,RuntimeError,ValueError)):set_mode(service,'follow-stable')
    assert fired and host.store.load().selection['selection_id']=='competing-native-writer'
    assert not (service.root/'policy-publication.json').exists()
    assert service.dispatch('policy-list',{},actor=ACTOR)['components']['grafana']['mode']=='pinned'


def test_follow_tracks_a_new_explicitly_installed_major(policy_product,admitted):
    from dc_overview import fleet_upgrade
    host,service,owner=policy_product;set_mode(service,'follow-stable')
    data=copy.deepcopy(host.store.load().manifest.data);data['baseline_id']='explicit-major-two'
    new=copy.deepcopy(data['components']['grafana']);new['release']='2.0.0'
    new['artifacts']['linux/amd64']['reference']='grafana/grafana@sha256:'+'c'*64
    data['components']['grafana']=new;path=host.config.config_dir/'explicit-major.json';path.write_text(json.dumps(data))
    fleet_upgrade.select_release_components(host.config,path,['grafana'],platform='linux/amd64')
    owner.installed_component=lambda current,name:copy.deepcopy(new) if name=='grafana' else None
    service.discovery=lambda:[admitted_version(admitted,'2.1.0',identity='d')]
    result=service.dispatch('policy-refresh',expected(service),actor=ACTOR)
    assert result['advanced']==['grafana'] and result['components']['grafana']['major']==2
    assert host.store.load().manifest.data['components']['grafana']['release']=='2.1.0'
    assert owner.calls==[]


def test_repin_revalidates_installed_identity_inside_native_locks(policy_product,monkeypatch):
    from dc_overview.release_broker import BrokerError
    policy=policy_module();host,service,owner=policy_product;set_mode(service,'follow-stable')
    before=snapshot(host,service);write=policy.private_write;fired=[]
    def change_installed(path,value):
        if path.name=='policy-candidate.json' and not fired:
            fired.append(True)
            owner.installed_component=lambda *a:None
        return write(path,value)
    with monkeypatch.context() as change:
        change.setattr(policy,'private_write',change_installed)
        with pytest.raises(BrokerError) as error:set_mode(service,'pinned')
    assert error.value.code=='installed-unverified' and fired and snapshot(host,service)==before


def test_cli_and_packaging_include_the_daily_policy_only_refresh():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    timer = (root / "src/dc_overview/templates/systemd/dc-overview-release-refresh.timer").read_text()
    service = (root / "src/dc_overview/templates/systemd/dc-overview-release-refresh.service").read_text()
    assert "OnCalendar=daily" in timer and "Persistent=true" in timer
    assert "release policy-refresh" in service and "--install" not in service
    assert '"templates/systemd/*.timer"' in (root / "pyproject.toml").read_text()

