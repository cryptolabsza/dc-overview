"""Host update authority requires the shipped exact live recovery policy."""
import json
import sys
from types import ModuleType,SimpleNamespace
from unittest.mock import Mock

import pytest

from dc_overview import fleet_upgrade
from dc_overview.fleet_config import FleetConfig
from test_release_selection_contract import manifest_data

POLICY='host-adoption-required-v1'
SAFE={'selection_contract':1,'proxy_replacement_policy':POLICY}
UNSAFE=[None,{}, {'selection_contract':1}, {'selection_contract':1,'proxy_replacement_policy':None},
        {'selection_contract':1,'proxy_replacement_policy':'unknown'},
        {'selection_contract':1,'proxy_replacement_policy':POLICY+'-unknown'},
        {'selection_contract':1,'proxy_replacement_policy':[POLICY]},
        {'selection_contract':True,'proxy_replacement_policy':POLICY},
        {'selection_contract':'1','proxy_replacement_policy':POLICY},
        ['selection_contract',1]]


def setup_preflight(tmp_path,monkeypatch):
    config=FleetConfig(config_dir=tmp_path/'config')
    config.release_selection.selection_id='synthetic'
    config.release_selection.selection_sha256='a'*64
    for name in ('dc_overview','ipmi_monitor','vast_exporter','runpod_exporter','vast_price_manager','dc_watchdog'):
        setattr(config.components,name,False)
    plan=SimpleNamespace(targets={'cryptolabs-proxy':{'owner':'proxy-updater'},'dc-overview-cli':{'owner':'host-cli'}})
    store=SimpleNamespace(root=config.config_dir/'releases',prepare=Mock(return_value=plan))
    monkeypatch.setattr(fleet_upgrade,'release_store',lambda config:store)
    load=Mock(return_value=plan);monkeypatch.setattr(fleet_upgrade,'load_release',load)
    verify=Mock();monkeypatch.setattr(fleet_upgrade,'verify_running_cli',verify)
    monkeypatch.setattr(fleet_upgrade,'adopt_existing_policies',lambda config,manifest,policies:policies)
    mutation=Mock(side_effect=AssertionError('No lifecycle mutation before authority'))
    monkeypatch.setattr(fleet_upgrade,'commit_release',mutation)
    monkeypatch.setattr(config,'persist_lifecycle',mutation)
    manifest=manifest_data()
    manifest['components']['dc-overview-cli']={'release':'1.4.0','owner':'host-cli','artifacts':{'any':{'kind':'wheel','url':'https://github.com/cryptolabsza/dc-overview/releases/download/v1.4.0/dc_overview-1.4.0-py3-none-any.whl','sha256':'a'*64}}}
    path=tmp_path/'manifest.json';path.write_text(json.dumps(manifest))
    return config,plan,store,load,verify,mutation,path


@pytest.mark.parametrize('capabilities',UNSAFE)
@pytest.mark.parametrize('selected',[False,True])
def test_AUTHORITY01_submission_rejects_unsafe_live_policy_even_legacy(monkeypatch,capabilities,selected):
    calls=[]
    def updater(*arguments):
        calls.append(arguments)
        return capabilities if arguments[0]=='capabilities' else {'id':'synthetic-job','state':'completed','success':True,'results':{}}
    monkeypatch.setattr(fleet_upgrade,'_updater',updater)
    args={'selection_id':'synthetic','selection_sha256':'a'*64} if selected else {}
    with pytest.raises(RuntimeError,match='configuration plan.*configuration adopt'):
        fleet_upgrade.run_fleet_upgrade('main',**args)
    assert calls==[('capabilities',)]


@pytest.mark.parametrize('capabilities',UNSAFE)
@pytest.mark.parametrize('from_manifest',[False,True])
def test_AUTHORITY02_preparation_refuses_before_load_recovery_or_prepare(tmp_path,monkeypatch,capabilities,from_manifest):
    config,plan,store,load,verify,mutation,path=setup_preflight(tmp_path,monkeypatch)
    monkeypatch.setattr(fleet_upgrade,'proxy_capabilities',lambda **kwargs:capabilities)
    with pytest.raises(RuntimeError,match='configuration plan.*configuration adopt'):
        fleet_upgrade.preflight_release(config,path if from_manifest else None,fresh_setup=True)
    store.prepare.assert_not_called();load.assert_not_called();verify.assert_not_called();mutation.assert_not_called()
    assert not config.config_dir.exists()


@pytest.mark.parametrize('from_manifest',[False,True])
def test_AUTHORITY03_second_capability_check_cannot_consume_stale_first_proof(tmp_path,monkeypatch,from_manifest):
    config,plan,store,load,verify,mutation,path=setup_preflight(tmp_path,monkeypatch)
    probe=Mock(side_effect=[SAFE,{'selection_contract':1}]);monkeypatch.setattr(fleet_upgrade,'proxy_capabilities',probe)
    with pytest.raises(RuntimeError,match='configuration plan.*configuration adopt'):
        fleet_upgrade.preflight_release(config,path if from_manifest else None,fresh_setup=True)
    assert probe.call_count==2
    verify.assert_not_called();mutation.assert_not_called()
    assert not config.config_dir.exists()


@pytest.mark.parametrize('branch,selected',[('main',False),('dev',False),('main',True)])
def test_AUTHORITY04_exact_live_policy_preserves_submit_and_job_results(monkeypatch,branch,selected):
    calls=[]
    def updater(*arguments):
        calls.append(arguments)
        if arguments[0]=='capabilities':return {**SAFE,'future_additive_capability':True}
        if arguments[0]=='submit':return {'id':'synthetic-job'}
        return {'state':'completed','success':True,'results':{'dc-overview':{'success':True,'state':'verified'}}}
    monkeypatch.setattr(fleet_upgrade,'_updater',updater)
    args={'selection_id':'synthetic','selection_sha256':'a'*64} if selected else {}
    result=fleet_upgrade.run_fleet_upgrade(branch,**args)
    assert result['success'] and result['results']['dc-overview']['state']=='verified'
    assert calls[0]==('capabilities',) and calls[1][:3]==('submit','--branch',branch)
    assert calls[1][3:]==('--service','all','--action','update')+(('--selection-id','synthetic','--selection-sha256','a'*64) if selected else ())


@pytest.mark.parametrize('from_manifest',[False,True])
def test_AUTHORITY04_exact_policy_passes_both_preparation_checks(tmp_path,monkeypatch,from_manifest):
    config,plan,store,load,verify,mutation,path=setup_preflight(tmp_path,monkeypatch)
    probe=Mock(return_value=SAFE);monkeypatch.setattr(fleet_upgrade,'proxy_capabilities',probe)
    assert fleet_upgrade.preflight_release(config,path if from_manifest else None,fresh_setup=True) is plan
    assert probe.call_count==2 and verify.call_count==1
    mutation.assert_not_called()


def installed_proxy(monkeypatch,getter=SAFE):
    package=ModuleType('cryptolabs_proxy');package.__path__=[]
    updates=ModuleType('cryptolabs_proxy.updates')
    function=Mock(return_value=getter);updates.get_capabilities=function
    setup=ModuleType('cryptolabs_proxy.setup');setup.SELECTION_CONTRACT=1
    monkeypatch.setitem(sys.modules,'cryptolabs_proxy',package)
    monkeypatch.setitem(sys.modules,'cryptolabs_proxy.updates',updates)
    monkeypatch.setitem(sys.modules,'cryptolabs_proxy.setup',setup)
    return function,updates


def test_AUTHORITY05_fresh_absent_proxy_uses_real_installed_getter(monkeypatch):
    getter,_=installed_proxy(monkeypatch)
    run=Mock(return_value=SimpleNamespace(returncode=1,stdout='',stderr='Error: No such object: cryptolabs-proxy'))
    monkeypatch.setattr(fleet_upgrade.subprocess,'run',run)
    live=Mock();monkeypatch.setattr(fleet_upgrade,'_updater',live)
    assert fleet_upgrade.proxy_capabilities(fresh_setup=True)==SAFE
    getter.assert_called_once_with();live.assert_not_called()
    assert run.call_args.args[0][:3]==['docker','inspect','cryptolabs-proxy']


def test_AUTHORITY05_old_installed_setup_constant_does_not_fabricate_policy(monkeypatch):
    _,updates=installed_proxy(monkeypatch);del updates.get_capabilities
    monkeypatch.setattr(fleet_upgrade.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=1,stdout='',stderr='No such container: cryptolabs-proxy'))
    assert fleet_upgrade.proxy_capabilities(fresh_setup=True) is None


@pytest.mark.parametrize('fresh_setup',[False,True])
@pytest.mark.parametrize('running',[False,True])
def test_AUTHORITY06_existing_old_runtime_is_not_blessed_by_new_host_package(monkeypatch,fresh_setup,running):
    getter,_=installed_proxy(monkeypatch)
    monkeypatch.setattr(fleet_upgrade.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=0,stdout=json.dumps({'Running':running}),stderr=''))
    old={'selection_contract':1,'proxy_replacement_policy':'old-runtime'}
    live=Mock(return_value=old);monkeypatch.setattr(fleet_upgrade,'_updater',live)
    assert fleet_upgrade.proxy_capabilities(fresh_setup=fresh_setup)==old
    live.assert_called_once_with('capabilities');getter.assert_not_called()


@pytest.mark.parametrize('failure',['unreachable','malformed-absence'])
def test_AUTHORITY06_unknown_runtime_presence_never_falls_back_to_host_getter(monkeypatch,failure):
    getter,_=installed_proxy(monkeypatch)
    run=Mock(side_effect=FileNotFoundError('docker') if failure=='missing-docker' else None,return_value=SimpleNamespace(returncode=1,stdout='',stderr='Cannot connect to Docker daemon' if failure=='unreachable' else 'No such container: unrelated'))
    monkeypatch.setattr(fleet_upgrade.subprocess,'run',run)
    assert fleet_upgrade.proxy_capabilities(fresh_setup=True) is None
    getter.assert_not_called()


def test_AUTHORITY07_missing_docker_has_actionable_selected_setup_prerequisite(monkeypatch):
    getter,_=installed_proxy(monkeypatch)
    monkeypatch.setattr(fleet_upgrade.subprocess,'run',Mock(side_effect=FileNotFoundError('docker')))
    live=Mock();monkeypatch.setattr(fleet_upgrade,'_updater',live)
    with pytest.raises(RuntimeError,match='Docker prerequisite:.*Docker Engine.*Compose'):
        fleet_upgrade.proxy_capabilities(fresh_setup=True)
    getter.assert_not_called();live.assert_not_called()


def test_AUTHORITY08_unselected_fresh_setup_retains_readonly_automatic_prerequisite_path(tmp_path,monkeypatch):
    config=FleetConfig(config_dir=tmp_path/'config')
    probe=Mock(side_effect=AssertionError('Unselected fresh setup must not require Docker before its installer'))
    monkeypatch.setattr(fleet_upgrade,'proxy_capabilities',probe)
    load=Mock(side_effect=AssertionError('No selection or recovery to load'))
    monkeypatch.setattr(fleet_upgrade,'load_release',load)
    assert fleet_upgrade.preflight_release(config,fresh_setup=True) is None
    probe.assert_not_called();load.assert_not_called()
    assert not config.config_dir.exists()


@pytest.mark.parametrize('existing',['id','hash','selection','journal'])
def test_AUTHORITY08_fresh_existing_selection_or_journal_requires_live_authority(tmp_path,monkeypatch,existing):
    config=FleetConfig(config_dir=tmp_path/'config')
    if existing=='id':config.release_selection.selection_id='synthetic'
    elif existing=='hash':config.release_selection.selection_sha256='a'*64
    else:
        root=config.config_dir/'releases';root.mkdir(parents=True)
        (root/('selection.json' if existing=='selection' else '.lifecycle-publication.json')).write_bytes(b'customer bytes')
    before={str(p):p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    probe=Mock(return_value={'selection_contract':1});monkeypatch.setattr(fleet_upgrade,'proxy_capabilities',probe)
    load=Mock();monkeypatch.setattr(fleet_upgrade,'load_release',load)
    with pytest.raises(RuntimeError,match='configuration plan.*configuration adopt'):
        fleet_upgrade.preflight_release(config,fresh_setup=True)
    probe.assert_called_once_with(fresh_setup=True);load.assert_not_called()
    assert before=={str(p):p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
