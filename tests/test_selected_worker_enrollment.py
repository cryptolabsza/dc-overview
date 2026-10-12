"""Ordinary selected enrollment; all external transports are controlled adapters."""
import base64
import importlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml
from click.testing import CliRunner

from dc_overview.fleet_config import FleetConfig, Server
from test_selected_worker_lifecycle import target


@pytest.fixture(autouse=True)
def _declared_api_rate_fixture(request, monkeypatch):
    if 'app' in request.fixturenames:
        request.getfixturevalue('app')
        # Fast in-process RPC controls do not exercise production rate limits.
        monkeypatch.setattr('dc_overview.app.limiter.enabled', False)


def _fixture_identity(server_id=43, name='gpu-01', address='192.0.2.8', inventory='fixture-identity'):
    return {'server_id':server_id, 'name':name, 'server_ip':address,
            'inventory_server_id':inventory, 'ssh_user':'root', 'ssh_port':22,
            'ssh_key_id':None, 'effective_key_path':'/declared/fixture/container-key', 'has_password':False}


def _selected_api_query(app, monkeypatch, server_id):
    from dc_overview.app import db, Server as InventoryServer
    from dc_overview.worker_lifecycle import _identity_query
    monkeypatch.setattr('dc_overview.app.resolve_ssh_key_path',lambda server,**kwargs:'/declared/fixture/container-key')
    with app.app_context():
        row=db.session.get(InventoryServer,server_id)
        identity=_fixture_identity(server_id,row.name,row.server_ip,row.inventory_server_id)
        identity.update(ssh_user=row.ssh_user or 'root',ssh_port=row.ssh_port or 22,ssh_key_id=row.ssh_key_id,has_password=bool(row.ssh_password))
    return _identity_query(identity)


def plan_for(*names):
    targets = {name: target(name, version={'dc-exporter':'0.2.9','node-exporter':'1.10.3','dc-watchdog-agent':'2.0.8'}[name]) for name in names}
    return SimpleNamespace(targets=targets, manifest=SimpleNamespace(data={'components': {
        name: {'owner':'dc-worker','release':value['release'], 'artifacts':{'linux/amd64':{k:v for k,v in value.items() if k in ('kind','url','sha256')}}}
        for name,value in targets.items()}}), selection={'components':{name:{'origin':'baseline','enabled':True} for name in names}})


def test_worker_cas_preserves_unknown_settings_exact_secret_files_and_repeat(tmp_path):
    path=tmp_path/'fleet-config.yaml'
    original=b'site_name: customer\nunknown:\n  keep: true\nrelease_selection:\n  selection_id: untouched\nservers: []\n'
    path.write_bytes(original); path.chmod(0o640)
    secret=tmp_path/'.secrets.yaml'; secret.write_bytes(b'opaque: exact-secret-bytes\n'); secret.chmod(0o600)
    config=FleetConfig(config_dir=tmp_path); worker=Server(name='gpu-01',server_ip='192.0.2.8',ssh_user='ubuntu',ssh_key_path='/vault/key',ssh_port=2222)
    config.persist_worker_entry(worker, expected_public=original)
    data=yaml.safe_load(path.read_bytes())
    assert data['unknown']=={'keep':True} and data['release_selection']=={'selection_id':'untouched'}
    assert data['servers'][0]['exporters_installed'] is False
    assert secret.read_bytes()==b'opaque: exact-secret-bytes\n' and secret.stat().st_mode & 0o777==0o600
    once=path.read_bytes(); inode=path.stat().st_ino
    config.persist_worker_entry(worker, expected_public=once)
    assert path.read_bytes()==once and path.stat().st_ino==inode
    with pytest.raises(RuntimeError,match='changed'):
        config.persist_worker_entry(worker,expected_public=original)
    assert path.stat().st_mode & 0o777==0o640
    assert FleetConfig.load(tmp_path).get_server_ssh_creds(FleetConfig.load(tmp_path).servers[0]).key_path=='/vault/key'


@pytest.mark.parametrize('existing',[{'name':'gpu-01','server_ip':'192.0.2.9'},{'name':'other','server_ip':'192.0.2.8'}])
def test_worker_cas_refuses_conflicting_identity(tmp_path,existing):
    path=tmp_path/'fleet-config.yaml';path.write_text(yaml.safe_dump({'servers':[existing]}));before=path.read_bytes()
    with pytest.raises(ValueError,match='conflict'):
        FleetConfig(config_dir=tmp_path).persist_worker_entry(Server(name='gpu-01',server_ip='192.0.2.8'),expected_public=before)
    assert path.read_bytes()==before


def test_selected_web_refusal_points_to_reachable_add_machine(tmp_path,monkeypatch):
    from dc_overview.worker_lifecycle import selected_worker_mutation_refusal
    monkeypatch.setenv('DC_RELEASE_SELECTION_REQUIRED','1')
    assert 'add-machine' in selected_worker_mutation_refusal(tmp_path)
    assert 'setup for a new worker' not in selected_worker_mutation_refusal(tmp_path)


def test_presence_modes_are_positive_per_component_not_failure_fallback(tmp_path,monkeypatch):
    mod=importlib.import_module('dc_overview.worker_lifecycle');config=FleetConfig(config_dir=tmp_path)
    config.servers=[Server(name='gpu-01',server_ip='192.0.2.8')]
    ssh=Mock();ssh.run_command.side_effect=[SimpleNamespace(success=True,output='Linux x86_64'),
        SimpleNamespace(success=True,output='WORKER_COMPONENT=dc-exporter|not-found|unknown|not-found|-\nWORKER_COMPONENT=node-exporter|loaded|inactive|disabled|'+'b'*64+'\nWORKER_SELECTED_BINARY=node-exporter|'+'a'*64+'\n'),
        SimpleNamespace(success=True,output='WORKER_PREFLIGHT=verified')]
    monkeypatch.setattr(mod,'SSHManager',lambda *a:ssh)
    inventory=mod.preflight_workers(config,plan_for('dc-exporter','node-exporter'),mode='reconcile')
    assert inventory['gpu-01']['dc-exporter']['delivery_mode']=='install'
    assert inventory['gpu-01']['node-exporter']['delivery_mode']=='update'


@pytest.mark.parametrize('state',['','WORKER_COMPONENT=dc-exporter|not-found|active|not-found|-\n','WORKER_COMPONENT=dc-exporter|loaded|mystery|enabled|'+'a'*64+'\n'])
def test_unknown_and_inconsistent_presence_hold(tmp_path,monkeypatch,state):
    mod=importlib.import_module('dc_overview.worker_lifecycle');config=FleetConfig(config_dir=tmp_path)
    config.servers=[Server(name='gpu-01',server_ip='192.0.2.8')]
    ssh=Mock();ssh.run_command.side_effect=[SimpleNamespace(success=True,output='Linux x86_64'),SimpleNamespace(success=True,output=state)]
    monkeypatch.setattr(mod,'SSHManager',lambda *a:ssh)
    with pytest.raises(ValueError,match='presence'):
        mod.preflight_workers(config,plan_for('dc-exporter'),mode='reconcile')
    assert ssh.run_command.call_count==2


class Response:
    def __init__(self,status,value): self.status_code=status;self.value=value
    def json(self):return self.value


def test_api_lost_created_response_readback_and_duplicate_preserve_id():
    from dc_overview.worker_lifecycle import register_worker
    worker=Server(name='gpu-01',server_ip='192.0.2.8')
    client=Mock(); client.request.side_effect=[Response(200,[]),Response(409,{'error':'duplicate'}),
        Response(200,[{'id':43,'name':'gpu-01','server_ip':'192.0.2.8','bmc_ip':None,'inventory_server_id':'fixture-identity','inventory':{'state':'pending','retry_id':7}}]),
        Response(200,{'ssh_user':'root','ssh_port':22,'ssh_key_id':None,'has_password':False,'auth_method':'key','enrollment_identity':_fixture_identity()}),
        Response(200,{'connected':True,'auth_method':'key','ssh_user':'root','ssh_port':22,'server_ip':worker.server_ip,'key_path':'/declared/fixture/container-key','enrollment_identity':_fixture_identity()})]
    result=register_worker(client,worker,FleetConfig(),base_url='https://fleet.example')
    assert result['id']==43 and result['inventory']['retry_id']==7
    assert [call.args[0] for call in client.request.call_args_list]==['GET','POST','GET','GET','POST']
    assert not any(call.args[0] in ('PUT','DELETE') for call in client.request.call_args_list)


@pytest.mark.parametrize('row',[{'id':1,'name':'gpu-01','server_ip':'192.0.2.9'}, {'id':1,'name':'other','server_ip':'192.0.2.8'}])
def test_api_conflicting_identity_holds_without_post(row):
    from dc_overview.worker_lifecycle import register_worker
    client=Mock();client.request.return_value=Response(200,[row])
    with pytest.raises(ValueError,match='conflict'):
        register_worker(client,Server(name='gpu-01',server_ip='192.0.2.8'),FleetConfig(),base_url='https://fleet.example')
    assert client.request.call_count==1


def test_selected_cli_routes_before_any_legacy_helper(tmp_path,monkeypatch):
    mod=importlib.import_module('dc_overview.cli'); worker=importlib.import_module('dc_overview.worker_lifecycle')
    config=FleetConfig(config_dir=tmp_path);config.release_selection.selection_id='selected';config.release_selection.selection_sha256='a'*64
    monkeypatch.setattr(mod.FleetConfig,'load',lambda *a,**k:config)
    monkeypatch.setattr(mod.os,'geteuid',lambda:0)
    monkeypatch.setattr(mod,'DOCKER_CONFIG_DIR',tmp_path)
    call=Mock(return_value={'success':True,'server_id':19,'components':{}})
    monkeypatch.setattr(worker,'enroll_selected_worker',call)
    monkeypatch.setattr('dc_overview.quickstart.test_machine_connection',Mock(side_effect=AssertionError('legacy')))
    monkeypatch.setattr('dc_overview.quickstart.update_prometheus_targets',Mock(side_effect=AssertionError('static discovery')))
    result=CliRunner().invoke(mod.main,['add-machine','192.0.2.8','--name','gpu-01','--fleet-url','https://fleet.example'],input='current-password\n')
    assert result.exit_code==0,result.output
    assert call.call_args.kwargs['password']=='current-password'
    assert call.call_args.args[1].server_ip=='192.0.2.8'


def test_first_worker_explicit_policy_has_no_identityless_delivery(tmp_path,monkeypatch):
    from dc_overview.fleet_upgrade import required_components, run_selected_upgrade
    from dc_overview.fleet_config import ComponentConfig
    config=FleetConfig(config_dir=tmp_path)
    config.components=ComponentConfig(worker_exporters=True)
    assert {'node-exporter','dc-exporter'} <= required_components(config)
    mod=importlib.import_module('dc_overview.fleet_upgrade')
    monkeypatch.setattr(mod,'run_fleet_upgrade',lambda *a,**k:{'success':True,'results':{}})
    prepared=plan_for('node-exporter','dc-exporter');prepared.selection['selection_id']='first-worker';prepared.selection_sha256='a'*64;prepared.manifest.sha256='b'*64
    delivery=Mock(side_effect=AssertionError('no worker identity exists yet'))
    monkeypatch.setattr('dc_overview.worker_lifecycle.upgrade_workers',delivery)
    result=run_selected_upgrade(config,prepared)
    assert result['success'] is True
    assert all(value['state']=='not_applicable' for value in result['external_owners'].values())
    delivery.assert_not_called()


def test_disabled_first_worker_selection_requires_explicit_transition(tmp_path,monkeypatch):
    from dc_overview.release_catalog import Manifest, resolve
    from dc_overview.fleet_upgrade import required_components, validate_configured_roles
    from test_release_selection_contract import manifest_data, encoded, selection
    data=manifest_data()
    for name,version in [('dc-exporter','0.2.9'),('node-exporter','1.10.3')]:
        t=target(name,version=version)
        data['components'][name]={'release':version,'owner':'dc-worker','artifacts':{'linux/amd64':{k:v for k,v in t.items() if k in ('kind','url','sha256')}}}
    config=FleetConfig(config_dir=tmp_path)
    raw=encoded(data);manifest=Manifest.from_bytes(raw)
    policy=selection(data, **{name:{'origin':'baseline','enabled':False} for name in ('dc-exporter','node-exporter')})
    # A controller-only vector cannot be reused for the first worker.
    with pytest.raises(ValueError,match='required'):
        resolve(manifest,policy,'linux/amd64',required_components={'node-exporter','dc-exporter'})
    # Enabling only stored selection policies conflicts with configured role intent.
    enabled=selection(data)
    prepared=SimpleNamespace(targets=resolve(manifest,enabled,'linux/amd64'))
    with pytest.raises(ValueError,match='disabled'):
        validate_configured_roles(config,prepared)
    config.components.worker_exporters=True
    validate_configured_roles(config,prepared)
    assert {'node-exporter','dc-exporter'} <= required_components(config)
    # Real prepare merges explicit configured policies over the former selection.
    catalog=importlib.import_module('dc_overview.release_catalog')
    monkeypatch.setattr(catalog,'_check_root_path',lambda *a,**k:None)
    store=catalog.ReleaseStore(tmp_path/'releases');store.root.mkdir();(store.root/'manifests').mkdir()
    import hashlib
    (store.root/'manifests'/f'{manifest.sha256}.json').write_bytes(raw)
    (store.root/'selection.json').write_bytes(encoded(policy))
    source=tmp_path/'manifest.json';source.write_bytes(raw)
    prepared=store.prepare(source,platform='linux/amd64',policies={name:{'origin':'baseline','enabled':True} for name in ('dc-exporter','node-exporter')},required_components={'node-exporter','dc-exporter'},enabled_components=required_components(config))
    assert {'node-exporter','dc-exporter'} <= set(prepared.targets)
    assert not config.servers


def test_exact_repeat_worker_delivery_does_not_run_installer(tmp_path,monkeypatch):
    mod=importlib.import_module('dc_overview.worker_lifecycle');config=FleetConfig(config_dir=tmp_path)
    config.servers=[Server(name='gpu-01',server_ip='192.0.2.8')]
    digest='a'*64
    presence='WORKER_COMPONENT=dc-exporter|loaded|inactive|disabled|'+digest+'\n'
    probe='WORKER_ARTIFACT='+digest+'\nWORKER_SERVICE=inactive\n'
    ssh=Mock();ssh.run_command.side_effect=[
        SimpleNamespace(success=True,output='Linux x86_64'),SimpleNamespace(success=True,output=presence),
        SimpleNamespace(success=True,output='WORKER_PREFLIGHT=verified'),SimpleNamespace(success=True,output=probe),
        SimpleNamespace(success=True,output='Linux x86_64'),SimpleNamespace(success=True,output='WORKER_PREFLIGHT=verified'),
        SimpleNamespace(success=True,output=presence)]
    monkeypatch.setattr(mod,'SSHManager',lambda *a:ssh)
    result=mod.upgrade_workers(config,plan_for('dc-exporter'),mode='reconcile')
    assert result['dc-exporter']['success'] is True
    assert result['dc-exporter']['workers']['gpu-01']['action']=='noop'
    assert all('DC_EXPORTER_INSTALL_SUCCESS' not in call.kwargs['command'] for call in ssh.run_command.call_args_list)
    assert ssh.run_command.call_count==7


def test_current_login_never_uses_stored_installer_password(monkeypatch):
    mod=importlib.import_module('dc_overview.worker_lifecycle')
    session=Mock();session.get.side_effect=[SimpleNamespace(status_code=200,text='Login'),Response(200,[])]
    session.post.return_value=SimpleNamespace(status_code=302,headers={'Location':'/'})
    monkeypatch.setattr('requests.Session',lambda:session)
    assert mod._fleet_login('https://fleet.example','operator','current-password',ca_file='/vault/ca.crt') is session
    assert session.verify=='/vault/ca.crt'
    assert session.post.call_args.kwargs['data']=={'username':'operator','password':'current-password'}
    assert session.post.call_args.kwargs['allow_redirects'] is False


@pytest.mark.parametrize('case',['fresh','readonly','password-change','tls'])
def test_login_holds_before_inventory_mutation(monkeypatch,case):
    import requests
    mod=importlib.import_module('dc_overview.worker_lifecycle');session=Mock()
    session.get.side_effect=[SimpleNamespace(status_code=200,text='name="confirm_password"' if case=='fresh' else 'Login'),Response(403 if case=='readonly' else 200,[])]
    session.post.return_value=SimpleNamespace(status_code=302,headers={'Location':'/auth/change-password' if case=='password-change' else '/'})
    if case=='tls':session.get.side_effect=requests.exceptions.SSLError('private TLS error')
    monkeypatch.setattr('requests.Session',lambda:session)
    with pytest.raises(RuntimeError):mod._fleet_login('https://fleet.example','operator','current-password')
    session.request.assert_not_called()
    assert session.verify is True


def test_real_api_registration_lost_response_reuses_committed_identity(app,client,auth_headers,monkeypatch):
    import requests
    from urllib.parse import urlsplit
    from dc_overview.worker_lifecycle import register_worker
    from dc_overview.app import Server as InventoryServer, db
    calls=[]
    monkeypatch.setattr('dc_overview.app.resolve_ssh_key_path',lambda server,**kwargs:'/declared/fixture/container-key')
    monkeypatch.setattr('dc_overview.app.check_ssh_connection',lambda server:{'connected':True})
    class Adapter:
        def request(self,method,url,**kwargs):
            path=urlsplit(url).path.removeprefix('/dc')
            calls.append((method,path))
            parsed=urlsplit(url)
            response=client.open(path+('?' + parsed.query if parsed.query else ''),method=method,json=kwargs.get('json'),headers=auth_headers)
            if method=='POST' and response.status_code==201:
                raise requests.ConnectionError('lost after committed 201')
            return SimpleNamespace(status_code=response.status_code,json=response.get_json)
    worker=Server(name='gpu-api',server_ip='192.0.2.81')
    registered=register_worker(Adapter(),worker,FleetConfig(),base_url='https://fleet.example')
    with app.app_context():
        row=InventoryServer.query.filter_by(name='gpu-api').one()
        assert row.id==registered['id'] and row.node_exporter_installed is False and row.dc_exporter_installed is False
        identity=row.inventory_server_id
    repeat=register_worker(Adapter(),worker,FleetConfig(),base_url='https://fleet.example')
    assert repeat['id']==registered['id']
    with app.app_context():assert InventoryServer.query.get(registered['id']).inventory_server_id==identity
    assert sum(method=='POST' and path=='/api/servers' for method,path in calls)==1


def test_real_api_conflicting_credentials_do_not_install_or_reassign(app,client,auth_headers):
    from urllib.parse import urlsplit
    from dc_overview.worker_lifecycle import register_worker
    calls=[]
    created=client.post('/api/servers',json={'name':'gpu-api','server_ip':'192.0.2.81','ssh_user':'ubuntu'},headers=auth_headers)
    assert created.status_code==201
    class Adapter:
        def request(self,method,url,**kwargs):
            calls.append(method)
            response=client.open(urlsplit(url).path.removeprefix('/dc'),method=method,json=kwargs.get('json'),headers=auth_headers)
            return SimpleNamespace(status_code=response.status_code,json=response.get_json)
    with pytest.raises(ValueError,match='authority conflict'):
        register_worker(Adapter(),Server(name='gpu-api',server_ip='192.0.2.81'),FleetConfig(),base_url='https://fleet.example')
    assert calls==['GET','GET']


def _selected_customer(tmp_path,monkeypatch):
    from test_release_selection_contract import manifest_data, encoded
    catalog=importlib.import_module('dc_overview.release_catalog')
    monkeypatch.setattr(catalog,'_check_root_path',lambda *a,**k:None)  # fixture custody; parser/hash checks remain real
    monkeypatch.setattr(catalog,'current_platform',lambda:'linux/amd64')  # declared Linux host fixture on Mac
    data=manifest_data()
    data['components']['dc-overview-cli']={'release':'1.4.0','owner':'host-cli','artifacts':{'any':{'kind':'wheel','url':'https://github.com/cryptolabsza/dc-overview/releases/download/v1.4.0/dc_overview-1.4.0-py3-none-any.whl','sha256':'a'*64}}}
    for name,version in [('dc-exporter','0.2.9'),('node-exporter','1.10.3')]:
        artifact=target(name,version=version)
        data['components'][name]={'release':version,'owner':'dc-worker','artifacts':{'linux/amd64':{k:v for k,v in artifact.items() if k in ('kind','url','sha256')}}}
    raw=encoded(data);manifest=catalog.Manifest.from_bytes(raw)
    import hashlib
    selection={'schema_version':1,'selection_id':'customer','manifest_sha256':manifest.sha256,'components':{name:{'origin':'baseline','enabled':True} for name in data['components']}}
    selected=encoded(selection)
    store=tmp_path/'releases';(store/'manifests').mkdir(parents=True)
    (store/'selection.json').write_bytes(selected);(store/'manifests'/f'{manifest.sha256}.json').write_bytes(raw)
    public={'components':{'worker_exporters':True},'unknown':{'customer':'preserve'},'ssh':{'username':'root','key_path':str(tmp_path/'existing-key'),'auth_method':'key'},'release_selection':{'selection_id':'customer','selection_sha256':hashlib.sha256(selected).hexdigest(),'release_selection_dir':str(store)},'servers':[]}
    (tmp_path/'existing-key').write_text('synthetic referenced key')
    (tmp_path/'fleet-config.yaml').write_text(yaml.safe_dump(public))
    (tmp_path/'.secrets.yaml').write_bytes(b'fleet_admin_pass: obsolete-installer-password\n')
    mod=importlib.import_module('dc_overview.fleet_upgrade')
    monkeypatch.setattr(mod,'proxy_capabilities',lambda:{'selection_contract':1,'proxy_replacement_policy':'host-adoption-required-v1'})
    monkeypatch.setattr(mod,'verify_running_cli',lambda target:{'success':True,'state':'verified'})
    return manifest,selected


def test_real_cli_parser_api_preflight_install_repeat_and_partial_resume(app,client,auth_headers,tmp_path,monkeypatch):
    monkeypatch.setattr('dc_overview.app.resolve_ssh_key_path',lambda server,**kwargs:'/declared/fixture/container-key')
    monkeypatch.setattr('dc_overview.app.check_services_installed',lambda server,**kwargs:{key:{'installed':key in ('node_exporter','dc_exporter'),'active':key in ('node_exporter','dc_exporter')} for key in ('node_exporter','dc_exporter','dcgm_exporter','watchdog_agent')})
    monkeypatch.setattr('dc_overview.app.update_prometheus_targets',lambda:True)
    import shlex
    from urllib.parse import urlsplit
    from dc_overview.app import Server as InventoryServer
    cli=importlib.import_module('dc_overview.cli');mod=importlib.import_module('dc_overview.worker_lifecycle')
    manifest,selected=_selected_customer(tmp_path,monkeypatch)
    monkeypatch.setattr(cli,'DOCKER_CONFIG_DIR',tmp_path);monkeypatch.setattr(cli.os,'geteuid',lambda:0)
    calls=[];installed={};fail_node=[True]
    class SSH:
        known_hosts_path=tmp_path/'known_hosts';key_path=tmp_path/'existing-key'
        def run_command(self,*,command,**kwargs):
            if command=='uname -s -m':return SimpleNamespace(success=True,output='Linux x86_64')
            script=base64.b64decode(shlex.split(command)[2]).decode()
            if 'WORKER_COMPONENT=' in script:
                names=[name for name in ('dc-exporter','node-exporter') if f'WORKER_COMPONENT={name}|' in script]
                lines=[]
                for name in names:
                    if name in installed:
                        lines.append(f'WORKER_COMPONENT={name}|loaded|active|enabled|{installed[name]}')
                        if name=='node-exporter':lines.append(f'WORKER_SELECTED_BINARY=node-exporter|{installed[name]}')
                    else:lines.append(f'WORKER_COMPONENT={name}|not-found|unknown|not-found|-')
                return SimpleNamespace(success=True,output='\n'.join(lines)+'\n')
            if 'WORKER_PREFLIGHT=verified' in script:return SimpleNamespace(success=True,output='WORKER_PREFLIGHT=verified\n')
            if 'WORKER_ARTIFACT=' in script:
                name='node-exporter' if '/usr/local/bin/node_exporter' in script else 'dc-exporter'
                return SimpleNamespace(success=True,output=f'WORKER_ARTIFACT={installed[name]}\nWORKER_SERVICE=active\n')
            name='node-exporter' if 'NODE_EXPORTER_INSTALL_SUCCESS' in script else 'dc-exporter'
            with app.app_context():assert InventoryServer.query.filter_by(name='gpu-01').count()==1,'identity must commit before installer'
            calls.append(('install',name))
            if name=='node-exporter' and fail_node[0]:
                fail_node[0]=False
                return SimpleNamespace(success=False,output='failed safely')
            installed[name]='b'*64 if name=='node-exporter' else 'a'*64
            output='DC_EXPORTER_INSTALL_SUCCESS' if name=='dc-exporter' else 'NODE_EXPORTER_INSTALL_SUCCESS\nNODE_EXPORTER_ARTIFACT_SHA256='+'a'*64+'\nNODE_EXPORTER_CANDIDATE_SHA256='+'b'*64
            return SimpleNamespace(success=True,output=output)
    monkeypatch.setattr(mod,'SSHManager',lambda *a:SSH())
    class API:
        def request(self,method,url,**kwargs):
            path=urlsplit(url).path.removeprefix('/dc');calls.append((method,path))
            query=urlsplit(url).query
            response=client.open(path+('?' + query if query else ''),method=method,json=kwargs.get('json'),headers=auth_headers)
            return SimpleNamespace(status_code=response.status_code,json=response.get_json)
        def close(self):pass
    monkeypatch.setattr(mod,'_fleet_login',lambda base_url,username,password,**kwargs:API())
    monkeypatch.setattr('dc_overview.app.check_ssh_connection',lambda server:{'connected':True})
    monkeypatch.setattr('dc_overview.app.check_exporter',lambda host,port:{'running':port in (9100,9835)})
    monkeypatch.setattr('dc_overview.exporters.get_exporter_version',lambda *a,**kwargs:'synthetic-observed-version')
    monkeypatch.setattr('dc_overview.app.check_watchdog_agent',lambda server:{'source':'database','installed':False,'running':False})
    monkeypatch.setattr('dc_overview.app.get_gpu_count_from_exporter',lambda *a:0)
    monkeypatch.setattr('dc_overview.app.check_and_apply_auto_updates',lambda *a:{})
    arguments=['add-machine','192.0.2.8','--name','gpu-01','--fleet-url','https://fleet.example']
    first=CliRunner().invoke(cli.main,arguments,input='current-password\n')
    assert first.exit_code==1 and 'identity retained' in first.output.lower(),first.output
    with app.app_context():
        row=InventoryServer.query.filter_by(name='gpu-01').one();saved_id=row.id;saved_identity=row.inventory_server_id
        assert not row.node_exporter_installed and not row.dc_exporter_installed
    after_partial=(tmp_path/'fleet-config.yaml').read_bytes()
    assert yaml.safe_load(after_partial)['servers'][0]['exporters_installed'] is False
    assert calls.index(('POST','/api/servers'))<calls.index(('install','node-exporter'))
    second=CliRunner().invoke(cli.main,arguments,input='current-password\n')
    assert second.exit_code==0,second.output
    third=CliRunner().invoke(cli.main,arguments,input='current-password\n')
    assert third.exit_code==0,third.output
    assert calls.count(('POST','/api/servers'))==1 and calls.count(('install','dc-exporter'))==1 and calls.count(('install','node-exporter'))==2
    assert (tmp_path/'fleet-config.yaml').read_bytes()==after_partial
    assert (tmp_path/'.secrets.yaml').read_bytes()==b'fleet_admin_pass: obsolete-installer-password\n'
    assert (tmp_path/'releases/selection.json').read_bytes()==selected
    assert (tmp_path/'releases/manifests'/f'{manifest.sha256}.json').read_bytes()==manifest.raw
    with app.app_context():assert InventoryServer.query.get(saved_id).inventory_server_id==saved_identity


@pytest.mark.parametrize('failure',['provenance','proxy','hash','pin','recovery'])
def test_real_cli_critical_hold_before_registration_and_config_write(tmp_path,monkeypatch,failure):
    cli=importlib.import_module('dc_overview.cli');mod=importlib.import_module('dc_overview.worker_lifecycle');upgrade=importlib.import_module('dc_overview.fleet_upgrade')
    _selected_customer(tmp_path,monkeypatch)
    monkeypatch.setattr(cli,'DOCKER_CONFIG_DIR',tmp_path);monkeypatch.setattr(cli.os,'geteuid',lambda:0)
    login=Mock(side_effect=AssertionError('no API before prerequisites'));monkeypatch.setattr(mod,'_fleet_login',login)
    def hold(*a,**k):raise RuntimeError('controlled prerequisite hold')
    if failure=='provenance':monkeypatch.setattr(upgrade,'verify_running_cli',hold)
    elif failure=='proxy':monkeypatch.setattr(upgrade,'proxy_capabilities',lambda:{})
    elif failure=='hash':(tmp_path/'releases/selection.json').write_bytes(b'changed')
    elif failure=='pin':
        path=tmp_path/'releases/selection.json';value=json.loads(path.read_bytes());value['components']['dc-exporter']={'origin':'customer-pin','enabled':True,'pin':'https://github.com/cryptolabsza/dc-exporter-releases/releases/download/v0.2.9/dc-exporter-rs#sha256='+'c'*64};raw=json.dumps(value).encode();path.write_bytes(raw)
        import hashlib
        cfg=tmp_path/'fleet-config.yaml';public=yaml.safe_load(cfg.read_bytes());public['release_selection']['selection_sha256']=hashlib.sha256(raw).hexdigest();cfg.write_text(yaml.safe_dump(public))
    elif failure=='recovery':monkeypatch.setattr('dc_overview.controller_adoption.ensure_mutation_allowed',hold)
    else:
        ssh=Mock();ssh.run_command.side_effect=[SimpleNamespace(success=True,output='Linux x86_64'),SimpleNamespace(success=True,output='WORKER_COMPONENT=dc-exporter|not-found|unknown|not-found|-\nWORKER_COMPONENT=node-exporter|not-found|unknown|not-found|-\n'),SimpleNamespace(success=False,output='privilege denied')]
        monkeypatch.setattr(mod,'SSHManager',lambda *a:ssh)
    before={str(p):p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    result=CliRunner().invoke(cli.main,['add-machine','192.0.2.8','--name','gpu-01','--fleet-url','https://fleet.example'],input='current-password\n')
    assert result.exit_code==1,result.output
    login.assert_not_called()
    assert before=={str(p):p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}


def test_api_malformed_inventory_holds_before_post():
    from dc_overview.worker_lifecycle import register_worker
    client=Mock();client.request.return_value=Response(200,[{'unexpected':'unknown row'}])
    with pytest.raises(ValueError,match='malformed'):
        register_worker(client,Server(name='gpu-01',server_ip='192.0.2.8'),FleetConfig(),base_url='https://fleet.example')
    assert client.request.call_count==1


def test_worker_cas_does_not_change_aliased_customer_field(tmp_path):
    path=tmp_path/'fleet-config.yaml';before=b'customer_list: &customer []\nservers: *customer\n';path.write_bytes(before)
    FleetConfig(config_dir=tmp_path).persist_worker_entry(Server(name='gpu-01',server_ip='192.0.2.8'),expected_public=before)
    data=yaml.safe_load(path.read_bytes())
    assert data['customer_list']==[]
    assert len(data['servers'])==1


def test_repeat_probe_requires_live_process_bytes_and_watchdog_config():
    import shlex
    from dc_overview.worker_lifecycle import _probe_command
    for name in ('dc-exporter','node-exporter','dc-watchdog-agent'):
        script=base64.b64decode(shlex.split(_probe_command(name,repeat=True))[2]).decode()
        assert 'MainPID' in script and '/proc/$pid/exe' in script
    watchdog=base64.b64decode(shlex.split(_probe_command('dc-watchdog-agent',repeat=True))[2]).decode()
    assert 'api_key:' in watchdog and 'server_url:' in watchdog
    assert '/health' in watchdog


def test_watchdog_absence_requires_authority_but_existing_held_repeat_does_not(tmp_path,monkeypatch):
    mod=importlib.import_module('dc_overview.worker_lifecycle');config=FleetConfig(config_dir=tmp_path)
    config.servers=[Server(name='gpu-01',server_ip='192.0.2.8')]
    ssh=Mock();monkeypatch.setattr(mod,'SSHManager',lambda *a:ssh)
    ssh.run_command.side_effect=[SimpleNamespace(success=True,output='Linux x86_64'),SimpleNamespace(success=True,output='WORKER_COMPONENT=dc-watchdog-agent|not-found|unknown|not-found|-\n')]
    with pytest.raises(ValueError,match='registration authority'):
        mod.preflight_workers(config,plan_for('dc-watchdog-agent'),mode='reconcile')
    digest='a'*64
    ssh.run_command.side_effect=[SimpleNamespace(success=True,output='Linux x86_64'),SimpleNamespace(success=True,output='WORKER_COMPONENT=dc-watchdog-agent|masked|inactive|masked|'+digest+'\n'),SimpleNamespace(success=True,output='WORKER_PREFLIGHT=verified\n'),SimpleNamespace(success=True,output='WORKER_ARTIFACT='+digest+'\nWORKER_SERVICE=inactive\nWORKER_HEALTH=verified\n')]
    result=mod.preflight_workers(config,plan_for('dc-watchdog-agent'),mode='reconcile')
    assert result['gpu-01']['dc-watchdog-agent']['delivery_mode']=='noop'


def test_real_api_repeat_preserves_pending_outbox_and_credentials(app,client,auth_headers,monkeypatch):
    from urllib.parse import urlsplit
    from dc_overview.worker_lifecycle import register_worker
    from dc_overview.app import Server as InventoryServer, InventoryOutbox
    monkeypatch.setattr('dc_overview.app.attempt_inventory_reconcile',lambda entry:False)
    monkeypatch.setattr('dc_overview.app.resolve_ssh_key_path',lambda server,**kwargs:'/declared/fixture/container-key')
    monkeypatch.setattr('dc_overview.app.check_ssh_connection',lambda server:{'connected':True})
    created=client.post('/api/servers',json={'name':'gpu-bmc','server_ip':'192.0.2.88','bmc_ip':'192.0.2.89'},headers=auth_headers)
    assert created.status_code==201 and created.get_json()['inventory']['state']=='pending'
    with app.app_context():
        row=InventoryServer.query.get(created.get_json()['id']);identity=row.inventory_server_id
        entry=InventoryOutbox.query.filter_by(source_server_id=identity).one()
        before=(entry.id,entry.payload,entry.revision,entry.delivered,entry.last_error)
    class API:
        def request(self,method,url,**kwargs):
            assert method=='GET' or urlsplit(url).path.endswith('/ssh-test')
            parsed=urlsplit(url)
            response=client.open(parsed.path.removeprefix('/dc')+('?' + parsed.query if parsed.query else ''),method=method,headers=auth_headers)
            return SimpleNamespace(status_code=response.status_code,json=response.get_json)
    observed=register_worker(API(),Server(name='gpu-bmc',server_ip='192.0.2.88',bmc_ip='192.0.2.89'),FleetConfig(),base_url='https://fleet.example')
    assert observed['id']==created.get_json()['id'] and observed['inventory']['state']=='pending'
    with app.app_context():
        entry=InventoryOutbox.query.filter_by(source_server_id=identity).one()
        assert (entry.id,entry.payload,entry.revision,entry.delivered,entry.last_error)==before


def test_enrollment_cas_detects_edit_after_preflight_without_api_write(tmp_path,monkeypatch):
    cli=importlib.import_module('dc_overview.cli');mod=importlib.import_module('dc_overview.worker_lifecycle')
    _selected_customer(tmp_path,monkeypatch)
    monkeypatch.setattr(cli,'DOCKER_CONFIG_DIR',tmp_path);monkeypatch.setattr(cli.os,'geteuid',lambda:0)
    monkeypatch.setattr(mod,'preflight_workers',lambda *a,**k:{})
    api=Mock()
    def login(*args,**kwargs):
        path=tmp_path/'fleet-config.yaml';path.write_bytes(path.read_bytes()+b'concurrent_customer_setting: true\n')
        return api
    monkeypatch.setattr(mod,'_fleet_login',login)
    result=CliRunner().invoke(cli.main,['add-machine','192.0.2.8','--name','gpu-01','--fleet-url','https://fleet.example'],input='current-password\n')
    assert result.exit_code==1 and 'changed' in result.output
    api.request.assert_not_called()
    assert yaml.safe_load((tmp_path/'fleet-config.yaml').read_bytes())['servers']==[]
    assert (tmp_path/'.secrets.yaml').read_bytes()==b'fleet_admin_pass: obsolete-installer-password\n'


def test_new_install_requires_active_final_service(tmp_path,monkeypatch):
    mod=importlib.import_module('dc_overview.worker_lifecycle');config=FleetConfig(config_dir=tmp_path)
    config.servers=[Server(name='gpu-01',server_ip='192.0.2.8')]
    absence='WORKER_COMPONENT=dc-exporter|not-found|unknown|not-found|-\n'
    ssh=Mock();ssh.run_command.side_effect=[SimpleNamespace(success=True,output='Linux x86_64'),SimpleNamespace(success=True,output=absence),SimpleNamespace(success=True,output='WORKER_PREFLIGHT=verified\n'),SimpleNamespace(success=True,output='Linux x86_64'),SimpleNamespace(success=True,output='WORKER_PREFLIGHT=verified\n'),SimpleNamespace(success=True,output=absence),SimpleNamespace(success=True,output='DC_EXPORTER_INSTALL_SUCCESS'),SimpleNamespace(success=True,output='WORKER_ARTIFACT='+'a'*64+'\nWORKER_SERVICE=inactive\n')]
    monkeypatch.setattr(mod,'SSHManager',lambda *a:ssh)
    assert mod.upgrade_workers(config,plan_for('dc-exporter'),mode='reconcile')['dc-exporter']['success'] is False


def test_container_ssh_authority_missing_holds_before_install():
    from dc_overview.worker_lifecycle import register_worker
    worker=Server(name='gpu-01',server_ip='192.0.2.8')
    client=Mock();client.request.side_effect=[Response(200,[{'id':3,'name':worker.name,'server_ip':worker.server_ip,'bmc_ip':None}]),Response(200,{'ssh_user':'root','ssh_port':22,'ssh_key_id':None,'has_password':False,'auth_method':'none'})]
    with pytest.raises(ValueError,match='container SSH'):
        register_worker(client,worker,FleetConfig(),base_url='https://fleet.example')
    assert client.request.call_count==2


def test_selected_server_check_preserves_held_installations_and_refreshes_after_commit(app,client,auth_headers,monkeypatch):
    from dc_overview.app import Server as InventoryServer, db
    created=client.post('/api/servers',json={'name':'held-worker','server_ip':'192.0.2.89'},headers=auth_headers)
    identity=created.get_json()['id'];seen=[]
    monkeypatch.setattr('dc_overview.app.check_ssh_connection',lambda server:{'connected':True})
    monkeypatch.setattr('dc_overview.app.check_services_installed',lambda server,**kwargs:{key:{'installed':True,'active':False} for key in ('node_exporter','dc_exporter','dcgm_exporter','watchdog_agent')})
    monkeypatch.setattr('dc_overview.app.check_exporter',lambda *a:{'running':False})
    monkeypatch.setattr('dc_overview.app.check_watchdog_agent',lambda server:{'source':'database','installed':False,'running':False})
    monkeypatch.setattr('dc_overview.app.get_gpu_count_from_exporter',lambda *a:0)
    monkeypatch.setattr('dc_overview.exporters.get_exporter_version',lambda *a,**kwargs:'synthetic-held-observation')
    monkeypatch.setattr('dc_overview.app.check_and_apply_auto_updates',lambda *a:{})
    def writer():
        # Expire identity cache: the committed owner observations must already be visible.
        db.session.expire_all();row=db.session.get(InventoryServer,identity)
        seen.append((row.node_exporter_installed,row.node_exporter_enabled,row.dc_exporter_installed,row.dc_exporter_enabled))
        return True
    monkeypatch.setattr('dc_overview.app.update_prometheus_targets',writer)
    response=client.get(f'/api/servers/{identity}/check'+_selected_api_query(app,monkeypatch,identity),headers=auth_headers)
    assert response.status_code==200
    assert seen==[(True,False,True,False)]


def test_selected_server_check_unknown_presence_preserves_observations(app,client,auth_headers,monkeypatch):
    from dc_overview.app import Server as InventoryServer, db
    from dc_overview.web_exporters import ServiceCheckUnavailable
    created=client.post('/api/servers',json={'name':'held-worker','server_ip':'192.0.2.89'},headers=auth_headers)
    identity=created.get_json()['id']
    with app.app_context():
        row=db.session.get(InventoryServer,identity);row.node_exporter_installed=True;row.node_exporter_enabled=False;db.session.commit()
    monkeypatch.setattr('dc_overview.app.check_ssh_connection',lambda server:{'connected':False})
    def unknown(*a,**k):raise ServiceCheckUnavailable('synthetic unknown; preserve observations')
    monkeypatch.setattr('dc_overview.app.check_services_installed',unknown)
    writer=Mock();monkeypatch.setattr('dc_overview.app.update_prometheus_targets',writer)
    response=client.get(f'/api/servers/{identity}/check'+_selected_api_query(app,monkeypatch,identity),headers=auth_headers)
    assert response.status_code==503
    with app.app_context():
        row=db.session.get(InventoryServer,identity);assert row.node_exporter_installed is True and row.node_exporter_enabled is False
    writer.assert_not_called()


@pytest.mark.parametrize('watchdog',['masked','active','absent','unknown','empty-token','missing-binary'])
def test_actual_selected_api_service_payload_reads_watchdog_without_mutating(tmp_path,monkeypatch,watchdog):
    import os
    import shlex
    import subprocess
    from dc_overview import web_exporters
    root=tmp_path/'declared-readonly-worker';root.mkdir();programs=root/'tools';programs.mkdir()
    binaries=root/'binaries';binaries.mkdir();config=root/'watchdog';config.mkdir()
    for name in ('node_exporter','dc-exporter-rs','dc-watchdog-agent'):
        path=binaries/name;path.write_text('synthetic existing artifact');path.chmod(0o755)
    if watchdog in ('absent','missing-binary'):(binaries/'dc-watchdog-agent').unlink()
    if watchdog!='absent':
        token="''" if watchdog=='empty-token' else 'synthetic-worker-token'
        (config/'agent.yaml').write_text(f'api_key: {token}\nserver_url: https://watchdog.example\nworker_name: gpu-01\nhealth_port: 9878\n')
    shell='''#!/bin/sh
case "$*" in
  "show node_exporter --property=LoadState --value"|"show dc-exporter --property=LoadState --value") echo loaded;;
  "show node_exporter --property=ActiveState --value"|"show dc-exporter --property=ActiveState --value") echo inactive;;
  "show dc-watchdog-agent --property=LoadState --value")
    case "$WATCHDOG_FIXTURE_STATE" in absent) echo not-found;; unknown) echo bad-setting;; masked) echo masked;; *) echo loaded;; esac;;
  "show dc-watchdog-agent --property=ActiveState --value")
    case "$WATCHDOG_FIXTURE_STATE" in active) echo active;; *) echo inactive;; esac;;
  *) exit 1;;
esac
'''
    for name,body in [('systemctl',shell),('docker','#!/bin/sh\necho "Error: No such object: dcgm-exporter" >&2\nexit 1\n')]:
        path=programs/name;path.write_text(body);path.chmod(0o755)
    env={**os.environ,'PATH':str(programs)+':'+os.environ['PATH'],'WATCHDOG_FIXTURE_STATE':watchdog,
         'ENROLLMENT_SCRIPT_FIXTURE':'1','ENROLLMENT_FIXTURE_ROOT':str(root)}
    monkeypatch.setattr(web_exporters,'build_ssh_cmd',lambda *a,**k:(['ssh'],{}))
    original_run=subprocess.run
    payloads=[]
    def transport(argv,**kwargs):
        script=shlex.split(argv[-1])[-1].replace('/usr/local/bin',str(binaries)).replace('/etc/dc-watchdog',str(config))
        payloads.append(script)
        return original_run(['bash','-s'],input=script,capture_output=True,text=True,env=env)
    monkeypatch.setattr(web_exporters.subprocess,'run',transport)
    before={str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()}
    server=SimpleNamespace(ssh_user='root')
    if watchdog in ('unknown','empty-token','missing-binary'):
        with pytest.raises(web_exporters.ServiceCheckUnavailable):web_exporters.check_services_installed(server,include_watchdog=True)
    else:
        result=web_exporters.check_services_installed(server,include_watchdog=True)
        assert result['watchdog_agent']=={'installed':watchdog!='absent','active':watchdog=='active'}
        assert result['node_exporter']=={'installed':True,'active':False}
    assert before=={str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()}
    assert all('synthetic-worker-token' not in payload for payload in payloads)


def test_selected_discovery_failure_keeps_committed_observations(app,client,auth_headers,monkeypatch):
    from dc_overview.app import Server as InventoryServer, db
    identity=client.post('/api/servers',json={'name':'held-discovery','server_ip':'192.0.2.91'},headers=auth_headers).get_json()['id']
    monkeypatch.setattr('dc_overview.app.check_services_installed',lambda server,**kwargs:{key:{'installed':key=='node_exporter','active':False} for key in ('node_exporter','dc_exporter','dcgm_exporter','watchdog_agent')})
    monkeypatch.setattr('dc_overview.app.check_ssh_connection',lambda server:{'connected':True})
    monkeypatch.setattr('dc_overview.app.check_exporter',lambda *a:{'running':False})
    monkeypatch.setattr('dc_overview.app.check_watchdog_agent',lambda server:{'source':'database','running':False,'installed':False})
    monkeypatch.setattr('dc_overview.app.get_gpu_count_from_exporter',lambda *a:0)
    monkeypatch.setattr('dc_overview.exporters.get_exporter_version',lambda *a,**kwargs:'observed-version')
    monkeypatch.setattr('dc_overview.app.update_prometheus_targets',lambda:False)
    response=client.get(f'/api/servers/{identity}/check'+_selected_api_query(app,monkeypatch,identity),headers=auth_headers)
    assert response.status_code==503 and 'committed' in response.get_json()['error']
    with app.app_context():
        row=db.session.get(InventoryServer,identity);assert row.node_exporter_installed is True and row.node_exporter_enabled is False


def test_selected_invalid_query_is_rejected_before_transport(app,client,auth_headers,monkeypatch):
    identity=client.post('/api/servers',json={'name':'invalid-query','server_ip':'192.0.2.91'},headers=auth_headers).get_json()['id']
    transport=Mock(side_effect=AssertionError('invalid query must not discover'))
    monkeypatch.setattr('dc_overview.app.check_services_installed',transport)
    assert client.get(f'/api/servers/{identity}/check?selected_enrollment=true',headers=auth_headers).status_code==400
    transport.assert_not_called()
