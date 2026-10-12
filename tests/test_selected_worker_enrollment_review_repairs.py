"""Desired preservation boundaries derived from independent reviewer counterexamples."""
import importlib
from types import SimpleNamespace
from urllib.parse import urlsplit
from unittest.mock import Mock
import pytest
from dc_overview.fleet_config import FleetConfig, Server
from test_selected_worker_enrollment import _selected_customer


def observations(monkeypatch, calls):
    mod=importlib.import_module('dc_overview.app')
    monkeypatch.setattr(mod.limiter,'enabled',False)
    def services(server, **kwargs):
        calls.append(('service-probe',server.name,server.server_ip))
        return {key:{'installed':key in ('node_exporter','dc_exporter'),'active':key in ('node_exporter','dc_exporter')} for key in ('node_exporter','dc_exporter','dcgm_exporter','watchdog_agent')}
    monkeypatch.setattr(mod,'check_services_installed',services)
    monkeypatch.setattr(mod,'check_ssh_connection',lambda server:{'connected':True})
    monkeypatch.setattr(mod,'check_exporter',lambda host,port:{'running':port in (9100,9835)})
    monkeypatch.setattr(mod,'check_watchdog_agent',lambda server:{'source':'database','installed':False,'running':False})
    monkeypatch.setattr(mod,'get_gpu_count_from_exporter',lambda *a:0)
    monkeypatch.setattr('dc_overview.exporters.get_exporter_version',lambda *a,**kwargs:'fixture-version')
    monkeypatch.setattr(mod,'check_and_apply_auto_updates',lambda *a:[])
    monkeypatch.setattr(mod,'resolve_ssh_key_path',lambda server,**kwargs:'/synthetic/container/key')
    monkeypatch.setattr(mod,'update_prometheus_targets',lambda: calls.append(('discovery-refresh',)) or True)


def test_repaired_readonly_query_commits_privileged_observations(app,client,auth_headers,monkeypatch):
    from dc_overview.app import db, Server as Row
    calls=[];observations(monkeypatch,calls)
    response=client.post('/api/servers',json={'name':'worker-a','server_ip':'192.0.2.8'},headers=auth_headers)
    identity=response.get_json()['id'];calls.clear()
    readonly=dict(auth_headers, **{'X-Fleet-Auth-Role':'readonly'})
    control=client.put(f'/api/servers/{identity}',json={'name':'worker-b','server_ip':'192.0.2.9'},headers=readonly)
    assert control.status_code==403
    response=client.get(f'/api/servers/{identity}/check?selected_enrollment=1',headers=readonly)
    assert response.status_code==403, response.get_json()
    assert calls==[]
    with app.app_context():
        row=db.session.get(Row,identity)
        assert not row.node_exporter_installed and not row.dc_exporter_installed
    calls.clear()
    response=client.get(f'/api/servers/{identity}/check?selected_enrollment=bad',headers=readonly)
    assert response.status_code==400 and not calls


def test_repaired_concurrent_rename_and_ip_change_returns_enrollment_success(app,client,auth_headers,tmp_path,monkeypatch):
    from dc_overview.app import db, Server as Row
    lifecycle=importlib.import_module('dc_overview.worker_lifecycle')
    _selected_customer(tmp_path,monkeypatch)
    config=FleetConfig.load(tmp_path); calls=[];observations(monkeypatch,calls)
    class API:
        def request(self, method, url, **kwargs):
            parsed=urlsplit(url)
            response=client.open(parsed.path.removeprefix('/dc')+('?' + parsed.query if parsed.query else ''),method=method,json=kwargs.get('json'),headers=auth_headers)
            return SimpleNamespace(status_code=response.status_code,json=response.get_json)
        def close(self):pass
    monkeypatch.setattr(lifecycle,'_fleet_login',lambda *a,**k:API())
    monkeypatch.setattr(lifecycle,'preflight_workers',lambda *a,**k:{})
    actual=config.persist_worker_entry
    def persist_then_concurrent_api_edit(server, **kwargs):
        result=actual(server,**kwargs)
        with app.app_context():identity=Row.query.filter_by(name='worker-a').one().id
        changed=client.put(f'/api/servers/{identity}',json={'name':'worker-b','server_ip':'192.0.2.9'},headers=auth_headers)
        assert changed.status_code==200
        calls.append(('concurrent-edit',identity,'worker-b','192.0.2.9'))
        return result
    monkeypatch.setattr(config,'persist_worker_entry',persist_then_concurrent_api_edit)
    def delivery(scoped,plan,**kwargs):
        calls.append(('delivery-target',scoped.servers[0].name,scoped.servers[0].server_ip))
        return {name:{'success':True,'workers':{'worker-a':{'service_state':'active'}}} for name in ('dc-exporter','node-exporter')}
    monkeypatch.setattr(lifecycle,'upgrade_workers',delivery)
    with pytest.raises((ValueError,RuntimeError),match='identity|changed|conflict'):
        lifecycle.enroll_selected_worker(config,Server(name='worker-a',server_ip='192.0.2.8'),base_url='https://fleet.example',username='admin',password='synthetic')
    assert not any(call[0] in ('delivery-target','service-probe') for call in calls)
    with app.app_context():
        row=Row.query.filter_by(name='worker-b').one();assert row.server_ip=='192.0.2.9'
    assert FleetConfig.load(tmp_path).servers[0].server_ip=='192.0.2.8'


def test_repaired_remote_preflight_precedes_current_admin_authentication(tmp_path,monkeypatch):
    lifecycle=importlib.import_module('dc_overview.worker_lifecycle')
    _selected_customer(tmp_path,monkeypatch);config=FleetConfig.load(tmp_path);calls=[]
    monkeypatch.setattr(lifecycle,'preflight_workers',lambda *a,**k:calls.append('remote-privileged-preflight'))
    def failed_login(*a,**k):
        calls.append('login-denied');raise RuntimeError('synthetic denied admin login')
    monkeypatch.setattr(lifecycle,'_fleet_login',failed_login)
    with pytest.raises(RuntimeError,match='denied'):
        lifecycle.enroll_selected_worker(config,Server(name='worker-a',server_ip='192.0.2.8'),base_url='https://fleet.example',username='readonly',password='synthetic')
    assert calls==['login-denied']


def test_repaired_missing_explicit_key_is_accepted_via_fallback_key(app,client,auth_headers,monkeypatch):
    from dc_overview.app import db, Server as Row, SSHKey
    helpers=importlib.import_module('dc_overview.ssh_helpers')
    lifecycle=importlib.import_module('dc_overview.worker_lifecycle')
    commands=[]
    # Synthetic path-existence and native SSH-success adapters; real resolver,
    # command builder, Flask ssh-config/ssh-test and enrollment validator execute.
    original_exists=helpers.os.path.exists
    def exists(path):
        if str(path)=='/synthetic/missing-explicit-key':return False
        if str(path)=='/etc/dc-overview/ssh_keys/fleet_key':return True
        return original_exists(path)
    monkeypatch.setattr(helpers.os.path,'exists',exists)
    monkeypatch.setattr(helpers,'openssh_trust_options',lambda server:['-o','StrictHostKeyChecking=yes'])
    def synthetic_ssh(argv,**kwargs):
        commands.append(argv);return SimpleNamespace(returncode=0)
    monkeypatch.setattr(helpers,'subprocess',SimpleNamespace(run=synthetic_ssh))
    with app.app_context():
        key=SSHKey(name='explicit-key',key_path='/synthetic/missing-explicit-key');db.session.add(key);db.session.flush()
        row=Row(name='worker-a',server_ip='192.0.2.8',ssh_key_id=key.id,ssh_user='root',ssh_port=22)
        db.session.add(row);db.session.commit();key_id=key.id;identity=row.id
    class API:
        def request(self,method,url,**kwargs):
            path=urlsplit(url).path.removeprefix('/dc')
            response=client.open(path,method=method,json=kwargs.get('json'),headers=auth_headers)
            return SimpleNamespace(status_code=response.status_code,json=response.get_json)
    with pytest.raises((ValueError,RuntimeError)):
        lifecycle.register_worker(API(),Server(name='worker-a',server_ip='192.0.2.8'),FleetConfig(),base_url='https://fleet.example',ssh_key_id=key_id)
    assert commands==[]


@pytest.mark.parametrize('field',['name','server_ip','ssh_user','ssh_port','ssh_key_id','recreated'])
def test_selected_completion_rejects_each_concurrent_identity_field_before_probe(app,client,auth_headers,tmp_path,monkeypatch,field):
    from dc_overview.app import db, Server as Row, SSHKey
    from dc_overview.worker_lifecycle import _identity_query
    calls=[];observations(monkeypatch,calls)
    created=client.post('/api/servers',json={'name':'worker-a','server_ip':'192.0.2.8'},headers=auth_headers)
    identity=created.get_json()['id']
    snapshot=client.get(f'/api/servers/{identity}/ssh-config?selected_enrollment=1',headers=auth_headers).get_json()['enrollment_identity']
    calls.clear()
    if field in ('name','server_ip'):
        changed=client.put(f'/api/servers/{identity}',json={'name':'worker-b' if field=='name' else 'worker-a','server_ip':'192.0.2.9' if field=='server_ip' else '192.0.2.8'},headers=auth_headers)
    elif field=='recreated':
        assert client.delete(f'/api/servers/{identity}',headers=auth_headers).status_code==200
        changed=client.post('/api/servers',json={'name':'worker-a','server_ip':'192.0.2.8'},headers=auth_headers)
    else:
        value='ubuntu' if field=='ssh_user' else 2222
        if field=='ssh_key_id':
            key_path=tmp_path/'declared-key-reference';key_path.write_text('synthetic nonsecret fixture')
            with app.app_context():
                key=SSHKey(name='new-key',key_path=str(key_path));db.session.add(key);db.session.commit();value=key.id
            monkeypatch.setattr('dc_overview.app._read_effective_private_key',lambda server:'declared credential-format adapter')
        changed=client.post(f'/api/servers/{identity}/ssh-config',json={field:value},headers=auth_headers)
    assert changed.status_code in (200,201)
    calls.clear()
    response=client.get(f'/api/servers/{identity}/check'+_identity_query(snapshot),headers=auth_headers)
    assert response.status_code==409,response.get_json()
    assert calls==[]
    with app.app_context():
        row=db.session.get(Row,identity);assert row is not None and not row.node_exporter_installed
        if field=='recreated':assert row.inventory_server_id!=snapshot['inventory_server_id']
        elif field=='ssh_key_id':assert row.ssh_key_id==value


@pytest.mark.parametrize('role',['readonly','readwrite'])
def test_selected_probe_requires_admin_while_ordinary_read_remains_compatible(app,client,auth_headers,monkeypatch,role):
    calls=[];observations(monkeypatch,calls)
    identity=client.post('/api/servers',json={'name':'worker-a','server_ip':'192.0.2.8'},headers=auth_headers).get_json()['id']
    calls.clear();headers=dict(auth_headers,**{'X-Fleet-Auth-Role':role})
    for suffix,method in [('check?selected_enrollment=1','GET'),('ssh-config?selected_enrollment=1','GET'),('ssh-test?selected_enrollment=1','POST')]:
        response=client.open(f'/api/servers/{identity}/{suffix}',method=method,headers=headers)
        assert response.status_code==403
    assert calls==[]
    assert client.get(f'/api/servers/{identity}/check',headers=headers).status_code==200
    assert not any(call[0]=='service-probe' for call in calls)


def test_strict_key_resolution_never_reads_material_and_keeps_default_compatibility(tmp_path,monkeypatch):
    import os
    from dc_overview import ssh_helpers
    explicit=tmp_path/'explicit';default=tmp_path/'default';default.write_text('synthetic metadata-only fixture')
    key=SimpleNamespace(key_path=str(explicit));server=SimpleNamespace(name='worker-fixture',ssh_key_id=7,ssh_key=key)
    def prohibited_read(*a,**k):raise AssertionError('selected custody must not read private key material')
    monkeypatch.setattr('pathlib.Path.read_bytes',prohibited_read)
    with pytest.raises(ValueError,match='fallback'):
        ssh_helpers.resolve_ssh_key_path(server,strict=True)
    explicit.write_text('synthetic metadata-only fixture')
    assert ssh_helpers.resolve_ssh_key_path(server,strict=True)==str(explicit)
    server.ssh_key=None;server.ssh_key_id=None
    original_open=ssh_helpers.os.open
    def default_open(path,*args,**kwargs):
        return original_open(str(default) if str(path)=='/etc/dc-overview/ssh_keys/fleet_key' else path,*args,**kwargs)
    monkeypatch.setattr(ssh_helpers.os,'open',default_open)
    assert ssh_helpers.resolve_ssh_key_path(server,strict=True)=='/etc/dc-overview/ssh_keys/fleet_key'
    monkeypatch.setattr(ssh_helpers.os.path,'exists',lambda path:str(path)=='/etc/dc-overview/ssh_keys/fleet_key')
    server.ssh_key=SimpleNamespace(key_path=str(tmp_path/'missing-ordinary'));server.ssh_key_id=8
    assert ssh_helpers.resolve_ssh_key_path(server)=='/etc/dc-overview/ssh_keys/fleet_key'


def test_identity_guard_interrupts_privileged_stage_before_installer(tmp_path,monkeypatch):
    from test_selected_worker_enrollment import plan_for
    lifecycle=importlib.import_module('dc_overview.worker_lifecycle');config=FleetConfig(config_dir=tmp_path)
    config.servers=[Server(name='worker-a',server_ip='192.0.2.8')]
    checks=[]
    def guard():
        checks.append('identity')
        if len(checks)==3:raise ValueError('identity changed before privilege stage')
    config._enrollment_identity_guard=guard
    ssh=Mock();ssh.run_command.side_effect=[SimpleNamespace(success=True,output='Linux x86_64'),SimpleNamespace(success=True,output='WORKER_COMPONENT=dc-exporter|not-found|unknown|not-found|-\n')]
    monkeypatch.setattr(lifecycle,'SSHManager',lambda *a:ssh)
    with pytest.raises(ValueError,match='identity changed'):
        lifecycle.upgrade_workers(config,plan_for('dc-exporter'),mode='reconcile')
    assert ssh.run_command.call_count==2


def test_missing_expected_identity_or_wrong_types_hold_before_probe(app,client,auth_headers,monkeypatch):
    from dc_overview.worker_lifecycle import _identity_query
    calls=[];observations(monkeypatch,calls)
    identity=client.post('/api/servers',json={'name':'worker-a','server_ip':'192.0.2.8'},headers=auth_headers).get_json()['id']
    snapshot=client.get(f'/api/servers/{identity}/ssh-config?selected_enrollment=1',headers=auth_headers).get_json()['enrollment_identity'];calls.clear()
    assert client.get(f'/api/servers/{identity}/check?selected_enrollment=1',headers=auth_headers).status_code==400
    snapshot['server_id']=True
    assert client.get(f'/api/servers/{identity}/check'+_identity_query(snapshot),headers=auth_headers).status_code==400
    assert calls==[]


def test_selected_pinned_default_reference_cannot_fall_back_during_probe(tmp_path,monkeypatch):
    from dc_overview import ssh_helpers
    missing=tmp_path/'old-default';other=tmp_path/'other-default';other.write_text('synthetic metadata fixture')
    server=SimpleNamespace(ssh_key_id=None,ssh_key=None,_selected_ssh_key_strict=True,_selected_effective_key_path=str(missing))
    original_open=ssh_helpers.os.open
    def opening(path,*args,**kwargs):
        return original_open(str(other) if str(path)=='/etc/dc-overview/ssh_keys/fleet_key' else path,*args,**kwargs)
    monkeypatch.setattr(ssh_helpers.os,'open',opening)
    with pytest.raises(ValueError,match='reference'):
        ssh_helpers.resolve_ssh_key_path(server)


def test_missing_immutable_inventory_identity_is_not_enrollment_authority(app,client,auth_headers,monkeypatch):
    from dc_overview.app import db, Server as Row
    calls=[];observations(monkeypatch,calls)
    identity=client.post('/api/servers',json={'name':'worker-a','server_ip':'192.0.2.8'},headers=auth_headers).get_json()['id']
    with app.app_context():
        row=db.session.get(Row,identity);row.inventory_server_id='';db.session.commit()
    calls.clear()
    response=client.get(f'/api/servers/{identity}/ssh-config?selected_enrollment=1',headers=auth_headers)
    assert response.status_code==409
    assert calls==[]


def test_authorized_registration_is_retained_when_remote_preflight_holds(app,client,auth_headers,tmp_path,monkeypatch):
    from dc_overview.app import db, Server as Row
    lifecycle=importlib.import_module('dc_overview.worker_lifecycle');_selected_customer(tmp_path,monkeypatch)
    calls=[];observations(monkeypatch,calls);config=FleetConfig.load(tmp_path)
    class API:
        def request(self,method,url,**kwargs):
            parsed=urlsplit(url);response=client.open(parsed.path.removeprefix('/dc')+('?' + parsed.query if parsed.query else ''),method=method,json=kwargs.get('json'),headers=auth_headers)
            return SimpleNamespace(status_code=response.status_code,json=response.get_json)
        def close(self):calls.append(('closed',))
    def login(*a,**k):calls.append(('authorized-login',));return API()
    monkeypatch.setattr(lifecycle,'_fleet_login',login)
    def unavailable(*a,**k):
        with app.app_context():assert Row.query.filter_by(name='worker-a').count()==1
        calls.append(('privileged-preflight',));raise ValueError('unknown unit or unavailable privilege')
    monkeypatch.setattr(lifecycle,'preflight_workers',unavailable)
    delivery=Mock();monkeypatch.setattr(lifecycle,'upgrade_workers',delivery)
    before=(tmp_path/'fleet-config.yaml').read_bytes()
    with pytest.raises(ValueError,match='unknown unit'):
        lifecycle.enroll_selected_worker(config,Server(name='worker-a',server_ip='192.0.2.8'),base_url='https://fleet.example',username='admin',password='synthetic')
    assert calls.index(('authorized-login',))<calls.index(('privileged-preflight',))
    assert (tmp_path/'fleet-config.yaml').read_bytes()==before
    with app.app_context():
        row=Row.query.filter_by(name='worker-a').one();assert not row.node_exporter_installed and not row.dc_exporter_installed
    delivery.assert_not_called()


def test_selected_completion_serializes_api_identity_writer_during_probe(app,client,auth_headers,monkeypatch):
    import threading
    from dc_overview.app import db, Server as Row
    from dc_overview.worker_lifecycle import _identity_query
    mod=importlib.import_module('dc_overview.app');calls=[];observations(monkeypatch,calls)
    identity=client.post('/api/servers',json={'name':'worker-a','server_ip':'192.0.2.8'},headers=auth_headers).get_json()['id']
    snapshot=client.get(f'/api/servers/{identity}/ssh-config?selected_enrollment=1',headers=auth_headers).get_json()['enrollment_identity']
    probing=threading.Event();release=threading.Event();write_attempt=threading.Event();write_finished=threading.Event()
    responses={};errors=[];original_begin=mod._begin_inventory_mutation
    def begin():
        if threading.current_thread().name=='declared-inventory-writer':write_attempt.set()
        return original_begin()
    monkeypatch.setattr(mod,'_begin_inventory_mutation',begin)
    def services(server,**kwargs):
        probing.set()
        if not release.wait(5):raise AssertionError('declared probe fixture release timed out')
        return {key:{'installed':key in ('node_exporter','dc_exporter'),'active':False} for key in ('node_exporter','dc_exporter','dcgm_exporter','watchdog_agent')}
    monkeypatch.setattr(mod,'check_services_installed',services)
    def check():
        try:
            with app.test_client() as independent:
                responses['check']=independent.get(f'/api/servers/{identity}/check'+_identity_query(snapshot),headers=auth_headers)
        except Exception as error:errors.append(error)
    def rename():
        try:
            with app.test_client() as independent:
                responses['rename']=independent.put(f'/api/servers/{identity}',json={'name':'worker-b','server_ip':'192.0.2.9'},headers=auth_headers)
        except Exception as error:errors.append(error)
        finally:write_finished.set()
    selected=threading.Thread(target=check,name='declared-selected-probe');writer=threading.Thread(target=rename,name='declared-inventory-writer')
    selected.start()
    try:
        assert probing.wait(5),'selected owner never entered service probe'
        writer.start()
        assert write_attempt.wait(5),'writer never attempted inventory reservation'
        assert not write_finished.wait(.05),'inventory identity mutated while selected probe held its transaction'
    finally:
        release.set();selected.join(5)
        if writer.ident is not None:writer.join(5)
    assert not selected.is_alive() and not writer.is_alive() and not errors,errors
    assert responses['check'].status_code==200 and responses['rename'].status_code==200
    assert responses['check'].get_json()['enrollment_identity']==snapshot
    with app.app_context():
        db.session.expire_all();row=db.session.get(Row,identity)
        assert (row.name,row.server_ip)==('worker-b','192.0.2.9')
        assert row.node_exporter_installed is True
