"""ADV-MON-01/02 caller controls; explicit Docker/archive/HTTP adapters."""
import copy
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from dc_overview import controller_adoption as adoption, fleet_manager, fleet_upgrade, monitoring
from test_standard_monitoring_path import customer, predecessor
from test_controller_adoption import bind, container, volume


def inspected(role, service, config_dir):
    mounts=[]
    for row in service.get('volumes', []):
        source, target, *options=row.split(':')
        if source.startswith('./'): source=str(config_dir/source[2:])
        mounts.append(bind(source,target,'ro' not in options) if source.startswith('/') else volume(source,target))
    value=container(role,mounts); value['Config'].update(Image=service['image'],Env=service.get('environment',[]),Cmd=service.get('command',[]))
    return value


def archive_adapter(monkeypatch, inventory, bound=None):
    monkeypatch.setattr(adoption.InstalledEngine,'__init__',lambda self,engine=None:setattr(self,'engine',engine or SimpleNamespace()))
    def file_state(self, role, target, **kwargs):
        value=inventory.get(role) or next(v for v in inventory.values() if v and v['Id']==role)
        mounts=[m for m in value['Mounts'] if target==m['Destination'] or target.startswith(m['Destination']+'/')]
        mount=max(mounts,key=lambda m:len(m['Destination']))
        source=Path(mount['Source'])
        if target!=mount['Destination']: source=source/Path(target).relative_to(mount['Destination'])
        if bound and target=='/etc/prometheus/recording_rules.yml':
            bound.seek(0); payload=bound.read(); metadata=os.fstat(bound.fileno())
        else: payload=source.read_bytes(); metadata=source.stat()
        return {'bytes':payload.hex(),'uid':metadata.st_uid,'gid':metadata.st_gid,'mode':metadata.st_mode & 0o7777,'inode':metadata.st_ino,'device':metadata.st_dev,'parents':{}}
    monkeypatch.setattr(adoption.InstalledEngine,'file_state',file_state)
    monkeypatch.setattr(adoption.InstalledEngine,'running_file_state',file_state)


@pytest.mark.parametrize('drift',[None,'id','mount','dc-stopped','capture-extra-bind'])
def test_real_deploy_stages_monitoring_before_dc_and_expires_fresh_authority(customer,monkeypatch,drift):
    manager=customer; inventory={r:None for r in adoption.ROLES}; calls=[]; configured=[]
    monkeypatch.setattr(adoption,'probe_controller_inventory',lambda:copy.deepcopy(inventory))
    monkeypatch.setattr(fleet_upgrade,'preflight_release',lambda *a,**k:manager.release_plan)
    monkeypatch.setattr(fleet_upgrade,'commit_release',lambda *a:None)
    for name in ('_install_prerequisites','_setup_ssh_keys','_import_dashboards','_setup_security_hardening','_show_completion','_populate_dc_overview_servers'):
        monkeypatch.setattr(manager,name,lambda:None)
    monkeypatch.setattr(fleet_manager,'_ALERTS_AVAILABLE',False)
    monkeypatch.setattr(fleet_manager,'_ensure_docker_network',lambda:None)
    monkeypatch.setattr(fleet_manager,'_get_docker_compose_cmd',lambda:['docker','compose'])
    monkeypatch.setattr(manager,'_wait_for_container',lambda *a,**k:True)
    monkeypatch.setattr(manager,'_grafana_request',lambda path,**k:{'database':'ok'} if path=='/api/health' else [{'type':'prometheus','uid':'prometheus','isDefault':True}] if path=='/api/datasources' else [])
    monkeypatch.setattr(fleet_upgrade,'observe_component',lambda role,*a:{'state':'running' if inventory.get(role) else 'unknown'})
    archive_adapter(monkeypatch,inventory)
    def docker(command,**kwargs):
        calls.append(command)
        if command[:2]==['docker','inspect']: return SimpleNamespace(returncode=1,stdout='',stderr='No such container: '+command[2])
        if command==['docker','compose','up','-d']:
            services=yaml.safe_load((manager.config.config_dir/'docker-compose.yml').read_bytes())['services']
            assert 'dc-overview' not in services
            inventory.update({r:inspected(r,s,manager.config.config_dir) for r,s in services.items() if r in adoption.ROLES})
            if drift=='capture-extra-bind': inventory['prometheus']['Mounts'].append(bind(manager.config.config_dir/'foreign','/etc/prometheus/ownership.json'))
        if command[:2]==['docker','ps']: return SimpleNamespace(returncode=0,stdout='prometheus:Up\ngrafana:Up\n',stderr='')
        if command[:3]==['docker','rm','-f']: inventory['dc-overview']=None
        if command[:3]==['docker','run','-d']:
            assert inventory['prometheus'] and inventory['grafana'] and inventory['dc-overview'] is None
            service={'image':command[-1],'environment':[command[i+1] for i,v in enumerate(command) if v=='-e'],'volumes':[command[i+1] for i,v in enumerate(command) if v=='-v']}
            inventory['dc-overview']=inspected('dc-overview',service,manager.config.config_dir)
            if drift=='dc-stopped': inventory['dc-overview']['State']['Running']=False
        return SimpleNamespace(returncode=0,stdout='',stderr='')
    monkeypatch.setattr(fleet_manager.subprocess,'run',docker)
    monkeypatch.setattr(manager,'_reload_baseline_prometheus',lambda *a:True)
    def proxy():
        inventory['cryptolabs-proxy']=container('cryptolabs-proxy'); inventory['cryptolabs-proxy']['Config']['Image']=manager.release_plan.targets['cryptolabs-proxy']['reference']
        manager._deploy_dc_overview_container()
    monkeypatch.setattr(manager,'_setup_reverse_proxy',proxy)
    configure=manager._configure_prometheus_targets
    def step5():
        configured.append(True)
        assert inventory['prometheus'] and inventory['grafana'] and inventory['dc-overview'] is None
        if drift=='id': inventory['prometheus']['Id']='foreign-id'
        if drift=='mount': inventory['prometheus']['Mounts'][0]['Source']=str(manager.config.config_dir/'foreign')
        configure()
    monkeypatch.setattr(manager,'_configure_prometheus_targets',step5)
    assert manager.deploy() is (drift is None)
    assert not getattr(manager,'_fresh_monitoring',None)
    if drift=='capture-extra-bind': assert configured==[]
    if drift in ('id','mount'):
        assert not any(c[:3]==['docker','run','-d'] for c in calls)
        with pytest.raises(ValueError): manager._monitoring_directory()
    elif drift is None:
        assert inventory['dc-overview'] is not None and adoption.upgrade_requires_adoption() is False


def test_unknown_partial_standalone_holds_before_remove(customer,monkeypatch):
    monkeypatch.setattr(adoption,'probe_controller_inventory',lambda:{r:container(r) if r in ('prometheus','grafana') else None for r in adoption.ROLES})
    calls=[];monkeypatch.setattr(fleet_manager.subprocess,'run',lambda args,**k:calls.append(args))
    with pytest.raises(ValueError,match='incomplete'): customer._deploy_dc_overview_container()
    assert calls==[]


def adopted(customer,monkeypatch,tmp_path):
    adapter,inventory,declaration,source=predecessor(customer,tmp_path)
    result=adoption.build_plan(*adapter.collect(declaration));adoption.stage_product_directory(result)
    for role in ('dc-overview','prometheus'):
        request=result.requests[role]; inventory[role]['Config']=request['Config']
        inventory[role]['Mounts']=[bind(m['Source'],m['Target'],not m['ReadOnly']) if m['Type']=='bind' else volume(m['Source'],m['Target']) for m in request['HostConfig']['Mounts']]
    monkeypatch.setattr(adoption,'probe_controller_inventory',lambda:copy.deepcopy(inventory))
    monkeypatch.setattr(fleet_upgrade,'observe_component',lambda *a:{'state':'unknown'})
    return Path(declaration['product_directory']),source,inventory


@pytest.mark.parametrize('drift',['atomic','generator'])
def test_retained_rule_drift_holds_actual_configuration_pipeline_before_write(customer,monkeypatch,tmp_path,drift):
    public,source,inventory=adopted(customer,monkeypatch,tmp_path); rules=source/'recording_rules.yml'
    before=(public/'prometheus.yml').read_bytes(); calls=[]
    with rules.open('rb') as bound:
        archive_adapter(monkeypatch,inventory,bound)
        revised=b'groups:\n- name: changed\n  rules: [{record: changed_metric, expr: vector(3)}]\n'
        if drift=='atomic': monitoring.atomic_write_bytes(rules,revised)
        else: monkeypatch.setattr(customer,'_generate_recording_rules',lambda:revised.decode())
        monkeypatch.setattr(customer,'_validate_baseline_prometheus',lambda mapping:type(customer)._validate_baseline_prometheus(customer,mapping))
        monkeypatch.setattr(fleet_manager.subprocess,'run',lambda *a,**k:calls.append('validator') or SimpleNamespace(returncode=0))
        monkeypatch.setattr(customer,'_reload_baseline_prometheus',lambda *a:calls.append('reload') or True)
        with pytest.raises((ValueError,RuntimeError),match='reference|rule|custody'):
            customer._configure_prometheus_targets()
        assert calls==[] and (public/'prometheus.yml').read_bytes()==before


def test_unchanged_retained_rule_positive_and_post_reload_archive_drift_hold(customer,monkeypatch,tmp_path):
    public,source,inventory=adopted(customer,monkeypatch,tmp_path)
    archive_adapter(monkeypatch,inventory)
    mapping=yaml.safe_load((public/'prometheus.yml').read_bytes())
    class Response(io.BytesIO): status=200
    def http(request,**kwargs):
        if isinstance(request,str): return Response(json.dumps({'status':'success','data':{'yaml':yaml.safe_dump(mapping)}}).encode())
        return Response(b'')
    monkeypatch.setattr(fleet_manager.urllib.request,'urlopen',http)
    assert customer._reload_baseline_prometheus(mapping)
    original=adoption.InstalledEngine.running_file_state; reads=[]
    def drifting(self,role,path,**kwargs):
        reads.append(path); state=original(self,role,path,**kwargs)
        if len(reads)>1: state['bytes']=b'groups: []\n'.hex()
        return state
    monkeypatch.setattr(adoption.InstalledEngine,'running_file_state',drifting)
    assert customer._reload_baseline_prometheus(mapping) is False
