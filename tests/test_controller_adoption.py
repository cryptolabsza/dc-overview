"""RED-first customer identity and compensation contract (no Engine access)."""
import copy
import fcntl
import json
import os
from pathlib import Path

import pytest

from dc_overview.controller_adoption import (
    AdoptionError, build_plan, bounded_lock, ensure_mutation_allowed,
    ControllerAdoption, InstalledEngine, Journal,
)


@pytest.fixture(autouse=True)
def no_network_or_subprocess_escape(monkeypatch):
    import socket
    import subprocess
    def forbidden(*a,**k): raise AssertionError('unit test external escape forbidden')
    monkeypatch.setattr(socket.socket,'connect',forbidden)
    monkeypatch.setattr(subprocess,'run',forbidden)


def container(role, mounts=()):
    return {'Id': role + '-actual-id', 'Name': '/' + role, 'Image': 'sha256:' + ('a' if role == 'dc-overview' else 'b') * 64,
        'Config': {'Image': 'customer/image:retained', 'Env': ['SECRET_KEY=synthetic-only', 'CUSTOMER_OPTION=retain'],
                   'Cmd': ['--config.file=/etc/prometheus/prometheus.yml'] if role == 'prometheus' else ['gunicorn', 'dc_overview.app:app'],
                   'Entrypoint': None, 'User': '1000:1000', 'Labels': {'customer.label': 'keep'}},
        'HostConfig': {'Binds': [], 'RestartPolicy': {'Name': 'unless-stopped'},
                       'PortBindings': {'9090/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '19090'}]},
                       'CapAdd': ['NET_BIND_SERVICE'], 'Memory': 104857600, 'NetworkMode': 'customer-net'},
        'Mounts': list(mounts), 'NetworkSettings': {'Networks': {'customer-net': {'Aliases': ['customer-name'],
            'IPAMConfig': {'IPv4Address': '172.29.0.19'}, 'EndpointID': 'engine-generated'}}},
        'State': {'Running': True, 'Health': {'Status': 'healthy'}}}


def bind(source, target, rw=False):
    return {'Type': 'bind', 'Source': str(source), 'Destination': target, 'RW': rw, 'Propagation': 'rprivate'}


def volume(name, target):
    return {'Type': 'volume', 'Name': name, 'Source': '/var/lib/docker/volumes/' + name + '/_data', 'Destination': target, 'RW': True}


@pytest.fixture
def inputs(tmp_path):
    source = tmp_path / 'old'; source.mkdir()
    config = b'global:\n  scrape_interval: 37s\nscrape_configs:\n- job_name: customer\n  static_configs:\n  - targets: ["customer:9100"]\nrule_files: [/etc/prometheus/customer/rules.yml]\n'
    (source/'prometheus.yml').write_bytes(config)
    rules=tmp_path/'rules.yml'; rules.write_text('groups: []\n')
    product=tmp_path/'public-monitoring'
    declaration={'schema_version': 1, 'product_directory':str(product),
        'dc_destination':'/var/lib/dc-monitoring', 'managed_jobs':['dc-managed'],
        'session_routes':['proxy-sso'], 'maintenance_owners':['external-compose'],
        'public_inputs':[]}
    inventory={
        'dc-overview':container('dc-overview',[volume('actual-anonymous-2894','/data'),volume('auth-shared-original','/data/auth'),bind(tmp_path/'private','/etc/dc-overview')]),
        'prometheus':container('prometheus',[volume('customer-tsdb','/prometheus'),bind(source/'prometheus.yml','/etc/prometheus/prometheus.yml'),bind(rules,'/etc/prometheus/customer/rules.yml')]),
        'grafana':container('grafana',[volume('customer-grafana','/var/lib/grafana'),bind(tmp_path/'dashboards','/etc/grafana/provisioning/dashboards')]),
        'cryptolabs-proxy':container('cryptolabs-proxy',[volume('auth-shared-original','/data/auth')])}
    evidence={'effective_source':{'dc-overview':True,'prometheus':True},'reference_files':{'/etc/prometheus/customer/rules.yml':b'groups: []\n'}}
    return inventory,declaration,config,evidence


def plan(inputs): return build_plan(*inputs)


def test_exact_anonymous_data_auth_tsdb_and_runtime(inputs):
    result=plan(inputs)
    assert result.mutations == ('dc-overview','prometheus')
    for role in result.mutations:
        source=inputs[0][role]; request=result.requests[role]
        assert request['Config']['Image'] == source['Image']
        assert request['HostConfig']['RestartPolicy'] == source['HostConfig']['RestartPolicy']
        assert request['HostConfig']['PortBindings'] == source['HostConfig']['PortBindings']
        assert request['HostConfig']['CapAdd'] == ['NET_BIND_SERVICE']
        assert request['HostConfig']['Memory'] == 104857600
        assert request['NetworkingConfig']['EndpointsConfig']['customer-net']['IPAMConfig']=={'IPv4Address':'172.29.0.19'}
        actual={m['Target']:m['Source'] for m in request['HostConfig']['Mounts']}
        for m in source['Mounts']:
            if m['Type']=='volume': assert actual[m['Destination']]==m['Name']
    assert result.prometheus_bytes==inputs[2]
    assert 'grafana' not in result.requests
    assert 'cryptolabs-proxy' not in result.requests
    assert 'synthetic-only' not in json.dumps(result.public())
    assert inputs[0]['dc-overview']['Config']['Env'][0]=='SECRET_KEY=synthetic-only'


@pytest.mark.parametrize('change,match',[
    ('missing','inventory'),('unknown_host','unsupported HostConfig.NewWriterSetting'),
    ('amended','source_normalization_required'),('inline','inline|unsupported'),('local_cookie','local_cookie'),
    ('unowned','ownership'),('missing_reference','reference')])
def test_prewrite_holds(inputs,change,match):
    inventory,declaration,config,evidence=inputs
    if change=='missing': inventory.pop('grafana')
    if change=='unknown_host': inventory['dc-overview']['HostConfig']['NewWriterSetting']=True
    if change=='amended': evidence['effective_source']['dc-overview']=False
    if change=='inline': config+=b'authorization:\n  credentials: private\n'
    if change=='local_cookie': declaration['session_routes']=['local-cookie']; inventory['dc-overview']['Config']['Env']=['FLASK_SECRET_KEY=synthetic-only']
    if change=='unowned': config=config.replace(b'job_name: customer',b'job_name: dc-managed'); declaration['managed_jobs']=[]
    if change=='missing_reference': evidence['reference_files']={}
    with pytest.raises(AdoptionError,match=match): build_plan(inventory,declaration,config,evidence)


def test_sso_without_dc_key_is_eligible(inputs):
    inputs[0]['dc-overview']['Config']['Env']=[]
    assert plan(inputs).mutations


def test_fully_adopted_noop_and_drift(inputs):
    first=plan(inputs)
    for role in first.mutations:
        request=first.requests[role]; inspected=inputs[0][role]
        inspected['Config']=copy.deepcopy(request['Config'])
        inspected['HostConfig']=copy.deepcopy(request['HostConfig'])
        inspected['Mounts']=[{'Type':m['Type'],'Source':m['Source'],'Name':m['Source'] if m['Type']=='volume' else '',
            'Destination':m['Target'],'RW':not m['ReadOnly'],'Propagation':'rprivate'} for m in request['HostConfig']['Mounts']]
    assert not plan(inputs).mutations
    inputs[0]['grafana']['Config']['Labels']['customer.label']='drift'
    assert first.matches(inputs[0],inputs[2],inputs[3]) is False


def test_bounded_real_file_lock(tmp_path):
    path=tmp_path/'lock'
    with path.open('w') as owner:
        fcntl.flock(owner,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(AdoptionError,match='busy'):
            with bounded_lock(path,timeout=.02): pass


class FakeEngine:
    def __init__(self,inventory): self.values=copy.deepcopy(inventory); self.trace=[]; self.fail=None; self.guard_alive=True; self.persisted_samples=17
    def inspect(self,name):
        if name in self.values: return copy.deepcopy(self.values[name])
        return next(copy.deepcopy(v) for v in self.values.values() if v['Id']==name)
    def stop(self,name):
        self.trace.append(('stop',name))
        if self.fail==('stop',name): raise AdoptionError('unknown stop')
        self._actual(name)['State']['Running']=False
    def _actual(self,name):
        return self.values[name] if name in self.values else next(v for v in self.values.values() if v['Id']==name)
    def rename(self,old,new):
        self.trace.append(('rename',old,new)); value=self._actual(old); self.values.pop(next(k for k,v in self.values.items() if v is value)); self.values[new]=value; value['Name']='/'+new
    def disconnect(self,name,network):
        self.trace.append(('disconnect',name,network)); self._actual(name)['NetworkSettings']['Networks'].pop(network,None)
    def connect(self,name,network,endpoint):
        self.trace.append(('connect',name,network,endpoint)); self._actual(name)['NetworkSettings']['Networks'][network]=copy.deepcopy(endpoint)
    def create(self,name,request):
        self.trace.append(('create',name)); self.values[name]=container(name); self.values[name].update(Config=copy.deepcopy(request['Config']),HostConfig=copy.deepcopy(request['HostConfig'])); self.values[name]['State']['Running']=False
        self.values[name]['Id']=name+'-candidate-id'
        self.values[name]['Image']=request['Config']['Image']
        self.values[name]['Mounts']=[{'Type':m['Type'],'Source':m['Source'],'Name':m['Source'] if m['Type']=='volume' else '',
            'Destination':m['Target'],'RW':not m['ReadOnly'],'Propagation':m.get('BindOptions',{}).get('Propagation','')} for m in request['HostConfig']['Mounts']]
        self.values[name]['NetworkSettings']={'Networks':copy.deepcopy(request['NetworkingConfig']['EndpointsConfig'])}
        if self.fail==('create',name): raise AdoptionError('create failed after creation')
    def start(self,name):
        self.trace.append(('start',name,self._actual(name)['Id'])); self._actual(name)['State']['Running']=True
        if name in ('prometheus','dc-overview'): self.persisted_samples+=1
        if self.fail==('start',name):
            self.fail=None
            raise AdoptionError('start failed')
    def readiness(self,name,expected):
        if name in ('dc-overview','prometheus'): self.trace.append(('ready',name))
        if self._actual(name).get('State',{}).get('Health',{}).get('Status')!='healthy': return False
        if self.fail==('ready',name):
            self.fail=None
            return False
        return True
    def monitoring_snapshot(self,plan):
        state={'config':plan.prometheus_bytes.hex(),
               'references':{k:v.hex() for k,v in plan.evidence['reference_files'].items()},
               'reference_custody':{k:{'uid':1000,'gid':1000,'mode':0o600} for k in plan.evidence['reference_files']},
               'public_inputs':copy.deepcopy(plan.evidence.get('public_inputs',{}))}
        drift=getattr(self,'monitoring_drift',None)
        if drift=='config': state['config']=b'scrape_configs: []\n'.hex()
        if drift=='reference': state['references'][next(iter(state['references']))]=b'changed'.hex()
        if drift=='public': state['public_inputs']['changed-public-input']='changed'
        return state
    def guard(self):
        if not self.guard_alive: raise AdoptionError('guard dead')


def executor(tmp_path,inputs):
    engine=FakeEngine(inputs[0]); journal=Journal(tmp_path/'private-recovery')
    return ControllerAdoption(engine,journal),engine,journal


def test_apply_changes_only_required_roles_and_preserves_evolving_data(tmp_path,inputs):
    runner,engine,journal=executor(tmp_path,inputs)
    result=runner.apply(plan(inputs),current=lambda:inputs,guard=engine.guard)
    assert result['state']=='adopted'
    assert all('grafana' not in action and 'cryptolabs-proxy' not in action for action in engine.trace)
    assert engine.persisted_samples==19
    assert journal.read()['state']=='adopted'
    assert (journal.root/'operation.json').stat().st_mode & 0o777==0o600


@pytest.mark.parametrize('failure', [('create','prometheus'),('start','prometheus'),('ready','prometheus'),('create','dc-overview'),('start','dc-overview'),('ready','dc-overview')])
def test_failure_compensates_only_runtime_retains_evolving_data(tmp_path,inputs,failure):
    runner,engine,journal=executor(tmp_path,inputs); engine.fail=failure
    result=runner.apply(plan(inputs),current=lambda:inputs,guard=engine.guard)
    assert result['state']=='restored'
    assert engine.inspect('dc-overview')['Id']=='dc-overview-actual-id'
    assert engine.inspect('prometheus')['Id']=='prometheus-actual-id'
    assert engine.persisted_samples>=17
    assert all('grafana' not in action for action in engine.trace)


def test_guard_death_and_stale_plan_zero_service_writes(tmp_path,inputs):
    runner,engine,journal=executor(tmp_path,inputs); intended=plan(inputs)
    inputs[0]['grafana']['Config']['User']='changed'
    with pytest.raises(AdoptionError,match='drift'): runner.apply(intended,current=lambda:inputs,guard=engine.guard)
    assert not engine.trace
    inputs[0]['grafana']['Config']['User']='1000:1000'; engine.guard_alive=False
    with pytest.raises(AdoptionError,match='guard'): runner.apply(intended,current=lambda:inputs,guard=engine.guard)
    assert not engine.trace


def test_uncertain_stop_never_starts_another_writer(tmp_path,inputs):
    runner,engine,journal=executor(tmp_path,inputs); engine.fail=('stop','dc-overview-actual-id')
    result=runner.apply(plan(inputs),current=lambda:inputs,guard=engine.guard)
    assert result['state']=='forward-repair-required'
    assert not any(action[0]=='start' for action in engine.trace)
    with pytest.raises(AdoptionError,match='recovery'): ensure_mutation_allowed(journal.root.parent,inventory=inputs[0],recovery_directory=journal.root)


def test_installed_adapter_missing_capability_holds_without_engine_actions():
    class Old: pass
    adapter=InstalledEngine(engine=Old())
    with pytest.raises(AdoptionError,match='controller_guard'): adapter.require_guard_capability()


@pytest.mark.parametrize('method,role',[('stop','dc-overview-actual-id'),('stop','prometheus-actual-id'),('rename','prometheus-actual-id'),('create','prometheus'),('start','prometheus'),('rename','dc-overview-actual-id'),('create','dc-overview'),('start','dc-overview')])
def test_crash_after_each_service_mutation_is_recoverable(tmp_path,inputs,method,role):
    runner,engine,journal=executor(tmp_path,inputs)
    original=getattr(engine,method); fired=False
    def crash(name,*args,**kwargs):
        nonlocal fired
        result=original(name,*args,**kwargs)
        if name==role and not fired:
            fired=True
            raise KeyboardInterrupt('synthetic crash after applied mutation')
        return result
    setattr(engine,method,crash)
    with pytest.raises(KeyboardInterrupt): runner.apply(plan(inputs),current=lambda:inputs,guard=engine.guard)
    assert journal.read()['state']=='applying'
    result=runner.recover(guard=engine.guard)
    assert result['state']=='restored'
    assert engine.inspect('dc-overview')['Id']=='dc-overview-actual-id'
    assert engine.inspect('prometheus')['Id']=='prometheus-actual-id'
    assert all('grafana' not in a and 'cryptolabs-proxy' not in a for a in engine.trace)


def test_prepared_journal_recovers_without_stopping_untouched_dependencies(tmp_path,inputs):
    runner,engine,journal=executor(tmp_path,inputs); intended=plan(inputs)
    journal.write({'operation_id':intended.operation_id,'state':'prepared','plan':intended.private(),'completed':[],
                   'predecessors':{},'candidate_ids':{}})
    assert runner.recover(guard=engine.guard)['state']=='restored'
    assert all(action[0]=='ready' for action in engine.trace)


def test_product_symlink_and_private_parent_hold_before_writes(tmp_path,inputs):
    from dc_overview.controller_adoption import stage_product_directory
    private=tmp_path/'private-parent'; private.mkdir(mode=0o700)
    inputs[1]['product_directory']=str(private/'new')
    with pytest.raises(AdoptionError,match='traversable'): stage_product_directory(plan(inputs))
    assert not (private/'new').exists()
    assert private.stat().st_mode & 0o777==0o700
    alias=tmp_path/'symlink'; alias.symlink_to(private,target_is_directory=True)
    inputs[1]['product_directory']=str(alias/'new')
    with pytest.raises(AdoptionError,match='symlink'): plan(inputs)


def test_reserved_customer_job_is_retained_without_inventory_ownership(inputs):
    inventory,declaration,config,evidence=inputs
    config=config.replace(b'job_name: customer',b'job_name: prometheus')
    result=build_plan(inventory,declaration,config,evidence)
    assert result.prometheus_bytes==config


def test_serving_proxy_capability_is_required_not_only_installed_api(monkeypatch):
    class New:
        def controller_guard(self,*args,**kwargs): pass
        def inspect(self,*args): return {'Id':'1'*64}
    monkeypatch.setattr('dc_overview.fleet_upgrade.proxy_capabilities',lambda **kwargs: {'selection_contract':1})
    with pytest.raises(AdoptionError,match='running proxy'): InstalledEngine(engine=New()).require_guard_capability()


def test_terminal_host_record_does_not_release_normal_mutations_before_marker(tmp_path,inputs):
    runner,engine,journal=executor(tmp_path,inputs)
    assert runner.apply(plan(inputs),current=lambda:inputs,guard=engine.guard)['state']=='adopted'
    with pytest.raises(AdoptionError,match='recovery'): ensure_mutation_allowed(tmp_path,recovery_directory=journal.root)
    record=journal.read(); record['exclusion_released']=True; journal.write(record)
    assert ensure_mutation_allowed(tmp_path,recovery_directory=journal.root)


@pytest.mark.parametrize('method',['disconnect','connect'])
def test_crash_after_network_mutation_recovers_exact_endpoints(tmp_path,inputs,method):
    runner,engine,journal=executor(tmp_path,inputs)
    original=getattr(engine,method); fired=False
    def crash(name,*args):
        nonlocal fired
        original(name,*args)
        if not fired:
            fired=True
            raise KeyboardInterrupt('network mutation applied')
    setattr(engine,method,crash)
    if method=='connect':
        engine.fail=('ready','prometheus')
    with pytest.raises(KeyboardInterrupt): runner.apply(plan(inputs),current=lambda:inputs,guard=engine.guard)
    assert runner.recover(guard=engine.guard)['state']=='restored'
    for role in ('prometheus','dc-overview'):
        endpoint=engine.inspect(role)['NetworkSettings']['Networks']['customer-net']
        assert endpoint['IPAMConfig']=={'IPv4Address':'172.29.0.19'}
        assert endpoint['Aliases']==['customer-name']


def test_adopted_recovery_binds_complete_runtime_not_only_ids(tmp_path,inputs):
    runner,engine,journal=executor(tmp_path,inputs)
    runner.apply(plan(inputs),current=lambda:inputs,guard=engine.guard)
    engine.values['dc-overview']['HostConfig']['CapAdd']=['SYS_ADMIN']
    with pytest.raises(AdoptionError,match='post-state drift'): runner.recover(guard=engine.guard)


@pytest.mark.parametrize('role',['prometheus','dc-overview'])
def test_crash_after_original_restart_can_finish_recovery(tmp_path,inputs,role):
    runner,engine,journal=executor(tmp_path,inputs); engine.fail=('ready','dc-overview')
    original=engine.start; fired=False
    def crash(name):
        nonlocal fired
        original(name)
        if name==role and engine.inspect(name)['Id']==role+'-actual-id' and not fired:
            fired=True
            raise KeyboardInterrupt('crash during original restoration')
    engine.start=crash
    with pytest.raises(KeyboardInterrupt): runner.apply(plan(inputs),current=lambda:inputs,guard=engine.guard)
    assert runner.recover(guard=engine.guard)['state']=='restored'


def test_image_compiler_helper_matches_normal_cache_without_executing_it(tmp_path,monkeypatch):
    import base64, py_compile, sys
    from dc_overview.controller_adoption import CACHE_PROOF_SCRIPT
    source=tmp_path/'module.py'; source.write_text('raise RuntimeError("source must never execute")\n')
    cache=tmp_path/'cache.pyc'; py_compile.compile(str(source),cfile=str(cache),dfile=str(source),doraise=True)
    rows=[{'source':str(source),'optimize':0,'cache':base64.b64encode(cache.read_bytes()).decode()}]
    output=tmp_path/'proof.json'
    monkeypatch.setattr(sys,'argv',['proof',base64.b64encode(json.dumps({'caches':rows,'directories':[]}).encode()).decode(),str(output)])
    exec(compile(CACHE_PROOF_SCRIPT,'trusted-fixed-helper','exec'),{})
    assert json.loads(output.read_bytes())=={'equivalent':True}
    source.write_text('raise RuntimeError("different effective code")\n')
    exec(compile(CACHE_PROOF_SCRIPT,'trusted-fixed-helper','exec'),{})
    assert json.loads(output.read_bytes())=={'equivalent':False}


def test_cache_adapter_uses_immutable_image_and_confined_helper_only():
    class Actual:
        def __init__(self): self.actions=[]
        def _file_bytes(self,name,path): return b'bounded-cache' if path.endswith('.pyc') else b'{"equivalent":true}'
        def inspect(self,name): return {'Image':'sha256:'+'a'*64,'Config':{'Entrypoint':['python3'],'Cmd':['/app/module.py'],'Env':[],'WorkingDir':'/app'},'State':{'Running':False,'ExitCode':0}}
        def image(self,name): return {'Id':name,'Config':self.inspect('source')['Config']}
        def create(self,name,request): self.actions.append(('create',name,request))
        def start(self,name): self.actions.append(('start',name))
        def stop(self,name): self.actions.append(('stop',name))
        def remove(self,name): self.actions.append(('remove',name))
    actual=Actual(); adapter=InstalledEngine(engine=actual)
    adapter.directory_custody=lambda *a:{'uid':1000,'gid':1000,'mode':0o755}
    adapter.file_state=lambda name,path,**kwargs:{'bytes':actual._file_bytes(name,path).hex()}
    changes=[{'Path':'/app/__pycache__','Kind':1},{'Path':'/app/__pycache__/module.cpython-311.pyc','Kind':1}]
    assert adapter.prove_effective_source('source-id',changes,[]) is True
    request=actual.actions[0][2]
    assert request['Config']['Image']=='sha256:'+'a'*64 and request['Config']['Env']==[]
    assert request['HostConfig']['NetworkMode']=='none' and request['HostConfig']['Mounts']==[]
    assert request['HostConfig']['ReadonlyRootfs'] and request['HostConfig']['CapDrop']==['ALL']
    assert request['HostConfig']['Memory']==128*1024*1024 and request['HostConfig']['NanoCpus']==250000000
    assert request['HostConfig']['PidsLimit']==16 and request['Config']['User']=='65534:65534'
    assert '-I' in request['Config']['Entrypoint'] and '-B' in request['Config']['Entrypoint'] and '-S' in request['Config']['Entrypoint']
    assert all(a[1].startswith('dc-controller-source-proof-') for a in actual.actions)
    actual.actions.clear()
    assert adapter.prove_effective_source('source-id',[{'Path':'/app/module.py','Kind':0}],[]) is False
    assert not actual.actions


def test_private_plan_tampering_cannot_change_preserved_authority(tmp_path,inputs):
    from dc_overview.controller_adoption import save_private_plan,read_private_plan
    private=tmp_path/'private'; private.mkdir(mode=0o700); path=private/'plan.json'
    save_private_plan(path,plan(inputs))
    value=json.loads(path.read_bytes()); value['requests']['dc-overview']['Config']['Env']=['SECRET_KEY=replacement']
    path.write_text(json.dumps(value))
    with pytest.raises(AdoptionError,match='plan integrity'): read_private_plan(path)


def test_conflicting_original_configuration_holds_before_any_original_restart(tmp_path,inputs):
    runner,engine,journal=executor(tmp_path,inputs); engine.fail=('ready','dc-overview')
    engine.read_file=lambda name,path:b'conflicting external configuration\n'
    result=runner.apply(plan(inputs),current=lambda:inputs,guard=engine.guard)
    assert result['state']=='forward-repair-required'
    assert not any(a[0]=='start' and a[2].endswith('actual-id') for a in engine.trace)
