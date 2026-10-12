"""Accepted CA-ADV defects; runner forbids escapes before these imports."""
import base64
import copy
import json
import os
import stat
from pathlib import Path
from contextlib import contextmanager

import pytest
import yaml

from dc_overview.controller_adoption import (AdoptionError,InstalledEngine,build_plan,stage_product_directory,host_recover)
from test_controller_adoption import inputs,executor,plan,container


@pytest.mark.parametrize('terminal',['adopted','restored'])
@pytest.mark.parametrize('drift',['stopped','unhealthy','config','reference','public','runtime'])
def test_terminal_recovery_revalidates_outcome_before_release(tmp_path,inputs,terminal,drift):
    runner,engine,journal=executor(tmp_path,inputs)
    if terminal=='restored': engine.fail=('ready','dc-overview')
    assert runner.apply(plan(inputs),current=lambda:inputs,guard=engine.guard)['state']==terminal
    if drift=='stopped': engine.values['prometheus']['State']['Running']=False
    if drift=='unhealthy': engine.values['prometheus']['State']['Health']['Status']='unhealthy'
    if drift=='runtime': engine.values['dc-overview']['HostConfig']['CapAdd']=['SYS_ADMIN']
    if drift in ('config','reference','public'):
        engine.monitoring_drift=drift
    before=[a for a in engine.trace if a[0] in ('start','stop','create','rename')]
    with pytest.raises(AdoptionError,match='terminal|post-state'): runner.recover(guard=engine.guard)
    assert [a for a in engine.trace if a[0] in ('start','stop','create','rename')]==before
    assert journal.read().get('exclusion_released') is not True


def test_host_recovery_never_completes_guard_when_terminal_function_failed(tmp_path,inputs):
    runner,engine,journal=executor(tmp_path,inputs)
    assert runner.apply(plan(inputs),current=lambda:inputs,guard=engine.guard)['state']=='adopted'
    Path(inputs[1]['product_directory']).mkdir()
    completed=[]
    class Guard:
        def __call__(self): pass
        def complete(self): completed.append(True)
    @contextmanager
    def guard(*a,**k): yield Guard()
    engine.require_guard_capability=lambda:None;engine.controller_guard=guard
    engine.readiness=lambda *a:False
    with pytest.raises(AdoptionError):host_recover(journal.root.parent,adapter=engine)
    assert completed==[] and journal.read().get('exclusion_released') is not True


@pytest.mark.parametrize('fragment',[
    {'ec2_sd_configs':[{'region':'us-east-1','secret_key':'synthetic-secret'}]},
    {'sigv4':{'region':'us-east-1','secret_key':'synthetic-secret'}},
    {'proxy_connect_header':{'Proxy-Authorization':['synthetic-secret']}},
    {'basic_auth':{'username':'reader','password':'synthetic-secret'}},
    {'authorization':{'credentials':'synthetic-secret'}},
    {'oauth2':{'client_id':'reader','client_secret':'synthetic-secret','token_url':'https://auth.invalid/token'}},
    {'tls_config':{'key':'synthetic-private-key'}},
    {'http_headers':{'Authorization':{'secrets':['synthetic-secret']}}},
    {'proxy_url':'http://reader:synthetic-secret@proxy.invalid:3128'},
    {'http_sd_configs':[{'url':'https://reader:synthetic-secret@discovery.invalid/targets'}]},
    {'future_sd_configs':[{'future_credential':'synthetic-secret'}]},
])
def test_inline_or_unknown_credential_context_never_reaches_public_staging(inputs,fragment):
    inventory,declaration,config,evidence=inputs
    value=yaml.safe_load(config);value['scrape_configs'][0].update(fragment)
    with pytest.raises(AdoptionError,match='unsupported|inline'):
        result=build_plan(inventory,declaration,yaml.safe_dump(value).encode(),evidence)
        stage_product_directory(result)
    assert not Path(declaration['product_directory']).exists()


def test_file_credentials_have_explicit_supported_schema_and_preserved_custody(inputs):
    inventory,declaration,config,evidence=inputs
    value=yaml.safe_load(config);value['scrape_configs'][0]['basic_auth']={'username':'reader','password_file':'/etc/prometheus/customer/token'}
    inventory['prometheus']['Mounts'].append({'Type':'bind','Source':'/private/token','Destination':'/etc/prometheus/customer/token','RW':False})
    evidence['reference_files']['/etc/prometheus/customer/token']=b'synthetic-private-token'
    result=build_plan(inventory,declaration,yaml.safe_dump(value).encode(),evidence)
    assert b'synthetic-private-token' not in result.prometheus_bytes
    assert next(m for m in result.requests['prometheus']['HostConfig']['Mounts'] if m['Target'].endswith('/token'))['ReadOnly'] is True


class SourceEngine:
    def __init__(self,entry=('/docker-entrypoint.sh',),cmd=(),env=(),working=''):
        self.source={'Image':'sha256:'+'a'*64,'Config':{'Entrypoint':list(entry),'Cmd':list(cmd),'Env':list(env),'WorkingDir':working}}
        self.defaults=copy.deepcopy(self.source['Config'])
    def inspect(self,name):return copy.deepcopy(self.source)
    def image(self,name):return {'Id':name,'Config':copy.deepcopy(self.defaults)}


def test_changed_declared_root_entrypoint_holds_before_recreate():
    adapter=InstalledEngine(engine=SourceEngine())
    assert adapter.prove_effective_source('source',[{'Path':'/docker-entrypoint.sh','Kind':0}],[]) is False


@pytest.mark.parametrize('field,value',[
    ('Entrypoint',['python3','/data/custom/controller.py']),('Env',['PYTHONPATH=/data/custom']),
    ('Env',['PATH=/data/bin:/usr/bin']),('Env',['BASH_ENV=/data/custom/startup.sh']),
    ('Cmd',['sh','-c','exec /data/custom/controller.py']),('WorkingDir','/data/custom')])
def test_runtime_executable_import_or_shell_override_is_named_hold(field,value):
    engine=SourceEngine(entry=(),cmd=('dc-overview','serve'),working='/app');engine.source['Config'][field]=value
    adapter=InstalledEngine(engine=engine)
    with pytest.raises(AdoptionError,match='unverified startup override'):
        adapter.prove_effective_source('source',[{'Path':'/data/custom/controller.py','Kind':1}],[])


def test_exact_image_proxy_startup_keeps_runtime_only_changes_eligible():
    engine=SourceEngine(entry=('/app/entrypoint.sh',));adapter=InstalledEngine(engine=engine)
    assert adapter.prove_effective_source('source',[{'Path':'/tmp/runtime','Kind':1}],[]) is True
    assert adapter.prove_effective_source('source',[{'Path':'/docker-entrypoint.d/custom.sh','Kind':1}],[]) is False


def test_staging_explicit_modes_survive_restrictive_umask(tmp_path,inputs,monkeypatch):
    # This fixture models ownership calls; Linux UID/GID acceptance stays held.
    from dc_overview import monitoring
    monkeypatch.setattr(os,'chown',lambda *a:None);monkeypatch.setattr(os,'fchown',lambda *a:None)
    monkeypatch.setattr(monitoring,'validate_product_monitoring_custody',lambda *a:None)
    import tempfile
    parent=Path(tempfile.mkdtemp(prefix='controller-public-umask-',dir='/private/tmp')).resolve(); parent.chmod(0o755)
    inputs[1]['product_directory']=str(parent/'monitoring')
    previous=os.umask(0o077)
    try: stage_product_directory(plan(inputs))
    finally: os.umask(previous)
    directory=Path(inputs[1]['product_directory'])
    assert stat.S_IMODE(directory.stat().st_mode)==0o755
    assert stat.S_IMODE((directory/'prometheus.yml').stat().st_mode)==0o644
    assert stat.S_IMODE((directory/'ownership.json').stat().st_mode)==0o644
    assert stat.S_IMODE((directory/'prometheus.yml.lock').stat().st_mode)==0o600


def test_oversized_cache_argument_holds_before_any_engine_create():
    class Engine:
        def create(self,*a):pytest.fail('oversized Linux argv attempted')
    adapter=InstalledEngine(engine=Engine())
    with pytest.raises(AdoptionError,match='cache proof payload'):
        adapter._prove_caches_in_image('sha256:'+'a'*64,[{'source':'/app/app.py','optimize':0,'cache':base64.b64encode(bytes(300*1024)).decode()}])


def test_supported_large_cache_payload_is_chunked_with_linux_argument_bounds():
    class Engine:
        def __init__(self): self.created=[]
        def create(self,name,request):self.created.append(request)
        def inspect(self,name):return {'State':{'Running':False,'ExitCode':0}}
        def start(self,*a):pass
        def stop(self,*a):pass
        def remove(self,*a):pass
        def _file_bytes(self,*a):return b'{"equivalent":true}'
    engine=Engine();adapter=InstalledEngine(engine=engine)
    assert adapter._prove_caches_in_image('sha256:'+'a'*64,[{'source':'/app/app.py','optimize':0,'cache':base64.b64encode(bytes(256*1024)).decode()}])
    arguments=engine.created[0]['Config']['Cmd']
    assert len(arguments)>2 and max(len(arg.encode()) for arg in arguments)<=48*1024
    assert sum(len(arg.encode())+1 for arg in engine.created[0]['Config']['Entrypoint']+arguments)<=512*1024
    assert engine.created[0]['HostConfig']['Ulimits']==[{'Name':'stack','Soft':8388608,'Hard':8388608}]


@pytest.mark.parametrize('method',['_prove_caches_in_image','_prove_cache_batch'])
@pytest.mark.parametrize('oversize',['directory-count','fixed-helper-overhead'])
def test_directory_only_helper_envelope_holds_before_any_engine_create(method,oversize):
    class Engine:
        def create(self,*a):pytest.fail('oversized helper envelope reached Engine create')
    adapter=InstalledEngine(engine=Engine())
    if oversize=='directory-count':
        directories=[{'path':'/app/'+str(i)+'/__pycache__','kind':1,'custody':{'uid':1000,'gid':1000,'mode':493}} for i in range(6000)]
    else:
        # Encoded metadata fits512KiB alone, but leaves too little room for the
        # real fixed interpreter/script/output arguments and terminating NULs.
        directories=[{'path':'/app/'+'a'*393000,'kind':1,'custody':{'uid':1000,'gid':1000,'mode':493}}]
        from dc_overview.controller_adoption import _encoded
        encoded=base64.b64encode(_encoded({'caches':[],'directories':directories}))
        assert 512*1024-2048<len(encoded)<=512*1024
    with pytest.raises(AdoptionError,match='cache proof payload argument bound'):
        getattr(adapter,method)('sha256:'+'a'*64,[],directories=directories)


def test_directory_only_and_every_cache_batch_share_total_helper_envelope():
    class Engine:
        def __init__(self):self.created=[]
        def create(self,name,request):self.created.append(request)
        def inspect(self,name):return {'State':{'Running':False,'ExitCode':0}}
        def start(self,*a):pass
        def stop(self,*a):pass
        def remove(self,*a):pass
        def _file_bytes(self,*a):return b'{"equivalent":true}'
    engine=Engine();adapter=InstalledEngine(engine=engine)
    directories=[{'path':'/app/__pycache__','kind':1,'custody':{'uid':1000,'gid':1000,'mode':493}}]
    assert adapter._prove_caches_in_image('sha256:'+'a'*64,[],directories=directories)
    row={'source':'/app/app.py','optimize':0,'cache':base64.b64encode(bytes(256*1024)).decode()}
    assert adapter._prove_caches_in_image('sha256:'+'a'*64,[row,row,row],directories=directories)
    assert len(engine.created)==4
    for request in engine.created:
        config=request['Config'];arguments=config['Entrypoint']+config['Cmd']
        assert max(len(arg.encode()) for arg in arguments)<=48*1024
        assert sum(len(arg.encode())+1 for arg in arguments)<=512*1024
        payload=json.loads(base64.b64decode(''.join(config['Cmd'][:-1])))
        assert payload['directories']==directories


@pytest.mark.parametrize('kind',['regular','symlink','hardlink','pax','wrong-name','short'])
def test_directory_metadata_rejects_unverified_archive_header(kind,monkeypatch):
    import sys,types,tarfile
    item=tarfile.TarInfo('dc_overview');item.type=tarfile.DIRTYPE;item.uid=1000;item.gid=1000;item.mode=0o755
    if kind=='regular':item.type=tarfile.REGTYPE
    if kind=='symlink':item.type=tarfile.SYMTYPE;item.linkname='/private'
    if kind=='hardlink':item.type=tarfile.LNKTYPE;item.linkname='/private'
    if kind=='pax':item.type=tarfile.XHDTYPE
    if kind=='wrong-name':item.name='other'
    data=item.tobuf() if kind!='short' else b'short'
    response=type('Response',(),{'status':200,'read':lambda self,size:data})()
    class Connection:
        def __init__(self,*a):pass
        def request(self,*a):pass
        def getresponse(self):return response
        def close(self):pass
    monkeypatch.setitem(sys.modules,'cryptolabs_proxy.migration',types.SimpleNamespace(_UnixHTTPConnection=Connection))
    adapter=InstalledEngine(engine=type('Engine',(),{'socket_path':'/owned/socket','timeout':15})())
    with pytest.raises(AdoptionError,match='directory'):adapter.directory_custody('source','/app/src/dc_overview')


def test_directory_metadata_reads_only_first512_bytes_and_preserves_custody(monkeypatch):
    import sys,types,tarfile
    item=tarfile.TarInfo('dc_overview');item.type=tarfile.DIRTYPE;item.uid=1000;item.gid=1000;item.mode=0o755
    reads=[];closed=[]
    class Response:
        status=200
        def read(self,size):reads.append(size);return item.tobuf()
    class Connection:
        def __init__(self,*a):pass
        def request(self,*a):pass
        def getresponse(self):return Response()
        def close(self):closed.append(True)
    monkeypatch.setitem(sys.modules,'cryptolabs_proxy.migration',types.SimpleNamespace(_UnixHTTPConnection=Connection))
    adapter=InstalledEngine(engine=type('Engine',(),{'socket_path':'/owned/socket','timeout':15})())
    assert adapter.directory_custody('source','/app/src/dc_overview')=={'uid':1000,'gid':1000,'mode':0o755}
    assert reads==[512] and closed==[True]


@pytest.mark.parametrize('field,value',[
    ('basic_auth',{'username':{'hidden_secret':'synthetic'},'password_file':'/etc/prometheus/customer/token'}),
    ('scrape_interval',{'hidden_secret':'synthetic'}),
    ('tls_config',{'server_name':{'hidden_secret':'synthetic'}})])
def test_supported_contexts_reject_nested_unknown_scalar_payloads(inputs,field,value):
    inventory,declaration,config,evidence=inputs
    mapping=yaml.safe_load(config);mapping['scrape_configs'][0][field]=value
    with pytest.raises(AdoptionError,match='unsupported'):
        build_plan(inventory,declaration,yaml.safe_dump(mapping).encode(),evidence)


@pytest.mark.parametrize('state',[{'Running':False},{'Running':True,'Paused':True}])
def test_stopped_or_paused_predecessor_holds_before_automatic_activation(inputs,state):
    inputs[0]['dc-overview']['State'].update(state)
    with pytest.raises(AdoptionError,match='stopped/paused'):plan(inputs)


def test_image_helper_validates_cache_ancestor_custody_and_rejects_changed_mode(tmp_path,monkeypatch):
    import py_compile,sys
    from dc_overview.controller_adoption import CACHE_PROOF_SCRIPT
    source=tmp_path/'module.py';source.write_text('raise RuntimeError("never execute inspected source")\n')
    cache=tmp_path/'cache.pyc';py_compile.compile(str(source),cfile=str(cache),dfile=str(source),doraise=True)
    metadata=tmp_path.stat(); output=tmp_path/'proof.json'
    payload={'caches':[{'source':str(source),'optimize':0,'cache':base64.b64encode(cache.read_bytes()).decode()}],
        'directories':[{'path':str(tmp_path),'kind':0,'custody':{'uid':metadata.st_uid,'gid':metadata.st_gid,'mode':stat.S_IMODE(metadata.st_mode)}}]}
    def invoke():
        encoded=base64.b64encode(json.dumps(payload).encode()).decode()
        monkeypatch.setattr(sys,'argv',['proof',encoded[:19],encoded[19:],str(output)])
        exec(compile(CACHE_PROOF_SCRIPT,'fixed-trusted-helper','exec'),{})
        return json.loads(output.read_bytes())['equivalent']
    assert invoke() is True
    payload['directories'][0]['custody']['mode']=0o777
    assert invoke() is False


def test_reference_archive_stream_is_bounded_and_tracks_file_custody(monkeypatch):
    import sys,types,tarfile,io
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w') as archive:
        entry=tarfile.TarInfo('token');entry.uid=65534;entry.gid=65534;entry.mode=0o600;entry.size=6
        archive.addfile(entry,io.BytesIO(b'opaque'))
    reads=[]
    class Response:
        status=200
        def read(self,size):reads.append(size);return buffer.getvalue()
    class Connection:
        def __init__(self,*a):pass
        def request(self,*a):pass
        def getresponse(self):return Response()
        def close(self):pass
    monkeypatch.setitem(sys.modules,'cryptolabs_proxy.migration',types.SimpleNamespace(_UnixHTTPConnection=Connection))
    adapter=InstalledEngine(engine=type('Engine',(),{'socket_path':'/owned/socket','timeout':15})())
    assert adapter.file_state('prometheus','/private/token')=={'bytes':b'opaque'.hex(),'uid':65534,'gid':65534,'mode':0o600}
    assert reads==[2*1024*1024+65536+1]


@pytest.mark.parametrize('drift',['reference_custody','config_custody'])
def test_terminal_file_custody_drift_is_hold(inputs,tmp_path,drift):
    runner,engine,journal=executor(tmp_path,inputs)
    assert runner.apply(plan(inputs),current=lambda:inputs,guard=engine.guard)['state']=='adopted'
    original=engine.monitoring_snapshot
    def changed(plan):
        result=original(plan)
        if drift=='reference_custody':result[drift][next(iter(result[drift]))]['mode']=0o644
        else:result[drift]={'uid':0,'gid':0,'mode':0o600}
        return result
    engine.monitoring_snapshot=changed
    with pytest.raises(AdoptionError,match='terminal'):runner.recover(guard=engine.guard)


def test_reference_parent_custody_is_frozen_without_copying_secret_bytes(monkeypatch):
    adapter=InstalledEngine(engine=object())
    adapter.file_state=lambda *a:pytest.fail('archive cannot establish running parent custody')
    observed=[]
    def running(name,path):
        observed.append((name,path))
        return {'bytes':b'opaque'.hex(),'uid':65534,'gid':65534,'mode':0o600,
                'parents':{p:{'uid':65534,'gid':65534,'mode':0o700} for p in ('/etc/prometheus/customer','/etc/prometheus','/etc')}}
    adapter.running_file_state=running
    adapter.directory_custody=lambda *a:pytest.fail('archive cannot establish running parent custody')
    result=adapter.reference_state('prometheus','/etc/prometheus/customer/token')
    assert observed==[('prometheus','/etc/prometheus/customer/token')]
    assert result['parents']['/etc/prometheus/customer']=={'uid':65534,'gid':65534,'mode':0o700}


def test_directory_timestamp_pax_header_is_bounded_without_dropping_custody(monkeypatch):
    import sys,types,tarfile,io
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w',format=tarfile.PAX_FORMAT) as archive:
        item=tarfile.TarInfo('dc_overview');item.type=tarfile.DIRTYPE;item.uid=1000;item.gid=1000;item.mode=0o755
        item.pax_headers={'mtime':'123.456'};archive.addfile(item)
    stream=io.BytesIO(output.getvalue());reads=[]
    class Response:
        status=200
        def read(self,size):reads.append(size);return stream.read(size)
    class Connection:
        def __init__(self,*a):pass
        def request(self,*a):pass
        def getresponse(self):return Response()
        def close(self):pass
    monkeypatch.setitem(sys.modules,'cryptolabs_proxy.migration',types.SimpleNamespace(_UnixHTTPConnection=Connection))
    adapter=InstalledEngine(engine=type('Engine',(),{'socket_path':'/owned/socket','timeout':15})())
    assert adapter.directory_custody('source','/app/src/dc_overview')=={'uid':1000,'gid':1000,'mode':0o755}
    assert sum(reads)<=5120


def test_serving_guard_capability_is_bound_to_inspected_container_id(monkeypatch):
    from dc_overview import fleet_upgrade
    source_id='1'*64; observed=[]
    class Engine(SourceEngine):
        def controller_guard(self,*a,**k):pass
        def inspect(self,name):
            result=super().inspect(name);result['Id']=source_id;result['Mounts']=[];return result
        def image(self,name):
            result=super().image(name);result['RepoDigests']=['ghcr.io/cryptolabsza/cryptolabs-proxy@sha256:'+'a'*64];return result
    adapter=InstalledEngine(engine=Engine(entry=('/app/entrypoint.sh',)));adapter.changes=lambda *a:[]
    def capabilities(**kwargs):
        observed.append(kwargs.get('container_id'))
        return {'controller_adoption_guard':{'schema_version':1,'api':'AdoptionEngine.controller_guard','durable_updater_exclusion':True}}
    monkeypatch.setattr(fleet_upgrade,'proxy_capabilities',capabilities)
    adapter.require_guard_capability()
    assert observed==[source_id]
