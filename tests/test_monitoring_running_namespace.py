"""Real tar/exec parsers with distinct reopen-source and running-FD transports."""
import copy
import http.client
import io
import json
import os
import sys
import tarfile
import types
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
import yaml

from dc_overview import controller_adoption as adoption, fleet_manager, monitoring
from test_standard_monitoring_path import customer
from test_standard_monitoring_review_repairs import adopted
from test_controller_adoption import bind

ACTUAL_ARCHIVE = adoption.InstalledEngine.file_state
ACTUAL_RUNNING = adoption.InstalledEngine.running_file_state


def transport(monkeypatch, inventory, bound, reference, fault=None, *, od_wire=False):
    value=inventory['prometheus']; value['Id']='b'*64
    value['State'].update(Pid=4242,StartedAt='2026-10-12T00:00:00Z',Paused=False,Restarting=False)
    calls=[]
    def source(target):
        mounts=[m for m in inventory['prometheus']['Mounts'] if target==m['Destination'] or target.startswith(m['Destination']+'/')]
        m=max(mounts,key=lambda m:len(m['Destination']));p=Path(m['Source'])
        return p if target==m['Destination'] else p/Path(target).relative_to(m['Destination'])
    def output(target):
        if target==reference:
            bound.seek(0);payload=bound.read();stat=os.fstat(bound.fileno())
        else:
            p=source(target);payload=p.read_bytes();stat=p.stat()
        metadata=f'{stat.st_uid} {stat.st_gid} {stat.st_mode & 0o7777:o} {len(payload)} {stat.st_ino} {stat.st_dev}\n'.encode()
        parents=b''.join(b'0 0 755 10 20\n' for p in Path(target).parents if str(p)!='/')
        encoded = (b''.join(b' ' + chunk.hex(' ').encode() + b'\n' for chunk in
                   (payload[i:i+16] for i in range(0,len(payload),16)))
                   if od_wire else payload.hex().encode())
        data=metadata+parents+b'DATA\n'+encoded+b'\nEND\n'+metadata+parents
        if fault=='malformed':data=b'bad\n'
        if fault=='oversized':data=b'x'*(7*1024*1024)
        if fault=='wire-overflow':data=b'x'*(9*1024*1024)
        stream=2 if fault=='stderr' else 1
        result=b''.join(bytes([stream,0,0,0])+len(chunk).to_bytes(4,'big')+chunk
                        for chunk in (data[i:i+16384] for i in range(0,len(data),16384)))
        return result[:-1] if fault=='truncated' else result
    class Engine:
        socket_path='/synthetic/no-socket';timeout=1
        reads=0
        def inspect(self,name):
            assert name==value['Id'];self.reads+=1
            result=copy.deepcopy(value)
            if fault=='identity' and self.reads>1:result['State']['Pid']+=1
            if fault=='user' and self.reads>1:result['Config']['User']='different-user'
            if fault=='start' and self.reads>1:result['State']['StartedAt']='different-start'
            if fault=='paused':result['State']['Paused']=True
            if fault=='stopped':result['State']['Running']=False
            if fault=='restarting':result['State']['Restarting']=True
            if fault=='no-image':result['Image']=None
            return result
        def _request(self,method,path,payload=None):
            calls.append((method,path,payload))
            if method=='POST':
                assert path=='/containers/'+value['Id']+'/exec'
                assert payload['AttachStdin'] is False and payload['Privileged'] is False and payload['Tty'] is False
                assert 'User' not in payload and payload['WorkingDir']=='/'
                assert payload['Env']==['ENV=','BASH_ENV=','LD_PRELOAD=','LD_LIBRARY_PATH=']
                assert payload['Cmd'][:6]==['/bin/busybox','timeout','10','/bin/busybox','sh','-c']
                self.target=payload['Cmd'][-1]
                return json.dumps({'Id':'e'*64}).encode()
            return json.dumps({'ContainerID':'f'*64 if fault=='exec-container' else value['Id'],'Running':False,'ExitCode':127 if fault=='missing-busybox' else False if fault=='bool-exit' else 0}).encode()
    engine=Engine()
    migration=types.ModuleType('cryptolabs_proxy.migration')
    class Connection:
        def __init__(self,*a):pass
        def request(self,method,url,body=None,headers=None):self.url=url;calls.append((method,url,body))
        def getresponse(self):
            if '/archive?' in self.url:
                target=parse_qs(urlparse(self.url).query)['path'][0];p=source(target);data=p.read_bytes();stat=p.stat();b=io.BytesIO()
                with tarfile.open(fileobj=b,mode='w') as archive:
                    member=tarfile.TarInfo(Path(target).name);member.size=len(data);member.uid=stat.st_uid;member.gid=stat.st_gid;member.mode=stat.st_mode & 0o7777
                    archive.addfile(member,io.BytesIO(data))
                data=b.getvalue()
            else:
                assert self.url=='/exec/'+'e'*64+'/start';data=output(engine.target)
            if od_wire:
                class WireSocket:
                    def makefile(self,*args):
                        return io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\n'+data)
                response=http.client.HTTPResponse(WireSocket());response.begin();return response
            response=io.BytesIO(data);response.status=200;return response
        def close(self):pass
    migration._UnixHTTPConnection=Connection
    monkeypatch.setitem(sys.modules,'cryptolabs_proxy',types.ModuleType('cryptolabs_proxy'))
    monkeypatch.setitem(sys.modules,'cryptolabs_proxy.migration',migration)
    monkeypatch.setattr(adoption.InstalledEngine,'__init__',lambda self,engine=None:setattr(self,'engine',engine or transport_engine))
    transport_engine=engine
    monkeypatch.setattr(adoption.InstalledEngine,'file_state',ACTUAL_ARCHIVE)
    monkeypatch.setattr(adoption.InstalledEngine,'running_file_state',ACTUAL_RUNNING)
    return calls,engine


@pytest.mark.parametrize('kind',['customer','product'])
def test_real_reopened_archive_cannot_prove_retained_runtime_reference(customer,monkeypatch,tmp_path,kind):
    public,old,inventory=adopted(customer,monkeypatch,tmp_path)
    reference='/etc/prometheus/recording_rules.yml';rules=old/'recording_rules.yml'
    if kind=='customer':
        rules=tmp_path/'customer.yml';rules.write_bytes(b'groups: []\n');reference='/etc/prometheus/customer/custom.yml'
        inventory['prometheus']['Mounts'].append(bind(rules,reference))
        value=yaml.safe_load((public/'prometheus.yml').read_bytes());value['rule_files'].append(reference);(public/'prometheus.yml').write_text(yaml.safe_dump(value))
        owner=json.loads((public/'ownership.json').read_bytes());owner['file_references'].append(reference);(public/'ownership.json').write_text(json.dumps(owner))
    before=(public/'prometheus.yml').read_bytes()
    with rules.open('rb') as runtime:
        revised=b'groups:\n- name: replacement\n  rules: [{record: replacement, expr: vector(9)}]\n'
        monitoring.atomic_write_bytes(rules,revised)
        if kind=='product':monkeypatch.setattr(customer,'_generate_recording_rules',lambda:revised.decode())
        calls,engine=transport(monkeypatch,inventory,runtime,reference)
        reader=adoption.InstalledEngine();assert reader.file_state('prometheus',reference)['bytes']==revised.hex()
        monkeypatch.setattr(customer,'_validate_baseline_prometheus',lambda mapping:type(customer)._validate_baseline_prometheus(customer,mapping))
        monkeypatch.setattr(fleet_manager.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=0))
        class Response(io.BytesIO):status=200
        monkeypatch.setattr(fleet_manager.urllib.request,'urlopen',lambda *a,**k:Response(json.dumps({'status':'success','data':{'yaml':(public/'prometheus.yml').read_text()}}).encode()))
        with pytest.raises((ValueError,RuntimeError),match='reference|custody|inode'):
            customer._configure_prometheus_targets()
        assert (public/'prometheus.yml').read_bytes()==before


@pytest.mark.parametrize('fault',[None,'paused','stopped','restarting','identity','user','start','no-image','exec-container','bool-exit','missing-busybox','malformed','oversized','stderr','truncated'])
def test_running_namespace_reader_bounds_and_identity(customer,monkeypatch,tmp_path,fault):
    public,old,inventory=adopted(customer,monkeypatch,tmp_path);rules=old/'recording_rules.yml';reference='/etc/prometheus/recording_rules.yml'
    with rules.open('rb') as runtime:
        calls,engine=transport(monkeypatch,inventory,runtime,reference,fault)
        reader=adoption.InstalledEngine()
        if fault:
            with pytest.raises(adoption.AdoptionError):reader.running_file_state(inventory['prometheus']['Id'],reference)
        else:
            state=reader.running_file_state(inventory['prometheus']['Id'],reference)
            assert state['bytes']==rules.read_bytes().hex() and state['inode']==rules.stat().st_ino and state['device']==rules.stat().st_dev
            assert set(state['parents'])=={str(p) for p in Path(reference).parents if str(p)!='/'}
        assert not any('/archive?' in call[1] for call in calls)


@pytest.mark.parametrize('size,fault',[(2*1024*1024,None),(2*1024*1024+1,None),(2*1024*1024,'wire-overflow')])
def test_running_namespace_exact_file_and_wire_bounds(customer,monkeypatch,tmp_path,size,fault):
    public,old,inventory=adopted(customer,monkeypatch,tmp_path)
    rules=old/'recording_rules.yml';reference='/etc/prometheus/recording_rules.yml'
    payload=b'groups: []\n#'+b'x'*(size-13)+b'\n'
    assert len(payload)==size
    rules.write_bytes(payload)
    with rules.open('rb') as runtime:
        transport(monkeypatch,inventory,runtime,reference,fault,od_wire=True)
        reader=adoption.InstalledEngine()
        if fault or size>2*1024*1024:
            with pytest.raises(adoption.AdoptionError,match='output bound' if fault else None):
                reader.running_file_state(inventory['prometheus']['Id'],reference)
        else:
            state=reader.running_file_state(inventory['prometheus']['Id'],reference)
            assert bytes.fromhex(state['bytes'])==payload
            assert state['inode']==rules.stat().st_ino and state['device']==rules.stat().st_dev
