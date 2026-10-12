import ast
from pathlib import Path
from types import SimpleNamespace
import socket
import subprocess

import pytest

from dc_overview import cli, fleet_manager
from dc_overview.fleet_config import FleetConfig, Server

@pytest.fixture(autouse=True)
def no_escape(monkeypatch):
    def forbidden(*a,**k): raise AssertionError('external escape forbidden')
    monkeypatch.setattr(subprocess,'run',forbidden)
    monkeypatch.setattr(socket.socket,'connect',forbidden)


def test_remove_worker_uses_existing_verified_trust_before_subprocess(tmp_path,monkeypatch):
    import base64, struct
    key_type=b'ssh-ed25519'; blob=struct.pack('>I',len(key_type))+key_type+struct.pack('>I',32)+bytes(range(32))
    known=tmp_path/'known_hosts'; known.write_text('192.0.2.1 ssh-ed25519 '+base64.b64encode(blob).decode()+'\n')
    monkeypatch.setenv('DC_OVERVIEW_SSH_KNOWN_HOSTS',str(known)); calls=[]
    monkeypatch.setattr(subprocess,'run',lambda args,**kwargs:calls.append(args) or SimpleNamespace(returncode=0,stdout='REMOVED',stderr=''))
    cli._remove_exporter_from_worker('root@192.0.2.1','/absent-key',22)
    assert len(calls)==1
    assert 'StrictHostKeyChecking=yes' in calls[0]
    assert 'UserKnownHostsFile="'+str(known)+'"' in calls[0]
    assert 'StrictHostKeyChecking=no' not in calls[0]


def test_remove_worker_unknown_trust_never_runs_remote_mutation(tmp_path,monkeypatch):
    monkeypatch.setenv('DC_OVERVIEW_SSH_KNOWN_HOSTS',str(tmp_path/'absent'))
    cli._remove_exporter_from_worker('root@192.0.2.1','/absent-key',22)


def test_fleet_watchdog_adapter_forwards_manager_known_hosts(tmp_path,monkeypatch):
    from dc_overview import web_watchdog
    config=FleetConfig(config_dir=tmp_path); config.servers=[Server(name='fixture',server_ip='192.0.2.1')]
    config.components.dc_watchdog=True; config.watchdog.api_key='synthetic'; calls=[]
    manager=fleet_manager.FleetManager(config); manager.ssh.known_hosts_path=tmp_path/'verified-known-hosts'
    monkeypatch.setattr(web_watchdog,'install_watchdog_agent_remote',lambda host,*a,**k:calls.append(host) or (True,''))
    manager._deploy_watchdog_agents()
    assert calls[0].ssh_known_hosts_path==str(manager.ssh.known_hosts_path)


def test_selected_watchdog_adapter_forwards_known_hosts_without_settings_rewrite():
    # Narrow source boundary: this extension may only add one adapter field to
    # the independently exercised selected lifecycle function.
    source=Path(fleet_manager.__file__).with_name('worker_lifecycle.py').read_text()
    function=next(n for n in ast.walk(ast.parse(source)) if isinstance(n,ast.FunctionDef) and n.name=='upgrade_workers')
    hosts=[n for n in ast.walk(function) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='SimpleNamespace' and any(k.arg=='server_ip' for k in n.keywords)]
    assert len(hosts)==1
    field=next(k for k in hosts[0].keywords if k.arg=='ssh_known_hosts_path')
    assert ast.unparse(field.value)=='str(ssh.known_hosts_path)'
