"""Selected worker delivery uses synthetic exact artifacts and the shipped safety script."""
import hashlib
import importlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import subprocess

import pytest


def worker_module():
    return importlib.import_module('dc_overview.worker_lifecycle')


def target(name='dc-exporter', version='0.2.9', digest='a'*64):
    owner={'dc-exporter':'cryptolabsza/dc-exporter-releases','node-exporter':'prometheus/node_exporter','dc-watchdog-agent':'cryptolabsza/dc-watchdog'}[name]
    filename={'dc-exporter':'dc-exporter-rs','node-exporter':f'node_exporter-{version}.linux-amd64.tar.gz','dc-watchdog-agent':'dc-watchdog-agent-linux-amd64'}[name]
    return {'kind':'binary','release':version,'owner':'dc-worker','platform':'linux/amd64','origin':'baseline',
            'url':f'https://github.com/{owner}/releases/download/v{version}/{filename}','sha256':digest}


def test_selected_dc_script_preserves_checksum_version_metrics_and_recovery(tmp_path):
    from test_safe_dc_exporter_delivery import _fake_delivery_environment
    from dc_overview.exporters import build_dc_exporter_install_script
    env, log, active, enabled=_fake_delivery_environment(tmp_path,candidate_version='0.2.9',metrics_version='0.2.9')
    digest=hashlib.sha256(Path(env['FAKE_RELEASE_BINARY']).read_bytes()).hexdigest()
    binary=tmp_path/'installed';unit=tmp_path/'unit'
    env['FAKE_SERVICE_PATH']=str(unit)
    script=build_dc_exporter_install_script(mode='install',selected_artifact=target(digest=digest),binary_path=str(binary),service_path=str(unit),backup_dir=str(tmp_path/'backup'),temp_parent=str(tmp_path),lock_path=str(tmp_path/'lock'),proc_root=str(tmp_path/'proc'),verification_attempts=1)
    result=subprocess.run(['bash','-s'],input=script,capture_output=True,text=True,env=env)
    assert result.returncode == 0, result.stderr
    assert 'DC_EXPORTER_INSTALL_SUCCESS' in result.stdout
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == digest
    assert 'VERSION=0.2.9' in script
    assert 'dc_exporter_build_info' in script


def test_selected_dc_checksum_failure_keeps_previous_binary(tmp_path):
    from test_safe_dc_exporter_delivery import _fake_delivery_environment
    from dc_overview.exporters import build_dc_exporter_install_script
    env, log, active, enabled=_fake_delivery_environment(tmp_path,candidate_version='0.2.9',metrics_version='0.2.9')
    binary=tmp_path/'installed';binary.write_text('old binary')
    env['FAKE_SERVICE_PATH']=str(tmp_path/'unit')
    script=build_dc_exporter_install_script(mode='install',selected_artifact=target(digest='0'*64),binary_path=str(binary),service_path=str(tmp_path/'unit'),backup_dir=str(tmp_path/'backup'),temp_parent=str(tmp_path),lock_path=str(tmp_path/'lock'),proc_root=str(tmp_path/'proc'),verification_attempts=1)
    result=subprocess.run(['bash','-s'],input=script,capture_output=True,text=True,env=env)
    assert result.returncode != 0
    assert binary.read_text() == 'old binary'
    assert not log.exists(), 'checksum validation comes before service mutation'


def test_selected_artifact_cannot_introduce_arbitrary_url_or_unknown_platform():
    from dc_overview.exporters import build_dc_exporter_install_script
    candidate=target();candidate['url']='https://evil.invalid/binary'
    with pytest.raises(ValueError):build_dc_exporter_install_script(selected_artifact=candidate)
    candidate=target();candidate['platform']='solar/quantum'
    with pytest.raises(ValueError):build_dc_exporter_install_script(selected_artifact=candidate)


def test_unreachable_worker_is_failed_without_install_or_observation_loss(tmp_path, monkeypatch):
    from dc_overview.fleet_config import FleetConfig,Server
    mod=worker_module()
    config=FleetConfig(config_dir=tmp_path);config.servers=[Server(name='synthetic-worker',server_ip='192.0.2.10',exporters_installed=True)]
    ssh=Mock();ssh.run_command.return_value=SimpleNamespace(success=False,output='synthetic-private-error')
    monkeypatch.setattr(mod,'SSHManager',lambda *a:ssh)
    prepared=SimpleNamespace(targets={'dc-exporter':target()},manifest=SimpleNamespace(data={'components':{'dc-exporter':{'release':'0.2.9','owner':'dc-worker','artifacts':{'linux/amd64':{k:v for k,v in target().items() if k in ('kind','url','sha256')}}}}}),selection={'components':{'dc-exporter':{'enabled':True,'origin':'baseline'}}})
    result=mod.upgrade_workers(config,prepared)
    assert result['dc-exporter']['success'] is False
    assert result['dc-exporter']['workers']['synthetic-worker']['state'] == 'unknown'
    assert config.servers[0].exporters_installed is True
    assert ssh.run_command.call_count == 1
    assert 'synthetic-private-error' not in json.dumps(result)


def test_worker_digest_drift_is_not_success_even_when_script_reports_success(tmp_path, monkeypatch):
    from dc_overview.fleet_config import FleetConfig,Server
    mod=worker_module()
    config=FleetConfig(config_dir=tmp_path);config.servers=[Server(name='synthetic-worker',server_ip='192.0.2.10')]
    ssh=Mock();ssh.run_command.side_effect=[SimpleNamespace(success=True,output='Linux x86_64'),SimpleNamespace(success=True,output='DC_EXPORTER_INSTALL_SUCCESS'),SimpleNamespace(success=True,output='b'*64+' active')]
    monkeypatch.setattr(mod,'SSHManager',lambda *a:ssh)
    artifact={k:v for k,v in target().items() if k in ('kind','url','sha256')}
    prepared=SimpleNamespace(targets={'dc-exporter':target()},manifest=SimpleNamespace(data={'components':{'dc-exporter':{'release':'0.2.9','owner':'dc-worker','artifacts':{'linux/amd64':artifact}}}}),selection={'components':{'dc-exporter':{'enabled':True,'origin':'baseline'}}})
    result=mod.upgrade_workers(config,prepared)
    assert result['dc-exporter']['success'] is False
    assert result['dc-exporter']['workers']['synthetic-worker']['state'] == 'failed'
    assert config.servers[0].exporters_installed is False


def test_selected_watchdog_validates_artifact_before_registration_and_never_discovers_latest(monkeypatch):
    import requests
    from dc_overview import web_watchdog
    from test_operational_customer_contract import host
    post=Mock(return_value=SimpleNamespace(ok=True,json=lambda:{'success':True,'worker_token':'synthetic-worker-token'}))
    monkeypatch.setattr(requests,'post',post)
    latest=Mock(side_effect=AssertionError('selected delivery must not discover latest'))
    monkeypatch.setattr(web_watchdog,'get_watchdog_latest_release',latest)
    monkeypatch.setattr(web_watchdog,'build_ssh_cmd',lambda *a,**k:(['ssh'],{}))
    run=Mock(return_value=subprocess.CompletedProcess([],0,'INSTALL_SUCCESS\nAGENT_VERSION=1.0.7',''))
    monkeypatch.setattr(web_watchdog.subprocess,'run',run)
    selected=target('dc-watchdog-agent',version='2.0.8')
    server=host()
    success,error=web_watchdog.install_watchdog_agent_remote(server,'synthetic-account-key',selected_artifact=selected,watchdog_url='https://watchdog.example.invalid')
    assert success and error is None
    latest.assert_not_called()
    script=run.call_args.kwargs['input']
    assert selected['url'] in script
    assert selected['sha256'] in script
    assert '/releases/latest/' not in script
    assert script.index('sha256sum') < script.index('changed=1')
    assert server.watchdog_agent_version == '1.0.7', 'release tag and telemetry version are separate'
    assert post.call_args.args[0] == 'https://watchdog.example.invalid/api/worker/register'
    post.reset_mock()
    selected['url']='https://evil.invalid/agent'
    assert web_watchdog.install_watchdog_agent_remote(server,'synthetic-account-key',selected_artifact=selected)[0] is False
    post.assert_not_called()


def test_selected_node_archive_is_checksum_verified_before_replacement():
    from dc_overview.exporters import build_node_exporter_install_script
    selected=target('node-exporter',version='1.10.3')
    script=build_node_exporter_install_script(selected_artifact=selected)
    assert selected['url'] in script
    assert selected['sha256'] in script
    assert script.index('sha256sum') < script.index('changed=1')
    assert 'node_exporter-1.10.3' in script


def test_selected_watchdog_checksum_failure_never_stops_existing_agent(tmp_path,monkeypatch):
    import os
    import requests
    from dc_overview import web_watchdog
    from test_operational_customer_contract import host
    fake_bin=tmp_path/'bin';fake_bin.mkdir()
    log=tmp_path/'calls'
    candidate=tmp_path/'candidate';candidate.write_text('#!/bin/sh\necho dc-watchdog-agent 1.0.7\n');candidate.chmod(0o755)
    programs={'curl':'cp "$CANDIDATE" "$4"', 'systemctl':'echo "$*" >> "$CALLS"\ncase "$*" in\n"is-active dc-watchdog-agent") echo active;;\n"is-enabled dc-watchdog-agent") echo enabled;;\nesac','apt-get':'exit 0','yum':'exit 0','dnf':'exit 0'}
    for name,body in programs.items():
        file=fake_bin/name;file.write_text('#!/bin/sh\n'+body+'\n');file.chmod(0o755)
    monkeypatch.setattr(requests,'post',lambda *a,**k:SimpleNamespace(ok=True,json=lambda:{'success':True,'worker_token':'synthetic-token'}))
    monkeypatch.setattr(web_watchdog,'build_ssh_cmd',lambda *a,**k:(['ssh'],{}))
    original_run=subprocess.run
    binary_dir=tmp_path/'installed';binary_dir.mkdir();binary=binary_dir/'dc-watchdog-agent';binary.write_text('old agent')
    config=tmp_path/'config';config.mkdir();units=tmp_path/'units';units.mkdir()
    def remote(cmd,**kwargs):
        script=kwargs['input'].replace('/usr/local/bin',str(binary_dir)).replace('/etc/dc-watchdog',str(config)).replace('/etc/systemd/system',str(units))
        return original_run(['bash','-s'],input=script,capture_output=True,text=True,env={**os.environ,'PATH':str(fake_bin)+':'+os.environ['PATH'],'CANDIDATE':str(candidate),'CALLS':str(log)})
    monkeypatch.setattr(web_watchdog.subprocess,'run',remote)
    success,error=web_watchdog.install_watchdog_agent_remote(host(),'synthetic-account',selected_artifact=target('dc-watchdog-agent',version='2.0.8',digest='0'*64))
    assert success is False
    assert binary.read_text() == 'old agent'
    assert 'stop dc-watchdog-agent' not in log.read_text()
    assert 'synthetic-token' not in error


def test_worker_preflight_blocks_unsupported_arch_before_installer(tmp_path,monkeypatch):
    from dc_overview.fleet_config import FleetConfig,Server
    mod=worker_module();config=FleetConfig(config_dir=tmp_path)
    config.servers=[Server(name='synthetic-worker',server_ip='192.0.2.10')]
    ssh=Mock();ssh.run_command.return_value=SimpleNamespace(success=True,output='Linux aarch64')
    monkeypatch.setattr(mod,'SSHManager',lambda *a:ssh)
    artifact={k:v for k,v in target().items() if k in ('kind','url','sha256')}
    plan=SimpleNamespace(targets={'dc-exporter':target()},manifest=SimpleNamespace(data={'components':{'dc-exporter':{'release':'0.2.9','owner':'dc-worker','artifacts':{'linux/amd64':artifact}}}}),selection={'components':{'dc-exporter':{'origin':'baseline','enabled':True}}})
    with pytest.raises(ValueError,match='platform'):
        mod.preflight_workers(config,plan)
    assert ssh.run_command.call_count == 1
    assert ssh.run_command.call_args.kwargs['command'] == 'uname -s -m'


def test_selected_node_archive_proves_installed_binary_and_preserves_stopped_update(tmp_path):
    import os,tarfile
    from dc_overview.exporters import build_node_exporter_install_script
    unpacked=tmp_path/'release'/'node_exporter-1.10.3.linux-amd64';unpacked.mkdir(parents=True)
    candidate=unpacked/'node_exporter';candidate.write_text('#!/bin/sh\necho node_exporter version 1.10.3\n');candidate.chmod(0o755)
    archive=tmp_path/'release.tar.gz'
    with tarfile.open(archive,'w:gz') as stream:stream.add(unpacked,arcname=unpacked.name)
    archive_sha=hashlib.sha256(archive.read_bytes()).hexdigest();binary_sha=hashlib.sha256(candidate.read_bytes()).hexdigest()
    assert archive_sha != binary_sha
    fake_bin=tmp_path/'bin';fake_bin.mkdir();calls=tmp_path/'calls'
    for name,body in {'uname':'echo x86_64','curl':'cp "$ARCHIVE" "$4"','useradd':'exit 0','systemctl':'echo "$*" >> "$CALLS"\ncase "$*" in\n"is-active node_exporter") echo inactive;exit 3;;\n"is-enabled node_exporter") echo disabled;exit 1;;\n*) exit 0;;\nesac'}.items():
        file=fake_bin/name;file.write_text('#!/bin/sh\n'+body+'\n');file.chmod(0o755)
    installed=tmp_path/'installed';installed.write_text('old binary');unit=tmp_path/'unit';unit.write_text('old unit')
    script=build_node_exporter_install_script(selected_artifact=target('node-exporter',version='1.10.3',digest=archive_sha),mode='update',binary_path=str(installed),service_path=str(unit),temp_parent=str(tmp_path))
    result=subprocess.run(['bash','-s'],input=script,capture_output=True,text=True,env={**os.environ,'PATH':str(fake_bin)+':'+os.environ['PATH'],'ARCHIVE':str(archive),'CALLS':str(calls)})
    assert result.returncode == 0,result.stderr
    assert 'NODE_EXPORTER_CANDIDATE_SHA256='+binary_sha in result.stdout
    assert 'NODE_EXPORTER_ARTIFACT_SHA256='+archive_sha in result.stdout
    assert hashlib.sha256(installed.read_bytes()).hexdigest() == binary_sha
    assert 'start node_exporter' not in calls.read_text()
    assert 'enable node_exporter' not in calls.read_text()


def test_node_worker_verifies_extracted_binary_hash_separately_from_archive(tmp_path,monkeypatch):
    from dc_overview.fleet_config import FleetConfig,Server
    mod=worker_module();config=FleetConfig(config_dir=tmp_path);config.servers=[Server(name='synthetic-worker',server_ip='192.0.2.10')]
    selected=target('node-exporter',version='1.10.3');binary_digest='b'*64
    ssh=Mock();ssh.run_command.side_effect=[SimpleNamespace(success=True,output='Linux x86_64'),SimpleNamespace(success=True,output='WORKER_PREFLIGHT=verified'),SimpleNamespace(success=True,output='NODE_EXPORTER_INSTALL_SUCCESS\nNODE_EXPORTER_ARTIFACT_SHA256='+selected['sha256']+'\nNODE_EXPORTER_CANDIDATE_SHA256='+binary_digest),SimpleNamespace(success=True,output='WORKER_ARTIFACT='+binary_digest+'\nWORKER_SERVICE=inactive\n')]
    monkeypatch.setattr(mod,'SSHManager',lambda *a:ssh)
    artifact={k:v for k,v in selected.items() if k in ('kind','url','sha256')}
    plan=SimpleNamespace(targets={'node-exporter':selected},manifest=SimpleNamespace(data={'components':{'node-exporter':{'release':'1.10.3','owner':'dc-worker','artifacts':{'linux/amd64':artifact}}}}),selection={'components':{'node-exporter':{'origin':'baseline','enabled':True}}})
    result=mod.upgrade_workers(config,plan)
    worker=result['node-exporter']['workers']['synthetic-worker']
    assert worker['success'] is True
    assert worker['observed_binary_sha256'] == binary_digest
    assert worker['observed'] == selected['sha256']
