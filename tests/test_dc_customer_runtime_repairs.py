"""Ordinary customer runtime interface regressions; no live SSH or Docker."""
import base64
import copy
import json
import os
import subprocess
import io
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest
import yaml

from dc_overview import fleet_manager, monitoring, worker_lifecycle, web_watchdog
from dc_overview.fleet_config import AuthMethod, FleetConfig, Server
from dc_overview.fleet_manager import FleetManager
from test_selected_worker_lifecycle import target


@pytest.fixture
def synthetic_ssh_trust(tmp_path_factory, monkeypatch):
    """Pre-enrolled public host keys for declared fake transport tests only."""
    import paramiko
    key = paramiko.RSAKey.generate(1024)
    path = tmp_path_factory.mktemp('runtime-enrolled-trust')/'known_hosts'
    path.write_text(','.join(f'192.0.2.{n}' for n in range(55, 68)) + f' {key.get_name()} {key.get_base64()}\n')
    monkeypatch.setenv('DC_OVERVIEW_SSH_KNOWN_HOSTS', str(path))
    return path


def host(user='root'):
    return SimpleNamespace(name='synthetic-worker',server_ip='192.0.2.10',ssh_user=user,ssh_port=22,ssh_key=None,ssh_password='synthetic-password')


def worker_plan():
    selected = target()
    return SimpleNamespace(targets={'dc-exporter':selected},manifest=SimpleNamespace(data={'components':{'dc-exporter':{'owner':'dc-worker','release':'0.2.9','artifacts':{'linux/amd64':{k:v for k,v in selected.items() if k in ('kind','url','sha256')}}}}},sha256='b'*64),selection={'selection_id':'synthetic','components':{'dc-exporter':{'origin':'baseline','enabled':True}}},selection_sha256='c'*64)


def images():
    return SimpleNamespace(targets={name:{'kind':'oci','reference':repo+'@sha256:'+'a'*64,'owner':'proxy-updater','origin':'baseline'} for name,repo in {'cryptolabs-proxy':'ghcr.io/cryptolabsza/cryptolabs-proxy','dc-overview':'ghcr.io/cryptolabsza/dc-overview','prometheus':'prom/prometheus','grafana':'grafana/grafana'}.items()})


def test_RUNTIME01_fresh_password_preflight_uses_current_auth_without_key_provisioning(tmp_path, monkeypatch, synthetic_ssh_trust):
    monkeypatch.setattr('dc_overview.ssh_manager.shutil.which',lambda name:'/synthetic/sshpass')
    config = FleetConfig(config_dir=tmp_path)
    config.ssh.username = 'operator'
    config.ssh.auth_method = AuthMethod.PASSWORD
    config.ssh.password = 'synthetic-secret-not-in-argv'
    config.servers = [Server(name='new-worker', server_ip='192.0.2.55')]
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, 'Linux x86_64' if argv[-1] == 'uname -s -m' else 'WORKER_PREFLIGHT=verified\n', '')
    monkeypatch.setattr('dc_overview.ssh_manager.subprocess.run', run)
    assert worker_lifecycle.preflight_workers(config, worker_plan(), mode='install')
    assert not list(tmp_path.iterdir()), 'readonly proof must not provision keys'
    assert len(calls) == 2
    for argv, kwargs in calls:
        assert argv[:3] == ['sshpass', '-e', 'ssh']
        assert config.ssh.password not in json.dumps(argv)
        assert kwargs['env']['SSHPASS'] == config.ssh.password
        assert 'StrictHostKeyChecking=yes' in argv
        assert f'UserKnownHostsFile="{synthetic_ssh_trust}"' in argv
    assert 'sudo -n --' in calls[-1][0][-1]


def test_RUNTIME02_vendor_only_watchdog_unit_refuses_before_controller(tmp_path, monkeypatch):
    """Execute the component-derived readonly script with a loaded vendor unit."""
    config = FleetConfig(config_dir=tmp_path)
    config.servers = [Server(name='vendor-worker', server_ip='192.0.2.56')]
    selected = target('dc-watchdog-agent', version='2.0.8')
    plan = worker_plan()
    plan.targets = {'dc-watchdog-agent': selected}
    plan.manifest.data['components'] = {'dc-watchdog-agent': {'owner':'dc-worker', 'release':'2.0.8', 'artifacts':{'linux/amd64':{k:v for k,v in selected.items() if k in ('kind','url','sha256')}}}}
    plan.selection['components'] = {'dc-watchdog-agent': {'origin':'baseline','enabled':True}}
    fake = tmp_path/'bin'; fake.mkdir()
    binary = tmp_path/'installed'; binary.mkdir()
    (binary/'dc-watchdog-agent').write_text('old binary'); (binary/'dc-watchdog-agent').chmod(0o755)
    cfg = tmp_path/'agent.yaml'; cfg.write_text('customer config\n')
    run = tmp_path/'systemd'; run.mkdir()
    vendor = tmp_path/'vendor.service'; vendor.write_text('customer vendor unit\n')
    ctl = fake/'systemctl'; ctl.write_text('#!/bin/sh\ncase "$*" in\n*LoadState*) echo loaded;;\n*FragmentPath*) echo "$VENDOR";;\nis-active*) echo inactive; exit 3;;\nis-enabled*) echo disabled; exit 1;;\nesac\n'); ctl.chmod(0o755)
    original_run = subprocess.run
    def execute(command, **kwargs):
        if command == 'uname -s -m': return SimpleNamespace(success=True, output='Linux x86_64')
        script = base64.b64decode(command.split()[2].strip("'")).decode()
        script = script.replace('/usr/local/bin', str(binary)).replace('/run/systemd/system', str(run)).replace('/etc/dc-watchdog/agent.yaml', str(cfg)).replace('/etc/systemd/system/dc-watchdog-agent.service', str(tmp_path/'missing-local.service'))
        script = script.replace('[ "$(id -u)" = 0 ]', ':').replace('for tool in ', 'for tool in ')
        script = script.replace('command -v "$tool" >/dev/null', ':')
        result = original_run(['bash','-s'], input=script, capture_output=True, text=True, env={**os.environ,'PATH':str(fake)+':'+os.environ['PATH'],'VENDOR':str(vendor)})
        return SimpleNamespace(success=result.returncode == 0, output=result.stdout+result.stderr)
    ssh = Mock(); ssh.run_command.side_effect = execute
    monkeypatch.setattr(worker_lifecycle, 'SSHManager', lambda *a: ssh)
    from dc_overview import fleet_upgrade
    controller = Mock(return_value={'success':False,'results':{}}); monkeypatch.setattr(fleet_upgrade, 'run_fleet_upgrade', controller)
    with pytest.raises(ValueError, match='preflight|prerequisite'):
        fleet_upgrade.run_selected_upgrade(config, plan)
    controller.assert_not_called()
    assert vendor.read_text() == 'customer vendor unit\n' and cfg.read_text() == 'customer config\n'


def test_RUNTIME03_watchdog_preflight_proves_its_actual_component_runner(tmp_path, monkeypatch):
    ssh = Mock(); ssh.run_command.return_value = SimpleNamespace(success=True, output='WORKER_PREFLIGHT=verified\n')
    worker_lifecycle._preflight_worker_privilege(ssh, {'host':'192.0.2.57','username':'operator','port':22,'key_path':'synthetic-key','sudo':False}, ['dc-watchdog-agent'])
    command = ssh.run_command.call_args.kwargs['command']
    monkeypatch.setattr(web_watchdog,'build_ssh_cmd',lambda *a,**k:(['ssh'],{}))
    installed = Mock(return_value=subprocess.CompletedProcess([],0,'WATCHDOG_PREFLIGHT=verified\nINSTALL_SUCCESS\nAGENT_VERSION=1.0.7',''))
    monkeypatch.setattr(web_watchdog.subprocess,'run',installed)
    assert web_watchdog.install_watchdog_agent_remote(host('operator'),'',selected_artifact=target('dc-watchdog-agent',version='2.0.8'),mode='update')[0]
    actual = installed.call_args.args[0][-1]
    assert command.endswith('| ' + actual)
    assert 'sudo -n -- timeout --signal=TERM --kill-after=30s 120s bash -s' == actual


def test_RUNTIME04_new_monitoring_product_mount_has_dc_writer_custody(tmp_path, monkeypatch):
    tmp_path = Path(tempfile.mkdtemp(prefix='runtime-public-contract-', dir='/private/tmp'))
    monkeypatch.setattr('dc_overview.controller_adoption.probe_controller_inventory', lambda: {r: None for r in ('dc-overview','prometheus','grafana','cryptolabs-proxy')})
    config = FleetConfig(config_dir=tmp_path); config.components.ipmi_monitor = False
    manager = FleetManager(config); manager.release_plan = images()
    manager.monitoring_plan = {'prometheus':manager._product_prometheus_config(), 'grafana':{'prometheus_datasource_uid':'prometheus','existing_datasource':None}}
    monkeypatch.setattr(manager,'_validate_baseline_prometheus',lambda mapping:True)
    chown = Mock(); monkeypatch.setattr(os,'chown',chown); monkeypatch.setattr(os,'fchown',chown)
    monkeypatch.setattr(os,'geteuid',lambda:0)
    class Produced(Exception): pass
    monkeypatch.setattr(fleet_manager,'_ensure_docker_network',Mock(side_effect=Produced))
    with pytest.raises(Produced): manager._deploy_prometheus_grafana()
    directory = tmp_path.with_name(tmp_path.name + '-monitoring')
    assert call(directory,1000,1000) in chown.call_args_list
    assert (directory.stat().st_mode & 0o777) == 0o755
    assert len([c for c in chown.call_args_list if c.args[1:] == (1000,1000)]) >= 3
    assert ((directory/'prometheus.yml').stat().st_mode & 0o777) == 0o644
    assert ((directory/'recording_rules.yml').stat().st_mode & 0o777) == 0o644


def test_RUNTIME05_host_reload_accepts_only_schema_duration_equivalence(tmp_path, monkeypatch):
    import io
    manager = FleetManager(FleetConfig(config_dir=tmp_path))
    expected = {'global':{'evaluation_interval':'300s','scrape_interval':'60000ms','external_labels':{'scrape_interval':'300s'}},'scrape_configs':[{'job_name':'300s','scrape_interval':'300s','metrics_path':'/300s','static_configs':[{'targets':['300s:9100'],'labels':{'scrape_interval':'300s'}}]}]}
    loaded = copy.deepcopy(expected)
    loaded['global'].update(evaluation_interval='5m',scrape_interval='1m')
    loaded['scrape_configs'][0]['scrape_interval'] = '5m'
    class Response(io.BytesIO): status=200
    monkeypatch.setattr(fleet_manager.urllib.request,'urlopen',lambda *a,**k:Response(json.dumps({'status':'success','data':{'yaml':yaml.safe_dump(loaded)}}).encode()))
    assert manager._reload_baseline_prometheus(expected)
    for scope, key in [(loaded['global'],'evaluation_interval'),(loaded['global']['external_labels'],'scrape_interval'),(loaded['scrape_configs'][0],'job_name'),(loaded['scrape_configs'][0],'metrics_path'),(loaded['scrape_configs'][0]['static_configs'][0]['labels'],'scrape_interval')]:
        original = scope[key]; scope[key] = '5m1s' if key == 'evaluation_interval' else '5m'
        assert not manager._reload_baseline_prometheus(expected)
        scope[key] = original
    loaded['scrape_configs'][0]['static_configs'][0]['targets'] = []
    assert not manager._reload_baseline_prometheus(expected)


@pytest.mark.parametrize('mode,auth', [('install',AuthMethod.KEY), ('update',AuthMethod.PASSWORD)])
def test_RUNTIME01_existing_key_transport_is_preserved(tmp_path, monkeypatch, mode, auth, synthetic_ssh_trust):
    config = FleetConfig(config_dir=tmp_path); config.ssh.auth_method = auth
    config.ssh.password = 'synthetic-unused-password'
    key = tmp_path/'fleet_key'; key.write_text('synthetic key'); key.chmod(0o600)
    config.servers = [Server(name='key-worker',server_ip='192.0.2.58')]
    calls = []
    def run(argv, **kwargs):
        calls.append((argv,kwargs))
        return subprocess.CompletedProcess(argv,0,'Linux x86_64' if argv[-1] == 'uname -s -m' else 'WORKER_PREFLIGHT=verified\n','')
    monkeypatch.setattr('dc_overview.ssh_manager.subprocess.run',run)
    assert worker_lifecycle.preflight_workers(config,worker_plan(),mode=mode)
    for argv, kwargs in calls:
        assert argv[0] == 'ssh'
        assert argv[argv.index('-i') + 1] == str(key)
        assert argv[argv.index('-F') + 1] == '/dev/null'
        options = {argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == '-o'}
        assert {
            'IdentitiesOnly=yes', 'IdentityAgent=none', 'IdentityFile=none',
            'BatchMode=yes', 'CertificateFile=none', 'PKCS11Provider=none',
            'SecurityKeyProvider=none', 'PreferredAuthentications=publickey',
            'AddKeysToAgent=no',
        } <= options
        assert kwargs['env'] is None
    assert key.stat().st_mode & 0o777 == 0o600


def test_RUNTIME01_password_does_not_bypass_denied_privilege_or_leak_exception(tmp_path,monkeypatch, synthetic_ssh_trust):
    monkeypatch.setattr('dc_overview.ssh_manager.shutil.which',lambda name:'/synthetic/sshpass')
    from dc_overview.ssh_manager import SSHManager
    config = FleetConfig(config_dir=tmp_path); config.ssh.username = 'operator'; config.ssh.password = 'synthetic-password'
    config.servers = [Server(name='denied-worker',server_ip='192.0.2.59')]
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv,0 if argv[-1]=='uname -s -m' else 1,'Linux x86_64' if argv[-1]=='uname -s -m' else 'sudo denied','')
    monkeypatch.setattr('dc_overview.ssh_manager.subprocess.run',run)
    with pytest.raises(ValueError,match='privilege|prerequisite'):
        worker_lifecycle.preflight_workers(config,worker_plan(),mode='install')
    assert not list(tmp_path.iterdir())
    monkeypatch.setattr('dc_overview.ssh_manager.subprocess.run',Mock(side_effect=OSError('synthetic-password')))
    result = SSHManager(tmp_path).run_command('192.0.2.59','uname -s -m',password=config.ssh.password)
    assert not result.success and config.ssh.password not in result.output


def test_RUNTIME03_permission_for_exporter_runner_cannot_authorize_watchdog_runner():
    ssh = Mock()
    ssh.run_command.side_effect = lambda command,**k:SimpleNamespace(success='60s 240s' in command,output='WORKER_PREFLIGHT=verified\n' if '60s 240s' in command else 'denied')
    options = {'host':'192.0.2.60','username':'operator','port':22,'key_path':'synthetic-key','sudo':False}
    with pytest.raises(ValueError,match='preflight'):
        worker_lifecycle._preflight_worker_privilege(ssh, options, ['dc-exporter','dc-watchdog-agent'])
    assert ssh.run_command.call_count == 2


@pytest.mark.parametrize('problem', ['owner','directory-mode','config-owner','config-gid','config-mode','lock-owner','symlink'])
def test_RUNTIME04_existing_incompatible_custody_refuses_before_writes(tmp_path,monkeypatch,problem):
    from test_controller_adoption import bind, container
    tmp_path = Path(tempfile.mkdtemp(prefix='runtime-public-custody-', dir='/private/tmp'))
    directory = tmp_path.with_name(tmp_path.name + '-monitoring'); directory.mkdir()
    inventory = {r: container(r) for r in ('dc-overview','prometheus','grafana','cryptolabs-proxy')}
    inventory['dc-overview']['Config']['Env'] = ['PROMETHEUS_CONFIG_PATH=/var/lib/dc-monitoring/prometheus.yml','PROMETHEUS_OWNERSHIP_PATH=/var/lib/dc-monitoring/ownership.json']
    inventory['dc-overview']['Mounts'] = [bind(directory, '/var/lib/dc-monitoring', True)]
    inventory['prometheus']['Mounts'] = [bind(directory, '/etc/prometheus')]
    monkeypatch.setattr('dc_overview.controller_adoption.probe_controller_inventory', lambda: inventory)
    config_file = directory/'prometheus.yml'; config_file.write_bytes(b'# customer config\nscrape_configs: []\n')
    rules = directory/'recording_rules.yml'; rules.write_bytes(b'# existing rules\n')
    unknown = directory/'customer.txt'; unknown.write_bytes(b'customer bytes\n')
    lock = directory/'prometheus.yml.lock'; lock.write_bytes(b'')
    compose = tmp_path/'docker-compose.yml'; compose.write_bytes(b'customer compose\n')
    if problem == 'symlink': config_file.unlink(); config_file.symlink_to(unknown)
    original_stat = Path.stat
    def metadata(path, *args, **kwargs):
        original = original_stat(path,*args,**kwargs)
        if path not in (directory,config_file,rules,lock): return original
        uid = 0 if (problem == 'owner' and path == directory) or (problem == 'config-owner' and path == config_file) or (problem == 'lock-owner' and path == lock) else 1000
        mode = (original.st_mode & ~0o777) | (0o755 if path == directory else 0o644)
        if problem == 'directory-mode' and path == directory: mode = (mode & ~0o777) | 0o555
        if problem == 'config-mode' and path == config_file: mode = (mode & ~0o777) | 0o600
        gid = 4242 if problem == 'config-gid' and path == config_file else 1000
        return SimpleNamespace(st_uid=uid,st_gid=gid,st_mode=mode)
    monkeypatch.setattr(Path,'stat',metadata)
    chown = Mock(); monkeypatch.setattr(os,'chown',chown)
    manager = FleetManager(FleetConfig(config_dir=tmp_path)); manager.release_plan = images()
    before = {path:path.read_bytes() for path in (compose,config_file,rules,unknown)}
    with pytest.raises(ValueError,match='custody|symlink|ownership|directory'):
        manager._prepare_baseline_monitoring()
    with pytest.raises(ValueError,match='custody|symlink|ownership|directory'):
        manager._deploy_prometheus_grafana()
    assert all(path.read_bytes() == value for path,value in before.items())
    chown.assert_not_called()


def test_RUNTIME04_new_host_lock_inherits_config_custody_without_changing_existing_file(tmp_path,monkeypatch):
    path = tmp_path/'prometheus.yml'; path.write_bytes(b'customer configuration\n'); path.chmod(0o640)
    original_stat = Path.stat
    def metadata(item,*a,**k):
        value = original_stat(item,*a,**k)
        return SimpleNamespace(st_uid=1000,st_gid=4242,st_mode=value.st_mode) if item == path else value
    monkeypatch.setattr(Path,'stat',metadata)
    change = Mock(); monkeypatch.setattr(os,'fchown',change)
    with monitoring._file_lock(path): pass
    assert change.call_args.args[1:] == (1000,4242)
    change.reset_mock()
    with monitoring._file_lock(path): pass
    change.assert_not_called()
    assert path.read_bytes() == b'customer configuration\n'
    assert path.stat().st_mode & 0o777 == 0o640


@pytest.mark.parametrize('declared,loaded', [('1h30m','90m'),('1y','365d'),('1w','7d'),('1s500ms','1500ms'),('0','0s'),(0,'0s')])
def test_RUNTIME05_supported_duration_grammar_at_declared_schema_paths(declared,loaded):
    expected = {'global':{'scrape_interval':declared},'scrape_configs':[{'scrape_timeout':declared,'http_sd_configs':[{'refresh_interval':declared,'url':'https://example.invalid/300s'}]}]}
    observed = copy.deepcopy(expected)
    observed['global']['scrape_interval'] = loaded
    observed['scrape_configs'][0]['scrape_timeout'] = loaded
    observed['scrape_configs'][0]['http_sd_configs'][0]['refresh_interval'] = loaded
    assert monitoring.declared_configuration_matches(expected,observed)
    observed['scrape_configs'][0]['http_sd_configs'][0]['url'] = 'https://example.invalid/5m'
    assert not monitoring.declared_configuration_matches(expected,observed)


@pytest.mark.parametrize('unsupported', ['1.5m','1m1h','1s1s','-1m','+1m','','0.0','1us','30000000000000000y'])
def test_RUNTIME05_unsupported_duration_strings_cannot_claim_equivalence(unsupported):
    assert not monitoring.declared_configuration_matches({'global':{'evaluation_interval':unsupported}}, {'global':{'evaluation_interval':'90s'}})


def test_RUNTIME01_fresh_controller_without_sshpass_uses_shipped_password_transport(tmp_path,monkeypatch, synthetic_ssh_trust):
    import paramiko
    config = FleetConfig(config_dir=tmp_path); config.ssh.username = 'operator'; config.ssh.password = 'synthetic-password'
    config.servers = [Server(name='fresh-worker',server_ip='192.0.2.61')]
    class Output(io.BytesIO):
        channel = SimpleNamespace(exit_status_ready=lambda:True,recv_exit_status=lambda:0)
    client = Mock()
    client.exec_command.side_effect = lambda command,**kwargs:(None,Output(('Linux x86_64' if command=='uname -s -m' else 'WORKER_PREFLIGHT=verified\n').encode()),Output(b''))
    monkeypatch.setattr(paramiko,'SSHClient',Mock(return_value=client))
    monkeypatch.setattr('dc_overview.ssh_manager.shutil.which',lambda name:None)
    monkeypatch.setattr('dc_overview.ssh_manager.subprocess.run',Mock(side_effect=FileNotFoundError('sshpass missing')))
    assert worker_lifecycle.preflight_workers(config,worker_plan(),mode='install')
    assert client.connect.call_count == 2 and client.close.call_count == 2
    for invocation in client.connect.call_args_list:
        assert invocation.kwargs['password'] == config.ssh.password
        assert invocation.kwargs['look_for_keys'] is False and invocation.kwargs['allow_agent'] is False
    assert isinstance(client.set_missing_host_key_policy.call_args.args[0],paramiko.RejectPolicy)
    assert not list(tmp_path.iterdir())


def test_RUNTIME04_compatible_existing_custody_is_readonly(tmp_path,monkeypatch):
    directory = tmp_path/'prometheus'; directory.mkdir()
    config = directory/'prometheus.yml'; config.write_bytes(b'# customer configuration\n')
    unknown = directory/'customer-extra.txt'; unknown.write_bytes(b'customer bytes\n'); unknown.chmod(0o600)
    original_stat = Path.stat
    def metadata(path,*args,**kwargs):
        prior = original_stat(path,*args,**kwargs)
        return SimpleNamespace(st_uid=1000,st_gid=1000,st_mode=prior.st_mode) if path in (directory,config) else prior
    directory.chmod(0o755); config.chmod(0o644)
    monkeypatch.setattr(Path,'stat',metadata)
    change = Mock(); monkeypatch.setattr(os,'chown',change); monkeypatch.setattr(Path,'chmod',change)
    monitoring.validate_product_monitoring_custody(directory)
    change.assert_not_called()
    assert config.read_bytes() == b'# customer configuration\n' and unknown.read_bytes() == b'customer bytes\n'
    assert unknown.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('user',['operator','root'])
@pytest.mark.parametrize('probe_change',[None,'digest','service','health','health-prefix','health-embedded','health-suffix'])
def test_FINAL01_whole_watchdog_update_keeps_exact_component_runner(tmp_path,monkeypatch,user,probe_change):
    import hashlib
    config = FleetConfig(config_dir=tmp_path); config.ssh.username=user
    config.servers = [Server(name='exact-worker',server_ip='192.0.2.62')]
    key = tmp_path/'fleet_key'; key.write_text('synthetic key')
    binary_dir = tmp_path/'installed'; binary_dir.mkdir()
    binary = binary_dir/'dc-watchdog-agent'; binary.write_text('old binary'); binary.chmod(0o755)
    cfgdir = tmp_path/'config'; cfgdir.mkdir()
    cfg = cfgdir/'agent.yaml'; cfg.write_bytes(b'health_port: 19878\nheartbeat_interval: 73s\n')
    units = tmp_path/'units'; units.mkdir(); unit=units/'dc-watchdog-agent.service'; unit.write_bytes(b'customer unit\n')
    systemd=tmp_path/'systemd'; systemd.mkdir()
    fake=tmp_path/'bin'; fake.mkdir()
    candidate=tmp_path/'candidate'; candidate.write_text('#!/bin/sh\necho dc-watchdog-agent 1.0.7\n'); candidate.chmod(0o755)
    digest=hashlib.sha256(candidate.read_bytes()).hexdigest()
    selected=target('dc-watchdog-agent',version='2.0.8',digest=digest)
    plan=worker_plan(); plan.targets={'dc-watchdog-agent':selected}
    plan.manifest.data['components']={'dc-watchdog-agent':{'owner':'dc-worker','release':'2.0.8','artifacts':{'linux/amd64':{k:v for k,v in selected.items() if k in ('kind','url','sha256')}}}}
    plan.selection['components']={'dc-watchdog-agent':{'origin':'baseline','enabled':True}}
    active=tmp_path/'active'; active.write_text('active\n'); calls=tmp_path/'calls'
    programs={'timeout':'shift 3\nexec "$@"','uname':'echo x86_64','sleep':'exit 0','curl':'''if [ "$1" = -fsSL ]; then cp "$CANDIDATE" "$4"
elif echo "$*" | /usr/bin/grep -q /health; then echo '{"status":"ok","version":"1.0.7"}'
else echo 'dc_watchdog_agent_up{version="1.0.7",worker="synthetic"} 1'; fi''','systemctl':'''echo "$*" >> "$CALLS"
case "$*" in
"show --property=SystemState --value") echo running;;
*LoadState*) echo loaded;;
"is-active dc-watchdog-agent") cat "$ACTIVE"; [ "$(cat "$ACTIVE")" = active ] || exit 3;;
"is-active --quiet dc-watchdog-agent") [ "$(cat "$ACTIVE")" = active ];;
"is-enabled dc-watchdog-agent") echo enabled;;
"start dc-watchdog-agent") echo active > "$ACTIVE";;
"stop dc-watchdog-agent") echo inactive > "$ACTIVE";;
esac'''}
    for name,body in programs.items():
        path=fake/name; path.write_text('#!/bin/sh\n'+body+'\n'); path.chmod(0o755)
    original_run=subprocess.run
    expected_runner=web_watchdog.watchdog_remote_runner(sudo=user!='root')
    commands=[]
    def execute(script):
        script=script.replace('/usr/local/bin',str(binary_dir)).replace('/etc/dc-watchdog',str(cfgdir)).replace('/etc/systemd/system',str(units)).replace('/run/systemd/system',str(systemd)).replace('/opt/dc-watchdog',str(tmp_path/'unused-fallback'))
        script=script.replace('[ "$(id -u)" = 0 ]',':').replace('command -v "$tool" >/dev/null',':')
        return original_run(['bash','-s'],input=script,capture_output=True,text=True,env={**os.environ,'PATH':str(fake)+':'+os.environ['PATH'],'CANDIDATE':str(candidate),'ACTIVE':str(active),'CALLS':str(calls)})
    def remote(command,**kwargs):
        if command=='uname -s -m': return SimpleNamespace(success=True,output='Linux x86_64')
        commands.append(command)
        if not command.endswith('| '+expected_runner):return SimpleNamespace(success=False,output='exact sudo policy denied')
        script=base64.b64decode(command.split()[2].strip("'")).decode()
        result=execute(script)
        output=result.stdout+result.stderr
        if 'WORKER_ARTIFACT=' in script:
            if probe_change=='digest':output=output.replace(digest,'0'*64)
            elif probe_change=='service':output=output.replace('WORKER_SERVICE=active','WORKER_SERVICE=unknown')
            elif probe_change=='health':output=output.replace('WORKER_HEALTH=verified','')
            elif probe_change=='health-prefix':output=output.replace('WORKER_HEALTH=verified','PREFIX_WORKER_HEALTH=verified')
            elif probe_change=='health-embedded':output=output.replace('WORKER_HEALTH=verified','note WORKER_HEALTH=verified in a message')
            elif probe_change=='health-suffix':output=output.replace('WORKER_HEALTH=verified','WORKER_HEALTH=verified-but-failed')
        return SimpleNamespace(success=result.returncode==0,output=output)
    ssh=Mock(); ssh.key_path=key; ssh.run_command.side_effect=remote
    monkeypatch.setattr(worker_lifecycle,'SSHManager',lambda *a:ssh)
    monkeypatch.setattr(web_watchdog,'build_ssh_cmd',lambda *a,**k:(['ssh'],{}))
    def installer(argv,**kwargs):
        assert argv==['ssh',expected_runner]
        if 'echo WATCHDOG_PREFLIGHT=verified' in kwargs['input']:
            return execute(kwargs['input'])
        assert 'INSTALL_SUCCESS' in kwargs['input'] and selected['url'] in kwargs['input']
        return execute(kwargs['input'])
    monkeypatch.setattr(web_watchdog.subprocess,'run',installer)
    result=worker_lifecycle.upgrade_workers(config,plan)['dc-watchdog-agent']
    observed=result['workers']['exact-worker']
    if probe_change is None:
        assert result['success'],result
        assert observed['observed_binary_sha256']==digest and observed['service_state']=='active'
        assert observed['observed_agent_version']=='1.0.7'
    else:
        assert not result['success'] and observed['state']=='failed'
    assert hashlib.sha256(binary.read_bytes()).hexdigest()==digest
    assert cfg.read_bytes()==b'health_port: 19878\nheartbeat_interval: 73s\n' and unit.read_bytes()==b'customer unit\n'
    assert len(commands)==2 and all(command.endswith('| '+expected_runner) for command in commands)


@pytest.mark.parametrize('transport',['key','sshpass','paramiko'])
def test_FINAL02_successful_warning_output_is_clean_for_actual_preflight(tmp_path,monkeypatch,transport, synthetic_ssh_trust):
    from dc_overview.ssh_manager import SSHManager
    config=FleetConfig(config_dir=tmp_path); config.ssh.auth_method=AuthMethod.KEY if transport=='key' else AuthMethod.PASSWORD
    config.ssh.password=None if transport=='key' else 'synthetic-password'
    config.servers=[Server(name='warn-worker',server_ip='192.0.2.63')]
    if transport=='key':(tmp_path/'fleet_key').write_text('synthetic key')
    warning="Warning: synthetic operational SSH diagnostic.\n"
    def run(argv,**kwargs):return subprocess.CompletedProcess(argv,0,'Linux x86_64\n' if argv[-1]=='uname -s -m' else 'WORKER_PREFLIGHT=verified\n',warning)
    monkeypatch.setattr('dc_overview.ssh_manager.shutil.which',lambda name:None if transport=='paramiko' else '/synthetic/sshpass')
    monkeypatch.setattr('dc_overview.ssh_manager.subprocess.run',run)
    if transport=='paramiko':
        import paramiko
        class Output(io.BytesIO):channel=SimpleNamespace(exit_status_ready=lambda:True,recv_exit_status=lambda:0)
        client=Mock(); client.exec_command.side_effect=lambda command,**k:(None,Output(('Linux x86_64\n' if command=='uname -s -m' else 'WORKER_PREFLIGHT=verified\n').encode()),Output(warning.encode()))
        monkeypatch.setattr(paramiko,'SSHClient',Mock(return_value=client))
    assert worker_lifecycle.preflight_workers(config,worker_plan(),mode='update' if transport=='key' else 'install')
    result=SSHManager(tmp_path).run_command('192.0.2.63','uname -s -m',password=config.ssh.password)
    assert result.output=='Linux x86_64\n' and result.stderr==warning


@pytest.mark.parametrize('transport',['key','sshpass','paramiko'])
def test_FINAL02_failed_transport_retains_stdout_and_stderr_diagnostics(tmp_path,monkeypatch,transport, synthetic_ssh_trust):
    from dc_overview.ssh_manager import SSHManager,SSHResult
    password=None if transport=='key' else 'synthetic-password'
    (tmp_path/'fleet_key').write_text('synthetic key')
    monkeypatch.setattr('dc_overview.ssh_manager.shutil.which',lambda name:None if transport=='paramiko' else '/synthetic/sshpass')
    monkeypatch.setattr('dc_overview.ssh_manager.subprocess.run',lambda argv,**k:subprocess.CompletedProcess(argv,23,'partial stdout\n','permission diagnostic\n'))
    if transport=='paramiko':
        import paramiko
        class Output(io.BytesIO):channel=SimpleNamespace(exit_status_ready=lambda:True,recv_exit_status=lambda:23)
        client=Mock(); client.exec_command.return_value=(None,Output(b'partial stdout\n'),Output(b'permission diagnostic\n'))
        monkeypatch.setattr(paramiko,'SSHClient',Mock(return_value=client))
    result=SSHManager(tmp_path).run_command('192.0.2.64','uname -s -m',password=password)
    assert not result.success and result.exit_code==23
    assert result.output=='partial stdout\npermission diagnostic\n' and result.stderr=='permission diagnostic\n'
    assert SSHResult(False,'legacy positional diagnostic',7).stderr==''


@pytest.mark.parametrize('stdout,stderr',[('Linux x86_64\nforged stdout\n',''),('','Linux x86_64\n'),('Darwin arm64\n','Linux x86_64\n')])
def test_FINAL02_platform_parser_still_requires_exact_supported_stdout(tmp_path,monkeypatch,stdout,stderr, synthetic_ssh_trust):
    config=FleetConfig(config_dir=tmp_path);config.ssh.auth_method=AuthMethod.KEY
    config.servers=[Server(name='unproved-worker',server_ip='192.0.2.65')]
    (tmp_path/'fleet_key').write_text('synthetic key')
    run=Mock(return_value=subprocess.CompletedProcess([],0,stdout,stderr))
    monkeypatch.setattr('dc_overview.ssh_manager.subprocess.run',run)
    with pytest.raises(ValueError,match='platform'):
        worker_lifecycle.preflight_workers(config,worker_plan())
    assert run.call_count==1


def test_FINAL02_proof_on_stderr_cannot_authorize_worker_mutation(tmp_path,monkeypatch, synthetic_ssh_trust):
    config=FleetConfig(config_dir=tmp_path);config.ssh.auth_method=AuthMethod.KEY
    config.servers=[Server(name='unproved-worker',server_ip='192.0.2.66')]
    (tmp_path/'fleet_key').write_text('synthetic key')
    monkeypatch.setattr('dc_overview.ssh_manager.subprocess.run',lambda argv,**k:subprocess.CompletedProcess(argv,0,'Linux x86_64\n' if argv[-1]=='uname -s -m' else '', 'WORKER_PREFLIGHT=verified\n'))
    with pytest.raises(ValueError,match='privilege|prerequisite'):
        worker_lifecycle.preflight_workers(config,worker_plan())


@pytest.mark.parametrize('phase',['connect','execute'])
def test_FINAL02_paramiko_exception_keeps_secret_sanitized_and_closes_transport(tmp_path,monkeypatch,phase, synthetic_ssh_trust):
    import paramiko
    from dc_overview.ssh_manager import SSHManager
    client=Mock()
    if phase=='connect':client.connect.side_effect=OSError('synthetic-secret')
    else:client.exec_command.side_effect=OSError('synthetic-secret')
    monkeypatch.setattr(paramiko,'SSHClient',Mock(return_value=client))
    monkeypatch.setattr('dc_overview.ssh_manager.shutil.which',lambda name:None)
    result=SSHManager(tmp_path).run_command('192.0.2.67','uname -s -m',password='synthetic-secret')
    assert not result.success and result.output=='SSH transport failed' and result.stderr==''
    client.close.assert_called_once()


@pytest.mark.parametrize('name',['dc-exporter','node-exporter'])
@pytest.mark.parametrize('sudo',[False,True])
def test_FINAL01_other_component_probe_keeps_existing_exporter_runner(name,sudo):
    command=worker_lifecycle._probe_command(name,sudo=sudo)
    expected=('sudo -n -- ' if sudo else '')+'timeout --signal=TERM --kill-after=60s 240s bash -s'
    assert command.endswith('| '+expected)
