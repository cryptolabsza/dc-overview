"""Regression proofs for independently reproduced ordinary customer blockers."""
import hashlib
import json
import os
import subprocess
import threading
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml

from dc_overview.fleet_config import FleetConfig, Server
from dc_overview.fleet_manager import FleetManager
from dc_overview import fleet_upgrade, monitoring, worker_lifecycle, web_watchdog, web_exporters
from dc_overview.release_catalog import ReleaseStore
from test_selected_worker_lifecycle import target
from test_operational_customer_contract import host


@pytest.fixture
def empty_controller_inventory(monkeypatch):
    """These render-only controls declare a fresh host with all roles absent."""
    from dc_overview import controller_adoption
    monkeypatch.setattr(controller_adoption, 'probe_controller_inventory',
                        lambda: {role: None for role in controller_adoption.ROLES})
    # Model a newly allocated traversable parent without changing private pytest
    # ancestors or customer config custody. Native UID acceptance is separate.
    with tempfile.TemporaryDirectory(prefix='dc-lifecycle-render-', dir='/private/tmp') as scratch:
        parent = Path(scratch); parent.chmod(0o755)
        private = parent / 'dc-overview'; private.mkdir(mode=0o700)
        yield private


def images():
    return SimpleNamespace(targets={name:{'kind':'oci','reference':repo+'@sha256:'+'a'*64,'owner':'proxy-updater','origin':'baseline'} for name,repo in {'cryptolabs-proxy':'ghcr.io/cryptolabsza/cryptolabs-proxy','dc-overview':'ghcr.io/cryptolabsza/dc-overview','prometheus':'prom/prometheus','grafana':'grafana/grafana'}.items()})


@pytest.mark.parametrize('existing', [False, True])
def test_ADV01_selected_real_compose_shapes_render(tmp_path, existing, empty_controller_inventory):
    config=FleetConfig(config_dir=empty_controller_inventory);config.ssl.use_existing_proxy=existing
    manager=FleetManager(config);manager.release_plan=images()
    services=yaml.safe_load(manager._generate_docker_compose())['services']
    assert {'prometheus','grafana'} <= services.keys()
    for name,service in services.items():
        assert service['image'] == manager.release_plan.targets[name]['reference']
    product = empty_controller_inventory.with_name(empty_controller_inventory.name + '-monitoring')
    assert str(product)+':/etc/prometheus:ro' in services['prometheus']['volumes']
    assert './prometheus:/etc/prometheus:ro' not in services['prometheus']['volumes']
    if existing:
        assert str(product)+':/var/lib/dc-monitoring' in services['dc-overview']['volumes']
        environment = services['dc-overview']['environment']
        assert 'PROMETHEUS_CONFIG_PATH=/var/lib/dc-monitoring/prometheus.yml' in environment
        assert 'PROMETHEUS_OWNERSHIP_PATH=/var/lib/dc-monitoring/ownership.json' in environment


def test_ADV02_host_reload_accepts_defaults_but_rejects_declared_drift(tmp_path, monkeypatch):
    import io
    manager=FleetManager(FleetConfig(config_dir=tmp_path))
    expected={'global':{'scrape_interval':'15s'},'scrape_configs':[]}
    loaded={'global':{'scrape_interval':'15s','scrape_timeout':'10s','evaluation_interval':'1m'},'scrape_configs':[]}
    class Response(io.BytesIO): status=200
    def response(*a,**k):return Response(json.dumps({'status':'success','data':{'yaml':yaml.safe_dump(loaded)}}).encode())
    monkeypatch.setattr('dc_overview.fleet_manager.urllib.request.urlopen',response)
    assert manager._reload_baseline_prometheus(expected)
    loaded['global']['scrape_interval']='30s'
    assert not manager._reload_baseline_prometheus(expected)


@pytest.mark.parametrize('accepted', [False,True])
def test_ADV03_reload_concurrent_customer_edit_is_retained_and_held(tmp_path, accepted):
    path=tmp_path/'prometheus.yml';path.write_bytes(b'scrape_configs: []\n')
    customer=b'scrape_configs: []\n# concurrent customer edit\n'
    calls=[]
    def reload():
        calls.append(1);path.write_bytes(customer);return accepted
    with pytest.raises(RuntimeError,match='conflict|changed.*reload'):
        monitoring.apply_prometheus_config(path,{'global':{'scrape_interval':'30s'},'scrape_configs':[]},validate_candidate=lambda p:True,reload_config=reload)
    assert path.read_bytes()==customer
    assert len(calls)==1


def test_ADV04_watchdog_update_retains_held_customer_state(tmp_path,monkeypatch):
    import requests
    fake=tmp_path/'bin';fake.mkdir();calls=tmp_path/'calls'
    installed=tmp_path/'installed';installed.mkdir();config=tmp_path/'config';config.mkdir();units=tmp_path/'units';units.mkdir()
    old=b'heartbeat_interval: 73s\nhealth_port: 9878\nlog_level: debug\n';(config/'agent.yaml').write_bytes(old)
    unit=units/'dc-watchdog-agent.service';unit.write_bytes(b'customer unit\n');(installed/'dc-watchdog-agent').write_text('old binary')
    candidate=tmp_path/'candidate';candidate.write_text('#!/bin/sh\necho dc-watchdog-agent 1.0.7\n');candidate.chmod(0o755)
    for name,body in {'uname':'echo x86_64','curl':'cp "$CANDIDATE" "$4"','sleep':'exit 0','apt-get':'exit 0','systemctl':'echo "$*" >> "$CALLS"\ncase "$*" in\n"is-active dc-watchdog-agent") echo inactive;exit 3;;\n"is-enabled dc-watchdog-agent") echo disabled;exit 1;;\n*) exit 0;;\nesac'}.items():
        p=fake/name;p.write_text('#!/bin/sh\n'+body+'\n');p.chmod(0o755)
    post=Mock(side_effect=AssertionError('update must retain existing worker custody'))
    monkeypatch.setattr(requests,'post',post)
    monkeypatch.setattr(web_watchdog,'build_ssh_cmd',lambda *a,**k:(['ssh'],{}))
    original_run=subprocess.run
    def run(cmd,**kwargs):
        if 'echo WATCHDOG_PREFLIGHT=verified' in kwargs['input']:
            return subprocess.CompletedProcess(cmd, 0, 'WATCHDOG_PREFLIGHT=verified\n', '')
        script=kwargs['input'].replace('/usr/local/bin',str(installed)).replace('/etc/dc-watchdog',str(config)).replace('/etc/systemd/system',str(units))
        return original_run(['bash','-s'],input=script,capture_output=True,text=True,env={**os.environ,'PATH':str(fake)+':'+os.environ['PATH'],'CANDIDATE':str(candidate),'CALLS':str(calls)})
    monkeypatch.setattr(web_watchdog.subprocess,'run',run)
    selected=target('dc-watchdog-agent',version='2.0.8',digest=hashlib.sha256(candidate.read_bytes()).hexdigest())
    assert web_watchdog.install_watchdog_agent_remote(host(),'synthetic-account',selected_artifact=selected,mode='update')[0]
    assert (config/'agent.yaml').read_bytes()==old and unit.read_bytes()==b'customer unit\n'
    assert 'enable dc-watchdog-agent' not in calls.read_text()
    assert 'restart dc-watchdog-agent' not in calls.read_text()
    assert 'start dc-watchdog-agent' not in calls.read_text()
    post.assert_not_called()


def prepare_store(tmp_path,monkeypatch):
    from dc_overview import release_catalog
    for name in ('_require_root','_check_root_path'):
        monkeypatch.setattr(release_catalog,name,lambda *a,**k:None)
    monkeypatch.setattr(release_catalog.os,'chown',lambda *a:None)
    monkeypatch.setattr(release_catalog.os,'fchown',lambda *a:None)
    public=tmp_path/'fleet-config.yaml';public.write_text('site_name: synthetic\n')
    store=ReleaseStore(tmp_path/'releases')
    def make(label,digest):
        value={'schema_version':1,'selection_contract':1,'baseline_id':label,'components':{'dc-overview':{'release':'1','owner':'proxy-updater','artifacts':{'linux/amd64':{'kind':'oci','reference':'ghcr.io/cryptolabsza/dc-overview@sha256:'+digest*64}}}}}
        p=tmp_path/(label+'.json');p.write_text(json.dumps(value));return store.prepare(p,platform='linux/amd64')
    return public,store,make


def test_ADV05_selection_publication_is_one_cas_transaction(tmp_path,monkeypatch):
    public,store,make=prepare_store(tmp_path,monkeypatch)
    a,b=FleetConfig(config_dir=tmp_path),FleetConfig(config_dir=tmp_path)
    a._lifecycle_public_snapshot=b._lifecycle_public_snapshot=public.read_bytes()
    errors=[];barrier=threading.Barrier(2)
    def run(config,plan):
        barrier.wait()
        try:fleet_upgrade.commit_release(config,plan)
        except RuntimeError as e:errors.append(str(e))
    threads=[threading.Thread(target=run,args=(c,make(label,label.lower()))) for c,label in [(a,'A'),(b,'B')]]
    for t in threads:t.start()
    for t in threads:t.join(5)
    assert not any(t.is_alive() for t in threads)
    selected=yaml.safe_load(public.read_bytes())['release_selection']
    assert hashlib.sha256((store.root/'selection.json').read_bytes()).hexdigest()==selected['selection_sha256']
    assert len(errors)==1


def test_ADV05_failed_publication_recovers_prior_selection(tmp_path,monkeypatch):
    public,store,make=prepare_store(tmp_path,monkeypatch)
    config=FleetConfig(config_dir=tmp_path);config._lifecycle_public_snapshot=public.read_bytes()
    first=make('A','a');fleet_upgrade.commit_release(config,first);before=(store.root/'selection.json').read_bytes();old=public.read_bytes()
    monkeypatch.setattr(config,'persist_lifecycle',Mock(side_effect=RuntimeError('synthetic crash before public write')))
    with pytest.raises(RuntimeError):fleet_upgrade.commit_release(config,make('B','b'))
    assert (store.root/'selection.json').read_bytes()==before
    assert public.read_bytes()==old


def worker_plan():
    selected=target();artifact={k:v for k,v in selected.items() if k in ('kind','url','sha256')}
    return SimpleNamespace(targets={'dc-exporter':selected,'cryptolabs-proxy':{'owner':'proxy-updater'}},manifest=SimpleNamespace(data={'components':{'dc-exporter':{'owner':'dc-worker','release':'0.2.9','artifacts':{'linux/amd64':artifact}}}},sha256='b'*64),selection={'selection_id':'synthetic','components':{'dc-exporter':{'origin':'baseline','enabled':True}}},selection_sha256='c'*64)


def test_ADV06_denied_exact_privilege_preflight_blocks_controller(tmp_path,monkeypatch):
    config=FleetConfig(config_dir=tmp_path);config.ssh.username='operator';config.servers=[Server(name='operator-only',server_ip='192.0.2.11')]
    ssh=Mock();ssh.run_command.side_effect=lambda command,**k:SimpleNamespace(success=command=='uname -s -m',output='Linux x86_64' if command=='uname -s -m' else 'permission denied')
    monkeypatch.setattr(worker_lifecycle,'SSHManager',lambda *a:ssh)
    proxy=Mock();monkeypatch.setattr(fleet_upgrade,'run_fleet_upgrade',proxy)
    with pytest.raises(ValueError,match='privilege|prerequisite'):
        worker_lifecycle.preflight_workers(config,worker_plan())
    proxy.assert_not_called()
    assert 'sudo -n --' in ssh.run_command.call_args.kwargs['command']
    with pytest.raises(ValueError):fleet_upgrade.run_selected_upgrade(config,worker_plan())
    proxy.assert_not_called()


@pytest.mark.parametrize('entry', ['install','update','watchdog','auto'])
def test_ADV07_app_mutation_entries_refuse_selected_latest_authority(tmp_path,monkeypatch,entry):
    (tmp_path/'fleet-config.yaml').write_text('release_selection:\n  selection_id: suite\n  selection_sha256: '+ 'a'*64+'\n')
    monkeypatch.setenv('DC_OVERVIEW_CONFIG_DIR',str(tmp_path))
    forbidden=Mock(side_effect=AssertionError('no remote/latest/registration calls under selected policy'))
    monkeypatch.setattr(web_exporters,'_run_dc_exporter_remote',forbidden)
    monkeypatch.setattr(web_watchdog,'get_watchdog_latest_release',forbidden)
    monkeypatch.setattr(web_watchdog,'build_ssh_cmd',forbidden)
    if entry=='install':outcome=web_exporters.install_exporter_remote(host(),'node_exporter',return_error=True)
    elif entry=='update':outcome=web_exporters.update_exporter_remote(host(),'node_exporter','1.10.3')
    elif entry=='watchdog':outcome=web_watchdog.install_watchdog_agent_remote(host(),'account')
    else:
        from dc_overview import app as module
        monkeypatch.setattr('dc_overview.exporters.check_for_updates',forbidden)
        result=module.check_and_apply_auto_updates(host())
        assert result and result[0]['status']=='blocked'
        outcome=(False,result[0]['error'])
    assert outcome[0] is False and 'dc-overview upgrade' in outcome[1]
    forbidden.assert_not_called()

@pytest.mark.parametrize('state,enabled,metric_version,success', [('inactive','masked','1.0.7',True),('inactive','masked-runtime','1.0.7',True),('active','enabled','1.0.7',True),('active','disabled','1.0.8',False)])
def test_ADV04_watchdog_update_health_and_failure_preserve_exact_state(tmp_path,monkeypatch,state,enabled,metric_version,success):
    fake=tmp_path/'bin';fake.mkdir();calls=tmp_path/'calls';active=tmp_path/'active';active.write_text(state)
    installed=tmp_path/'installed';installed.mkdir();config=tmp_path/'config';config.mkdir();units=tmp_path/'units';units.mkdir()
    old_config=b'heartbeat_interval: 73s\nhealth_port: 19878\nlog_level: debug\n';(config/'agent.yaml').write_bytes(old_config)
    unit=units/'dc-watchdog-agent.service'
    if enabled.startswith('masked'):unit.symlink_to('/dev/null')
    else:unit.write_bytes(b'customer unit\n')
    binary=installed/'dc-watchdog-agent';binary.write_bytes(b'old binary');binary.chmod(0o755)
    candidate=tmp_path/'candidate';candidate.write_text('#!/bin/sh\necho dc-watchdog-agent 1.0.7\n');candidate.chmod(0o755)
    programs={'uname':'echo x86_64','sleep':'exit 0','curl':'''echo "$*" >> "$CALLS"
if [ "$1" = -fsSL ]; then cp "$CANDIDATE" "$4"
elif echo "$*" | /usr/bin/grep -q /health; then echo '{"status":"ok","version":"1.0.7"}'
else printf 'dc_watchdog_agent_up{version="%s",worker="synthetic"} 1\n' "$METRIC_VERSION"; fi''','systemctl':'''echo "$*" >> "$CALLS"
case "$*" in
"is-active dc-watchdog-agent") cat "$ACTIVE"; [ "$(cat "$ACTIVE")" = active ] || exit 3;;
"is-active --quiet dc-watchdog-agent") [ "$(cat "$ACTIVE")" = active ];;
"is-enabled dc-watchdog-agent") echo "$ENABLED"; [ "$ENABLED" = enabled ] || exit 1;;
"start dc-watchdog-agent") echo active > "$ACTIVE";;
"stop dc-watchdog-agent") echo inactive > "$ACTIVE";;
*) exit 0;;
esac'''}
    for name,body in programs.items():
        p=fake/name;p.write_text('#!/bin/sh\n'+body+'\n');p.chmod(0o755)
    monkeypatch.setattr(web_watchdog,'build_ssh_cmd',lambda *a,**k:(['ssh'],{}));original_run=subprocess.run
    def run(cmd,**kwargs):
        if 'echo WATCHDOG_PREFLIGHT=verified' in kwargs['input']:
            return subprocess.CompletedProcess(cmd, 0, 'WATCHDOG_PREFLIGHT=verified\n', '')
        script=kwargs['input'].replace('/usr/local/bin',str(installed)).replace('/etc/dc-watchdog',str(config)).replace('/etc/systemd/system',str(units))
        return original_run(['bash','-s'],input=script,capture_output=True,text=True,env={**os.environ,'PATH':str(fake)+':'+os.environ['PATH'],'CANDIDATE':str(candidate),'CALLS':str(calls),'ACTIVE':str(active),'ENABLED':enabled,'METRIC_VERSION':metric_version})
    monkeypatch.setattr(web_watchdog.subprocess,'run',run)
    selected=target('dc-watchdog-agent',version='2.0.8',digest=hashlib.sha256(candidate.read_bytes()).hexdigest())
    assert web_watchdog.install_watchdog_agent_remote(host(),'account',selected_artifact=selected,mode='update')[0] is success
    assert active.read_text().strip()==state
    assert (config/'agent.yaml').read_bytes()==old_config
    if enabled.startswith('masked'):assert unit.is_symlink() and os.readlink(unit)=='/dev/null'
    else:assert unit.read_bytes()==b'customer unit\n'
    assert 'enable dc-watchdog-agent' not in calls.read_text()
    if state=='active':assert 'http://127.0.0.1:19878/metrics' in calls.read_text()
    if not success:assert binary.read_bytes()==b'old binary'


def test_ADV05_interrupted_store_publication_recovers_under_lock(tmp_path,monkeypatch):
    public,store,make=prepare_store(tmp_path,monkeypatch);config=FleetConfig(config_dir=tmp_path)
    first=make('A','a');fleet_upgrade.commit_release(config,first);before=public.read_bytes()
    second=make('B','b');store.begin_publication(second,before);store.commit(second)
    with config.lifecycle_lock():store.recover_publication(public)
    assert (store.root/'selection.json').read_bytes()==first.selection_raw
    assert public.read_bytes()==before
    assert not (store.root/'.lifecycle-publication.json').exists()


def test_ADV05_interrupted_publication_with_customer_conflict_retains_all_bytes(tmp_path,monkeypatch):
    public,store,make=prepare_store(tmp_path,monkeypatch);config=FleetConfig(config_dir=tmp_path)
    first=make('A','a');fleet_upgrade.commit_release(config,first)
    second=make('B','b');store.begin_publication(second,public.read_bytes());store.commit(second)
    public.write_bytes(public.read_bytes()+b'# customer edit during interrupted publication\n');customer=public.read_bytes()
    with config.lifecycle_lock(),pytest.raises(RuntimeError,match='conflicts'):
        store.recover_publication(public)
    assert public.read_bytes()==customer and (store.root/'selection.json').read_bytes()==second.selection_raw
    assert (store.root/'.lifecycle-publication.json').exists()


def test_promtool_validation_mount_public_permissions(tmp_path,monkeypatch,empty_controller_inventory):
    manager=FleetManager(FleetConfig(config_dir=empty_controller_inventory));manager.release_plan=images()
    def run(command,**k):
        assert command[:8] == ['docker','run','--rm','--network','none','--entrypoint','/bin/promtool','-v']
        assert command.count('-v') == 1
        source, target, access = command[8].rsplit(':', 2)
        assert target == '/etc/prometheus' and access == 'ro'
        assert command[9:] == [manager.release_plan.targets['prometheus']['reference'],
                               'check','config','/etc/prometheus/prometheus.yml']
        mount=Path(source)
        assert {p.name for p in mount.iterdir()} == {'prometheus.yml','recording_rules.yml'}
        assert mount.stat().st_mode & 0o777 == 0o755
        assert all(p.stat().st_mode & 0o777 == 0o644 for p in mount.iterdir())
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr('dc_overview.fleet_manager.subprocess.run',run)
    assert manager._validate_baseline_prometheus({'scrape_configs':[]})

@pytest.mark.parametrize('endpoint', ['watchdog-agent/reinstall','exporters/node_exporter/update'])
def test_ADV07_api_refuses_before_reinstall_remove_or_latest_discovery(tmp_path,monkeypatch,client,sample_server,auth_headers,endpoint):
    from dc_overview import app as module
    (tmp_path/'fleet-config.yaml').write_text('release_selection:\n  selection_id: suite\n  selection_sha256: '+ 'a'*64+'\n');monkeypatch.setenv('DC_OVERVIEW_CONFIG_DIR',str(tmp_path))
    remove=Mock();latest=Mock(return_value='1.10.3')
    monkeypatch.setattr(module,'remove_watchdog_agent_remote',remove)
    monkeypatch.setattr('dc_overview.exporters.get_latest_exporter_version',latest)
    response=client.post(f'/api/servers/{sample_server}/{endpoint}',json={},headers=auth_headers)
    assert response.status_code==409
    assert 'dc-overview upgrade' in response.json['error']
    remove.assert_not_called();latest.assert_not_called()


def test_ADV01_existing_compose_exposes_selected_policy_to_app(tmp_path,empty_controller_inventory):
    config=FleetConfig(config_dir=empty_controller_inventory);config.ssl.use_existing_proxy=True
    manager=FleetManager(config);manager.release_plan=images()
    service=yaml.safe_load(manager._generate_docker_compose())['services']['dc-overview']
    assert str(empty_controller_inventory)+':/etc/dc-overview:ro' in service['volumes']


def test_ADV01_preflight_renderer_cannot_create_inventory_custody(tmp_path,monkeypatch,empty_controller_inventory):
    config=FleetConfig(config_dir=empty_controller_inventory);config.ssl.use_existing_proxy=True;config.components.ipmi_monitor=True
    manager=FleetManager(config);manager.release_plan=images();manager._render_only=True
    monkeypatch.setattr(manager,'_inspect_ipmi_monitor',lambda:None)
    manager._generate_docker_compose()
    assert not (empty_controller_inventory/'secrets').exists()


def test_ADV05_failed_publication_restores_in_memory_reference(tmp_path,monkeypatch):
    public,store,make=prepare_store(tmp_path,monkeypatch);config=FleetConfig(config_dir=tmp_path)
    first=make('A','a');fleet_upgrade.commit_release(config,first)
    monkeypatch.setattr(config,'persist_lifecycle',Mock(side_effect=RuntimeError('synthetic error')))
    with pytest.raises(RuntimeError):fleet_upgrade.commit_release(config,make('B','b'))
    assert config.release_selection.selection_id=='A'
    assert config.release_selection.selection_sha256==first.selection_sha256


def test_ADV06_readonly_privilege_response_requires_proof_marker(tmp_path,monkeypatch):
    config=FleetConfig(config_dir=tmp_path);config.servers=[Server(name='fake-worker',server_ip='192.0.2.11')]
    ssh=Mock();ssh.run_command.return_value=SimpleNamespace(success=True,output='Linux x86_64')
    monkeypatch.setattr(worker_lifecycle,'SSHManager',lambda *a:ssh)
    with pytest.raises(ValueError,match='privilege|prerequisite'):
        worker_lifecycle.preflight_workers(config,worker_plan())


def test_ADV06_preflight_proves_platform_privilege_and_retains_watchdog_custody(tmp_path,monkeypatch):
    config=FleetConfig(config_dir=tmp_path);config.ssh.username='operator';config.servers=[Server(name='worker',server_ip='192.0.2.11')]
    selected=target('dc-watchdog-agent',version='2.0.8');artifact={k:v for k,v in selected.items() if k in ('kind','url','sha256')}
    plan=SimpleNamespace(targets={'dc-watchdog-agent':selected},manifest=SimpleNamespace(data={'components':{'dc-watchdog-agent':{'release':'2.0.8','owner':'dc-worker','artifacts':{'linux/amd64':artifact}}}}),selection={'components':{'dc-watchdog-agent':{'origin':'baseline','enabled':True}}})
    ssh=Mock();ssh.run_command.side_effect=[SimpleNamespace(success=True,output='Linux x86_64'),SimpleNamespace(success=True,output='WORKER_PREFLIGHT=verified')]
    monkeypatch.setattr(worker_lifecycle,'SSHManager',lambda *a:ssh)
    assert worker_lifecycle.preflight_workers(config,plan,mode='update')['worker']['dc-watchdog-agent']['release']=='2.0.8'
    import base64,shlex
    command=ssh.run_command.call_args.kwargs['command'];script=base64.b64decode(shlex.split(command)[2]).decode()
    assert 'sudo -n --' in command and 'is-enabled' in script and 'is-active' in script
    assert 'systemctl start' not in script and 'systemctl enable' not in script
    assert '/etc/dc-watchdog/agent.yaml' in script


def test_ADV07_required_but_missing_selection_never_falls_back_to_latest(tmp_path,monkeypatch):
    monkeypatch.setenv('DC_OVERVIEW_CONFIG_DIR',str(tmp_path));monkeypatch.setenv('DC_RELEASE_SELECTION_REQUIRED','1')
    refusal=worker_lifecycle.selected_worker_mutation_refusal()
    assert refusal and 'dc-overview upgrade' in refusal


def test_ADV07_selected_compose_marks_policy_required_even_if_mount_unavailable(tmp_path,empty_controller_inventory):
    config=FleetConfig(config_dir=empty_controller_inventory);config.ssl.use_existing_proxy=True
    manager=FleetManager(config);manager.release_plan=images()
    environment=yaml.safe_load(manager._generate_docker_compose())['services']['dc-overview']['environment']
    assert 'DC_RELEASE_SELECTION_REQUIRED=1' in environment
