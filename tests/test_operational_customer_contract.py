"""Customer lifecycle regressions; all subprocess/API/credential inputs are synthetic."""
import json
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
import requests

from dc_overview import web_exporters, web_watchdog
from dc_overview.app import AppSettings, Server, db, _build_exporter_response, _do_live_exporter_check


def host(user='root'):
    return SimpleNamespace(name='synthetic-worker', server_ip='192.0.2.10', ssh_user=user,
                           ssh_port=22, ssh_key=None, ssh_password='synthetic-password')


def test_cached_stopped_service_remains_installed(app, sample_server):
    with app.app_context():
        server = db.session.get(Server, sample_server)
        server.node_exporter_installed = True
        server.node_exporter_enabled = False
        result = _build_exporter_response(server, source='cached')
        assert result['installed']['node_exporter'] is True
        assert result['enabled']['node_exporter'] is False


@pytest.mark.parametrize('failure', ['exit', 'timeout', 'malformed'])
def test_discovery_failure_preserves_database_and_freshness(app, sample_server, failure):
    with app.app_context():
        server = db.session.get(Server, sample_server)
        server.node_exporter_installed = True
        server.node_exporter_enabled = True
        server.node_exporter_version = '1.10.2'
        db.session.add(AppSettings(key=f'_exporter_check_ts_{sample_server}', value='old-time'))
        db.session.add(AppSettings(key=f'_exporter_updates_{sample_server}', value='{"old":true}'))
        db.session.commit()
        output = subprocess.CompletedProcess([], 255 if failure == 'exit' else 0, 'garbled', 'synthetic failure')
        side_effect = subprocess.TimeoutExpired(['ssh'], 20) if failure == 'timeout' else None
        with patch.object(web_exporters, 'build_ssh_cmd', return_value=(['ssh'], {})), \
             patch.object(web_exporters.subprocess, 'run', return_value=output, side_effect=side_effect), \
             patch('dc_overview.app.check_exporter', return_value={'running':False}), \
             patch('dc_overview.app.check_watchdog_agent', return_value={'source':'none'}), \
             patch('dc_overview.exporters.check_for_updates', return_value={}):
            _do_live_exporter_check(sample_server)
        db.session.refresh(server)
        assert server.node_exporter_installed is True
        assert server.node_exporter_enabled is True
        assert server.node_exporter_version == '1.10.2'
        assert AppSettings.query.filter_by(key=f'_exporter_check_ts_{sample_server}').one().value == 'old-time'
        assert AppSettings.query.filter_by(key=f'_exporter_updates_{sample_server}').one().value == '{"old":true}'


@pytest.mark.parametrize('registration', ['http', 'network', 'missing', 'denied', 'json'])
def test_watchdog_registration_failure_never_reaches_ssh(registration, monkeypatch):
    response = Mock(ok=registration != 'http', status_code=403)
    response.json.return_value = {'success':registration != 'denied'}
    if registration == 'denied':
        response.json.return_value['error'] = 'synthetic-account-key'
    if registration == 'json':
        response.json.side_effect = ValueError('synthetic-account-key')
    post = Mock(return_value=response)
    if registration == 'network':
        post.side_effect = requests.RequestException('synthetic-account-key')
    monkeypatch.setattr(requests, 'post', post)
    ssh = Mock(return_value=(['ssh'], {}))
    monkeypatch.setattr(web_watchdog, 'build_ssh_cmd', ssh)
    monkeypatch.setattr(web_watchdog, 'get_watchdog_latest_release', lambda: {'version':'1.0.0'})
    monkeypatch.setattr(web_watchdog.subprocess, 'run', Mock(return_value=subprocess.CompletedProcess([], 0, 'INSTALL_SUCCESS', '')))
    success, error = web_watchdog.install_watchdog_agent_remote(host(), 'synthetic-account-key')
    assert success is False
    ssh.assert_not_called()
    assert 'synthetic-account-key' not in error


@pytest.mark.parametrize('user,prefix', [('root',''), ('operator','sudo -n -- ')])
def test_dc_delivery_uses_correct_privilege(user, prefix, monkeypatch):
    monkeypatch.setattr(web_exporters, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    run = Mock(return_value=subprocess.CompletedProcess([], 0, 'DC_EXPORTER_INSTALL_SUCCESS', ''))
    monkeypatch.setattr(web_exporters.subprocess, 'run', run)
    assert web_exporters.install_exporter_remote(host(user), 'dc_exporter') is True
    assert run.call_args.args[0][-1].startswith(prefix + 'timeout ')


def test_install_api_reports_sanitized_failure_and_keeps_prior_state(app, client, auth_headers, sample_server):
    with app.app_context():
        server = db.session.get(Server, sample_server)
        server.node_exporter_installed = True
        server.node_exporter_enabled = False
        db.session.commit()
        with patch.object(web_exporters, 'build_ssh_cmd', return_value=(['ssh'], {})), \
             patch.object(web_exporters.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'password=synthetic-password token=synthetic-token Permission denied')):
            response = client.post(f'/api/servers/{sample_server}/install-exporters', headers=auth_headers,
                                   json={'exporters':['node_exporter','invalid']})
        assert response.status_code == 200
        result = response.get_json()
        assert result['node_exporter'] == 'failed'
        assert result['invalid'] == 'failed'
        assert result['errors']['node_exporter']
        assert 'synthetic-password' not in response.get_data(as_text=True)
        assert 'synthetic-token' not in response.get_data(as_text=True)
        db.session.refresh(server)
        assert server.node_exporter_installed is True
        assert server.node_exporter_enabled is False


def test_install_success_requires_verification_marker(monkeypatch):
    monkeypatch.setattr(web_exporters, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    monkeypatch.setattr(web_exporters.subprocess, 'run', Mock(return_value=subprocess.CompletedProcess([], 0, '', '')))
    assert web_exporters.install_exporter_remote(host(), 'node_exporter') is False


def test_dcgm_toggle_error_is_not_masked(monkeypatch):
    monkeypatch.setattr(web_exporters, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    def run(cmd, **kwargs):
        assert "|| echo 'not found'" not in cmd[-1]
        return subprocess.CompletedProcess(cmd, 1, '', 'synthetic-password')
    monkeypatch.setattr(web_exporters.subprocess, 'run', run)
    success, error = web_exporters.toggle_exporter_service(host('operator'), 'dcgm_exporter', True)
    assert success is False
    assert 'synthetic-password' not in error


def test_discovery_uses_systemd_load_state_and_rejects_permission_failures(tmp_path, monkeypatch):
    """Run the actual emitted discovery shell against deterministic command fakes."""
    fake_bin = tmp_path / 'bin'
    fake_bin.mkdir()
    systemctl = fake_bin / 'systemctl'
    systemctl.write_text('#!/bin/sh\ncase "$*" in\n*LoadState*) echo loaded;;\n*ActiveState*) echo inactive;;\n*) echo inactive; exit 3;;\nesac\n')
    systemctl.chmod(0o755)
    docker = fake_bin / 'docker'
    docker.write_text('#!/bin/sh\necho "permission denied" >&2\nexit 1\n')
    docker.chmod(0o755)
    import os
    real_run = subprocess.run
    def remote(cmd, **kwargs):
        return real_run(['bash','-c',cmd[-1]], capture_output=True, text=True,
                        env={**os.environ, 'PATH':f'{fake_bin}:'+os.environ['PATH']})
    monkeypatch.setattr(web_exporters, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    monkeypatch.setattr(web_exporters.subprocess, 'run', remote)
    with pytest.raises(Exception):
        web_exporters.check_services_installed(host())
    docker.write_text('#!/bin/sh\necho "Error: No such object: dcgm-exporter" >&2\nexit 1\n')
    result = web_exporters.check_services_installed(host())
    assert result['node_exporter'] == {'installed':True, 'active':False}
    assert result['dcgm_exporter'] == {'installed':False, 'active':False}


def test_dcgm_toggle_command_does_not_hide_exit_failure(monkeypatch):
    monkeypatch.setattr(web_exporters, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    run = Mock(return_value=subprocess.CompletedProcess([], 1, '', 'synthetic-password'))
    monkeypatch.setattr(web_exporters.subprocess, 'run', run)
    success, error = web_exporters.toggle_exporter_service(host('operator'), 'dcgm_exporter', True)
    assert "|| echo 'not found'" not in run.call_args.args[0][-1]
    assert run.call_args.args[0][-1].startswith('sudo -n -- ')
    assert success is False
    assert 'synthetic-password' not in error


def test_stopped_watchdog_observation_is_preserved(monkeypatch):
    server = host()
    server.watchdog_agent_installed = True
    server.watchdog_agent_enabled = False
    server.watchdog_agent_version = '1.0.0'
    monkeypatch.setattr(web_watchdog, 'get_watchdog_agents_from_api', lambda: {})
    monkeypatch.setattr(web_watchdog, 'check_watchdog_health_port', lambda ip: None)
    monkeypatch.setattr(web_watchdog, 'check_exporter', lambda *a: {'running':False})
    result = web_watchdog.check_watchdog_agent(server)
    assert result['installed'] is True
    assert result['source'] == 'database'


@pytest.mark.parametrize('user,prefix', [('root',''), ('operator','sudo -n -- ')])
def test_watchdog_delivery_uses_stdin_and_privilege(user, prefix, monkeypatch):
    monkeypatch.setattr(requests, 'post', lambda *a, **k: SimpleNamespace(ok=True, json=lambda: {'success':True,'worker_token':'synthetic-worker-token'}))
    monkeypatch.setattr(web_watchdog, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    monkeypatch.setattr(web_watchdog, 'get_watchdog_latest_release', lambda: {'version':'1.0.0'})
    run = Mock(return_value=subprocess.CompletedProcess([], 0, 'INSTALL_SUCCESS', ''))
    monkeypatch.setattr(web_watchdog.subprocess, 'run', run)
    assert web_watchdog.install_watchdog_agent_remote(host(user), 'synthetic-account-key') == (True,None)
    assert run.call_args.args[0][-1] == prefix + 'timeout --signal=TERM --kill-after=30s 120s bash -s'
    assert 'synthetic-account-key' not in run.call_args.kwargs['input']
    assert 'synthetic-worker-token' in run.call_args.kwargs['input']


@pytest.mark.parametrize('fails', [False, True])
def test_node_install_verifies_and_recovers_previous_binary(tmp_path, monkeypatch, fails):
    """Exercise product-generated Bash, real filesystem and process exit handling."""
    from dc_overview import exporters
    import os
    import tarfile
    builder = getattr(exporters, 'build_node_exporter_install_script', None)
    assert builder is not None, 'Node installer needs verified staging and rollback'
    target = tmp_path / 'node_exporter'
    target.write_text('old-binary')
    unit = tmp_path / 'node_exporter.service'
    unit.write_text('old-unit')
    release = tmp_path / 'release'
    release.mkdir()
    binary = release / 'node_exporter'
    binary.write_text('#!/bin/sh\necho node_exporter, version 1.10.2\n')
    binary.chmod(0o755)
    archive = tmp_path / 'release.tar.gz'
    with tarfile.open(archive,'w:gz') as tar:
        arch = 'arm64' if __import__('platform').machine() in ('arm64','aarch64') else 'amd64'
        tar.add(binary, arcname=f'node_exporter-1.10.2.linux-{arch}/node_exporter')
    fake_bin = tmp_path / 'bin'
    fake_bin.mkdir()
    programs = {
        'curl':'if [ "$1" = -fsSL ]; then cp "$ARCHIVE" "$4"; else echo node_exporter_build_info; fi',
        'useradd':'exit 0',
        'systemctl':'''case "$*" in
"is-active --quiet node_exporter") [ "$FAIL" = 0 ] ;;
"is-active node_exporter") echo active;;
"is-enabled node_exporter") echo enabled;;
"is-enabled --quiet node_exporter") exit 0;;
*) exit 0;;
esac''',
    }
    for name, body in programs.items():
        path = fake_bin / name
        path.write_text('#!/bin/sh\n'+body+'\n')
        path.chmod(0o755)
    script = builder(binary_path=str(target), service_path=str(unit), temp_parent=str(tmp_path))
    result = subprocess.run(['bash','-s'], input=script, capture_output=True, text=True,
                            env={**os.environ, 'PATH':f'{fake_bin}:'+os.environ['PATH'], 'ARCHIVE':str(archive),'FAIL':str(int(fails))})
    if fails:
        assert result.returncode != 0
        assert target.read_text() == 'old-binary'
        assert unit.read_text() == 'old-unit'
    else:
        assert result.returncode == 0, result.stderr
        assert 'NODE_EXPORTER_INSTALL_SUCCESS' in result.stdout
        assert 'version 1.10.2' in target.read_text()


@pytest.mark.parametrize('operation', ['exporter_remove','exporter_update','watchdog_toggle','watchdog_remove'])
def test_nonroot_mutations_use_noninteractive_sudo(operation, monkeypatch):
    monkeypatch.setattr(web_exporters, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    monkeypatch.setattr(web_watchdog, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    monkeypatch.setattr('dc_overview.exporters.get_exporter_download_url', lambda *a: 'https://example.invalid/release')
    run = Mock(return_value=subprocess.CompletedProcess([], 0, 'UPDATE_SUCCESS REMOVE_SUCCESS', ''))
    monkeypatch.setattr(subprocess, 'run', run)
    server = host('operator')
    if operation == 'exporter_remove':
        web_exporters.remove_exporter_remote(server, 'node_exporter')
    elif operation == 'exporter_update':
        web_exporters.update_exporter_remote(server, 'node_exporter', '1.10.2')
    elif operation == 'watchdog_toggle':
        web_watchdog.toggle_watchdog_service(server, True)
    else:
        web_watchdog.remove_watchdog_agent_remote(server)
    assert run.call_args.args[0][-1].startswith('sudo -n -- ')


@pytest.mark.parametrize('api_result,expected', [({},False), ({'node_exporter':'failed','errors':{'node_exporter':'Permission denied'}},False), ({'node_exporter':'installed'},True)])
def test_install_ui_requires_explicit_success_and_displays_api_diagnostic(api_result, expected):
    """Execute the shipped handler with real API-shaped JSON, no DOM browser required."""
    from pathlib import Path
    import shutil
    node = shutil.which('node')
    assert node, 'Node is required to execute the shipped installation UI handler'
    template = Path('src/dc_overview/web_templates/servers.html').read_text()
    handler = template[template.index('    async function installSingleExporter('):template.index('    async function removeSingleExporter(')]
    harness = f'''
const currentServerId=1, serverNames={{}}, basePath='';
const document={{getElementById:()=>({{textContent:'synthetic-worker'}})}};
const markPendingAndRender=async()=>{{}};
let task, result;
const enqueueServerOp=(id, f)=>{{task=f();}};
const fetch=async()=>({{ok:true,json:async()=>({json.dumps(api_result)})}});
const handleOpComplete=(...args)=>{{result=args;}};
{handler}
(async()=>{{await installSingleExporter('node_exporter');await task;process.stdout.write(JSON.stringify(result));}})();
'''
    run = subprocess.run([node,'-e',harness], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    result = json.loads(run.stdout)
    assert result[4] is expected
    if api_result.get('errors'):
        assert result[5] == 'Permission denied'


@pytest.mark.parametrize('failure', ['download','startup'])
def test_watchdog_failed_install_preserves_previous_install(tmp_path, monkeypatch, failure):
    import os
    target = tmp_path / 'usr-local-bin'
    config = tmp_path / 'config'
    units = tmp_path / 'units'
    target.mkdir(); config.mkdir(); units.mkdir()
    binary = target / 'dc-watchdog-agent'
    binary.write_text('old-watchdog-binary')
    settings = config / 'agent.yaml'
    settings.write_text('old-watchdog-config')
    unit = units / 'dc-watchdog-agent.service'
    unit.write_text('old-watchdog-unit')
    state = tmp_path / 'state'
    state.write_text('active')
    fake_bin = tmp_path / 'bin'
    fake_bin.mkdir()
    programs = {
        'curl':'''[ "$FAILURE" != download ] || exit 22
printf '#!/bin/sh\\necho dc-watchdog-agent 1.0.0\\n' > "$4"
''',
        'systemctl':'''case "$*" in
"is-active dc-watchdog-agent") cat "$STATE";;
"is-enabled dc-watchdog-agent") echo enabled;;
"stop dc-watchdog-agent") echo inactive > "$STATE";;
"restart dc-watchdog-agent") echo failed > "$STATE";;
"start dc-watchdog-agent") echo active > "$STATE";;
"is-active --quiet dc-watchdog-agent") [ "$(cat "$STATE")" = active ];;
*) exit 0;;
esac''',
        'sleep':'exit 0', 'journalctl':'exit 0',
        'apt-get':'exit 0', 'yum':'exit 0', 'dnf':'exit 0',
    }
    for name, body in programs.items():
        path = fake_bin / name
        path.write_text('#!/bin/sh\n'+body+'\n')
        path.chmod(0o755)
    monkeypatch.setattr(requests, 'post', lambda *a, **k: SimpleNamespace(ok=True, json=lambda: {'success':True,'worker_token':'synthetic-worker-token'}))
    monkeypatch.setattr(web_watchdog, 'get_watchdog_latest_release', lambda: {'version':'1.0.0'})
    monkeypatch.setattr(web_watchdog, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    real_run = subprocess.run
    def remote(cmd, **kwargs):
        script = kwargs['input'].replace('/usr/local/bin',str(target)).replace('/etc/dc-watchdog',str(config)).replace('/etc/systemd/system',str(units)).replace('/opt/dc-watchdog',str(tmp_path/'obsolete'))
        return real_run(['bash','-s'], input=script, capture_output=True, text=True,
                        env={**os.environ,'PATH':f'{fake_bin}:'+os.environ['PATH'],'STATE':str(state),'FAILURE':failure})
    monkeypatch.setattr(web_watchdog.subprocess, 'run', remote)
    success, error = web_watchdog.install_watchdog_agent_remote(host(), 'synthetic-account-key')
    assert success is False
    assert binary.read_text() == 'old-watchdog-binary'
    assert settings.read_text() == 'old-watchdog-config'
    assert unit.read_text() == 'old-watchdog-unit'
    assert state.read_text().strip() == 'active'
    assert 'synthetic-worker-token' not in error


@pytest.mark.parametrize('kind', ['exporter','watchdog'])
def test_remove_reports_remote_failure_instead_of_success_marker(tmp_path, monkeypatch, kind):
    import os
    fake_bin = tmp_path / 'bin'
    fake_bin.mkdir()
    for name, body in {'systemctl':'[ "$1" != daemon-reload ]', 'rm':'exit 0'}.items():
        path = fake_bin / name
        path.write_text('#!/bin/sh\n'+body+'\n')
        path.chmod(0o755)
    real_run = subprocess.run
    def remote(cmd, **kwargs):
        return real_run(['bash','-s'], input=kwargs.get('input', ''), capture_output=True, text=True,
                        env={**os.environ,'PATH':f'{fake_bin}:'+os.environ['PATH']}) if kwargs.get('input') else real_run(['bash','-c',cmd[-1]], capture_output=True, text=True, env={**os.environ,'PATH':f'{fake_bin}:'+os.environ['PATH']})
    monkeypatch.setattr(web_exporters, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    monkeypatch.setattr(web_watchdog, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    monkeypatch.setattr(subprocess, 'run', remote)
    if kind == 'exporter':
        assert web_exporters.remove_exporter_remote(host(), 'node_exporter') is False
    else:
        assert web_watchdog.remove_watchdog_agent_remote(host()) is False


def test_node_preflight_failure_cleans_staging_without_mutating(tmp_path):
    from dc_overview.exporters import build_node_exporter_install_script
    import os
    fake_bin = tmp_path / 'bin'
    fake_bin.mkdir()
    ctl = fake_bin / 'systemctl'
    ctl.write_text('#!/bin/sh\necho synthetic-dbus-failure >&2\nexit 1\n')
    ctl.chmod(0o755)
    target = tmp_path / 'target'
    target.write_text('old-binary')
    script = build_node_exporter_install_script(binary_path=str(target), service_path=str(tmp_path/'unit'), temp_parent=str(tmp_path))
    result = subprocess.run(['bash','-s'], input=script, capture_output=True, text=True, env={**os.environ,'PATH':f'{fake_bin}:'+os.environ['PATH']})
    assert result.returncode != 0
    assert target.read_text() == 'old-binary'
    assert list(tmp_path.glob('node-exporter.*')) == []


def test_encoded_dc_delivery_requests_noninteractive_sudo(tmp_path):
    from dc_overview.exporters import build_dc_exporter_remote_command
    import os
    fake_bin = tmp_path / 'bin'
    fake_bin.mkdir()
    for name, body in {'sudo':'[ "$1" = -n ] || exit 77\nshift\n[ "$1" = -- ] || exit 77\nshift\nexec "$@"', 'timeout':'shift 3\nexec "$@"'}.items():
        executable = fake_bin / name
        executable.write_text('#!/bin/sh\n'+body+'\n')
        executable.chmod(0o755)
    command = build_dc_exporter_remote_command('printf synthetic-delivery-success', sudo=True)
    result = subprocess.run(['bash','-c',command], capture_output=True, text=True, env={**os.environ,'PATH':f'{fake_bin}:'+os.environ['PATH']})
    assert result.returncode == 0
    assert result.stdout == 'synthetic-delivery-success'


@pytest.mark.parametrize('component', ['node_exporter','watchdog'])
def test_delivery_bounds_remote_execution_and_leaves_recovery_grace(component, monkeypatch):
    import re
    monkeypatch.setattr(web_exporters, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    monkeypatch.setattr(web_watchdog, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    monkeypatch.setattr(requests, 'post', lambda *a, **k: SimpleNamespace(ok=True, json=lambda: {'success':True,'worker_token':'synthetic-worker-token'}))
    monkeypatch.setattr(web_watchdog, 'get_watchdog_latest_release', lambda: {'version':'1.0.0'})
    run = Mock(return_value=subprocess.CompletedProcess([], 0, 'NODE_EXPORTER_INSTALL_SUCCESS INSTALL_SUCCESS', ''))
    monkeypatch.setattr(subprocess, 'run', run)
    if component == 'watchdog':
        web_watchdog.install_watchdog_agent_remote(host(), 'synthetic-account-key')
    else:
        web_exporters.install_exporter_remote(host(), component)
    cmd = run.call_args.args[0][-1]
    matched = re.search(r'timeout --signal=TERM --kill-after=(\d+)s (\d+)s bash -s$',cmd)
    assert matched, 'Remote Bash needs a bounded execution and recovery window'
    assert sum(map(int,matched.groups())) < run.call_args.kwargs['timeout']
    assert run.call_args.kwargs['input']
