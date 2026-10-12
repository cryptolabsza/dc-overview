"""Watchdog boundaries exercised with supported customer configuration and fake IO."""
import builtins
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from dc_overview import web_watchdog
from dc_overview.fleet_config import FleetConfig, Server
from test_operational_customer_contract import host
from test_selected_worker_lifecycle import target


@pytest.mark.parametrize('explicit,domain,master,expected', [
    ('customer-site', 'fleet.example.invalid', '192.0.2.1', 'customer-site'),
    ('', 'fleet.example.invalid', '192.0.2.1', 'fleet.example.invalid'),
    ('', '', '192.0.2.1', '192.0.2.1'),
])
def test_site_identity_reads_normal_serialized_config(tmp_path, monkeypatch, explicit, domain, master, expected):
    config = FleetConfig(config_dir=tmp_path)
    config.ssl.domain = domain
    config.master_ip = master
    path = config.save()
    original_open = builtins.open
    monkeypatch.setenv('WATCHDOG_SITE_ID', explicit)
    monkeypatch.setattr(web_watchdog.os.path, 'exists', lambda p: str(p) == '/etc/dc-overview/fleet-config.yaml')
    monkeypatch.setattr(builtins, 'open', lambda p, *a, **k: original_open(path if str(p) == '/etc/dc-overview/fleet-config.yaml' else p, *a, **k))
    assert web_watchdog.get_site_id() == expected


@pytest.mark.parametrize('user', ['root', 'operator'])
@pytest.mark.parametrize('selected', [False, True])
@pytest.mark.parametrize('proof', ['denied', 'missing-marker', 'timeout'])
def test_privilege_failure_precedes_registration(monkeypatch, user, selected, proof):
    events = []
    def remote(cmd, **kwargs):
        events.append((cmd, kwargs))
        if proof == 'timeout':
            raise subprocess.TimeoutExpired(cmd, 30)
        return subprocess.CompletedProcess(cmd, 1 if proof == 'denied' else 0, '', 'sudo denied')
    post = Mock(return_value=SimpleNamespace(ok=True, json=lambda: {'success': True, 'worker_token': 'worker-only'}))
    monkeypatch.setattr(requests, 'post', post)
    monkeypatch.setattr(web_watchdog, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    monkeypatch.setattr(web_watchdog.subprocess, 'run', remote)
    result = web_watchdog.install_watchdog_agent_remote(host(user), 'synthetic-account', selected_artifact=target('dc-watchdog-agent', version='2.0.8') if selected else None)
    assert result[0] is False
    post.assert_not_called()
    assert len(events) == 1
    cmd, kwargs = events[0]
    assert cmd[-1] == web_watchdog.watchdog_remote_runner(sudo=user != 'root')
    assert '[ "$(id -u)" = 0 ]' in kwargs['input']
    assert 'systemctl stop' not in kwargs['input'] and 'agent.yaml' not in kwargs['input']


@pytest.mark.parametrize('token', ['synthetic-account', ' synthetic-account ', '', ' ', None, 42])
def test_registration_cannot_deliver_account_credential(monkeypatch, token):
    payloads = []
    def remote(cmd, **kwargs):
        payloads.append(kwargs['input'])
        return subprocess.CompletedProcess(cmd, 0, 'WATCHDOG_PREFLIGHT=verified\nINSTALL_SUCCESS', '')
    monkeypatch.setattr(requests, 'post', lambda *a, **k: SimpleNamespace(ok=True, json=lambda: {'success': True, 'worker_token': token}))
    monkeypatch.setattr(web_watchdog, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    monkeypatch.setattr(web_watchdog.subprocess, 'run', remote)
    assert web_watchdog.install_watchdog_agent_remote(host(), 'synthetic-account', selected_artifact=target('dc-watchdog-agent', version='2.0.8'))[0] is False
    assert len(payloads) == 1
    assert 'synthetic-account' not in payloads[0]
    assert 'systemctl stop' not in payloads[0]


def test_valid_worker_token_follows_readonly_exact_runner(monkeypatch):
    events = []
    def remote(cmd, **kwargs):
        events.append(('ssh', cmd, kwargs['input']))
        return subprocess.CompletedProcess(cmd, 0, 'WATCHDOG_PREFLIGHT=verified\nINSTALL_SUCCESS', '')
    def register(*args, **kwargs):
        events.append(('register', args, kwargs))
        return SimpleNamespace(ok=True, json=lambda: {'success': True, 'worker_token': 'synthetic-worker-only'})
    monkeypatch.setattr(requests, 'post', register)
    monkeypatch.setattr(web_watchdog, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    monkeypatch.setattr(web_watchdog.subprocess, 'run', remote)
    selected = target('dc-watchdog-agent', version='2.0.8')
    assert web_watchdog.install_watchdog_agent_remote(host('operator'), 'synthetic-account', selected_artifact=selected)[0]
    assert [e[0] for e in events] == ['ssh', 'register', 'ssh']
    assert events[0][1][-1] == events[2][1][-1] == web_watchdog.watchdog_remote_runner(sudo=True)
    script = events[2][2]
    assert 'synthetic-worker-only' in script and 'synthetic-account' not in script
    assert selected['url'] in script and selected['sha256'] in script
    assert script.index('sha256sum') < script.index('changed=1')


@pytest.mark.parametrize('domain,expected_site', [('fleet.example.invalid', 'fleet.example.invalid'), ('', 'default')])
def test_legacy_fleet_delegates_with_merged_customer_config(tmp_path, monkeypatch, domain, expected_site):
    from dc_overview.fleet_manager import FleetManager
    config = FleetConfig(config_dir=tmp_path)
    config.components.dc_watchdog = True
    config.watchdog.api_key = 'synthetic-account'
    config.watchdog.server_url = 'https://watchdog.example.invalid'
    config.watchdog.ping_interval = 45
    config.watchdog.agent_use_mtr = False
    config.ssl.domain = domain
    config.master_ip = ''
    monkeypatch.delenv('WATCHDOG_SITE_ID', raising=False)
    key = tmp_path / 'synthetic-key'; key.write_text('synthetic')
    config.ssh.key_path = str(key)
    config.ssh.username = 'global-operator'
    config.ssh.port = 2201
    config.servers = [Server(name='worker', server_ip='192.0.2.10', ssh_user='worker-operator', ssh_port=2202, ssh_password='synthetic-password')]
    manager = object.__new__(FleetManager)
    manager.config = config
    manager.ssh = Mock()
    install = Mock(return_value=(True, None))
    monkeypatch.setattr(web_watchdog, 'install_watchdog_agent_remote', install)
    post = Mock(side_effect=AssertionError('Fleet must not register independently'))
    monkeypatch.setattr(requests, 'post', post)
    FleetManager._deploy_watchdog_agents(manager)
    assert install.call_count == 1
    server, key_arg = install.call_args.args
    assert key_arg == 'synthetic-account'
    assert (server.ssh_user, server.ssh_port, server.ssh_password, server.ssh_key.key_path) == ('worker-operator', 2202, 'synthetic-password', str(key))
    assert install.call_args.kwargs == {'watchdog_url': 'https://watchdog.example.invalid', 'site_id': expected_site, 'heartbeat_interval': 45, 'use_mtr': False}
    post.assert_not_called()
    manager.ssh.run_command.assert_not_called()


def test_status_exception_does_not_log_credential_url(monkeypatch, caplog):
    monkeypatch.setattr(web_watchdog, 'get_watchdog_api_key', lambda: 'synthetic-account')
    monkeypatch.setattr(web_watchdog, '_watchdog_api_cache', {'ts': 0, 'data': None})
    monkeypatch.setattr(web_watchdog.http_requests, 'get', Mock(side_effect=requests.RequestException('https://watchdog.example.invalid/api?api_key=synthetic-account')))
    with caplog.at_level('DEBUG', logger=web_watchdog.__name__):
        assert web_watchdog.get_watchdog_agents_from_api() == {}
    assert 'synthetic-account' not in caplog.text and 'api_key=' not in caplog.text
    assert 'RequestException' in caplog.text


@pytest.mark.parametrize('uid,expected', [('0', True), ('1001', False)])
def test_readonly_privilege_payload_executes_root_check(tmp_path, monkeypatch, uid, expected):
    """Run the actual readonly product payload with synthetic platform tools."""
    import os
    fake = tmp_path / 'bin'; fake.mkdir()
    systemd = tmp_path / 'systemd'; systemd.mkdir()
    tools = ['bash', 'timeout', 'curl', 'sha256sum', 'systemctl', 'mktemp', 'cp', 'mv', 'chmod', 'grep', 'sed']
    for name in ['id', *tools]:
        path = fake / name
        body = f'echo {uid}\n' if name == 'id' else 'exit 0\n'
        if name == 'timeout': body = 'shift 3\nexec "$@"\n'
        elif name == 'systemctl': body = '[ "$*" = "show --property=SystemState --value" ] || exit 2\necho running\n'
        path.write_text('#!/bin/sh\n' + body)
        path.chmod(0o755)
    original_run = subprocess.run
    payloads = []
    def remote(cmd, **kwargs):
        script = kwargs['input']; payloads.append(script)
        if 'echo WATCHDOG_PREFLIGHT=verified' in script:
            return original_run(['/bin/bash', '-s'], input=script.replace('/run/systemd/system', str(systemd)), capture_output=True, text=True, env={**os.environ, 'PATH': str(fake)})
        return subprocess.CompletedProcess(cmd, 0, 'INSTALL_SUCCESS', '')
    post = Mock(return_value=SimpleNamespace(ok=True, json=lambda: {'success': True, 'worker_token': 'worker-only'}))
    monkeypatch.setattr(requests, 'post', post)
    monkeypatch.setattr(web_watchdog, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    monkeypatch.setattr(web_watchdog.subprocess, 'run', remote)
    assert web_watchdog.install_watchdog_agent_remote(host('operator'), 'synthetic-account', selected_artifact=target('dc-watchdog-agent', version='2.0.8'))[0] is expected
    assert post.call_count == int(expected)
    assert len(payloads) == 1 + int(expected)


def test_customer_settings_and_unusual_token_are_literal_yaml(tmp_path, monkeypatch):
    import os
    import yaml
    scripts = []
    token = 'worker-$(touch ' + str(tmp_path / 'executed') + ')-"quoted"'
    site = 'customer-`touch ' + str(tmp_path / 'executed-site') + '`'
    def remote(cmd, **kwargs):
        scripts.append(kwargs['input'])
        return subprocess.CompletedProcess(cmd, 0, 'WATCHDOG_PREFLIGHT=verified\nINSTALL_SUCCESS', '')
    original_run = subprocess.run
    monkeypatch.setattr(requests, 'post', lambda *a, **k: SimpleNamespace(ok=True, json=lambda: {'success': True, 'worker_token': token}))
    monkeypatch.setattr(web_watchdog, 'build_ssh_cmd', lambda *a, **k: (['ssh'], {}))
    monkeypatch.setattr(web_watchdog.subprocess, 'run', remote)
    assert web_watchdog.install_watchdog_agent_remote(host(), 'synthetic-account', selected_artifact=target('dc-watchdog-agent', version='2.0.8'), site_id=site, heartbeat_interval=45, use_mtr=False)[0]
    script = scripts[-1]
    start = script.index("printf '%s'")
    end = script.index('\nYAMLEOF', start) + len('\nYAMLEOF')
    payload = 'CONFIG_DIR=' + str(tmp_path) + '\nMONITOR_LEVEL=basic\nHAS_GPU=false\n' + script[start:end]
    result = original_run(['/bin/bash', '-s'], input=payload, capture_output=True, text=True, env=os.environ.copy())
    assert result.returncode == 0, result.stderr
    config = yaml.safe_load((tmp_path / 'agent.yaml').read_text())
    assert config['api_key'] == token and config['site_id'] == site
    assert config['heartbeat_interval'] == '45s' and config['network']['mtr']['enabled'] is False
    assert not (tmp_path / 'executed').exists() and not (tmp_path / 'executed-site').exists()


@pytest.mark.parametrize('settings', [{'site_id': 42}, {'site_id': ''}, {'heartbeat_interval': True}, {'heartbeat_interval': '$(id)'}, {'heartbeat_interval': 0}, {'use_mtr': 'false'}])
def test_invalid_customer_settings_stop_before_ssh_and_registration(monkeypatch, settings):
    post = Mock(); ssh = Mock()
    monkeypatch.setattr(requests, 'post', post)
    monkeypatch.setattr(web_watchdog, 'build_ssh_cmd', ssh)
    assert web_watchdog.install_watchdog_agent_remote(host(), 'synthetic-account', selected_artifact=target('dc-watchdog-agent', version='2.0.8'), **settings)[0] is False
    post.assert_not_called(); ssh.assert_not_called()


@pytest.mark.parametrize('config,expected', [({'domain': 'legacy.example.invalid', 'master_ip': '192.0.2.1'}, 'legacy.example.invalid'), ({'master_ip': '192.0.2.1'}, '192.0.2.1'), ({}, 'synthetic-host')])
def test_site_identity_retains_legacy_and_hostname_fallback(monkeypatch, config, expected):
    import socket
    monkeypatch.delenv('WATCHDOG_SITE_ID', raising=False)
    monkeypatch.setattr(web_watchdog.os.path, 'exists', lambda p: False)
    monkeypatch.setattr(socket, 'gethostname', lambda: 'synthetic-host')
    assert web_watchdog.get_site_id(config) == expected
