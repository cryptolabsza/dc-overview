"""Selected coordinator preserves normal Watchdog settings in actual emitted YAML.

Regression derived from independent PRESERVE-SEL-001 validation. Transport and
provider responses are synthetic; configuration serialization executes real Bash.
"""
import base64
import os
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests
import yaml

from dc_overview import web_watchdog, worker_lifecycle
from dc_overview.fleet_config import FleetConfig, Server
from test_selected_worker_lifecycle import target


def selected_plan(artifact):
    return SimpleNamespace(
        targets={'dc-watchdog-agent': artifact},
        manifest=SimpleNamespace(data={'components': {'dc-watchdog-agent': {
            'release': artifact['release'], 'owner': 'dc-worker',
            'artifacts': {'linux/amd64': {key: artifact[key] for key in ('kind', 'url', 'sha256')}}}}}),
        selection={'components': {'dc-watchdog-agent': {'origin': 'baseline', 'enabled': True}}})


def selected_transport(config, artifact, monkeypatch):
    ssh = Mock(); ssh.key_path = config.config_dir / 'synthetic-key-not-read'
    def remote(command, **kwargs):
        if command == 'uname -s -m':
            return SimpleNamespace(success=True, output='Linux x86_64')
        script = base64.b64decode(command.split()[2].strip("'")).decode()
        if 'echo WORKER_PREFLIGHT=verified' in script:
            return SimpleNamespace(success=True, output='WORKER_PREFLIGHT=verified\n')
        assert 'WORKER_ARTIFACT=' in script and 'WORKER_HEALTH=verified' in script
        return SimpleNamespace(success=True, output='WORKER_ARTIFACT=' + artifact['sha256'] + '\nWORKER_SERVICE=active\nWORKER_HEALTH=verified\n')
    ssh.run_command.side_effect = remote
    monkeypatch.setattr(worker_lifecycle, 'SSHManager', lambda *a: ssh)
    monkeypatch.setattr(web_watchdog, 'build_ssh_cmd', lambda *a, **k: (['synthetic-ssh-never-executed'], {}))
    return ssh


@pytest.mark.parametrize('domain,master,explicit,expected', [
    ('customer.example.invalid', '192.0.2.100', '', 'customer.example.invalid'),
    ('customer.example.invalid', '192.0.2.100', 'explicit-customer', 'explicit-customer'),
    ('', '192.0.2.100', '', '192.0.2.100'),
    ('', '', '', 'default'),
])
def test_selected_install_preserves_normal_fleet_site_heartbeat_mtr(tmp_path, monkeypatch, domain, master, explicit, expected):
    config = FleetConfig(config_dir=tmp_path)
    config.ssl.domain = domain; config.master_ip = master
    config.watchdog.api_key = 'synthetic-account'
    config.watchdog.ping_interval = 73; config.watchdog.agent_use_mtr = False
    config.servers = [Server(name='synthetic-worker', server_ip='192.0.2.22')]
    monkeypatch.setenv('WATCHDOG_SITE_ID', explicit)
    artifact = target('dc-watchdog-agent', version='2.0.8')
    selected_transport(config, artifact, monkeypatch)
    registration = Mock(return_value=SimpleNamespace(ok=True, json=lambda: {'success': True, 'worker_token': 'synthetic-worker-token'}))
    monkeypatch.setattr(requests, 'post', registration)
    original_run = subprocess.run; scripts = []
    def remote(argv, **kwargs):
        scripts.append(kwargs['input'])
        return subprocess.CompletedProcess(argv, 0, 'WATCHDOG_PREFLIGHT=verified\nINSTALL_SUCCESS\nAGENT_VERSION=1.0.7\n', '')
    monkeypatch.setattr(web_watchdog.subprocess, 'run', remote)
    outcome = worker_lifecycle.upgrade_workers(config, selected_plan(artifact), mode='install')
    assert outcome['dc-watchdog-agent']['success'], outcome
    script = scripts[-1]
    start = script.index("printf '%s'"); end = script.index('\nYAMLEOF', start) + len('\nYAMLEOF')
    actual = original_run(['/bin/bash', '-s'], input='CONFIG_DIR=' + str(tmp_path) + '\nMONITOR_LEVEL=basic\nHAS_GPU=false\n' + script[start:end], capture_output=True, text=True)
    assert actual.returncode == 0, actual.stderr
    observed = yaml.safe_load((tmp_path / 'agent.yaml').read_text())
    assert observed.get('site_id') == expected, observed
    assert observed['heartbeat_interval'] == '73s'
    assert observed['network']['mtr']['enabled'] is False
    assert observed['api_key'] == 'synthetic-worker-token'
    registration.assert_called_once()
    assert 'synthetic-account' not in scripts[-1]


def test_selected_update_retains_custody_despite_changed_controller_settings(tmp_path, monkeypatch):
    """Execute real update payload through selected coordinator; held files stay exact."""
    import hashlib
    config = FleetConfig(config_dir=tmp_path)
    config.ssl.domain = 'new-controller.example.invalid'
    config.watchdog.ping_interval = 73; config.watchdog.agent_use_mtr = False
    config.servers = [Server(name='synthetic-worker', server_ip='192.0.2.22')]
    monkeypatch.setenv('WATCHDOG_SITE_ID', 'new-controller-site')
    fake = tmp_path / 'bin'; fake.mkdir()
    installed = tmp_path / 'installed'; installed.mkdir()
    agent = tmp_path / 'config'; agent.mkdir()
    units = tmp_path / 'units'; units.mkdir()
    systemd = tmp_path / 'systemd'; systemd.mkdir()
    old = b'api_key: synthetic-held-token\nsite_id: original-held-site\nheartbeat_interval: 91s\nnetwork:\n  mtr:\n    enabled: true\n'
    settings = agent / 'agent.yaml'; settings.write_bytes(old); settings.chmod(0o600)
    unit = units / 'dc-watchdog-agent.service'; unit.write_bytes(b'customer unit\n'); unit.chmod(0o640)
    binary = installed / 'dc-watchdog-agent'; binary.write_bytes(b'old binary')
    candidate = tmp_path / 'candidate'; candidate.write_text('#!/bin/sh\necho dc-watchdog-agent 1.0.7\n'); candidate.chmod(0o755)
    calls = tmp_path / 'calls'
    for name, body in {'id': 'echo 0', 'timeout': 'shift 3\nexec "$@"', 'uname': 'echo x86_64', 'curl': 'cp "$CANDIDATE" "$4"', 'systemctl': 'echo "$*" >> "$CALLS"\ncase "$*" in\n"show --property=SystemState --value") echo running;;\n"is-active dc-watchdog-agent") echo inactive;exit 3;;\n"is-enabled dc-watchdog-agent") echo masked;exit 1;;\nesac\nexit 0'}.items():
        program = fake / name; program.write_text('#!/bin/sh\n' + body + '\n'); program.chmod(0o755)
    artifact = target('dc-watchdog-agent', version='2.0.8', digest=hashlib.sha256(candidate.read_bytes()).hexdigest())
    selected_transport(config, artifact, monkeypatch)
    registration = Mock(side_effect=AssertionError('update must not register'))
    monkeypatch.setattr(requests, 'post', registration)
    original_run = subprocess.run
    def remote(argv, **kwargs):
        script = kwargs['input'].replace('/usr/local/bin', str(installed)).replace('/etc/dc-watchdog', str(agent)).replace('/etc/systemd/system', str(units)).replace('/run/systemd/system', str(systemd)).replace('/opt/dc-watchdog', str(tmp_path / 'obsolete'))
        return original_run(['/bin/bash', '-s'], input=script, capture_output=True, text=True, env={**os.environ, 'PATH': str(fake) + ':' + os.environ['PATH'], 'CANDIDATE': str(candidate), 'CALLS': str(calls)})
    monkeypatch.setattr(web_watchdog.subprocess, 'run', remote)
    outcome = worker_lifecycle.upgrade_workers(config, selected_plan(artifact), mode='update')
    assert outcome['dc-watchdog-agent']['success'], outcome
    registration.assert_not_called()
    assert settings.read_bytes() == old and unit.read_bytes() == b'customer unit\n'
    assert settings.stat().st_mode & 0o777 == 0o600 and unit.stat().st_mode & 0o777 == 0o640
    assert binary.read_bytes() == candidate.read_bytes()
    assert not any(line.split()[0] in ('enable', 'disable', 'start', 'restart', 'stop') for line in calls.read_text().splitlines())
