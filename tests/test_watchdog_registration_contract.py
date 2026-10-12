"""Independent review repairs: manager proof and strict registration contract."""
import os
import subprocess
from collections import UserDict
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from dc_overview import web_watchdog
from test_operational_customer_contract import host
from test_selected_worker_lifecycle import target


@pytest.mark.parametrize('user', ['root', 'operator'])
@pytest.mark.parametrize('code,state,expected', [(0, 'running', True), (0, 'degraded', True),
    (1, 'running', False), (124, 'running', False), (0, '', False),
    (0, 'synthetic-garbage', False), (0, 'running\ndegraded', False),
    (0, 'stopping', False), (0, 'offline', False)])
def test_actual_readonly_manager_proof_precedes_registration(tmp_path, monkeypatch, user, code, state, expected):
    fake = tmp_path / 'fake'; fake.mkdir()
    systemd = tmp_path / 'systemd'; systemd.mkdir()
    for name in ['id', 'bash', 'timeout', 'curl', 'sha256sum', 'systemctl', 'mktemp', 'cp', 'mv', 'chmod', 'grep', 'sed']:
        if name == 'id': body = 'echo 0'
        elif name == 'timeout': body = '[ "$1" = --signal=TERM ] && [ "$2" = --kill-after=2s ] && [ "$3" = 10s ] || exit 2\nshift 3\nexec "$@"'
        elif name == 'systemctl': body = '[ "$*" = "show --property=SystemState --value" ] || exit 2\nprintf "%s\\n" "$MANAGER_STATE"\nexit "$MANAGER_CODE"'
        else: body = 'exit 0'
        program = fake / name; program.write_text('#!/bin/sh\n' + body + '\n'); program.chmod(0o755)
    original_run = subprocess.run; scripts = []
    def remote(argv, **kwargs):
        script = kwargs['input']; scripts.append(script)
        assert argv[-1] == web_watchdog.watchdog_remote_runner(sudo=user != 'root')
        if 'WATCHDOG_PREFLIGHT=verified' in script:
            return original_run(['/bin/bash', '-s'], input=script.replace('/run/systemd/system', str(systemd)), capture_output=True, text=True,
                env={**os.environ, 'PATH': str(fake), 'MANAGER_CODE': str(code), 'MANAGER_STATE': state})
        return subprocess.CompletedProcess(argv, 0, 'INSTALL_SUCCESS', '')
    registration = Mock(return_value=SimpleNamespace(ok=True, json=lambda: {'success': True, 'worker_token': 'worker-only'}))
    monkeypatch.setattr(requests, 'post', registration)
    monkeypatch.setattr(web_watchdog, 'build_ssh_cmd', lambda *a, **k: (['declared-fake-ssh'], {}))
    monkeypatch.setattr(subprocess, 'run', remote)
    assert web_watchdog.install_watchdog_agent_remote(host(user), 'synthetic-account', selected_artifact=target('dc-watchdog-agent', version='2.0.8'))[0] is expected
    assert registration.call_count == int(expected) and len(scripts) == 1 + int(expected)
    assert 'synthetic-account' not in scripts[0] and 'systemctl stop' not in scripts[0]


@pytest.mark.parametrize('value', [None, [], 'not-a-mapping', {'success': 'false'},
    {'success': 1}, {'success': {'malformed': 'truthy'}}, {'success': []},
    {'success': False}, {'success': None}])
def test_registration_contract_failure_never_dispatches_mutation(monkeypatch, value):
    response = {**value, 'worker_token': 'worker-only'} if isinstance(value, dict) else value
    payloads = []
    def remote(argv, **kwargs):
        payloads.append(kwargs['input'])
        return subprocess.CompletedProcess(argv, 0, 'WATCHDOG_PREFLIGHT=verified\nINSTALL_SUCCESS', '')
    monkeypatch.setattr(requests, 'post', lambda *a, **k: SimpleNamespace(ok=True, json=lambda: response))
    monkeypatch.setattr(web_watchdog, 'build_ssh_cmd', lambda *a, **k: (['declared-fake-ssh'], {}))
    monkeypatch.setattr(subprocess, 'run', remote)
    ok, error = web_watchdog.install_watchdog_agent_remote(host(), 'synthetic-account', selected_artifact=target('dc-watchdog-agent', version='2.0.8'))
    assert not ok and len(payloads) == 1
    assert 'worker-only' not in payloads[0] and 'synthetic-account' not in error


@pytest.mark.parametrize('mapping', [dict, UserDict])
def test_true_mapping_registration_retains_opaque_supported_token(mapping):
    value = mapping(success=True, worker_token='opaque-worker-format')
    request = SimpleNamespace(post=lambda *a, **k: SimpleNamespace(ok=True, json=lambda: value))
    assert web_watchdog._register_watchdog_worker(request, 'https://watchdog.invalid', 'worker', 'synthetic-account') == 'opaque-worker-format'
