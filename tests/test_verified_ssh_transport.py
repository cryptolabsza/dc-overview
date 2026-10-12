"""Strict SSH trust regressions; only synthetic files and declared fake transports."""
import base64
import socket
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import paramiko
import pytest

# Only local configuration evaluation is authorized; never launch ssh without -G.
_LOCAL_CONFIGURATION_RUN = subprocess.run
_LOCAL_CONFIGURATION_POPEN = subprocess.Popen

from dc_overview.ssh_manager import SSHManager
from dc_overview.ssh_helpers import build_ssh_cmd
from dc_overview.exporters import _build_exporter_ssh_cmd


@pytest.fixture(autouse=True)
def no_external_transports(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Undeclared external transport')
    monkeypatch.delenv('DC_OVERVIEW_SSH_KNOWN_HOSTS', raising=False)
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)


@pytest.fixture
def trust(tmp_path):
    key = paramiko.RSAKey.generate(1024)
    p = tmp_path / 'trust with spaces'
    p.write_text(f'worker.test,[worker.test]:2202 {key.get_name()} {key.get_base64()}\n')
    p.chmod(0o644)
    return p, key


def server(trust_path=None, password=None):
    return SimpleNamespace(name='worker', server_ip='worker.test', ssh_user='operator',
                           ssh_port=2202, ssh_key=None, ssh_password=password,
                           ssh_known_hosts_path=str(trust_path) if trust_path else None)


@pytest.mark.parametrize('auth', ['key', 'password', 'default'])
def test_helper_requires_explicit_strict_trust(trust, monkeypatch, auth):
    p, _ = trust
    monkeypatch.setattr('dc_overview.ssh_helpers.resolve_ssh_key_path', lambda s: '/synthetic/key' if auth == 'key' else None)
    cmd, env = build_ssh_cmd(server(p, 'synthetic-secret' if auth == 'password' else None))
    assert 'StrictHostKeyChecking=yes' in cmd
    ssh_index = cmd.index('ssh')
    assert cmd[ssh_index+1:ssh_index+3] == ['-o', 'StrictHostKeyChecking=yes']
    assert 'ForwardAgent=no' in cmd
    assert 'UpdateHostKeys=no' in cmd
    assert 'GlobalKnownHostsFile=/dev/null' in cmd
    assert 'KnownHostsCommand=none' in cmd and 'VerifyHostKeyDNS=no' in cmd
    assert 'ControlPath=none' in cmd and 'ControlMaster=no' in cmd
    assert '-F' not in cmd
    known = next(x for x in cmd if x.startswith('UserKnownHostsFile='))
    assert known == f'UserKnownHostsFile="{p}"'
    assert cmd[-1] == 'operator@worker.test'
    assert cmd[cmd.index('-p')+1] == '2202'
    assert 'synthetic-secret' not in cmd
    assert env == ({'SSHPASS': 'synthetic-secret'} if auth == 'password' else {})


@pytest.mark.parametrize('option', [
    ['-o', 'StrictHostKeyChecking=no'], ['-oStrictHostKeyChecking=accept-new'],
    ['-o', 'UserKnownHostsFile=/dev/null'], ['-F', '/synthetic/config'],
    ['-o', 'HostKeyAlias=other'], ['-o', 'ProxyCommand=unsafe'], ['-A'],
    ['-o', 'GlobalKnownHostsFile=/synthetic/trust'], ['-o', 'UpdateHostKeys=yes'],
])
def test_extra_options_cannot_downgrade_trust(trust, option):
    with pytest.raises(ValueError):
        build_ssh_cmd(server(trust[0]), extra_opts=option)


def test_safe_extra_options_preserved(trust):
    cmd, _ = build_ssh_cmd(server(trust[0]), extra_opts=['-o', 'ServerAliveInterval=10'])
    assert 'ServerAliveInterval=10' in cmd


@pytest.mark.parametrize('kind', ['missing', 'directory', 'empty', 'malformed', 'relative', 'control', 'writable'])
def test_bad_trust_fails_before_transport_or_credentials(tmp_path, monkeypatch, kind):
    p = tmp_path / 'known_hosts'
    if kind == 'directory': p.mkdir()
    elif kind == 'empty': p.write_text('')
    elif kind == 'malformed': p.write_text('worker.test ssh-ed25519 garbage\n')
    elif kind == 'writable': p.write_text('invalid'); p.chmod(0o666)
    elif kind == 'relative': p = Path('relative-trust')
    elif kind == 'control': p = Path(str(p) + '\n')
    monkeypatch.setenv('DC_OVERVIEW_SSH_KNOWN_HOSTS', str(p))
    with pytest.raises(ValueError): build_ssh_cmd(server(password='synthetic-secret'))
    result = SSHManager(tmp_path).run_command('worker.test', 'mutation', password='synthetic-secret')
    assert not result.success and 'synthetic-secret' not in result.output


def test_trust_resolution_precedence(trust, tmp_path, monkeypatch):
    from dc_overview.ssh_trust import resolve_known_hosts_path
    p, _ = trust
    assert resolve_known_hosts_path(server(p)) == p
    assert resolve_known_hosts_path(known_hosts_path=p) == p
    monkeypatch.setenv('DC_OVERVIEW_SSH_KNOWN_HOSTS', str(p))
    assert resolve_known_hosts_path(server('/missing')) == p
    monkeypatch.setenv('DC_OVERVIEW_SSH_KNOWN_HOSTS', '/missing')
    with pytest.raises(ValueError): resolve_known_hosts_path(server(p))


@pytest.mark.parametrize('operation', ['run_key', 'run_password', 'test', 'scp', 'provision_key', 'provision_password'])
def test_manager_transports_strict_and_preserve_port(trust, tmp_path, monkeypatch, operation):
    p, _ = trust
    manager = SSHManager(tmp_path)
    manager.known_hosts_path = p
    manager.key_path.write_text('synthetic private key')
    manager.pub_key_path.write_text('synthetic public key')
    fake = Mock(return_value=subprocess.CompletedProcess([], 0, 'ok', ''))
    monkeypatch.setattr(subprocess, 'run', fake)
    monkeypatch.setattr('dc_overview.ssh_manager.shutil.which', lambda x: '/synthetic/sshpass')
    if operation.startswith('run'): result = manager.run_command('worker.test', 'mutation', port=2202, password='synthetic-secret' if operation.endswith('password') else None); assert result.success
    elif operation == 'test': assert manager.test_connection('worker.test', port=2202)
    elif operation == 'scp': assert manager.copy_file('worker.test', '/synthetic/local', '/synthetic/remote', port=2202)
    elif operation == 'provision_key': assert manager.deploy_key_with_existing_key('worker.test', 'operator', '/synthetic/key', port=2202)
    else: assert manager.deploy_key_with_password('worker.test', 'operator', 'synthetic-secret', port=2202)
    cmd = fake.call_args.args[0]
    assert 'StrictHostKeyChecking=yes' in cmd and 'ForwardAgent=no' in cmd
    assert f'UserKnownHostsFile="{p}"' in cmd
    flag = '-P' if operation == 'scp' else '-p'
    assert cmd[cmd.index(flag)+1] == '2202'
    assert 'synthetic-secret' not in cmd
    if operation.endswith('password'): assert fake.call_args.kwargs['env']['SSHPASS'] == 'synthetic-secret'


@pytest.mark.parametrize('operation', ['provision_key', 'provision_password'])
def test_provisioning_missing_trust_does_not_generate_key(tmp_path, monkeypatch, operation):
    manager = SSHManager(tmp_path)
    generate = Mock(side_effect=AssertionError('key mutation before trust'))
    monkeypatch.setattr(manager, 'generate_key', generate)
    monkeypatch.setattr('dc_overview.ssh_manager.shutil.which', lambda x: '/synthetic/sshpass')
    if operation.endswith('password'): assert not manager.deploy_key_with_password('worker.test', 'root', 'synthetic-secret')
    else: assert not manager.deploy_key_with_existing_key('worker.test', 'root', '/synthetic/key')
    generate.assert_not_called()


@pytest.mark.parametrize('state', ['matching', 'unknown', 'changed'])
@pytest.mark.parametrize('port', [22, 2202])
@pytest.mark.parametrize('command', ['uname -s -m', 'sudo -n -- privilege-probe', 'install-worker',
                                     'update-worker', 'verify-worker', 'rollback-worker', 'recover-worker'])
def test_paramiko_policy_authenticates_only_matching_enrolled_key(trust, tmp_path, monkeypatch, state, port, command):
    p, key = trust
    manager = SSHManager(tmp_path); manager.known_hosts_path = p
    client = paramiko.SSHClient()
    mutations = []
    credentials = []
    def connect(**kwargs):
        assert kwargs['allow_agent'] is False and kwargs['look_for_keys'] is False
        assert kwargs['auth_timeout'] == 10 and kwargs['banner_timeout'] == 10
        assert isinstance(client._policy, paramiko.RejectPolicy)
        host = 'unknown.test' if state == 'unknown' else 'worker.test'
        lookup = host if port == 22 else f'[{host}]:{port}'
        enrolled = client.get_host_keys().lookup(lookup)
        if not enrolled: raise paramiko.SSHException('Host is not enrolled')
        presented = paramiko.RSAKey.generate(1024) if state == 'changed' else key
        if enrolled[presented.get_name()] != presented: raise paramiko.BadHostKeyException(host, presented, enrolled[presented.get_name()])
        credentials.append(kwargs['password'])
    monkeypatch.setattr(client, 'connect', connect)
    monkeypatch.setattr(paramiko, 'SSHClient', lambda: client)
    monkeypatch.setattr('dc_overview.ssh_manager.shutil.which', lambda x: None)
    monkeypatch.setattr('dc_overview.quickstart._run_paramiko_command', lambda *args: (mutations.append(args[1]) or (0, 'verified', '')))
    before = p.read_bytes()
    result = manager.run_command('worker.test' if state != 'unknown' else 'unknown.test', command, port=port, password='synthetic-secret')
    assert isinstance(client._policy, paramiko.RejectPolicy)
    assert result.success == (state == 'matching')
    assert bool(credentials) == bool(mutations) == (state == 'matching')
    assert p.read_bytes() == before


@pytest.mark.parametrize('auth', ['key', 'password', 'default'])
def test_legacy_exporter_builder_uses_same_trust(trust, monkeypatch, auth):
    monkeypatch.setenv('DC_OVERVIEW_SSH_KNOWN_HOSTS', str(trust[0]))
    cmd, env = _build_exporter_ssh_cmd('worker.test', ssh_port=2202, ssh_key_path='/synthetic/key' if auth == 'key' else None, ssh_password='synthetic-secret' if auth == 'password' else None)
    assert 'StrictHostKeyChecking=yes' in cmd and 'ForwardAgent=no' in cmd
    assert f'UserKnownHostsFile="{trust[0]}"' in cmd
    assert 'synthetic-secret' not in cmd


def test_owned_outbound_sources_have_no_implicit_trust_downgrade():
    import dc_overview
    root = Path(dc_overview.__file__).parent
    for name in ['ssh_manager.py', 'ssh_helpers.py', 'deploy.py', 'fleet_wizard.py', 'quickstart.py', 'exporters.py']:
        source = (root/name).read_text()
        assert 'StrictHostKeyChecking=no' not in source
        assert 'AutoAddPolicy' not in source


@pytest.mark.parametrize('operation', ['test', 'run', 'provision'])
def test_legacy_deploy_routes_use_canonical_or_explicit_trust(trust, tmp_path, monkeypatch, operation):
    from dc_overview.deploy import DeployManager, Worker
    monkeypatch.setenv('DC_OVERVIEW_SSH_KNOWN_HOSTS', str(trust[0]))
    manager = DeployManager(tmp_path)
    worker = Worker('worker', 'worker.test', ssh_port=2202)
    generate = Mock(return_value=('/synthetic/key', 'synthetic public key'))
    monkeypatch.setattr(manager, 'generate_ssh_key', generate)
    fake = Mock(return_value=subprocess.CompletedProcess([], 0, 'ok', ''))
    monkeypatch.setattr(subprocess, 'run', fake)
    if operation == 'test': assert manager.test_ssh_connection(worker)
    elif operation == 'run': assert manager.run_remote_command(worker, 'mutation')[0]
    else: assert manager.deploy_ssh_key_to_worker(worker, 'synthetic-secret')
    cmd = fake.call_args.args[0]
    assert 'StrictHostKeyChecking=yes' in cmd and 'ControlPath=none' in cmd
    assert cmd[cmd.index('-p')+1] == '2202'
    assert 'synthetic-secret' not in cmd
    if operation == 'provision': assert fake.call_args.kwargs['env']['SSHPASS'] == 'synthetic-secret'


def test_legacy_provision_missing_trust_holds_before_key_mutation(tmp_path, monkeypatch):
    from dc_overview.deploy import DeployManager, Worker
    monkeypatch.setenv('DC_OVERVIEW_SSH_KNOWN_HOSTS', '/synthetic/missing')
    manager = DeployManager(tmp_path)
    generate = Mock()
    monkeypatch.setattr(manager, 'generate_ssh_key', generate)
    assert not manager.deploy_ssh_key_to_worker(Worker('worker', 'worker.test'), 'synthetic-secret')
    generate.assert_not_called()


@pytest.mark.parametrize('auth', ['password', 'ed25519-key'])
def test_quickstart_loads_trust_before_auth_and_preserves_generic_key_loader(trust, monkeypatch, auth):
    from dc_overview import quickstart
    monkeypatch.setenv('DC_OVERVIEW_SSH_KNOWN_HOSTS', str(trust[0]))
    client = Mock()
    monkeypatch.setattr(paramiko, 'SSHClient', lambda: client)
    monkeypatch.setattr(quickstart, '_run_paramiko_command', lambda *a: (1, '', ''))
    quickstart.install_exporters_remote('worker.test', 'operator', port=2202,
                                      password='synthetic-secret' if auth == 'password' else None,
                                      key_path='/synthetic/id_ed25519' if auth != 'password' else None)
    client.load_host_keys.assert_called_once_with(str(trust[0]))
    assert isinstance(client.set_missing_host_key_policy.call_args.args[0], paramiko.RejectPolicy)
    kwargs = client.connect.call_args.kwargs
    assert kwargs['allow_agent'] is False and kwargs['look_for_keys'] is False
    assert kwargs['port'] == 2202
    if auth != 'password': assert kwargs['key_filename'] == '/synthetic/id_ed25519'
    client.close.assert_called_once()


def test_paramiko_missing_trust_never_connects_or_mutates(tmp_path, monkeypatch):
    from dc_overview import quickstart
    monkeypatch.setenv('DC_OVERVIEW_SSH_KNOWN_HOSTS', str(tmp_path/'missing'))
    client = Mock(); monkeypatch.setattr(paramiko, 'SSHClient', lambda: client)
    assert not quickstart.install_exporters_remote('worker.test', 'root', password='synthetic-secret')
    client.connect.assert_not_called(); client.exec_command.assert_not_called()


def test_fleet_hostname_uses_config_directory_trust(trust, tmp_path, monkeypatch):
    from dc_overview.fleet_wizard import FleetWizard
    manager = FleetWizard.__new__(FleetWizard)
    manager.config_dir = tmp_path
    (tmp_path/'known_hosts').write_bytes(trust[0].read_bytes())
    manager.config = SimpleNamespace(ssh=SimpleNamespace(port=2202, key_path='/synthetic/key', username='operator'))
    fake = Mock(return_value=subprocess.CompletedProcess([], 0, 'worker', ''))
    monkeypatch.setattr(subprocess, 'run', fake)
    assert manager._get_remote_hostname('worker.test') == 'worker'
    assert 'StrictHostKeyChecking=yes' in fake.call_args.args[0]


@pytest.mark.parametrize('marker', ['@cert-authority', '@revoked'])
def test_openssh_authorized_markers_preserved_paramiko_fails_closed(trust, marker):
    from dc_overview.ssh_trust import openssh_trust_options, configure_paramiko_host_trust
    p, _ = trust
    p.write_text(marker + ' ' + p.read_text())
    assert 'StrictHostKeyChecking=yes' in openssh_trust_options(known_hosts_path=p)
    client = Mock()
    with pytest.raises(ValueError, match='OpenSSH'):
        configure_paramiko_host_trust(client, known_hosts_path=p)
    client.load_host_keys.assert_not_called()


def synthetic_ed25519_host_key():
    import struct
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    public = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    kind = b'ssh-ed25519'
    blob = struct.pack('>I', len(kind)) + kind + struct.pack('>I', len(public)) + public
    return paramiko.Ed25519Key(data=blob)


@pytest.mark.parametrize('factory', [lambda: paramiko.RSAKey.generate(1024), lambda: paramiko.ECDSAKey.generate(), synthetic_ed25519_host_key])
def test_valid_host_key_algorithms_and_hashed_names_load(factory, tmp_path):
    from dc_overview.ssh_trust import configure_paramiko_host_trust
    key = factory(); hostname = '[worker.test]:2202'
    hashed = paramiko.HostKeys.hash_host(hostname)
    p = tmp_path/'known_hosts'; p.write_text(f'{hashed} {key.get_name()} {key.get_base64()}\n')
    client = paramiko.SSHClient()
    configure_paramiko_host_trust(client, known_hosts_path=p)
    assert client.get_host_keys().check(hostname, key)
    assert isinstance(client._policy, paramiko.RejectPolicy)


def test_provision_password_failure_never_prints_secret(trust, tmp_path, monkeypatch, capsys):
    manager = SSHManager(tmp_path); manager.known_hosts_path = trust[0]
    manager.key_path.write_text('synthetic'); manager.pub_key_path.write_text('synthetic')
    monkeypatch.setattr('dc_overview.ssh_manager.shutil.which', lambda x: '/synthetic/sshpass')
    monkeypatch.setattr(subprocess, 'run', Mock(side_effect=OSError('synthetic-secret')))
    assert not manager.deploy_key_with_password('worker.test', 'root', 'synthetic-secret')
    assert 'synthetic-secret' not in capsys.readouterr().out


@pytest.mark.parametrize('name', ['literal${HOME}', 'literal%h'])
def test_expanding_trust_paths_cannot_select_another_file(trust, tmp_path, name):
    from dc_overview.ssh_trust import openssh_trust_options
    p = tmp_path/name; p.write_bytes(trust[0].read_bytes())
    if '$' in name:
        with pytest.raises(ValueError): openssh_trust_options(known_hosts_path=p)
    else:
        options = openssh_trust_options(known_hosts_path=p)
        assert f'UserKnownHostsFile="{str(p).replace("%", "%%")}"' in options


def test_local_openssh_effective_options_preserve_routing_and_pin_trust(trust, tmp_path, monkeypatch):
    from dc_overview.ssh_trust import openssh_trust_options
    config = tmp_path/'ssh_config'
    config.write_text('Host worker.test\n HostName 192.0.2.77\n ProxyJump bastion.test:2203\n'
                      ' StrictHostKeyChecking no\n UserKnownHostsFile /synthetic/other\n'
                      ' GlobalKnownHostsFile /synthetic/global\n KnownHostsCommand /synthetic/helper\n'
                      ' VerifyHostKeyDNS yes\n UpdateHostKeys yes\n ForwardAgent yes\n'
                      ' ControlMaster auto\n ControlPath /synthetic/socket\n')
    cmd = ['/usr/bin/ssh', '-G', *openssh_trust_options(known_hosts_path=trust[0]),
           '-F', str(config), '-p', '2202', 'operator@worker.test']
    def configuration_only(argv, **kwargs):
        assert argv == cmd and argv[:2] == ['/usr/bin/ssh', '-G']
        return _LOCAL_CONFIGURATION_POPEN(argv, **kwargs)
    monkeypatch.setattr(subprocess, 'Popen', configuration_only)
    result = _LOCAL_CONFIGURATION_RUN(cmd, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0
    options = dict(line.split(' ', 1) for line in result.stdout.splitlines())
    assert options['hostname'] == '192.0.2.77'
    assert options['proxyjump'] == 'bastion.test:2203'
    assert options['stricthostkeychecking'] in ('yes', 'true')
    assert options['userknownhostsfile'] == str(trust[0])
    assert options['globalknownhostsfile'] == '/dev/null'
    assert options.get('knownhostscommand', 'none') == 'none'
    assert options['verifyhostkeydns'] in ('no', 'false')
    assert options['updatehostkeys'] in ('no', 'false')
    assert options['forwardagent'] in ('no', 'false')
    assert options['controlmaster'] in ('no', 'false')
    assert options.get('controlpath', 'none') == 'none'
    assert options['port'] == '2202'
