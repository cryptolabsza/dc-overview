"""Desired selected key-authority boundaries, derived from independent counterexamples."""
from types import SimpleNamespace
from urllib.parse import urlsplit
import importlib
import pytest

from conftest import app, client, auth_headers


@pytest.mark.parametrize('restrict_agent', [False, True])
def test_readable_rejected_key_can_be_certified_using_ambient_identity(
        app, client, auth_headers, tmp_path, monkeypatch, restrict_agent):
    from dc_overview.app import db, Server as Row, SSHKey
    from dc_overview.fleet_config import FleetConfig, Server
    from dc_overview.worker_lifecycle import register_worker
    helpers = importlib.import_module('dc_overview.ssh_helpers')
    mod = importlib.import_module('dc_overview.app')
    monkeypatch.setattr(mod.limiter, 'enabled', False)
    explicit = tmp_path / 'readable-but-not-authorized-key'
    explicit.write_text('synthetic reference only; no real credential')
    commands = []
    monkeypatch.setattr(helpers, 'openssh_trust_options',
                        lambda server: ['-o', 'StrictHostKeyChecking=yes'] +
                        (['-o', 'IdentitiesOnly=yes'] if restrict_agent else []))

    def documented_openssh_agent_adapter(argv, **kwargs):
        # Constructed environment: the explicit identity is rejected, but an
        # unrelated agent identity is accepted. OpenSSH tries agent identities
        # by default even with -i; see local ssh_config(5), IdentityFile.
        commands.append(argv)
        assert argv[argv.index('-i') + 1] == str(explicit)
        restricted = 'IdentitiesOnly=yes' in argv or 'IdentityAgent=none' in argv
        return SimpleNamespace(returncode=255 if restricted else 0)

    monkeypatch.setattr(helpers, 'subprocess', SimpleNamespace(run=documented_openssh_agent_adapter))
    with app.app_context():
        key = SSHKey(name='explicit-test-key', key_path=str(explicit))
        db.session.add(key)
        db.session.flush()
        row = Row(name='worker-a', server_ip='192.0.2.8', ssh_key_id=key.id,
                  ssh_user='root', ssh_port=22)
        db.session.add(row)
        db.session.commit()
        key_id = key.id

    class API:
        def request(self, method, url, **kwargs):
            parsed = urlsplit(url)
            path = parsed.path.removeprefix('/dc')
            if parsed.query:
                path += '?' + parsed.query
            response = client.open(path, method=method, json=kwargs.get('json'), headers=auth_headers)
            return SimpleNamespace(status_code=response.status_code, json=response.get_json)

    with pytest.raises(ValueError, match='reachability'):
        register_worker(API(), Server(name='worker-a', server_ip='192.0.2.8'),
                        FleetConfig(), base_url='https://fleet.example', ssh_key_id=key_id)
    assert len(commands)==1


def test_host_installer_transport_also_allows_ambient_identities(tmp_path, monkeypatch):
    from dc_overview.ssh_manager import SSHManager
    mod = importlib.import_module('dc_overview.ssh_manager')
    key = tmp_path / 'host-explicit-key'
    key.write_text('synthetic reference only; no real credential')
    monkeypatch.setattr(mod, 'openssh_trust_options', lambda **kwargs: ['-o', 'StrictHostKeyChecking=yes'])
    calls = []

    def transport(argv, **kwargs):
        calls.append(argv)
        assert argv[argv.index('-i') + 1] == str(key)
        return SimpleNamespace(returncode=0, stdout='synthetic success', stderr='')

    monkeypatch.setattr(mod, 'subprocess', SimpleNamespace(run=transport))
    result = SSHManager(tmp_path).run_command('192.0.2.8', 'synthetic-command', key_path=str(key), selected_identity=True)
    assert result.success
    assert 'IdentitiesOnly=yes' in calls[0] and 'IdentityAgent=none' in calls[0]
    assert calls[0][calls[0].index('-F')+1]=='/dev/null'


@pytest.mark.parametrize('disappears', [False, True])
def test_watchdog_keeps_declared_identity_after_preflight(tmp_path, monkeypatch, disappears):
    from dc_overview.fleet_config import FleetConfig, Server
    from test_selected_worker_enrollment import plan_for
    from unittest.mock import Mock
    lifecycle = importlib.import_module('dc_overview.worker_lifecycle')
    helpers = importlib.import_module('dc_overview.ssh_helpers')
    watchdog = importlib.import_module('dc_overview.web_watchdog')
    explicit = tmp_path / 'host-explicit'
    explicit.write_text('synthetic nonsecret reference')
    config = FleetConfig(config_dir=tmp_path)
    config.servers = [Server(name='worker-a', server_ip='192.0.2.8', ssh_key_path=str(explicit))]
    checks = []

    def identity_guard():
        checks.append('container identity unchanged')
        if disappears and len(checks) == 3:
            explicit.unlink()

    config._enrollment_identity_guard = identity_guard
    ssh = Mock(known_hosts_path=tmp_path/'known_hosts', key_path=explicit)
    ssh.run_command.side_effect = [SimpleNamespace(success=True, output='Linux x86_64'),
                                   SimpleNamespace(success=True, output='WORKER_PREFLIGHT=verified')]
    monkeypatch.setattr(lifecycle, 'SSHManager', lambda *a: ssh)
    # Declared already-installed observation at the reconcile boundary; the
    # per-component lifecycle, host construction and real Watchdog builder run.
    monkeypatch.setattr(lifecycle, 'preflight_workers', lambda *a, **k:
                        {'worker-a': {'dc-watchdog-agent': {'delivery_mode': 'update'}}})
    monkeypatch.setattr(lifecycle, '_observe_worker_components', lambda *a, **k:
                        {'dc-watchdog-agent': 'update'})
    original_exists = helpers.os.path.exists
    monkeypatch.setattr(helpers.os.path, 'exists', lambda path:
                        True if str(path) == '/etc/dc-overview/ssh_keys/fleet_key' else original_exists(path))
    monkeypatch.setattr(helpers, 'openssh_trust_options', lambda server:
                        ['-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={server.ssh_known_hosts_path}'])
    calls = []

    def stop_after_actual_command_construction(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=255, stdout='', stderr='declared stop before remote execution')

    monkeypatch.setattr(watchdog, 'subprocess', SimpleNamespace(run=stop_after_actual_command_construction,TimeoutExpired=__import__('subprocess').TimeoutExpired))
    outcome = lifecycle.upgrade_workers(config, plan_for('dc-watchdog-agent'), mode='reconcile')
    assert not outcome['dc-watchdog-agent']['success']
    if disappears:
        assert calls == []
    else:
        assert len(calls) == 1
        _assert_selected_profile(calls[0], explicit)
        assert f'UserKnownHostsFile={tmp_path / "known_hosts"}' in calls[0]


def _assert_selected_profile(argv,key):
    assert argv[argv.index('-F')+1]=='/dev/null'
    assert [argv[index+1] for index,item in enumerate(argv) if item=='-i']==[str(key)]
    for option in ('IdentitiesOnly=yes','IdentityAgent=none','IdentityFile=none','CertificateFile=none','BatchMode=yes','PreferredAuthentications=publickey'):
        assert option in argv


@pytest.mark.parametrize('accepted',[False,True])
def test_selected_container_profile_excludes_config_cert_and_agent(tmp_path,monkeypatch,accepted):
    helpers=importlib.import_module('dc_overview.ssh_helpers')
    key=tmp_path/'declared key';key.write_text('synthetic reference only')
    host=SimpleNamespace(name='worker-a',server_ip='192.0.2.8',ssh_user='ubuntu',ssh_port=2202,
                         ssh_password=None,ssh_key_id=4,ssh_key=SimpleNamespace(key_path=str(key)),
                         _selected_ssh_key_strict=True,_selected_effective_key_path=str(key))
    monkeypatch.setattr(helpers,'openssh_trust_options',lambda server:['-o','StrictHostKeyChecking=yes'])
    calls=[]
    def transport(argv,**kwargs):
        calls.append(argv)
        # Declared competing config/certificate/agent identities accept this
        # worker, while the selected key succeeds only in the positive case.
        exclusive=('-F' in argv and argv[argv.index('-F')+1]=='/dev/null'
                   and 'IdentityAgent=none' in argv and 'CertificateFile=none' in argv)
        return SimpleNamespace(returncode=0 if accepted or not exclusive else 255)
    monkeypatch.setattr(helpers,'subprocess',SimpleNamespace(run=transport))
    result=helpers.check_ssh_connection(host)
    assert result['connected'] is accepted
    _assert_selected_profile(calls[0],key)
    assert calls[0][-2]=='ubuntu@192.0.2.8' and calls[0][calls[0].index('-p')+1]=='2202'


def test_selected_native_openssh_parser_excludes_ambient_configuration(tmp_path,monkeypatch):
    import os
    import subprocess
    from dc_overview.ssh_helpers import build_ssh_cmd
    from test_verified_ssh_transport import server
    key=tmp_path/'declared-key';key.write_text('synthetic reference only')
    known=tmp_path/'known_hosts'
    import base64,struct
    algorithm=b'ssh-ed25519';blob=struct.pack('>I',len(algorithm))+algorithm+struct.pack('>I',32)+b'a'*32
    known.write_text('192.0.2.8 ssh-ed25519 '+base64.b64encode(blob).decode()+'\n');known.chmod(0o600)
    home=tmp_path/'synthetic-home';(home/'.ssh').mkdir(parents=True)
    other=tmp_path/'ambient-identity';other.write_text('synthetic reference only')
    (home/'.ssh/config').write_text(f'Host *\n IdentityFile {other}\n CertificateFile {other}-cert.pub\n IdentityAgent {tmp_path}/ambient-agent\n ProxyJump unrelated.test\n')
    monkeypatch.setenv('HOME',str(home));monkeypatch.setenv('SSH_AUTH_SOCK',str(tmp_path/'ambient-agent'))
    host=SimpleNamespace(name='worker-a',server_ip='192.0.2.8',ssh_user='operator',ssh_port=2202,
        ssh_known_hosts_path=str(known),ssh_password=None,ssh_key_id=1,ssh_key=SimpleNamespace(key_path=str(key)),
        _selected_ssh_key_strict=True,_selected_effective_key_path=str(key))
    command,_=build_ssh_cmd(host)
    _assert_selected_profile(command,key)  # RED stops before any non-exclusive native parser execution.
    result=subprocess.run(['/usr/bin/ssh','-G',*command[1:]],capture_output=True,text=True,timeout=10,
                          env={**os.environ,'SELECTED_IDENTITY_CONFIG_FIXTURE':'1','SELECTED_IDENTITY_FIXTURE_ROOT':str(tmp_path)})
    assert result.returncode==0,result.stderr
    pairs=[line.split(' ',1) for line in result.stdout.splitlines()]
    values={name:value for name,value in pairs}
    assert [value for name,value in pairs if name=='identityfile' and value!='none']==[str(key)]
    assert ('identityfile','none') in [tuple(pair) for pair in pairs]
    assert values['identityagent']=='none' and values['certificatefile']=='none'
    assert values['identitiesonly'] in ('yes','true') and values['batchmode'] in ('yes','true')
    assert values['preferredauthentications']=='publickey'
    assert values['user']=='operator' and values['port']=='2202' and values['hostname']=='192.0.2.8'
    assert values.get('proxyjump','none')=='none'
    assert values['stricthostkeychecking'] in ('yes','true')


@pytest.mark.parametrize('bad',['token','relative','missing'])
def test_selected_host_key_reference_invalid_never_invokes_native_transport(tmp_path,monkeypatch,bad):
    from dc_overview.ssh_manager import SSHManager
    mod=importlib.import_module('dc_overview.ssh_manager')
    monkeypatch.setattr(mod,'openssh_trust_options',lambda **kwargs:['-o','StrictHostKeyChecking=yes'])
    key=tmp_path/('key-%h' if bad=='token' else 'missing')
    if bad!='missing':key.write_text('synthetic reference only')
    path='relative-key' if bad=='relative' else str(key)
    calls=[];monkeypatch.setattr(mod,'subprocess',SimpleNamespace(run=lambda *a,**k:calls.append(a)))
    result=SSHManager(tmp_path).run_command('192.0.2.8','bounded-command',key_path=path,selected_identity=True)
    assert not result.success and calls==[]


def test_selected_client_file_disappearance_cannot_activate_default_identity(tmp_path,monkeypatch):
    from dc_overview.ssh_manager import SSHManager
    mod=importlib.import_module('dc_overview.ssh_manager');key=tmp_path/'disappearing-key';key.write_text('synthetic reference')
    monkeypatch.setattr(mod,'openssh_trust_options',lambda **kwargs:['-o','StrictHostKeyChecking=yes'])
    calls=[]
    def transport(argv,**kwargs):
        # If -i becomes inaccessible at client startup, OpenSSH may omit it;
        # explicit IdentityFile=none must still suppress default file identities.
        key.unlink();calls.append(argv)
        restricted='IdentityFile=none' in argv
        return SimpleNamespace(returncode=255 if restricted else 0,stdout='',stderr='declared missing identity')
    monkeypatch.setattr(mod,'subprocess',SimpleNamespace(run=transport,TimeoutExpired=__import__('subprocess').TimeoutExpired))
    result=SSHManager(tmp_path).run_command('192.0.2.8','bounded-command',key_path=str(key),selected_identity=True)
    assert not result.success
    assert 'IdentityFile=none' in calls[0]


def test_selected_key_transport_rejects_password_before_any_fallback(tmp_path,monkeypatch):
    from dc_overview.ssh_manager import SSHManager
    mod=importlib.import_module('dc_overview.ssh_manager')
    monkeypatch.setattr(mod,'openssh_trust_options',lambda **kwargs:['-o','StrictHostKeyChecking=yes'])
    def undeclared(*args,**kwargs):
        pytest.fail('Selected password fallback must not enter another transport')
    monkeypatch.setattr(mod.shutil,'which',undeclared)
    monkeypatch.setattr(mod,'subprocess',SimpleNamespace(run=undeclared))
    result=SSHManager(tmp_path).run_command('192.0.2.8','bounded-command',
        key_path=str(tmp_path/'declared-key'),password='synthetic-current-password',selected_identity=True)
    assert not result.success and 'password fallback' in result.output
