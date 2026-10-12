"""Selected completion must not drop authority when falling back from metrics."""
from types import SimpleNamespace
import importlib
import pytest
from conftest import app, client, auth_headers


@pytest.mark.parametrize('mode', ['rejected', 'accepted', 'missing', 'midway', 'metrics'])
def test_selected_completion_version_fallback_loses_identity_policy(
        app, client, auth_headers, tmp_path, monkeypatch, mode):
    accepted = mode in ('accepted', 'midway')
    mod = importlib.import_module('dc_overview.app')
    helpers = importlib.import_module('dc_overview.ssh_helpers')
    exporters = importlib.import_module('dc_overview.exporters')
    from dc_overview.worker_lifecycle import _identity_query
    from dc_overview.app import db, SSHKey, Server
    monkeypatch.setattr(mod.limiter, 'enabled', False)
    explicit = tmp_path / 'declared-key'
    explicit.write_text('synthetic reference only')
    trust = lambda *a, **k: ['-o', 'StrictHostKeyChecking=yes']
    monkeypatch.setattr(helpers, 'openssh_trust_options', trust)
    monkeypatch.setattr('dc_overview.ssh_trust.openssh_trust_options', trust)
    with app.app_context():
        key = SSHKey(name='version-key', key_path=str(explicit))
        db.session.add(key)
        db.session.flush()
        row = Server(name='worker-a', server_ip='192.0.2.8', ssh_key_id=key.id,
                     ssh_user='root', ssh_port=22)
        db.session.add(row)
        db.session.commit()
        server_id = row.id

    # A valid, intentionally held service has no metrics endpoint, so the real
    # get_exporter_version implementation naturally takes its SSH fallback.
    monkeypatch.setattr(mod, 'check_services_installed', lambda *a, **k: {
        name: {'installed': name in ('node_exporter', 'dc_exporter'), 'active': False}
        for name in ('node_exporter', 'dc_exporter', 'dcgm_exporter', 'watchdog_agent')})
    monkeypatch.setattr(mod, 'check_exporter', lambda *a, **k: {'running': False})
    monkeypatch.setattr(mod, 'check_watchdog_agent', lambda *a, **k: {'running': False, 'installed': False})
    monkeypatch.setattr(mod, 'get_gpu_count_from_exporter', lambda *a, **k: 0)
    monkeypatch.setattr(mod, 'update_prometheus_targets', lambda: True)
    monkeypatch.setattr(exporters, 'get_version_from_metrics', lambda *a, **k: '2.4.1' if mode == 'metrics' else None)
    primary_commands = []
    version_commands = []

    def selected_probe(argv, **kwargs):
        primary_commands.append(argv)
        assert '-F' in argv and 'IdentityAgent=none' in argv
        if mode == 'missing':
            explicit.unlink()
        return SimpleNamespace(returncode=0)

    def alternate_identity_version_transport(argv, **kwargs):
        version_commands.append(argv)
        # Explicit key is rejected for this later command. An unrelated agent
        # or configured identity is accepted only if the builder leaves it eligible.
        restricted = '-F' in argv and 'IdentityAgent=none' in argv
        if mode == 'midway':
            explicit.unlink()
        return SimpleNamespace(returncode=0 if accepted or not restricted else 255,
                               stdout='node_exporter, version 9.9.9\n' if accepted or not restricted else '', stderr='')

    monkeypatch.setattr(helpers, 'subprocess', SimpleNamespace(run=selected_probe))
    monkeypatch.setattr(exporters, 'subprocess', SimpleNamespace(run=alternate_identity_version_transport))
    identity = client.get(f'/api/servers/{server_id}/ssh-config?selected_enrollment=1',
                          headers=auth_headers).get_json()['enrollment_identity']
    response = client.get(f'/api/servers/{server_id}/check' + _identity_query(identity), headers=auth_headers)
    if mode in ('missing', 'midway'):
        assert response.status_code == 503, response.get_json()
        assert len(version_commands) == (1 if mode == 'midway' else 0)
        with app.app_context():
            row = db.session.get(Server, server_id)
            assert row.node_exporter_installed is False and row.node_exporter_version is None
            assert row.dc_exporter_installed is False and row.dc_exporter_version is None
        return
    assert response.status_code == 200, response.get_json()
    if mode == 'metrics':
        assert len(primary_commands) == 1 and version_commands == []
        with app.app_context():
            assert db.session.get(Server, server_id).node_exporter_version == '2.4.1'
        return
    assert len(primary_commands) == 1 and len(version_commands) == 2
    for command in version_commands:
        assert command[command.index('-i') + 1] == str(explicit)
        assert 'IdentityAgent=none' in command and 'IdentityFile=none' in command and 'CertificateFile=none' in command
        assert command[command.index('-F')+1] == '/dev/null'
    with app.app_context():
        row = db.session.get(Server, server_id)
        assert row.node_exporter_version == ('9.9.9' if accepted else None)
        assert row.dc_exporter_version == ('9.9.9' if accepted else None)


def selected_host(tmp_path):
    key=tmp_path/'declared-key';key.write_text('synthetic reference only')
    return SimpleNamespace(name='worker-a',server_ip='192.0.2.8',ssh_user='operator',ssh_port=2202,
        ssh_password='synthetic-unused-password',ssh_key=SimpleNamespace(key_path=str(key)),ssh_key_id=1,
        ssh_known_hosts_path=str(tmp_path/'known_hosts'),_selected_ssh_key_strict=True,
        _selected_effective_key_path=str(key))


@pytest.mark.parametrize('exporter,output,version',[
    ('node_exporter','node_exporter, version 1.7.0','1.7.0'),
    ('dc_exporter','dc-exporter-rs 0.2.9','0.2.9'),
    ('dcgm_exporter','nvidia/dcgm-exporter:3.3.5-3.4.1-ubuntu','3.3.5-3.4.1')])
@pytest.mark.parametrize('selected', [False, True])
def test_version_builder_preserves_context_and_parsers(tmp_path,monkeypatch,exporter,output,version,selected):
    mod=importlib.import_module('dc_overview.exporters');helpers=importlib.import_module('dc_overview.ssh_helpers')
    host=selected_host(tmp_path);calls=[]
    monkeypatch.setattr(helpers,'openssh_trust_options',lambda server:
        ['-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={server.ssh_known_hosts_path}'])
    monkeypatch.setattr('dc_overview.ssh_trust.openssh_trust_options',lambda:
        ['-o','StrictHostKeyChecking=yes'])
    monkeypatch.setattr(mod,'get_version_from_metrics',lambda *a:None)
    def transport(argv,**kwargs):
        calls.append(argv);assert kwargs['env'] is None
        return SimpleNamespace(returncode=0,stdout=output,stderr='')
    monkeypatch.setattr(mod,'subprocess',SimpleNamespace(run=transport))
    assert mod.get_exporter_version(host.server_ip,exporter,host.ssh_user,host.ssh_port,
        host._selected_effective_key_path,host.ssh_password,
        **({'selected_server':host} if selected else {}))==version
    command=calls[0]
    from test_selected_ssh_identity_authority import _assert_selected_profile
    if selected:
        _assert_selected_profile(command,host._selected_effective_key_path)
        assert f'UserKnownHostsFile={host.ssh_known_hosts_path}' in command
    else:
        assert '-F' not in command and 'IdentityAgent=none' not in command
        assert command[command.index('-i')+1] == host._selected_effective_key_path
    assert command[-2]=='operator@192.0.2.8' and command[command.index('-p')+1]=='2202'


@pytest.mark.parametrize('fault',['missing','context','endpoint'])
def test_selected_version_missing_reference_or_context_cannot_use_password_or_ambient(tmp_path,monkeypatch,fault):
    mod=importlib.import_module('dc_overview.exporters');helpers=importlib.import_module('dc_overview.ssh_helpers')
    host=selected_host(tmp_path);calls=[]
    monkeypatch.setattr(helpers,'openssh_trust_options',lambda server:['-o','StrictHostKeyChecking=yes'])
    monkeypatch.setattr(mod,'get_version_from_metrics',lambda *a:None)
    monkeypatch.setattr(mod,'subprocess',SimpleNamespace(run=lambda *a,**k:calls.append(a)))
    if fault=='missing': __import__('pathlib').Path(host._selected_effective_key_path).unlink()
    if fault=='context': host._selected_ssh_key_strict=False
    with pytest.raises(ValueError):
        mod.get_exporter_version('192.0.2.9' if fault=='endpoint' else host.server_ip,'node_exporter',
            host.ssh_user,host.ssh_port,host._selected_effective_key_path,host.ssh_password,selected_server=host)
    assert calls==[]
