"""Installer coverage for the shared DC/IPMI credential transport secret."""

import stat
import json
import subprocess
from types import SimpleNamespace as Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest
from jinja2 import Environment, FileSystemLoader

from dc_overview.fleet_config import FleetConfig
from dc_overview.fleet_manager import FleetManager
from dc_overview.quickstart import _render_quickstart_environment


@pytest.fixture
def absent_ipmi(monkeypatch):
    def inspect(command, **kwargs):
        assert command == ['docker', 'inspect', 'ipmi-monitor']
        return SimpleNamespace(returncode=1, stdout='[]\n', stderr='Error: No such object: ipmi-monitor\n')
    monkeypatch.setattr('dc_overview.fleet_manager.subprocess.run', inspect)


def _fleet_config(tmp_path, *, existing_proxy=True):
    config = FleetConfig(config_dir=tmp_path)
    config.components.ipmi_monitor = True
    config.ssl.use_existing_proxy = existing_proxy
    return config


def _existing_inspect(tmp_path):
    secret = tmp_path / 'customer-inventory-secret'
    secret.write_text('customer' * 8)
    return {'Name':'/ipmi-monitor', 'Config':{'Image':'ghcr.io/cryptolabsza/ipmi-monitor:customer',
             'Env':['FLEET_CREDENTIAL_AUTHORITY=vault', 'IPMI_INVENTORY_SECRET_FILE=/run/secrets/dc-ipmi-inventory']},
            'HostConfig':{'Binds':[f'{secret}:/run/secrets/dc-ipmi-inventory:ro']}, 'Mounts':[]}


@pytest.mark.parametrize('failure', ['timeout','missing-client','daemon','permission','wrong-absence',
    'mixed-absence','malformed','empty','mapping','multiple','scalar','wrong-name','config','env','host-config','binds','mounts',
    'missing-env','missing-binds','missing-mounts','null-mounts','mount-source','mount-destination'])
@pytest.mark.parametrize('render_only', [False,True])
def test_ipmi_inspection_unknown_custody_fails_before_compose_or_secret_write(tmp_path, monkeypatch, failure, render_only):
    from dc_overview import fleet_manager
    inspected=_existing_inspect(tmp_path)
    raw=json.dumps([inspected]); stderr=''; code=0
    if failure=='daemon':code=1;stderr='Cannot connect to the Docker daemon'
    elif failure=='permission':code=1;stderr='permission denied while trying to connect to the Docker daemon socket'
    elif failure=='wrong-absence':code=1;stderr='Error: No such object: unrelated'
    elif failure=='mixed-absence':code=1;stderr='Error: No such object: ipmi-monitor\npermission denied'
    elif failure=='malformed':raw='not json'
    elif failure=='empty':raw='[]'
    elif failure=='mapping':raw=json.dumps(inspected)
    elif failure=='multiple':raw=json.dumps([inspected,inspected])
    elif failure=='scalar':raw='[1]'
    elif failure=='wrong-name':inspected['Name']='/unrelated';raw=json.dumps([inspected])
    elif failure=='config':inspected['Config']=[];raw=json.dumps([inspected])
    elif failure=='env':inspected['Config']['Env']=[1];raw=json.dumps([inspected])
    elif failure=='host-config':inspected['HostConfig']=[];raw=json.dumps([inspected])
    elif failure=='binds':inspected['HostConfig']['Binds']=[1];raw=json.dumps([inspected])
    elif failure=='mounts':inspected['Mounts']=[1];raw=json.dumps([inspected])
    elif failure=='missing-env':del inspected['Config']['Env'];raw=json.dumps([inspected])
    elif failure=='missing-binds':del inspected['HostConfig']['Binds'];raw=json.dumps([inspected])
    elif failure=='missing-mounts':del inspected['Mounts'];raw=json.dumps([inspected])
    elif failure=='null-mounts':inspected['Mounts']=None;raw=json.dumps([inspected])
    elif failure=='mount-source':inspected['Mounts']=[{'Type':'bind','Source':1,'Destination':'/custom/data'}];raw=json.dumps([inspected])
    elif failure=='mount-destination':inspected['Mounts']=[{'Type':'bind','Source':'/customer/data','Destination':1}];raw=json.dumps([inspected])
    calls=[]
    def run(command, **kwargs):
        calls.append((command,kwargs))
        if failure=='timeout':raise subprocess.TimeoutExpired(command,kwargs.get('timeout',999))
        if failure=='missing-client':raise FileNotFoundError('docker')
        return SimpleNamespace(returncode=code,stdout=raw,stderr=stderr)
    monkeypatch.setattr(fleet_manager.subprocess,'run',run)
    manager=FleetManager(_fleet_config(tmp_path));manager._render_only=render_only
    before={str(p):p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    with pytest.raises(RuntimeError,match='IPMI Monitor inspection prerequisite:'):
        manager._generate_docker_compose()
    assert calls[0][0]==['docker','inspect','ipmi-monitor']
    assert calls[0][1]['timeout']==15
    assert before=={str(p):p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    assert not (tmp_path/'secrets').exists()


@pytest.mark.parametrize('stderr',['Error: No such object: ipmi-monitor\n','Error response from daemon: No such container: ipmi-monitor\n'])
def test_ipmi_inspection_exact_named_absence_is_bounded_and_readonly(monkeypatch, stderr):
    from dc_overview.fleet_manager import inspect_ipmi_monitor
    calls=[]
    def run(command, **kwargs):
        calls.append((command,kwargs))
        return SimpleNamespace(returncode=1,stdout='[]\n',stderr=stderr)
    monkeypatch.setattr('dc_overview.fleet_manager.subprocess.run',run)
    assert inspect_ipmi_monitor() is None
    assert calls==[(['docker','inspect','ipmi-monitor'],{'capture_output':True,'text':True,'timeout':15})]


@pytest.mark.parametrize('render_only',[False,True])
def test_ipmi_genuine_inspection_retains_customer_mount_and_authority(tmp_path,monkeypatch,render_only):
    inspected=_existing_inspect(tmp_path)
    monkeypatch.setattr('dc_overview.fleet_manager.subprocess.run',lambda *a,**k:SimpleNamespace(returncode=0,stdout=json.dumps([inspected]),stderr=''))
    manager=FleetManager(_fleet_config(tmp_path));manager._render_only=render_only
    before={str(p):p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    compose=manager._generate_docker_compose()
    assert f'{tmp_path}/customer-inventory-secret:/run/secrets/dc-ipmi-inventory:ro' in compose
    assert 'FLEET_CREDENTIAL_AUTHORITY=vault' in compose
    assert before=={str(p):p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    assert not (tmp_path/'secrets').exists()


def test_ipmi_render_only_absent_custody_does_not_create_secret(tmp_path, absent_ipmi):
    manager=FleetManager(_fleet_config(tmp_path));manager._render_only=True
    compose=manager._generate_docker_compose()
    assert f'{tmp_path}/secrets/dc-ipmi-inventory:/run/secrets/dc-ipmi-inventory:ro' in compose
    assert not (tmp_path/'secrets').exists()


@pytest.mark.parametrize('canonical',[False,True])
@pytest.mark.parametrize('render_only',[False,True])
def test_IPMI_INSPECT01_missing_mounted_secret_holds_even_canonical_path(tmp_path,monkeypatch,canonical,render_only):
    from dc_overview import fleet_manager
    secret=tmp_path/'secrets'/'dc-ipmi-inventory' if canonical else tmp_path/'customer-secret'
    existing={'Name':'/ipmi-monitor','Config':{'Env':['FLEET_CREDENTIAL_AUTHORITY=vault']},
              'HostConfig':{'Binds':[f'{secret}:/run/secrets/dc-ipmi-inventory:ro']},'Mounts':[]}
    monkeypatch.setattr(fleet_manager.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=0,stdout=json.dumps([existing]),stderr=''))
    mutation=[];monkeypatch.setattr(fleet_manager.os,'chmod',lambda *args:mutation.append(('chmod',args)))
    monkeypatch.setattr(fleet_manager.os,'chown',lambda *args:mutation.append(('chown',args)))
    manager=FleetManager(_fleet_config(tmp_path));manager._render_only=render_only
    with pytest.raises(RuntimeError,match='Existing IPMI inventory secret mount is unavailable'):
        manager._generate_docker_compose()
    assert list(tmp_path.iterdir())==[] and mutation==[]


@pytest.mark.parametrize('existing_secret',[False,True])
@pytest.mark.parametrize('render_only',[False,True])
def test_IPMI_INSPECT02_invalid_authority_rejects_before_custody_mutation(tmp_path,monkeypatch,existing_secret,render_only):
    from dc_overview import fleet_manager
    secret=tmp_path/'secrets'/'dc-ipmi-inventory'
    if existing_secret:
        secret.parent.mkdir();secret.write_text('customer'*8);secret.chmod(0o640)
    existing={'Name':'/ipmi-monitor','Config':{'Env':['FLEET_CREDENTIAL_AUTHORITY=unsupported-authority']},
              'HostConfig':{'Binds':None},'Mounts':[]}
    monkeypatch.setattr(fleet_manager.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=0,stdout=json.dumps([existing]),stderr=''))
    mutation=[];monkeypatch.setattr(fleet_manager.os,'chown',lambda *args:mutation.append(('chown',args)))
    real_chmod=fleet_manager.os.chmod
    def chmod(*args):mutation.append(('chmod',args));return real_chmod(*args)
    monkeypatch.setattr(fleet_manager.os,'chmod',chmod)
    before={str(p):(p.read_bytes(),stat.S_IMODE(p.stat().st_mode)) for p in tmp_path.rglob('*') if p.is_file()}
    manager=FleetManager(_fleet_config(tmp_path));manager._render_only=render_only
    with pytest.raises(RuntimeError,match='FLEET_CREDENTIAL_AUTHORITY must be local or vault'):
        manager._generate_docker_compose()
    assert mutation==[]
    assert before=={str(p):(p.read_bytes(),stat.S_IMODE(p.stat().st_mode)) for p in tmp_path.rglob('*') if p.is_file()}
    assert secret.parent.exists()==existing_secret


@pytest.mark.parametrize('binding',[':',':/app/data','/customer/data:',' :/app/data','/customer/data: '])
def test_IPMI_INSPECT03_malformed_binding_holds_before_new_custody(tmp_path,monkeypatch,binding):
    from dc_overview import fleet_manager
    existing={'Name':'/ipmi-monitor','Config':{'Env':[]},'HostConfig':{'Binds':[binding]},'Mounts':[]}
    monkeypatch.setattr(fleet_manager.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=0,stdout=json.dumps([existing]),stderr=''))
    manager=FleetManager(_fleet_config(tmp_path))
    with pytest.raises(RuntimeError,match='inspection prerequisite'):
        manager._generate_docker_compose()
    assert list(tmp_path.iterdir())==[]


@pytest.mark.parametrize('read_only',[False,True])
def test_IPMI_INSPECT04_engine_request_and_resolved_volume_preserve_identity(tmp_path,monkeypatch,read_only):
    from dc_overview import fleet_manager
    existing=_existing_inspect(tmp_path)
    existing['HostConfig']['Mounts']=[{'Type':'volume','Source':'ipmi-monitor-data','Target':'/app/data','ReadOnly':read_only,'VolumeOptions':{}}]
    existing['Mounts']=[{'Type':'volume','Name':'ipmi-monitor-data','Source':'/var/lib/docker/volumes/ipmi-monitor-data/_data','Destination':'/app/data','RW':not read_only}]
    monkeypatch.setattr(fleet_manager.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=0,stdout=json.dumps([existing]),stderr=''))
    inspected=fleet_manager.inspect_ipmi_monitor()
    assert inspected==existing
    suffix=':ro' if read_only else ''
    specs=fleet_manager._ipmi_mount_specs(inspected)
    assert specs.count('ipmi-monitor-data:/app/data'+suffix)==1
    assert not any('/var/lib/docker/volumes' in spec for spec in specs)
    manager=FleetManager(_fleet_config(tmp_path));manager._render_only=True
    before=(tmp_path/'customer-inventory-secret').read_bytes()
    compose=manager._generate_docker_compose()
    assert 'FLEET_CREDENTIAL_AUTHORITY=vault' in compose
    assert (tmp_path/'customer-inventory-secret').read_bytes()==before
    assert not (tmp_path/'secrets').exists()
    manager._render_only=False
    manager._wait_for_ipmi_monitor_ready=lambda:True
    manager._import_ssh_key_to_ipmi_monitor=lambda:None
    manager._activate_ai_license_in_ipmi_monitor=lambda:None
    monkeypatch.setattr(fleet_manager,'_ensure_docker_network',lambda:True)
    monkeypatch.setattr(fleet_manager,'Path',lambda value:tmp_path/'product-ipmi-config' if value=='/etc/ipmi-monitor' else Path(value))
    calls=[]
    def run(command,**kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0,stdout=json.dumps([existing]) if command==['docker','inspect','ipmi-monitor'] else '',stderr='')
    monkeypatch.setattr(fleet_manager.subprocess,'run',run)
    manager._deploy_ipmi_monitor()
    recreated=next(command for command in calls if command[:3]==['docker','run','-d'])
    assert 'ipmi-monitor-data:/app/data'+suffix in recreated
    assert f'{tmp_path}/customer-inventory-secret:/run/secrets/dc-ipmi-inventory:ro' in recreated
    assert 'FLEET_CREDENTIAL_AUTHORITY=vault' in recreated
    assert (tmp_path/'customer-inventory-secret').read_bytes()==before


def test_fleet_manager_creates_one_shared_local_secret_and_compose_wires_dc(tmp_path, absent_ipmi):
    manager = FleetManager(_fleet_config(tmp_path))

    secret_path, authority = manager._prepare_inventory_credential_transport()
    first_secret = secret_path.read_text(encoding="utf-8")
    second_path, second_authority = manager._prepare_inventory_credential_transport()

    assert second_path == secret_path
    assert first_secret == second_path.read_text(encoding="utf-8")
    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600
    assert authority == second_authority == "local"

    compose = manager._generate_docker_compose()
    assert "DC_IPMI_INVENTORY_SECRET_FILE=/run/secrets/dc-ipmi-inventory" in compose
    assert "IPMI_INVENTORY_URL=http://ipmi-monitor:5000" in compose
    assert "FLEET_CREDENTIAL_AUTHORITY=local" in compose
    assert f"{secret_path}:/run/secrets/dc-ipmi-inventory:ro" in compose


def test_root_provisioning_assigns_canonical_secret_to_dc_container_uid(tmp_path, monkeypatch, absent_ipmi):
    manager = FleetManager(_fleet_config(tmp_path))
    chowns = []
    monkeypatch.setattr("dc_overview.fleet_manager.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "dc_overview.fleet_manager.os.chown",
        lambda path, uid, gid: chowns.append((Path(path), uid, gid)),
    )

    secret_path, _ = manager._prepare_inventory_credential_transport()
    secret = secret_path.read_text(encoding="utf-8")
    manager._prepare_inventory_credential_transport()

    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600
    assert secret_path.read_text(encoding="utf-8") == secret
    assert chowns == [(secret_path, 1000, -1), (secret_path, 1000, -1)]


def test_fleet_manager_preserves_vault_authority_from_manifest(tmp_path, absent_ipmi):
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "credential-sources.json").write_text("{}", encoding="utf-8")
    manager = FleetManager(_fleet_config(tmp_path))

    _, authority = manager._prepare_inventory_credential_transport()

    assert authority == "vault"
    assert "FLEET_CREDENTIAL_AUTHORITY=vault" in manager._generate_docker_compose()


def test_blank_or_invalid_existing_inventory_secret_fails_closed(tmp_path, absent_ipmi):
    manager = FleetManager(_fleet_config(tmp_path))
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "dc-ipmi-inventory").write_text("\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="invalid"):
        manager._prepare_inventory_credential_transport()


def test_existing_noncanonical_ipmi_secret_mount_is_preserved(tmp_path):
    existing_secret = tmp_path / "legacy-inventory-secret"
    existing_secret.write_text("a" * 32, encoding="utf-8")
    manager = FleetManager(_fleet_config(tmp_path))

    secret_path, authority = manager._prepare_inventory_credential_transport(
        {"HostConfig": {"Binds": [f"{existing_secret}:/run/secrets/dc-ipmi-inventory:ro"]}}
    )

    assert secret_path == existing_secret
    assert authority == "local"
    assert not (tmp_path / "secrets" / "dc-ipmi-inventory").exists()


@pytest.mark.parametrize("owner, mode", [(0, 0o600), (1000, 0o640)])
def test_root_provisioning_rejects_unsafe_custom_inventory_secret(
    tmp_path, monkeypatch, owner, mode
):
    custom_secret = tmp_path / "custom-inventory-secret"
    custom_secret.write_text("a" * 32, encoding="utf-8")
    manager = FleetManager(_fleet_config(tmp_path))
    import dc_overview.fleet_manager as fleet_manager

    real_stat = fleet_manager.os.stat

    def custom_stat(path, *args, **kwargs):
        current = real_stat(path, *args, **kwargs)
        if Path(path) == custom_secret:
            return Namespace(st_mode=(current.st_mode & ~0o777) | mode, st_uid=owner)
        return current

    monkeypatch.setattr(fleet_manager.os, "geteuid", lambda: 0)
    monkeypatch.setattr(fleet_manager.os, "stat", custom_stat)

    with pytest.raises(RuntimeError, match="unsafe"):
        manager._prepare_inventory_credential_transport(
            {"HostConfig": {"Binds": [f"{custom_secret}:/run/secrets/dc-ipmi-inventory:ro"]}}
        )


def test_root_provisioning_preserves_safe_custom_inventory_secret_without_mutation(
    tmp_path, monkeypatch
):
    custom_secret = tmp_path / "custom-inventory-secret"
    custom_secret.write_text("b" * 32, encoding="utf-8")
    manager = FleetManager(_fleet_config(tmp_path))
    import dc_overview.fleet_manager as fleet_manager

    real_stat = fleet_manager.os.stat
    chmod_calls = []
    chown_calls = []

    def custom_stat(path, *args, **kwargs):
        current = real_stat(path, *args, **kwargs)
        if Path(path) == custom_secret:
            return Namespace(st_mode=(current.st_mode & ~0o777) | 0o400, st_uid=1000)
        return current

    monkeypatch.setattr(fleet_manager.os, "geteuid", lambda: 0)
    monkeypatch.setattr(fleet_manager.os, "stat", custom_stat)
    monkeypatch.setattr(fleet_manager.os, "chmod", lambda *args: chmod_calls.append(args))
    monkeypatch.setattr(fleet_manager.os, "chown", lambda *args: chown_calls.append(args))

    secret_path, authority = manager._prepare_inventory_credential_transport(
        {"HostConfig": {"Binds": [f"{custom_secret}:/run/secrets/dc-ipmi-inventory:ro"]}}
    )

    assert secret_path == custom_secret
    assert authority == "local"
    assert custom_secret.read_text(encoding="utf-8") == "b" * 32
    assert chmod_calls == []
    assert chown_calls == []


def test_quickstart_template_wires_local_transport_when_ipmi_is_present(tmp_path):
    secret_path = tmp_path / "secrets" / "dc-ipmi-inventory"
    secret_path.parent.mkdir()
    secret_path.write_text("shared-install-secret", encoding="utf-8")
    template_dir = Path(__file__).parents[1] / "src" / "dc_overview" / "templates"
    template = Environment(loader=FileSystemLoader(template_dir)).get_template(
        "docker-compose.yml.j2"
    )
    compose = template.render(
        ipmi_enabled=True,
        inventory_secret_path=secret_path,
        credential_authority="local",
    )

    assert "DC_IPMI_INVENTORY_SECRET_FILE=/run/secrets/dc-ipmi-inventory" in compose
    assert "IPMI_INVENTORY_URL=http://ipmi-monitor:5000" in compose
    assert "FLEET_CREDENTIAL_AUTHORITY=local" in compose
    assert f"{secret_path}:/run/secrets/dc-ipmi-inventory:ro" in compose


def test_quickstart_environment_keeps_existing_settings_and_authority():
    rendered = _render_quickstart_environment(
        "app-secret",
        "grafana-secret",
        inventory_secret_path="/run/secrets/dc-ipmi-inventory",
        credential_authority="vault",
    )

    assert "SECRET_KEY=app-secret\n" in rendered
    assert "GRAFANA_PASSWORD=grafana-secret\n" in rendered
    assert "FLEET_CREDENTIAL_AUTHORITY=vault\n" in rendered


def test_ipmi_recreate_merges_existing_updater_environment_and_mounts(tmp_path, monkeypatch):
    manager = FleetManager(_fleet_config(tmp_path))
    manager._wait_for_ipmi_monitor_ready = lambda: True
    manager._import_ssh_key_to_ipmi_monitor = lambda: None
    manager._activate_ai_license_in_ipmi_monitor = lambda: None
    monkeypatch.setattr("dc_overview.fleet_manager._ensure_docker_network", lambda: True)
    from pathlib import Path as NativePath

    monkeypatch.setattr(
        "dc_overview.fleet_manager.Path",
        lambda value: tmp_path / "ipmi-config" if value == "/etc/ipmi-monitor" else NativePath(value),
    )
    monkeypatch.setattr(
        manager,
        "_inspect_ipmi_monitor",
        lambda: {
            "Config": {
                "Image": "ghcr.io/cryptolabsza/ipmi-monitor:older",
                "Env": [
                    "UPDATER_CHANNEL=stable",
                    "IPMI_BMC_CREDENTIALS_FILE=/run/secrets/ipmi-bmc.json",
                    "SECRET_KEY=preserved-secret",
                    "ADMIN_USER=preserved-admin",
                    "ADMIN_PASS=preserved-password",
                    "DATA_DIR=/persisted-data",
                ],
            },
            "HostConfig": {
                "Binds": ["/opt/updater:/opt/updater:ro", "/etc/vault-bmc.json:/run/secrets/ipmi-bmc.json:ro"],
            },
        },
    )
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("dc_overview.fleet_manager.subprocess.run", run)

    manager._deploy_ipmi_monitor()

    docker_run = next(command for command in calls if command[:3] == ["docker", "run", "-d"])
    assert "UPDATER_CHANNEL=stable" in docker_run
    assert "/opt/updater:/opt/updater:ro" in docker_run
    assert "/etc/vault-bmc.json:/run/secrets/ipmi-bmc.json:ro" in docker_run
    assert "SECRET_KEY=preserved-secret" in docker_run
    assert "ADMIN_USER=preserved-admin" in docker_run
    assert "ADMIN_PASS=preserved-password" in docker_run
    assert "DATA_DIR=/persisted-data" in docker_run
    assert "FLEET_CREDENTIAL_AUTHORITY=vault" in docker_run
    assert "IPMI_INVENTORY_SECRET_FILE=/run/secrets/dc-ipmi-inventory" in docker_run


def test_unwired_existing_ipmi_preserves_its_custom_servers_and_data_mounts(
    tmp_path, monkeypatch
):
    manager = FleetManager(_fleet_config(tmp_path))
    manager._wait_for_ipmi_monitor_ready = lambda: True
    manager._import_ssh_key_to_ipmi_monitor = lambda: None
    manager._activate_ai_license_in_ipmi_monitor = lambda: None
    monkeypatch.setattr("dc_overview.fleet_manager._ensure_docker_network", lambda: True)
    from pathlib import Path as NativePath

    monkeypatch.setattr(
        "dc_overview.fleet_manager.Path",
        lambda value: tmp_path / "unused-default-config" if value == "/etc/ipmi-monitor" else NativePath(value),
    )
    servers_path = tmp_path / "standalone-servers.yaml"
    original_servers = "servers:\n  - name: standalone\n    bmc_ip: 10.0.0.90\n"
    servers_path.write_text(original_servers, encoding="utf-8")
    data_path = tmp_path / "standalone-data"
    data_path.mkdir()
    monkeypatch.setattr(
        manager,
        "_inspect_ipmi_monitor",
        lambda: {
            "Config": {"Image": "ghcr.io/cryptolabsza/ipmi-monitor:older", "Env": []},
            "HostConfig": {
                "Binds": [
                    f"{servers_path}:/app/config/servers.yaml:ro",
                    f"{data_path}:/app/data",
                ]
            },
        },
    )
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("dc_overview.fleet_manager.subprocess.run", run)

    manager._deploy_ipmi_monitor()

    docker_run = next(command for command in calls if command[:3] == ["docker", "run", "-d"])
    assert servers_path.read_text(encoding="utf-8") == original_servers
    assert f"{servers_path}:/app/config/servers.yaml:ro" in docker_run
    assert f"{data_path}:/app/data" in docker_run
    assert "ipmi-monitor-data:/app/data" not in docker_run


def test_unwired_mount_style_ipmi_preserves_custom_data_config_and_vault_mounts(
    tmp_path, monkeypatch
):
    manager = FleetManager(_fleet_config(tmp_path))
    manager._wait_for_ipmi_monitor_ready = lambda: True
    manager._import_ssh_key_to_ipmi_monitor = lambda: None
    manager._activate_ai_license_in_ipmi_monitor = lambda: None
    monkeypatch.setattr("dc_overview.fleet_manager._ensure_docker_network", lambda: True)
    from pathlib import Path as NativePath

    monkeypatch.setattr(
        "dc_overview.fleet_manager.Path",
        lambda value: tmp_path / "unused-default-config" if value == "/etc/ipmi-monitor" else NativePath(value),
    )
    servers_path = tmp_path / "mounted-servers.yaml"
    original_servers = "servers:\n  - name: mounted-standalone\n"
    servers_path.write_text(original_servers, encoding="utf-8")
    vault_path = tmp_path / "vault.json"
    vault_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        manager,
        "_inspect_ipmi_monitor",
        lambda: {
            "Config": {"Image": "ghcr.io/cryptolabsza/ipmi-monitor:older", "Env": []},
            "HostConfig": {"Binds": None},
            "Mounts": [
                {"Type": "bind", "Source": str(servers_path), "Destination": "/app/config/servers.yaml", "RW": False},
                {
                    "Type": "volume",
                    "Name": "standalone-ipmi-data",
                    "Source": "/var/lib/docker/volumes/standalone-ipmi-data/_data",
                    "Destination": "/app/data",
                    "RW": True,
                },
                {"Type": "bind", "Source": str(vault_path), "Destination": "/run/secrets/ipmi-bmc.json", "RW": False},
            ],
        },
    )
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("dc_overview.fleet_manager.subprocess.run", run)

    manager._deploy_ipmi_monitor()

    docker_run = next(command for command in calls if command[:3] == ["docker", "run", "-d"])
    assert servers_path.read_text(encoding="utf-8") == original_servers
    assert f"{servers_path}:/app/config/servers.yaml:ro" in docker_run
    assert "standalone-ipmi-data:/app/data" in docker_run
    assert f"{vault_path}:/run/secrets/ipmi-bmc.json:ro" in docker_run
