"""Installer coverage for the shared DC/IPMI credential transport secret."""

import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from jinja2 import Environment, FileSystemLoader

from dc_overview.fleet_config import FleetConfig
from dc_overview.fleet_manager import FleetManager
from dc_overview.quickstart import _render_quickstart_environment


def _fleet_config(tmp_path, *, existing_proxy=True):
    config = FleetConfig(config_dir=tmp_path)
    config.components.ipmi_monitor = True
    config.ssl.use_existing_proxy = existing_proxy
    return config


def test_fleet_manager_creates_one_shared_local_secret_and_compose_wires_dc(tmp_path):
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


def test_fleet_manager_preserves_vault_authority_from_manifest(tmp_path):
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "credential-sources.json").write_text("{}", encoding="utf-8")
    manager = FleetManager(_fleet_config(tmp_path))

    _, authority = manager._prepare_inventory_credential_transport()

    assert authority == "vault"
    assert "FLEET_CREDENTIAL_AUTHORITY=vault" in manager._generate_docker_compose()


def test_blank_or_invalid_existing_inventory_secret_fails_closed(tmp_path):
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
