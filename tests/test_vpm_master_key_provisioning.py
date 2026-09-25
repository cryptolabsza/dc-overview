"""Provisioning of the VPM master key on first install only (ledger vpm-public-release, D10).

Without a master key, VPMServiceManager._validate_master_key fails first
install with "VPM provisioned master-key file is missing" -- nothing in
dc-overview ever created one. `_deploy_vast_price_manager` is the only
caller of `create_master_key_if_missing`; `vpm configure` / `vpm update`
(cli.py, unmodified) must never create one, since creating -- or
overwriting -- a key outside first install would silently orphan
credentials already encrypted with the old one.
"""

import os
import stat
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import MagicMock

from click.testing import CliRunner
from cryptography.fernet import Fernet

import dc_overview.cli as cli_module
from dc_overview import vpm_service
from dc_overview.cli import main
from dc_overview.fleet_config import FleetConfig
from dc_overview.fleet_manager import FleetManager
from dc_overview.vpm_service import create_master_key_if_missing

PIN = "ghcr.io/cryptolabsza/vast-price-manager@sha256:" + "a" * 64


def test_create_master_key_if_missing_writes_a_valid_fernet_key_with_owner_only_mode(tmp_path, monkeypatch):
    # Not root in this test environment: real chown(uid=999) would fail, so
    # the ownership change itself is mocked and its arguments asserted.
    chown_calls = []
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: chown_calls.append((path, uid, gid)))

    key_path = tmp_path / "secrets" / "vpm-master.key"

    created = create_master_key_if_missing(str(key_path))

    assert created is True
    assert key_path.is_file()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o400
    assert stat.S_IMODE(key_path.parent.stat().st_mode) == 0o700
    # A valid, usable Fernet key -- constructing Fernet(...) raises on garbage.
    Fernet(key_path.read_bytes())
    assert chown_calls == [(str(key_path), 999, 999)]


def test_create_master_key_if_missing_never_overwrites_an_existing_key(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "chown", lambda *a, **k: None)
    key_path = tmp_path / "vpm-master.key"
    original = b"already-in-use-key-material-do-not-touch"
    key_path.write_bytes(original)
    os.chmod(key_path, 0o400)
    original_mtime_ns = key_path.stat().st_mtime_ns

    created = create_master_key_if_missing(str(key_path))

    assert created is False
    assert key_path.read_bytes() == original
    assert key_path.stat().st_mtime_ns == original_mtime_ns


def test_create_master_key_if_missing_treats_a_lost_o_excl_race_as_an_existing_key(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "chown", lambda *a, **k: None)
    key_path = tmp_path / "vpm-master.key"
    winner_content = b"the-other-process-wrote-this-first"
    key_path.write_bytes(winner_content)
    os.chmod(key_path, 0o400)

    # Simulate the TOCTOU gap: our own is_file() check ran before the other
    # process's write landed, so the function must proceed to os.open() and
    # hit the OS's real O_EXCL failure against the file that is already there,
    # rather than trusting a stale "missing" answer.
    monkeypatch.setattr(vpm_service.Path, "is_file", lambda self: False)

    created = create_master_key_if_missing(str(key_path))

    assert created is False
    assert key_path.read_bytes() == winner_content


def test_deploy_vast_price_manager_creates_the_master_key_on_first_install(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(os, "chown", lambda *a, **k: None)
    key_path = tmp_path / "secrets" / "vpm-master.key"

    config = FleetConfig(config_dir=tmp_path)
    config.components.vast_price_manager = True
    config.ssl.domain = "dc.example.com"
    config.vast_price_manager.image = PIN
    config.vast_price_manager.master_key_file = str(key_path)
    config.save()
    loaded = FleetConfig.load(tmp_path)
    assert loaded.vast_price_manager.master_key_file == str(key_path)

    mock_manager = MagicMock()
    mock_manager.enable_proxy_route = object()
    monkeypatch.setattr(vpm_service, "VPMServiceManager", MagicMock(return_value=mock_manager))

    FleetManager(loaded)._deploy_vast_price_manager()

    assert key_path.is_file()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o400
    notice = capsys.readouterr().out
    assert str(key_path) in notice
    assert "Vast API key" in notice


def test_vpm_configure_and_update_never_create_a_master_key(monkeypatch, tmp_path: Path):
    mock_create = MagicMock()
    monkeypatch.setattr(vpm_service, "create_master_key_if_missing", mock_create)

    class FakeManager:
        def __init__(self, _config_dir):
            pass

        def operation_lock(self):
            return nullcontext()

        def install(self, *_args, **_kwargs):
            pass

    config = FleetConfig(config_dir=tmp_path)
    config.ssl.domain = "dc.example.com"
    config.save()
    monkeypatch.setattr(cli_module, "VPMServiceManager", FakeManager)

    configure_result = CliRunner().invoke(
        main, ["vpm", "--config-dir", str(tmp_path), "configure", "--image", PIN]
    )
    update_result = CliRunner().invoke(
        main, ["vpm", "--config-dir", str(tmp_path), "update", "--image", PIN]
    )

    assert configure_result.exit_code == 0, configure_result.output
    assert update_result.exit_code == 0, update_result.output
    mock_create.assert_not_called()
