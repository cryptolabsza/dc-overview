"""`_deploy_vast_price_manager` falls back to this release's pinned image
when `vast_price_manager.image` is unset (vpm-public-release ledger, D5).

The config is built the way cli.py / FleetConfig.load() build it from a
saved fleet-config.yaml with `image: null`; only VPMServiceManager is
mocked, so the real VPMServiceSpec validation still runs against the
default pin.
"""

from pathlib import Path
from unittest.mock import MagicMock

from dc_overview import vpm_service
from dc_overview.fleet_config import FleetConfig
from dc_overview.fleet_manager import FleetManager
from dc_overview.vpm_service import DEFAULT_VPM_IMAGE


def _fleet_config_with_null_vpm_image(tmp_path: Path) -> FleetConfig:
    config = FleetConfig(config_dir=tmp_path)
    config.components.vast_price_manager = True
    config.ssl.domain = "dc.example.com"
    config.save()
    # Confirms the on-disk shape matches what the README documents for
    # "use the VPM image pinned by this dc-overview release".
    assert "image: null" in (tmp_path / "fleet-config.yaml").read_text()
    return FleetConfig.load(tmp_path)


def test_deploy_vast_price_manager_uses_default_pin_and_prints_notice_when_image_is_null(
    tmp_path, monkeypatch, capsys
):
    config = _fleet_config_with_null_vpm_image(tmp_path)
    assert config.vast_price_manager.image is None

    mock_manager = MagicMock()
    mock_manager.enable_proxy_route = object()
    monkeypatch.setattr(vpm_service, "VPMServiceManager", MagicMock(return_value=mock_manager))

    fleet_manager = FleetManager(config)
    fleet_manager._deploy_vast_price_manager()

    assert mock_manager.install.call_count == 1
    installed_spec = mock_manager.install.call_args.args[0]
    assert installed_spec.image == DEFAULT_VPM_IMAGE

    notice = capsys.readouterr().out
    assert DEFAULT_VPM_IMAGE in notice


def test_deploy_vast_price_manager_keeps_an_explicitly_configured_image(tmp_path, monkeypatch):
    pinned = "ghcr.io/cryptolabsza/vast-price-manager@sha256:" + "d" * 64
    config = FleetConfig(config_dir=tmp_path)
    config.components.vast_price_manager = True
    config.ssl.domain = "dc.example.com"
    config.vast_price_manager.image = pinned
    config.save()
    loaded = FleetConfig.load(tmp_path)
    assert loaded.vast_price_manager.image == pinned

    mock_manager = MagicMock()
    mock_manager.enable_proxy_route = object()
    monkeypatch.setattr(vpm_service, "VPMServiceManager", MagicMock(return_value=mock_manager))

    FleetManager(loaded)._deploy_vast_price_manager()

    installed_spec = mock_manager.install.call_args.args[0]
    assert installed_spec.image == pinned
