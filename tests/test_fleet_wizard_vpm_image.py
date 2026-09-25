"""Wizard coverage for choosing the VPM image pin (vpm-public-release ledger, D5).

The wizard must offer the released default pin as the recommended choice and
a custom pin as the alternative, and the custom pin must be validated with
the exact same compiled patterns `vpm_service` already enforces -- not a
second copy of the regexes.
"""

from types import SimpleNamespace

from dc_overview import fleet_wizard
from dc_overview.fleet_wizard import FleetWizard
from dc_overview.vpm_service import _LOCAL_IMAGE_ID, _PINNED_IMAGE, DEFAULT_VPM_IMAGE

CUSTOM_PIN = "ghcr.io/cryptolabsza/vast-price-manager@sha256:" + "b" * 64
CUSTOM_LOCAL_ID = "sha256:" + "c" * 64


def _answer(value):
    """Stand in for questionary's fluent `.ask()` builder result."""
    return SimpleNamespace(ask=lambda: value)


def test_wizard_reuses_vpm_service_regex_objects_instead_of_copying_them():
    # "import and reuse; do not copy the regexes" -- assert identity, not
    # just equivalent behaviour, so a future copy/paste regresses loudly.
    assert fleet_wizard._PINNED_IMAGE is _PINNED_IMAGE
    assert fleet_wizard._LOCAL_IMAGE_ID is _LOCAL_IMAGE_ID


def test_select_vpm_image_returns_default_pin_when_recommended_choice_is_picked(tmp_path, monkeypatch):
    wizard = FleetWizard(config_dir=tmp_path)
    monkeypatch.setattr(fleet_wizard.questionary, "select", lambda *a, **k: _answer("default"))

    image = wizard._select_vpm_image()

    assert image == DEFAULT_VPM_IMAGE


def test_select_vpm_image_prompts_for_and_validates_a_custom_pin(tmp_path, monkeypatch):
    wizard = FleetWizard(config_dir=tmp_path)
    monkeypatch.setattr(fleet_wizard.questionary, "select", lambda *a, **k: _answer("custom"))

    captured_kwargs = {}

    def fake_text(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return _answer(CUSTOM_PIN)

    monkeypatch.setattr(fleet_wizard.questionary, "text", fake_text)

    image = wizard._select_vpm_image()

    assert image == CUSTOM_PIN
    validate = captured_kwargs["validate"]
    assert validate(CUSTOM_PIN) is True
    assert validate(CUSTOM_LOCAL_ID) is True
    assert validate("not-a-pin") is not True


def test_select_vpm_image_choices_show_the_default_pin_and_a_custom_option(tmp_path, monkeypatch):
    wizard = FleetWizard(config_dir=tmp_path)
    captured_kwargs = {}

    def fake_select(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return _answer("default")

    monkeypatch.setattr(fleet_wizard.questionary, "select", fake_select)

    wizard._select_vpm_image()

    choice_titles = [choice.title for choice in captured_kwargs["choices"]]
    assert any("recommended" in title.lower() and DEFAULT_VPM_IMAGE in title for title in choice_titles)
    assert any("custom" in title.lower() for title in choice_titles)
