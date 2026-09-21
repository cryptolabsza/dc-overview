"""Authority selection must fail closed around protected vault markers."""

from unittest.mock import patch


def test_unreadable_vault_manifest_fails_closed_to_vault(monkeypatch):
    monkeypatch.delenv('FLEET_CREDENTIAL_AUTHORITY', raising=False)
    monkeypatch.delenv('IPMI_BMC_CREDENTIALS_FILE', raising=False)
    from dc_overview.credential_authority import credential_authority

    with patch('dc_overview.credential_authority.Path.exists', side_effect=PermissionError):
        assert credential_authority() == 'vault'


def test_configured_bmc_file_skips_protected_manifest_probe(monkeypatch):
    monkeypatch.delenv('FLEET_CREDENTIAL_AUTHORITY', raising=False)
    monkeypatch.setenv('IPMI_BMC_CREDENTIALS_FILE', '/protected/bmc.json')
    from dc_overview.credential_authority import credential_authority

    with patch('dc_overview.credential_authority.Path.exists', side_effect=AssertionError):
        assert credential_authority() == 'vault'


def test_explicit_authority_skips_manifest_probe(monkeypatch):
    monkeypatch.setenv('FLEET_CREDENTIAL_AUTHORITY', 'local')
    monkeypatch.delenv('IPMI_BMC_CREDENTIALS_FILE', raising=False)
    from dc_overview.credential_authority import credential_authority

    with patch('dc_overview.credential_authority.Path.exists', side_effect=AssertionError):
        assert credential_authority() == 'local'
