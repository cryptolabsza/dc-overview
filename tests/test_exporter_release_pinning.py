"""Regression tests for immutable dc-exporter release selection."""

from dc_overview.exporters import (
    DC_EXPORTER_RS_VERSION,
    get_dc_exporter_checksum_url,
    get_dc_exporter_download_url,
    get_exporter_download_url,
)


def test_default_dc_exporter_release_is_pinned_to_0_2_8():
    assert DC_EXPORTER_RS_VERSION == "0.2.8"
    assert get_dc_exporter_download_url() == (
        "https://github.com/cryptolabsza/dc-exporter-releases/"
        "releases/download/v0.2.8/dc-exporter-rs"
    )
    assert "/latest/" not in get_dc_exporter_download_url()


def test_requested_dc_exporter_version_is_used_in_binary_and_checksum_urls():
    assert get_exporter_download_url("dc_exporter", "0.2.7") == (
        "https://github.com/cryptolabsza/dc-exporter-releases/"
        "releases/download/v0.2.7/dc-exporter-rs"
    )
    assert get_dc_exporter_checksum_url("0.2.7") == (
        "https://github.com/cryptolabsza/dc-exporter-releases/"
        "releases/download/v0.2.7/SHA256SUMS"
    )
