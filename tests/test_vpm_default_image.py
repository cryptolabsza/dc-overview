"""Guardrail for the release-time replacement of the default VPM image pin.

`DEFAULT_VPM_IMAGE` ships on this branch as a clearly-marked placeholder
digest (all zeros) until the orchestrator substitutes the real released
digest immediately before merge (vpm-public-release ledger, decision D6).

This test is EXPECTED TO FAIL on this branch: it is the release gate that
proves the placeholder was replaced. Every other test in the suite must
pass.
"""

from dc_overview.vpm_service import _PINNED_IMAGE, DEFAULT_VPM_IMAGE

_PLACEHOLDER_DIGEST = "0" * 64


def test_default_vpm_image_is_a_real_release_pin():
    # The default must be a syntactically valid immutable pin...
    assert _PINNED_IMAGE.fullmatch(DEFAULT_VPM_IMAGE) is not None
    # ...and it must not still be the all-zeros placeholder.
    assert not DEFAULT_VPM_IMAGE.endswith(f"@sha256:{_PLACEHOLDER_DIGEST}")
