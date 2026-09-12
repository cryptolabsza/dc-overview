"""Offline immutable Docker image-ID coverage for VPM installation."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from dc_overview.cli import main
from dc_overview.vpm_service import VPMServiceManager, VPMServiceSpec


LOCAL_ID = "sha256:" + "b" * 64
REPO_PIN = "ghcr.io/cryptolabsza/vast-price-manager@sha256:" + "a" * 64


class Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _manager(tmp_path: Path, calls, image_result: Result) -> VPMServiceManager:
    def runner(command, **_kwargs):
        calls.append(command)
        if command == ["docker", "image", "inspect", "--format", "{{.Id}}", LOCAL_ID]:
            return image_result
        if command[:3] == ["systemctl", "is-active", "--quiet"]:
            return Result(3)
        if command[:2] == ["systemctl", "is-enabled"]:
            return Result(1)
        if command[:2] == ["systemctl", "is-active"]:
            return Result(3)
        if command[:2] == ["docker", "inspect"]:
            return Result(stdout="healthy\n")
        return Result()

    manager = VPMServiceManager(tmp_path, unit_dir=tmp_path / "units", runner=runner)
    manager._validate_master_key = lambda _spec: None
    return manager


def test_spec_accepts_a_full_canonical_local_docker_image_id():
    spec = VPMServiceSpec(image=LOCAL_ID, allowed_host="dc.example.com")

    assert spec.image == LOCAL_ID
    assert LOCAL_ID in VPMServiceManager.render(spec).compose


def test_install_reuses_exact_present_local_image_id_without_pulling(tmp_path: Path):
    calls = []
    manager = _manager(tmp_path, calls, Result(stdout=f"{LOCAL_ID}\n"))

    manager.install(VPMServiceSpec(image=LOCAL_ID, allowed_host="dc.example.com"))

    assert ["docker", "image", "inspect", "--format", "{{.Id}}", LOCAL_ID] in calls
    assert ["docker", "pull", LOCAL_ID] not in calls
    assert all(command[-1] != "pull" for command in calls)


def test_missing_local_image_id_fails_closed_before_quiescing_or_pulling(tmp_path: Path):
    calls = []
    manager = _manager(tmp_path, calls, Result(1, stderr="No such image"))

    with pytest.raises(RuntimeError, match="offline image missing"):
        manager.install(VPMServiceSpec(image=LOCAL_ID, allowed_host="dc.example.com"))

    assert ["docker", "pull", LOCAL_ID] not in calls
    assert ["systemctl", "disable", "--now", *manager.timer_names] not in calls
    assert ["systemctl", "stop", *manager.service_names] not in calls


def test_mismatched_local_image_id_fails_closed_before_quiescing_or_pulling(tmp_path: Path):
    calls = []
    manager = _manager(tmp_path, calls, Result(stdout="sha256:" + "c" * 64 + "\n"))

    with pytest.raises(RuntimeError, match="offline image missing"):
        manager.install(VPMServiceSpec(image=LOCAL_ID, allowed_host="dc.example.com"))

    assert ["docker", "pull", LOCAL_ID] not in calls
    assert ["systemctl", "disable", "--now", *manager.timer_names] not in calls


@pytest.mark.parametrize(
    "image",
    [
        "sha256:" + "a" * 63,
        "sha256:" + "A" * 64,
        "sha256:not-a-canonical-image-id",
    ],
)
def test_spec_rejects_truncated_or_noncanonical_local_image_ids(image: str):
    with pytest.raises(ValueError, match="immutable"):
        VPMServiceSpec(image=image, allowed_host="dc.example.com")


def test_repository_digest_pins_keep_the_existing_inspect_then_pull_behavior(tmp_path: Path):
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        if command == ["docker", "image", "inspect", REPO_PIN]:
            return Result(1)
        return Result()

    manager = VPMServiceManager(tmp_path, runner=runner)
    manager._ensure_exact_image_available(VPMServiceSpec(image=REPO_PIN, allowed_host="dc.example.com"))

    assert calls == [["docker", "image", "inspect", REPO_PIN], ["docker", "pull", REPO_PIN]]


def test_vpm_install_help_documents_the_offline_local_image_id_form():
    result = CliRunner().invoke(main, ["vpm", "install", "--help"])

    assert result.exit_code == 0
    assert "full local sha256 image ID" in result.output
