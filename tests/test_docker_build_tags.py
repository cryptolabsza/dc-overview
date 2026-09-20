"""Regression coverage for Docker image tags emitted by the CI workflow."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOW_PATH = Path(__file__).parents[1] / ".github/workflows/docker-build.yml"
EXPORTER_JOBS = {
    "build-runpod-exporter": "runpod-exporter",
    "build-vastai-exporter": "vastai-exporter",
}


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW_PATH.read_text())


def _compute_tags_script(job_name: str) -> str:
    steps = _workflow()["jobs"][job_name]["steps"]
    return next(step["run"] for step in steps if step["name"] == "Compute tags")


def _tags_from_workflow_script(
    tmp_path: Path, job_name: str, *, ref: str, ref_name: str
) -> list[str]:
    """Run the parsed GitHub Actions tag script with a representative event."""
    script = _compute_tags_script(job_name)
    replacements = {
        "${{ env.REGISTRY }}": "ghcr.io",
        "${{ github.sha }}": "0123456789abcdef",
        "${{ github.ref }}": "${GITHUB_REF}",
        "${{ github.ref_name }}": "${GITHUB_REF_NAME}",
        "${{ github.event.inputs.tag_override }}": "${TAG_OVERRIDE}",
    }
    for expression, value in replacements.items():
        script = script.replace(expression, value)

    output_path = tmp_path / "github-output"
    result = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", script],
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "GITHUB_OUTPUT": str(output_path),
            "GITHUB_REF": ref,
            "GITHUB_REF_NAME": ref_name,
            "TAG_OVERRIDE": "",
        },
    )
    assert result.returncode == 0, result.stderr
    outputs = dict(line.split("=", 1) for line in output_path.read_text().splitlines())
    return outputs["tags"].split(",")


@pytest.mark.parametrize("job_name", EXPORTER_JOBS)
@pytest.mark.parametrize("branch", ["dev", "develop"])
def test_exporter_development_tags_do_not_update_release_channels(
    tmp_path: Path, job_name: str, branch: str
):
    tags = _tags_from_workflow_script(
        tmp_path, job_name, ref=f"refs/heads/{branch}", ref_name=branch
    )

    assert tags == [f"ghcr.io/cryptolabsza/{EXPORTER_JOBS[job_name]}:dev", f"ghcr.io/cryptolabsza/{EXPORTER_JOBS[job_name]}:sha-0123456"]
    assert all(not tag.endswith((":latest", ":stable", ":main")) for tag in tags)


@pytest.mark.parametrize("job_name", EXPORTER_JOBS)
def test_exporter_main_and_release_tag_contract_is_preserved(tmp_path: Path, job_name: str):
    image = f"ghcr.io/cryptolabsza/{EXPORTER_JOBS[job_name]}"

    assert _tags_from_workflow_script(
        tmp_path, job_name, ref="refs/heads/main", ref_name="main"
    ) == [f"{image}:main", f"{image}:sha-0123456"]
    assert _tags_from_workflow_script(
        tmp_path, job_name, ref="refs/tags/v1.2.3", ref_name="v1.2.3"
    ) == [f"{image}:1.2.3", f"{image}:latest", f"{image}:sha-0123456"]


def test_pull_requests_cannot_push_any_workflow_image():
    workflow = _workflow()
    push_steps = [
        step
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if step["name"].startswith("Push ")
    ]

    assert push_steps
    assert all(step.get("if") == "github.event_name != 'pull_request'" for step in push_steps)
