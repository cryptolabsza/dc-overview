"""Regression coverage for Docker image tags emitted by the CI workflow."""

from __future__ import annotations

import os
import subprocess
import sys
import re
from pathlib import Path

import pytest
import yaml

WORKFLOW_PATH = Path(__file__).parents[1] / ".github/workflows/docker-build.yml"
ROOT = WORKFLOW_PATH.parents[2]
VERSION = re.search(r'^version = "([^\"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)
SHA = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
IMAGE_JOBS = {
    "build": "dc-overview",
    "build-runpod-exporter": "runpod-exporter",
    "build-vastai-exporter": "vastai-exporter",
}


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW_PATH.read_text())


def _compute_tags_script(job_name: str) -> str:
    image=IMAGE_JOBS[job_name]
    caller=_workflow()['jobs']['build'];recipe=caller['uses'].split('/.github/workflows/',1)[1].split('@',1)[0]
    steps=yaml.safe_load((ROOT/'.github/workflows'/recipe).read_text())['jobs']['build']['steps']
    return next(s['run'] for s in steps if s.get('run')=='python scripts/image_promotion.py tags --image ghcr.io/cryptolabsza/'+image)



def _tags_from_workflow_script(
    tmp_path: Path, job_name: str, *, ref: str, ref_name: str
) -> list[str]:
    """Run the parsed GitHub Actions tag script with a representative event."""
    script = _compute_tags_script(job_name).replace("python ", f'"{sys.executable}" ')
    output_path = tmp_path / "github-output"
    result = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", script],
        check=False,
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "GITHUB_OUTPUT": str(output_path),
            "GITHUB_REF": ref,
            "GITHUB_SHA": SHA,
            "GITHUB_REPOSITORY": "cryptolabsza/dc-overview",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF_NAME": ref_name,
            "TAG_OVERRIDE": "",
        },
    )
    assert result.returncode == 0, result.stderr
    outputs = dict(line.split("=", 1) for line in output_path.read_text().splitlines())
    return outputs["tags"].split(",")


@pytest.mark.parametrize("job_name", IMAGE_JOBS)
@pytest.mark.parametrize("branch", ["dev", "develop"])
def test_exporter_development_tags_do_not_update_release_channels(
    tmp_path: Path, job_name: str, branch: str
):
    tags = _tags_from_workflow_script(
        tmp_path, job_name, ref=f"refs/heads/{branch}", ref_name=branch
    )

    assert tags == [f"ghcr.io/cryptolabsza/{IMAGE_JOBS[job_name]}:dev", f"ghcr.io/cryptolabsza/{IMAGE_JOBS[job_name]}:develop", f"ghcr.io/cryptolabsza/{IMAGE_JOBS[job_name]}:sha-dev-{SHA}"]
    assert all(not tag.endswith((":latest", ":stable", ":main")) for tag in tags)


@pytest.mark.parametrize("job_name", IMAGE_JOBS)
def test_exporter_main_and_release_tag_contract_is_preserved(tmp_path: Path, job_name: str):
    image = f"ghcr.io/cryptolabsza/{IMAGE_JOBS[job_name]}"

    assert _tags_from_workflow_script(
        tmp_path, job_name, ref="refs/heads/main", ref_name="main"
    ) == [f"{image}:main", f"{image}:sha-main-{SHA}"]
    assert _tags_from_workflow_script(
        tmp_path, job_name, ref=f"refs/tags/v{VERSION}", ref_name=f"v{VERSION}"
    ) == [f"{image}:{VERSION}", f"{image}:v{VERSION}", f"{image}:sha-{SHA}"]


def test_pull_requests_cannot_push_any_workflow_image():
    workflow=_workflow();job=workflow['jobs']['publish-build']
    assert job['if']=="github.event_name != 'pull_request'"
    for event in ['pull_request','push','workflow_dispatch']:
        assert eval(job['if'].replace('github.event_name',repr(event)),{'__builtins__':{}})==(event!='pull_request')
    leaf=yaml.safe_load((ROOT/'.github/workflows/ci-image-publish-recipe.yml').read_text())['jobs']['publish']
    assert "github.ref == 'refs/heads/main'" in leaf['if'] and 'github.ref_protected == true' in leaf['if']
    assert 'docker build' not in str(leaf)
