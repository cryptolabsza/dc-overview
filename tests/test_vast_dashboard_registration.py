"""Evaluate the shipped registration query with Prometheus, not a Python imitation."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
DASHBOARDS = [
    "src/dc_overview/dashboards/Vast_Dashboard.json",
    "dashboards/Vast_Dashboard.json",
    "server/grafana/dashboards/Vast_Dashboard.json",
    "server/grafana/dashboards/vast-dashboard.json",
]


def registration_panel(filename):
    dashboard = json.loads((ROOT / filename).read_text())
    return next(panel for panel in dashboard["panels"] if panel.get("id") == 5)


@pytest.mark.parametrize("filename", DASHBOARDS)
def test_registration_is_current_and_has_clear_units(filename):
    panel = registration_panel(filename)
    assert panel["title"] == "Actual vs Vast registered"
    assert "physical GPU UUID" in panel["description"]
    assert panel["targets"][0].get("instant") is True
    assert panel["targets"][0].get("range") is False
    assert panel["fieldConfig"]["defaults"]["unit"] == "%"


def gpu(hostname, uuid, job="dcgm"):
    labels = {"Hostname": hostname, "UUID": uuid, "job": job}
    return {
        "series": "DCGM_FI_DEV_GPU_UTIL{"
        + ",".join(f'{key}="{value}"' for key, value in labels.items())
        + "}",
        "values": "0 0",
    }


def registered(hostname, count, machine_id="1", job="vastai"):
    labels = {"hostname": hostname, "machine_id": machine_id, "job": job}
    suffix = "{" + ",".join(f'{key}="{value}"' for key, value in labels.items()) + "}"
    return [
        {"series": metric + suffix, "values": f"{count} {count}"}
        for metric in ["vast_machine_num_gpus", "vast_machine_gpu_name"]
    ]


@pytest.mark.parametrize("filename", DASHBOARDS)
def test_registration_semantics_with_prometheus(filename, tmp_path):
    promtool = shutil.which("promtool")
    if not promtool:
        if os.environ.get("REQUIRE_PROMTOOL") == "1":
            pytest.fail("promtool is required in CI")
        pytest.skip("promtool is required for semantic PromQL tests")
    expr = registration_panel(filename)["targets"][0]["expr"]
    owned = [gpu("vast-host", f"GPU-{i}") for i in range(24)]
    extra = [gpu("runpod-host", f"GPU-extra-{i}") for i in range(54)]
    cases = [
        ("unrelated fleet GPUs", owned + extra + registered("vast-host", 24), 100),
        (
            "duplicate scrape and provider targets",
            owned
            + [gpu("vast-host", f"GPU-{i}", "duplicate") for i in range(24)]
            + registered("vast-host", 24)
            + registered("vast-host", 24, job="duplicate"),
            100,
        ),
        (
            "genuine excess GPUs",
            [gpu("vast-host", f"GPU-{i}") for i in range(3)] + registered("vast-host", 2),
            150,
        ),
        ("missing detected GPU", [gpu("vast-host", "GPU-0")] + registered("vast-host", 2), 50),
        (
            "multiple Vast hosts",
            [gpu("first", "GPU-a"), gpu("second", "GPU-b")]
            + registered("first", 1, "1")
            + registered("second", 1, "2"),
            100,
        ),
        (
            "physical identity on multiple hosts",
            [gpu("first", "GPU-a"), gpu("second", "GPU-a")]
            + registered("first", 1, "1")
            + registered("second", 1, "2"),
            None,
        ),
        (
            "missing host mapping",
            [gpu("different-host", "GPU-0")] + registered("vast-host", 1),
            None,
        ),
        (
            "missing physical GPU identity",
            [gpu("vast-host", "")] + registered("vast-host", 1),
            None,
        ),
        (
            "mixed missing physical GPU identity",
            [gpu("vast-host", "GPU-0"), gpu("vast-host", "")] + registered("vast-host", 2),
            None,
        ),
        (
            "passthrough placeholder identity",
            [gpu("vast-host", "GPU-0"), gpu("vast-host", "VM-PASSTHROUGH")]
            + registered("vast-host", 2),
            None,
        ),
        (
            "unrelated missing identity",
            [gpu("vast-host", "GPU-0"), gpu("runpod-host", "")] + registered("vast-host", 1),
            100,
        ),
        ("zero registered GPUs", [gpu("vast-host", "GPU-0")] + registered("vast-host", 0), None),
        ("missing registration telemetry", [gpu("vast-host", "GPU-0")], None),
        (
            "ambiguous hostname",
            [gpu("same-host", "GPU-0")]
            + registered("same-host", 1, "1")
            + registered("same-host", 1, "2"),
            None,
        ),
        (
            "partial host telemetry",
            [gpu("first", "GPU-0")] + registered("first", 1, "1") + registered("second", 1, "2"),
            50,
        ),
    ]
    tests = []
    for name, series, expected in cases:
        tests.append(
            {
                "name": name,
                "interval": "1m",
                "input_series": series,
                "promql_expr_test": [
                    {
                        "expr": expr,
                        "eval_time": "1m",
                        "exp_samples": (
                            [] if expected is None else [{"labels": "{}", "value": expected}]
                        ),
                    }
                ],
            }
        )
    path = tmp_path / "registration.yml"
    path.write_text(yaml.safe_dump({"evaluation_interval": "1m", "tests": tests}))
    result = subprocess.run(
        [promtool, "test", "rules", str(path)], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_docker_publish_requires_semantic_dashboard_checks():
    workflow = yaml.safe_load((ROOT / ".github/workflows/docker-build.yml").read_text())
    steps = workflow["jobs"]["build"]["steps"]
    names = [step.get("name") for step in steps]
    assert "Test Vast dashboards" in names
    assert names.index("Test Vast dashboards") < names.index("Build Docker image")
    test_step = steps[names.index("Test Vast dashboards")]
    assert test_step["env"]["REQUIRE_PROMTOOL"] == "1"
    assert "test_vast_dashboard_registration.py" in test_step["run"]
    assert "test_vast_income_dashboard.py" in test_step["run"]
