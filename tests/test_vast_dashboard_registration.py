# TRACEWEAVER: file-role=shipped-dashboard-verification; req=REQ-EARN-009; trace=TRACE-EARN-009; ver=VER-EARN-009
# TRACEWEAVER: verifies=VER-EARN-009; req=REQ-EARN-009; trace=TRACE-EARN-009
# TRACEWEAVER: file-role=shipped-dashboard-verification; req=REQ-EARN-009; trace=TRACE-EARN-009; ver=VER-EARN-009
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


# These evaluate the actual shipped earnings expressions with promtool. The
# synthetic test clock begins at Unix epoch zero; report `day` stays numeric.
DAILY_QUERY_COMPONENTS = {14: ["gpu", "sto", "bwu", "bwd"], 15: ["gpu"],
                          16: ["sto"], 17: ["bwu", "bwd"]}


def earnings_panel(filename, panel_id):
    dashboard = json.loads((ROOT / filename).read_text())
    return next(panel for panel in dashboard["panels"] if panel.get("id") == panel_id)


def daily_series(metric, value, *, at=25, provider="101", account="first", machine="7", job="vastai", instance="host:8622"):
    labels = dict(job=job, instance=instance, provider_account_id=provider, account=account)
    if metric.startswith("vastai_per_machine_"):
        labels["machine_id"] = machine
    return {"series": metric + "{" + ",".join(f'{k}="{v}"' for k, v in labels.items()) + "}",
            "values": " ".join(["_"] * at + [str(value)])}


def daily_report(amounts=(10, 2, 3, 4), *, at=25, day=0, valid=1, age=0, omit=(), **labels):
    result = [daily_series("vastai_earnings_report_day_timestamp_seconds", day, at=at, **labels),
              daily_series("vastai_earnings_report_valid", valid, at=at, **labels),
              daily_series("vastai_earnings_last_success_timestamp_seconds", at * 3600 - age, at=at, **labels)]
    result += [daily_series("vastai_per_machine_" + component + "_earn", value, at=at, **labels)
               for component, value in zip(["gpu", "sto", "bwu", "bwd"], amounts) if component not in omit]
    return result


def daily_expected(panel_id, value, *, provider="101", account="first", machine="7", job="vastai", instance="host:8622"):
    labels = dict(job=job, instance=instance, provider_account_id=provider, account=account, machine_id=machine)
    metric_name = "vastai_per_machine_" + DAILY_QUERY_COMPONENTS[panel_id][0] + "_earn" if panel_id in [15, 16] else ""
    return {"labels": metric_name + "{" + ",".join(f'{k}="{v}"' for k, v in labels.items()) + "}", "value": value}


DAILY_SEMANTIC_CASES = ["all-components", "explicit-zero", "negative-adjustment", "missing-upload",
    "missing-storage", "missing-gpu", "missing-download", "no-amounts", "invalid-report", "wrong-day", "missing-day", "missing-success",
    "expired", "future-success", "freshness-boundary", "two-accounts-same-machine", "different-job-no-cross-join",
    "different-instance-no-cross-join", "duplicate-canonical-target", "duplicate-conflicting-target",
    "duplicate-stale-target", "duplicate-with-no-amount", "historical-evaluation-day", "predecessor-stale-clears-gap"]


@pytest.mark.parametrize("filename", DASHBOARDS)
@pytest.mark.parametrize("panel_id", [14, 15, 16, 17])
def test_daily_shipped_queries_with_real_prometheus(filename, panel_id, tmp_path):
    promtool = shutil.which("promtool")
    if not promtool:
        if os.environ.get("REQUIRE_PROMTOOL") == "1": pytest.fail("promtool required in CI")
        pytest.skip("promtool required for semantic query evaluation")
    expression = earnings_panel(filename, panel_id)["targets"][0]["expr"]
    expected_full = {14: 19, 15: 10, 16: 2, 17: 7}[panel_id]
    tests = []
    for name in DAILY_SEMANTIC_CASES:
        series, expected, at = daily_report(), [daily_expected(panel_id, expected_full)], 25
        if name == "explicit-zero":
            series, expected = daily_report((0, 0, 0, 0)), [daily_expected(panel_id, 0)]
        elif name == "negative-adjustment":
            series = daily_report((-10, 2, 3, 4))
            expected = [daily_expected(panel_id, {14: -1, 15: -10, 16: 2, 17: 7}[panel_id])]
        elif name.startswith("missing-") and name.split("missing-")[1] in ["upload", "storage", "gpu", "download"]:
            missing = {"upload": "bwu", "storage": "sto", "gpu": "gpu", "download": "bwd"}[name.split("missing-")[1]]
            series = daily_report(omit=[missing])
            if missing in DAILY_QUERY_COMPONENTS[panel_id]: expected = []
        elif name == "no-amounts": series, expected = daily_report(omit=["gpu", "sto", "bwu", "bwd"]), []
        elif name == "invalid-report": series, expected = daily_report(valid=0), []
        elif name == "wrong-day": series, expected = daily_report(day=86400), []
        elif name == "missing-day": series, expected = [s for s in series if not s["series"].startswith("vastai_earnings_report_day_")], []
        elif name == "missing-success": series, expected = [s for s in series if not s["series"].startswith("vastai_earnings_last_success_")], []
        elif name == "expired": series, expected = daily_report(age=7201), []
        elif name == "future-success": series, expected = daily_report(age=-1), []
        elif name == "freshness-boundary": series = daily_report(age=7200)
        elif name == "two-accounts-same-machine":
            series += daily_report(provider="102", account="second", amounts=(20, 4, 6, 8))
            expected += [daily_expected(panel_id, expected_full * 2, provider="102", account="second")]
        elif name in ["different-job-no-cross-join", "different-instance-no-cross-join"]:
            label = "job" if "job" in name else "instance"
            # Metadata belongs to source A; amounts are present only at B.
            series = [s for s in series if not s["series"].startswith("vastai_per_machine_")]
            series += [s for s in daily_report(**{label: "other"}) if s["series"].startswith("vastai_per_machine_")]
            expected = []
        elif name.startswith("duplicate-"):
            kwargs = {"instance": "replica:8622"}
            if name == "duplicate-conflicting-target": kwargs["amounts"] = (100, 200, 300, 400)
            if name == "duplicate-stale-target": kwargs.update(day=-86400, age=7201)
            if name == "duplicate-with-no-amount": kwargs["omit"] = ["gpu", "sto", "bwu", "bwd"]
            series += daily_report(**kwargs)
            expected = []
        elif name == "historical-evaluation-day":
            # Evaluate yesterday's observations at their historical time and
            # today's observations at today's time within one loaded fixture.
            later = daily_report(at=49, day=86400, amounts=(20, 4, 6, 8))
            for first, last in zip(series, later):
                first["values"] += " " + " ".join(["_"] * 23 + [last["values"].split()[-1]])
            tests.append({"name": name + "-later", "interval": "1h", "input_series": series,
                          "promql_expr_test": [{"expr": expression, "eval_time": "49h",
                                               "exp_samples": [daily_expected(panel_id, expected_full * 2)]}]})
        elif name == "predecessor-stale-clears-gap":
            # Source switch preserves unconstrained history. Stale predecessor
            # metadata produces an intentional gap until its marker is stale.
            series += [{"series": s["series"], "values": " ".join(["_"] * 24 + ["0", "stale"])}
                       for s in daily_report(instance="predecessor:8622")[:3]]
        tests.append({"name": name, "interval": "1h", "input_series": series,
                      "promql_expr_test": [{"expr": expression, "eval_time": str(at) + "h", "exp_samples": expected}]})
    path = tmp_path / ("daily-" + str(panel_id) + ".yml")
    path.write_text(yaml.safe_dump({"evaluation_interval": "1h", "tests": tests}))
    result = subprocess.run([promtool, "test", "rules", str(path)], capture_output=True, text=True, timeout=30)
    (tmp_path / "promtool-result.json").write_text(json.dumps({"command": result.args, "exit_code": result.returncode,
                                                             "stdout": result.stdout, "stderr": result.stderr}, indent=2))
    assert result.returncode == 0, result.stdout + result.stderr
