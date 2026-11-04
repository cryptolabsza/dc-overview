# TRACEWEAVER: file-role=gpu-alert-verification; req=REQ-GPUALERT-002; trace=TRACE-GPUALERT-002; ver=VER-GPUALERT-002
# TRACEWEAVER: verifies=VER-GPUALERT-002; req=REQ-GPUALERT-002; trace=TRACE-GPUALERT-002
"""Collector coverage is distinct from healthy scraping and physical GPU faults."""
import json
import shutil
import subprocess
from pathlib import Path
import pytest
import yaml
from types import SimpleNamespace
from dc_overview.web_prometheus import TelemetryMonitoringCollector
from dc_overview.grafana_alerts import MANAGED_ALERT_UIDS, render_grafana_alerts

UID = "fleet-gpu-collector-unavailable"


def collector_rule(instance_matcher=".+"):
    rules = [r for g in yaml.safe_load(render_grafana_alerts(instance_matcher=instance_matcher))["groups"] for r in g["rules"]]
    return next(r for r in rules if r["uid"] == UID)


def test_collector_alert_is_host_level_persistent_and_does_not_claim_hardware_failure():
    rule = collector_rule()
    assert UID in MANAGED_ALERT_UIDS
    assert rule["for"] == "2m"
    assert rule["keepFiringFor"] == "2m"
    assert rule["labels"]["alert_category"] == "gpu_collection"
    assert rule["labels"]["severity"] == "warning"
    assert "hardware failure" not in json.dumps(rule["annotations"]).lower()
    assert "recovery_summary" in rule["annotations"]
    assert "gpu" not in rule.get("notification_settings", {}).get("group_by", [])


@pytest.mark.skipif(not shutil.which("promtool"), reason="promtool unavailable")
# TRACEWEAVER: entrypoint=test_real_promql_detects_missing_stale_and_zero_inventory_without_fanout; req=REQ-GPUALERT-002; trace=TRACE-GPUALERT-002; ver=VER-GPUALERT-002
def test_real_promql_detects_missing_stale_and_zero_inventory_without_fanout(tmp_path):
    rule = collector_rule()
    expression = next(d["model"]["expr"] for d in rule["data"] if d["refId"] == "A")
    def series(name, values):
        return {"series": name, "values": values}
    base = 'instance="h100x8",Hostname="venter-h100x8-01"'
    up = series('up{instance="h100x8",exporter="dc",job="dc-managed"}', "1+0x20")
    pcie = series(f'DCXP_GPU_COUNT{{{base},type="pcie"}}', "8+0x20")
    def case(name, nvml, want, extra=(), when="3m", pcie_series=pcie):
        inputs = [up, pcie_series, *extra]
        if nvml is not None:
            inputs.append(series(f'DCXP_GPU_COUNT{{{base},type="nvml"}}', nvml))
        return {"name": name, "interval": "30s", "input_series": inputs,
                "promql_expr_test": [{"expr": expression, "eval_time": when,
                                      "exp_samples": [] if want is None else [{"labels": '{instance="h100x8"}', "value": want}]}]}
    cases = [
        case("NVML zero despite successful HTTP scrape", "0+0x20", 1),
        case("NVML metric missing despite successful scrape", None, 1),
        case("GPU counts old but still queryable despite live target", "8 _ _ _ _ _ _", 1,
             pcie_series=series(f'DCXP_GPU_COUNT{{{base},type="pcie"}}', "8 _ _ _ _ _ _")),
        case("GPU counts explicitly stale despite live target", "8 stale", 1,
             pcie_series=series(f'DCXP_GPU_COUNT{{{base},type="pcie"}}', "8 stale")),
        case("Complete source restoration", "8+0x20", 0),
        case("Partial coverage cannot claim complete recovery", "7+0x20", 1),
        case("Explicit GPU monitoring disabled", "0+0x20", None,
             [series('dc_overview_telemetry_monitoring_enabled{server_name="h100x8",telemetry="gpu"}', "0+0x20")]),
        case("Missing policy retains fallback expectation", "0+0x20", 1),
        case("Old disabled policy does not hide collector failure", "0+0x20", 1,
             [series('dc_overview_telemetry_monitoring_enabled{server_name="h100x8",telemetry="gpu"}', "0 _ _ _ _ _ _")]),
    ]
    disabled_dc = case("DC disabled while DCGM still enabled", "0+0x20", None,
                       [series('up{instance="h100x8",exporter="dcgm"}', "1+0x20"),
                        series('dc_overview_telemetry_monitoring_enabled{server_name="h100x8",telemetry="gpu"}', "1+0x20")])
    disabled_dc["input_series"] = [s for s in disabled_dc["input_series"] if s is not up]
    cases.append(disabled_dc)
    no_targets = case("Fresh source-specific disable does not resurrect removed DC target", "0+0x20", None,
                      [series('dc_overview_telemetry_monitoring_enabled{server_name="h100x8",telemetry="dc_exporter"}', "0+0x20"),
                       series('dc_overview_telemetry_monitoring_enabled{server_name="h100x8",telemetry="gpu"}', "1+0x20")])
    no_targets["input_series"] = [s for s in no_targets["input_series"] if s is not up]
    cases.append(no_targets)
    scrape_down = case("Failed scrape is not hidden by recent healthy counts", "8+0x20", 1)
    scrape_down["input_series"] = [s for s in scrape_down["input_series"] if s is not up]
    scrape_down["input_series"].append(series('up{instance="h100x8",exporter="dc"}', "0+0x20"))
    cases.append(scrape_down)
    cases.append(case("Host GPUs plus confirmed passthrough are complete", "6+0x20", 0, [
        series(f'DCXP_GPU_STATE{{{base},gpu="6",UUID="GPU-vm6"}}', "3+0x20"),
        series(f'DCXP_GPU_STATE{{{base},gpu="7",UUID="GPU-vm7"}}', "3+0x20"),
    ]))
    cases.append(case("Healthy CPU-only exporter has no GPU collection fault", "0+0x20", 0,
                      pcie_series=series(f'DCXP_GPU_COUNT{{{base},type="pcie"}}', "0+0x20")))
    legacy = case("Legacy scrape plus fresh aggregate policy still detects incident", "0+0x20", 1,
                  [series('up{instance="h100x8",job="legacy-h100x8"}', "1+0x20"),
                   series('dc_overview_telemetry_monitoring_enabled{server_name="h100x8",telemetry="gpu"}', "1+0x20")])
    legacy["input_series"] = [s for s in legacy["input_series"] if s is not up]
    cases.append(legacy)
    missing = case("Explicitly enabled DC source with all metrics missing still alerts", None, 1,
                   [series('dc_overview_telemetry_monitoring_enabled{server_name="h100x8",telemetry="dc_exporter"}', "1+0x20")])
    missing["input_series"] = [s for s in missing["input_series"] if s is not up and not s["series"].startswith('DCXP_GPU_COUNT')]
    cases.append(missing)
    excluded = case("Source policy respects site instance scope", "0+0x20", None,
                    [series('dc_overview_telemetry_monitoring_enabled{server_name="h100x8",telemetry="dc_exporter"}', "1+0x20")])
    scoped_rule = collector_rule("allowed-.+")
    excluded["promql_expr_test"][0]["expr"] = next(d["model"]["expr"] for d in scoped_rule["data"] if d["refId"] == "A")
    cases.append(excluded)
    fixture = tmp_path / "collector.test.yml"
    fixture.write_text(yaml.safe_dump({"evaluation_interval": "30s", "tests": cases}))
    result = subprocess.run(["promtool", "test", "rules", str(fixture)], text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("dc_enabled,dcgm_enabled", [(False, True), (True, False), (False, False)])
def test_source_specific_policy_preserves_aggregate_gpu_intent(dc_enabled, dcgm_enabled):
    server = SimpleNamespace(name="host", monitoring_name="h100x8", node_exporter_enabled=True,
                             dc_exporter_enabled=dc_enabled, dcgm_exporter_enabled=dcgm_enabled)
    sample = next(TelemetryMonitoringCollector(lambda: [server]).collect()).samples
    values = {(s.labels["server_name"], s.labels["telemetry"]): s.value for s in sample}
    assert values[("h100x8", "dc_exporter")] == int(dc_enabled)
    assert values[("h100x8", "gpu")] == int(dc_enabled or dcgm_enabled)


@pytest.mark.skipif(not shutil.which("promtool"), reason="promtool unavailable")
def test_actual_alert_waits_for_sustained_loss_and_stable_recovery(tmp_path):
    rule = collector_rule()
    expression = next(d["model"]["expr"] for d in rule["data"] if d["refId"] == "A")
    rule_path = tmp_path / "rules.yml"
    rule_path.write_text(yaml.safe_dump({"groups": [{"name": "GPU collection", "rules": [{"alert": UID, "expr": f"({expression}) > 0", "for": rule["for"], "keep_firing_for": rule["keepFiringFor"]}]}]}))
    fired = [{"exp_labels": {"instance": "h100x8"}, "exp_annotations": {}}]
    fixture = {"rule_files": [str(rule_path)], "evaluation_interval": "30s", "tests": [{"interval": "30s", "input_series": [
        {"series": 'up{instance="h100x8",exporter="dc"}', "values": "1+0x15"},
        {"series": 'DCXP_GPU_COUNT{instance="h100x8",type="pcie"}', "values": "8+0x15"},
        {"series": 'DCXP_GPU_COUNT{instance="h100x8",type="nvml"}', "values": "0+0x5 8+0x9"},
    ], "alert_rule_test": [{"eval_time": time, "alertname": UID, "exp_alerts": expected} for time, expected in [("1m", []), ("2m", fired), ("4m", fired), ("5m", [])]]}]}
    path = tmp_path / "temporal.test.yml"; path.write_text(yaml.safe_dump(fixture))
    result = subprocess.run(["promtool", "test", "rules", str(path)], text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(not shutil.which("go"), reason="Go unavailable")
@pytest.mark.parametrize("reason,expected,absent", [
    ("", "GPU telemetry restored", "Check dc-exporter"),
    ("MissingSeries", "monitoring changed", "GPU telemetry restored"),
    ("NoData", "monitoring changed", "GPU telemetry restored"),
    ("Paused", "monitoring changed", "GPU telemetry restored"),
])
def test_actual_notification_template_uses_truthful_resolution_text(tmp_path, reason, expected, absent):
    root = Path(__file__).parents[1]
    template = yaml.safe_load((root / "src/dc_overview/templates/grafana/provisioning/alerting/dc-overview-notifications.yml").read_text())["templates"][0]["template"]
    (tmp_path / "template.txt").write_text(template)
    go = '''package main
import("os";"text/template";"encoding/json")
func main(){b,_:=os.ReadFile(os.Args[1]); var d interface{};json.Unmarshal([]byte(os.Args[2]),&d);t:=template.Must(template.New("root").Parse(string(b)));if err:=t.ExecuteTemplate(os.Stdout,"cryptolabs.telegram.message",d);err!=nil{panic(err)}}
'''
    (tmp_path / "main.go").write_text(go)
    data = {"Alerts": {"Firing": [], "Resolved": [{"Labels": {"alert_category": "gpu_collection"}, "Annotations": {"summary": "h100x8 · GPU telemetry unavailable", "description": "Check dc-exporter collection.", "recovery_summary": "h100x8 · GPU telemetry restored", "grafana_state_reason": reason}}]}}
    result = subprocess.run(["go", "run", str(tmp_path / "main.go"), str(tmp_path / "template.txt"), json.dumps(data)], text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert expected in result.stdout
    assert absent not in result.stdout
