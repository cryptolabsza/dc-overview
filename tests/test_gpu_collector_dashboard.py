# TRACEWEAVER: file-role=gpu-alert-verification; req=REQ-GPUALERT-003; trace=TRACE-GPUALERT-003; ver=VER-GPUALERT-003
# TRACEWEAVER: verifies=VER-GPUALERT-003; req=REQ-GPUALERT-003; trace=TRACE-GPUALERT-003
"""Source quality must not be presented as eight confirmed physical failures."""
import json
import shutil
import subprocess
from pathlib import Path
import pytest
import yaml

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize("name,panel_id", [("DC_Exporter_Details.json", 12), ("DC_Overview.json", 11)])
def test_dashboard_distinguishes_synthetic_telemetry_failure(name, panel_id):
    packaged = ROOT / "src/dc_overview/dashboards" / name
    mirrored = ROOT / "dashboards" / name
    d = json.loads(packaged.read_text())
    panel = next(p for p in d["panels"] if p.get("id") == panel_id)
    assert "Telemetry unavailable" in json.dumps(panel["fieldConfig"])
    assert "collection" in panel["description"].lower()
    for target in panel["targets"]:
        assert 'UUID="DRIVER-ERROR"' in target["expr"]
    mirror = json.loads(mirrored.read_text())
    mirror_panel = next(p for p in mirror["panels"] if p.get("id") == panel_id)
    assert [t["expr"] for t in mirror_panel["targets"]] == [t["expr"] for t in panel["targets"]]
    assert "Telemetry unavailable" in json.dumps(mirror_panel["fieldConfig"])


@pytest.mark.skipif(not shutil.which("promtool"), reason="promtool unavailable")
# TRACEWEAVER: entrypoint=test_dashboard_promql_keeps_real_faults_and_passthrough; req=REQ-GPUALERT-003; trace=TRACE-GPUALERT-003; ver=VER-GPUALERT-003
def test_dashboard_promql_keeps_real_faults_and_passthrough(tmp_path):
    d = json.loads((ROOT / "src/dc_overview/dashboards/DC_Exporter_Details.json").read_text())
    expression = next(p for p in d["panels"] if p.get("id") == 12)["targets"][0]["expr"]
    inputs = []
    expected = []
    for host, uuid, value, displayed in [("collector", "DRIVER-ERROR", 2, 6), ("physical", "GPU-real", 2, 2), ("passthrough", "GPU-vm", 3, 3)]:
        labels = f'instance="{host}",gpu="0",UUID="{uuid}"'
        inputs.extend([{"series": f'GPU_ERROR_STATE{{{labels}}}', "values": str(value)}, {"series": f'DCXP_GPU_STATE{{{labels}}}', "values": str(value)}])
        expected.append({"labels": "{" + labels + "}", "value": displayed})
    fixture = {"evaluation_interval": "1m", "tests": [{"interval": "1m", "input_series": inputs, "promql_expr_test": [{"expr": expression, "eval_time": "0m", "exp_samples": expected}]}]}
    p = tmp_path / "dashboard.test.yml"; p.write_text(yaml.safe_dump(fixture))
    r = subprocess.run(["promtool", "test", "rules", str(p)], text=True, capture_output=True)
    assert r.returncode == 0, r.stdout + r.stderr
