"""Snapshot queries preserve the approved Vast dashboard contract."""
import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
CANONICAL = ("dashboards/Vast_Dashboard.json", "src/dc_overview/dashboards/Vast_Dashboard.json")
OUTSIDE_SNAPSHOT_SHA256 = {'dashboards/Vast_Dashboard.json': 'e5fd19b71a5de609176042ee3ac16f4da95f4b8e26a2d4c8ee2a9b5c3fc1aa01', 'src/dc_overview/dashboards/Vast_Dashboard.json': 'e5fd19b71a5de609176042ee3ac16f4da95f4b8e26a2d4c8ee2a9b5c3fc1aa01'}
LEGACY_SHA256 = {'server/grafana/dashboards/Vast_Dashboard.json': '0293affb7394af7c8826d885b761bda3ecf822731f11cbb70d520d30399f68bc', 'server/grafana/dashboards/vast-dashboard.json': '09d10a7737f9e7662fd7f61659d20fa475fb53a4db2a585996c669a25f0b6a56'}
TARGET_CONTRACT_SHA256 = {'39': '676dddcc18d637afda58b402d81b6226079b0dfa98dfa0bd04ed49246845e649', '41': '1b07fcc874fdcaa8d218b0d260d1f2388c4f6d462af511cf47761d1e89039626'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def panel(dashboard, panel_id):
    return next(p for p in dashboard["panels"] if p.get("id") == panel_id)


@pytest.mark.parametrize("path", CANONICAL)
def test_snapshot_targets_are_instant_and_preserve_queries(path):
    dashboard = json.loads((ROOT / path).read_text())
    for panel_id, count in ((39, 9), (41, 1)):
        targets = panel(dashboard, panel_id)["targets"]
        assert len(targets) == count
        assert all(t.get("instant") is True and t.get("range") is False for t in targets)
        contract = [{k: v for k, v in t.items() if k not in ("instant", "range")
                     and not (panel_id == 39 and t["refId"] == "I" and k == "expr")} for t in targets]
        assert digest(contract) == TARGET_CONTRACT_SHA256[str(panel_id)]
    thermal = next(t for t in panel(dashboard, 39)["targets"] if t["refId"] == "I")
    assert thermal["expr"] == 'avg by(instance)(node_thermal_zone_temp{type="x86_pkg_temp"})'


@pytest.mark.parametrize("path", CANONICAL)
def test_all_other_panels_and_dashboard_settings_are_unchanged(path):
    dashboard = json.loads((ROOT / path).read_text())
    dashboard["panels"] = [p for p in dashboard["panels"] if p.get("id") not in (39, 41)]
    assert digest(dashboard) == OUTSIDE_SNAPSHOT_SHA256[path]


def test_canonical_copies_match_and_legacy_bytes_are_preserved():
    assert (ROOT / CANONICAL[0]).read_bytes() == (ROOT / CANONICAL[1]).read_bytes()
    for path, expected in LEGACY_SHA256.items():
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == expected


@pytest.mark.parametrize("path", CANONICAL)
def test_overview_preserves_columns_and_hides_uname_metadata(path):
    dashboard = json.loads((ROOT / path).read_text())
    overview = panel(dashboard, 39)
    join, organize, sort = overview["transformations"]
    assert join == {"id": "joinByField", "options": {"byField": "instance", "mode": "outer"}}
    assert sort["options"]["sort"] == [{"field": "Machine"}]
    expected = json.loads((ROOT / "tests/fixtures/vast_snapshot_expected_table.json").read_text())
    options = organize["options"]
    assert options["excludeByName"].get("exporter") is True
    assert list(options["renameByName"].values()).count("Machine") == 1
    assert set(expected["columns"]) <= set(options["renameByName"].values())


def test_sanitized_raw_label_fixture_has_missing_field_cases():
    import re

    lines = (ROOT / "tests/fixtures/vast_snapshot_labels.prom").read_text().splitlines()
    samples = []
    for line in lines:
        if not line or line.startswith("#"):
            continue
        metric, value = line.rsplit(" ", 1)
        name, labels = metric.split("{", 1)
        labels = {key: json.loads(value) for key, value in re.findall(r'(\w+)=("(?:[^"\\]|\\.)*")', labels)}
        samples.append((name, labels, float(value)))
    uname = {labels["instance"]: labels for name, labels, _ in samples if name == "node_uname_info"}
    thermal = [(labels, value) for name, labels, value in samples if name == "node_thermal_zone_temp"]
    docker = {labels["instance"] for name, labels, _ in samples
              if name == "node_filesystem_avail_bytes" and labels["mountpoint"] == "/var/lib/docker"}
    expected = json.loads((ROOT / "tests/fixtures/vast_snapshot_expected_table.json").read_text())
    assert len(uname) == len(expected["rows"]) == 9
    assert len(thermal) == 8
    assert len({labels["instance"] for labels, _ in thermal}) == 4
    assert len(docker) == 5
    for row in expected["rows"]:
        instance = row["instance"]
        assert row["Machine"] == uname[instance]["nodename"]
        assert row["Kernel"] == uname[instance]["release"]
        assert uname[instance]["exporter"] == "node"
        temperatures = [value for labels, value in thermal if labels["instance"] == instance]
        assert row["CPU Temp C"] == (sum(temperatures) / len(temperatures) if temperatures else None)
        assert row["Docker Disk Usage %"] == (50 if instance in docker else None)


@pytest.mark.parametrize("path", CANONICAL)
def test_overview_selects_existing_joined_frame(path):
    # Native Grafana 13.2.3 emits one joined frame for the nine instant targets.
    dashboard = json.loads((ROOT / path).read_text())
    assert panel(dashboard, 39)["options"]["frameIndex"] == 0
