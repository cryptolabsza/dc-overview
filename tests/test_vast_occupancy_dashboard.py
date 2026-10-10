"""Real Prometheus evaluation of the shipped, fixed-window occupancy summary."""

import copy
import hashlib
import importlib.util
import json
import math
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
DASHBOARDS = [
    "dashboards/Vast_Dashboard.json",
    "src/dc_overview/dashboards/Vast_Dashboard.json",
    "server/grafana/dashboards/Vast_Dashboard.json",
    "server/grafana/dashboards/vast-dashboard.json",
]
METRICS = [
    "vastai_machine_gpu_rented_on_demand",
    "vastai_machine_gpu_rented_on_reserved",
    "vastai_machine_gpu_rented_bid_demand",
    "vastai_machine_gpu_idle",
]
MINUTES = 43200
# Reviewed base d910a642: every previous panel/root property is preserved, apart
# from the explicitly approved y += 8 below the new full-width summary.
BASELINE = {
    "dashboards/Vast_Dashboard.json": "f1b2f9ad47e8e1e70331576deeb19f6c204de099ee766051ae9194a6bd4cfd1f",
    "src/dc_overview/dashboards/Vast_Dashboard.json": "f1b2f9ad47e8e1e70331576deeb19f6c204de099ee766051ae9194a6bd4cfd1f",
    "server/grafana/dashboards/Vast_Dashboard.json": "49b6e1876e3bb85f94e98092eec256c0aea221230a70fc7cd0e9c98c373063ec",
    "server/grafana/dashboards/vast-dashboard.json": "d29c92d10187699a10872df943d0d9d9c77190d51e6839f581b0695f69cf0cac",
}


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def panel(filename):
    matches = [p for p in json.loads((ROOT / filename).read_text())["panels"] if p.get("id") == 43]
    assert len(matches) == 1, "missing/duplicate 30-day occupancy panel 43"
    return matches[0]


@pytest.mark.parametrize("filename", DASHBOARDS)
def test_panel_layout_datasource_and_existing_configuration(filename):
    dashboard = json.loads((ROOT / filename).read_text())
    current = panel(filename)
    restored = copy.deepcopy(dashboard)
    restored["panels"] = [p for p in restored["panels"] if p["id"] != 43]
    assert len(restored["panels"]) == 40
    for previous in restored["panels"]:
        if previous["gridPos"]["y"] >= 56:
            previous["gridPos"]["y"] -= 8
    assert digest(restored) == BASELINE[filename], "unapproved previous panel/root change"
    assert current["gridPos"] == {"x": 0, "y": 48, "w": 24, "h": 8}
    assert current["type"] == "table"
    assert current["title"] == "30-day machine occupancy"
    assert (
        current["datasource"] == next(p for p in dashboard["panels"] if p["id"] == 37)["datasource"]
    )
    assert [t["refId"] for t in current["targets"]] == ["A", "B"]
    for target in current["targets"]:
        assert target["instant"] is True and target["range"] is False
        assert target["format"] == "table"
        assert target["datasource"] == current["datasource"]
        assert "[30d:1m]" in target["expr"]
        assert "$__" not in target["expr"]
    assert "timeFrom" not in current and "timeShift" not in current
    help_text = current["description"].lower()
    for phrase in [
        "on-demand",
        "reserved",
        "bid",
        "gpu capacity",
        "observed",
        "coverage",
        "90 seconds",
        "1-minute",
        "unavailable",
        "conflicting",
    ]:
        assert phrase in help_text
    organize = current["transformations"][-1]["options"]
    assert set(organize["includeByName"]) == {"machine", "Value #A", "Value #B"}
    assert organize["renameByName"]["Value #A"] == "Occupancy % (observed data)"
    assert organize["renameByName"]["Value #B"] == "30-day data coverage %"
    assert current["fieldConfig"]["defaults"]["noValue"] == "Unavailable"
    assert current["fieldConfig"]["defaults"]["unit"] == "percent"


def test_all_copies_have_identical_summary_behavior():
    first = copy.deepcopy(panel(DASHBOARDS[0]))
    first.pop("datasource")
    for target in first["targets"]:
        target.pop("datasource")
    for filename in DASHBOARDS[1:]:
        other = copy.deepcopy(panel(filename))
        other.pop("datasource")
        for target in other["targets"]:
            target.pop("datasource")
        assert other == first


def states(
    values,
    *,
    account="team",
    machine_id="7",
    hostname="host",
    job="vastai",
    instance="exporter",
    omit=(),
):
    """Input raw exporter counts; extra labels model Prometheus scrape replicas."""
    labels = {
        "account": account,
        "machine_id": machine_id,
        "hostname": hostname,
        "job": job,
        "instance": instance,
    }
    suffix = "{" + ",".join(f'{k}="{v}"' for k, v in labels.items()) + "}"
    return [
        {"series": metric + suffix, "values": str(value)}
        for metric, value in zip(METRICS, values)
        if metric not in omit
    ]


def constant(values, n=60, **kwargs):
    return states([f"{v}+0x{n}" for v in values], **kwargs)


def expected(value, account="team", machine_id="7"):
    return {
        "labels": '{account="'
        + account
        + '",machine="'
        + account
        + " / "
        + machine_id
        + '",machine_id="'
        + machine_id
        + '"}',
        "value": value,
    }


def exporter_fixture_series():
    """The integration scenario is produced by the actual exporter and fixture."""
    spec = importlib.util.spec_from_file_location(
        "occupancy_exporter", ROOT / "vastai-exporter/vastai_exporter.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    captured = json.loads((ROOT / "tests/fixtures/vastai_host_occupancy.json").read_text())[
        "machine"
    ]
    _, totals = module.MetricsCollector([])._gpu_occupancy(captured, captured["num_gpus"])
    return constant(
        [totals[k] for k in ["on_demand", "on_reserved", "bid_demand", "idle"]],
        machine_id=str(captured["id"]),
    )


def semantic_cases():
    """Expected values are hand-calculated GPU-minutes; no Python query imitation."""
    coverage = 100 * 61 / MINUTES
    cases = []

    def add(name, series, occupancy, cov=coverage, at="1h", identities=None):
        identities = identities or [("team", "7")]
        a = (
            []
            if occupancy is None
            else [
                expected(v, *identity)
                for identity, v in zip(
                    identities, occupancy if isinstance(occupancy, list) else [occupancy]
                )
            ]
        )
        b = (
            []
            if cov is None
            else [
                expected(v, *identity)
                for identity, v in zip(identities, cov if isinstance(cov, list) else [cov])
            ]
        )
        cases.append((name, series, at, a, b))

    add(
        "captured exporter integration",
        exporter_fixture_series(),
        100,
        identities=[("team", "150663")],
    )
    add("mixed on-demand and reserved", constant([2, 2, 1, 3]), 50)
    add("reserved alone counts", constant([0, 4, 0, 4]), 50)
    add("half GPU capacity", constant([4, 0, 0, 4]), 50)
    add("idle is known zero", constant([0, 0, 0, 8]), 0)
    add("bid is capacity but not occupied", constant([0, 0, 8, 0]), 0)
    add(
        "two IDs sharing a hostname",
        constant([4, 0, 0, 4]) + constant([8, 0, 0, 0], machine_id="8"),
        [50, 100],
        [coverage, coverage],
        identities=[("team", "7"), ("team", "8")],
    )
    add(
        "same machine ID in distinct accounts",
        constant([4, 0, 0, 4]) + constant([8, 0, 0, 0], account="other"),
        [50, 100],
        [coverage, coverage],
        identities=[("team", "7"), ("other", "7")],
    )
    add(
        "identical replicas",
        constant([4, 0, 0, 4]) + constant([4, 0, 0, 4], job="duplicate", instance="second"),
        50,
    )
    add(
        "contradictory replicas unavailable",
        constant([8, 0, 0, 0]) + constant([0, 0, 0, 8], job="duplicate", instance="second"),
        None,
        None,
    )
    add(
        "same total and occupied but conflicting states",
        constant([4, 0, 0, 4]) + constant([0, 4, 0, 4], job="duplicate", instance="second"),
        None,
        None,
    )
    add(
        "duplicate only while busy",
        states(["8+0x29 0+0x30", "0+0x60", "0+0x60", "0+0x29 8+0x30"])
        + states(["8+0x29 stale", "0+0x29 stale", "0+0x29 stale", "0+0x29 stale"], job="duplicate"),
        100 * 30 / 61,
    )
    add(
        "hostname rename retains stable ID",
        states(["4+0x29 stale", "0+0x29 stale", "0+0x29 stale", "4+0x29 stale"], hostname="old")
        + states(["_x29 4+0x30", "_x29 0+0x30", "_x29 0+0x30", "_x29 4+0x30"], hostname="new"),
        50,
    )
    # Equal-duration 4/8 then 4/4: 4*60 / (8*30+4*30) = 2/3.
    add(
        "changing capacity weights GPU-minutes",
        states(["_ 4+0x59", "_ 0+0x59", "_ 0+0x59", "_ 4+0x29 0+0x29"]),
        100 * 2 / 3,
        100 * 60 / MINUTES,
    )
    for index, metric in enumerate(METRICS):
        invalid = [4, 0, 0, 4]
        invalid[index] = "NaN"
        add(f"NaN in {metric}", constant(invalid), None, None)
        invalid[index] = "+Inf"
        add(f"infinite {metric}", constant(invalid), None, None)
        invalid[index] = -1
        add(f"negative {metric}", constant(invalid), None, None)
        add(f"missing {metric}", constant([4, 0, 0, 4], omit=[metric]), None, None)
    add("absent telemetry", [], None, None)
    add("legacy demand plus idle only", constant([4, 0, 0, 4], omit=METRICS[1:3]), None, None)
    add("zero capacity", constant([0, 0, 0, 0]), None, None)
    registered = [
        {
            "series": 'vast_machine_num_gpus{account="team",machine_id="7",hostname="host",job="vastai",instance="exporter"}',
            "values": "8+0x60",
        }
    ]
    add(
        "registered machine unknown history remains unavailable",
        constant(["NaN", "NaN", "NaN", "NaN"]) + registered,
        "NaN",
        0,
    )
    add(
        "registered legacy history remains unavailable",
        constant([4, 0, 0, 4], omit=METRICS[1:3]) + registered,
        "NaN",
        0,
    )
    add("registered-only machine has no state history", registered, "NaN", 0)
    add(
        "known idle beside current CCC153016 with unknown history",
        constant([0, 0, 0, 8])
        + constant(["NaN", "NaN", "NaN", "NaN"], machine_id="153016", hostname="CCC")
        + [
            {
                "series": sample["series"]
                .replace('machine_id="7"', 'machine_id="153016"')
                .replace('hostname="host"', 'hostname="CCC"'),
                "values": sample["values"],
            }
            for sample in registered
        ],
        [0, "NaN"],
        [coverage, 0],
        identities=[("team", "7"), ("team", "153016")],
    )

    add(
        "absent account identity",
        [
            {**sample, "series": sample["series"].replace('account="team",', "")}
            for sample in constant([4, 0, 0, 4])
        ],
        None,
        None,
    )
    add(
        "absent machine identity",
        [
            {**sample, "series": sample["series"].replace('machine_id="7",', "")}
            for sample in constant([4, 0, 0, 4])
        ],
        None,
        None,
    )

    for field in ["account", "machine_id"]:
        for invalid in ["", "unknown", "null", "none", "n/a"]:
            add(
                f"invalid {field} {invalid!r}",
                constant([4, 0, 0, 4], **{field: invalid}),
                None,
                None,
            )
    add(
        "missing scrape raw timestamp bounded",
        states(["4 _x59", "0 _x59", "0 _x59", "4 _x59"]),
        50,
        100 * 2 / MINUTES,
    )
    add(
        "explicit stale marker",
        states(["4 stale _x58", "0 stale _x58", "0 stale _x58", "4 stale _x58"]),
        50,
        100 / MINUTES,
    )
    add(
        "components from different scrape timestamps",
        states(["_ 4+0x59", "0 _x59", "_ 0+0x59", "_ 4+0x59"]),
        None,
        None,
    )
    add(
        "long internal gap excluded",
        states(
            [
                "4+0x9 stale _x39 4+0x9",
                "0+0x9 stale _x39 0+0x9",
                "0+0x9 stale _x39 0+0x9",
                "4+0x9 stale _x39 4+0x9",
            ]
        ),
        50,
        100 * 20 / MINUTES,
    )
    add(
        "unknown intervals do not dilute occupancy",
        states(["4+0x29 NaN+0x30", "0+0x60", "0+0x60", "4+0x60"]),
        50,
        100 * 30 / MINUTES,
    )
    add("complete 30-day history exact boundary", constant([4, 0, 0, 4], MINUTES), 50, 100, "30d")
    add("complete window off-grid evaluation", constant([4, 0, 0, 4], MINUTES), 50, 100, "30d30s")
    add(
        "one day of retained history",
        states(["_x41760 4+0x1439", "_x41760 0+0x1439", "_x41760 0+0x1439", "_x41760 4+0x1439"]),
        50,
        100 * 1440 / MINUTES,
        "30d",
    )
    return cases


def expanded_samples(values):
    """Expand promtool fixture notation into raw observations, never occupancy math."""
    for token in values.split():
        if token == "_":
            yield None
        elif token.startswith("_x"):
            yield from [None] * (int(token[2:]) + 1)
        elif "+0x" in token:
            value, repeats = token.split("+0x")
            yield from [value] * (int(repeats) + 1)
        else:
            # OpenMetrics NaN makes an explicitly stale/unknown observation invalid
            # under the shipped full-state mask just as an absent stale series is.
            yield "NaN" if token == "stale" else token


def duration_seconds(value):
    return sum(
        int(n) * {"d": 86400, "h": 3600, "m": 60, "s": 1}[unit]
        for n, unit in re.findall(r"(\d+)([dhms])", value)
    )


@pytest.fixture(scope="module")
def prometheus_fixture(tmp_path_factory, request):
    promtool = shutil.which("promtool")
    prometheus = shutil.which("prometheus")
    if not promtool or not prometheus:
        if os.environ.get("REQUIRE_PROMTOOL") == "1":
            pytest.fail("promtool and matching prometheus are required in CI")
        pytest.skip("promtool and matching prometheus are required for semantic tests")
    directory = tmp_path_factory.mktemp("occupancy-prometheus")
    storage = directory / "data"
    evaluation = int(time.time() // 60) * 60
    cases = semantic_cases()
    if hasattr(request, "param"):
        cases = [case for case in cases if case[0] in request.param]
        assert len(cases) == len(request.param)
    expectations = {"A": {}, "B": {}}
    scenario_names = {}
    (directory / "scenario-inputs.json").write_text(
        json.dumps(
            {"evaluation_timestamp": evaluation, "grid_seconds": 60, "scenarios": cases}, indent=2
        )
    )
    metrics = directory / "fixture.om"
    with metrics.open("w") as output:
        for index, (name, series, at, occupancy, coverage) in enumerate(cases):
            prefix = f"case{index:02d}_"
            scenario_names[prefix] = name
            # Align each scenario's evaluation end to the same real UTC minute.
            # Its input series timestamps remain exactly 60s apart. The explicit
            # off-grid assertion queries the same fixtures at evaluation + 30s.
            beginning = evaluation - (duration_seconds(at) // 60) * 60
            for sample in series:
                raw_series = re.sub(
                    r'account="([^"]*)"',
                    lambda match, case_prefix=prefix: 'account="'
                    + (
                        match[1]
                        if match[1].lower() in ["", "unknown", "null", "none", "n/a"]
                        else case_prefix + match[1]
                    )
                    + '"',
                    sample["series"],
                )
                raw_series = raw_series.replace('job="', 'job="' + prefix)
                for minute, value in enumerate(expanded_samples(sample["values"])):
                    if value is not None:
                        output.write(f"{raw_series} {value} {beginning + minute * 60}\n")
            for ref, expected_samples in [("A", occupancy), ("B", coverage)]:
                for sample in expected_samples:
                    # Parse labels only: the numeric expectations remain the hand
                    # calculations defined above and are not recomputed here.
                    labels = dict(re.findall(r'(\w+)="([^"]*)"', sample["labels"]))
                    labels["account"] = prefix + labels["account"]
                    labels["machine"] = prefix + labels["machine"]
                    expectations[ref][tuple(sorted(labels.items()))] = sample["value"]
        output.write("# EOF\n")
    # Pinned promtool v3.13.1 has an import-only max-block-duration option.
    # Large fixture blocks avoid rescanning a month's input 360 times; this
    # does not change raw observations or any shipped expression/grid.
    result = subprocess.run(
        [
            promtool,
            "tsdb",
            "create-blocks-from",
            "--max-block-duration=30d",
            "openmetrics",
            "--quiet",
            str(metrics),
            str(storage),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    (directory / "import-result.json").write_text(
        json.dumps(
            {
                "command": result.args,
                "exit_status": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
            indent=2,
        )
    )
    assert result.returncode == 0, result.stdout + result.stderr
    config = directory / "prometheus.yml"
    config.write_text("global:\n  scrape_interval: 1m\nscrape_configs: []\n")
    with socket.socket() as available:
        available.bind(("127.0.0.1", 0))
        port = available.getsockname()[1]
    server = f"http://127.0.0.1:{port}"
    log = (directory / "prometheus.log").open("w")
    process = subprocess.Popen(
        [
            prometheus,
            f"--config.file={config}",
            f"--storage.tsdb.path={storage}",
            "--storage.tsdb.retention.time=45d",
            "--query.max-samples=50000000",
            "--query.timeout=120s",
            f"--web.listen-address=127.0.0.1:{port}",
        ],
        stdout=log,
        stderr=log,
    )
    try:
        ready = False
        for _ in range(300):
            if process.poll() is not None:
                break
            try:
                with urllib.request.urlopen(server + "/-/ready", timeout=1) as response:
                    ready = response.status == 200
                if ready:
                    break
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        assert ready, (directory / "prometheus.log").read_text()
        yield promtool, server, evaluation, expectations, scenario_names, directory
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()


@pytest.mark.parametrize("filename", DASHBOARDS)
def test_shipped_occupancy_queries_with_prometheus(filename, prometheus_fixture):
    # promtool test rules hardcodes MaxSamples=10,000; a 43,200-point time()
    # grid exceeds that even without input data. Use real promtool TSDB loading
    # and query commands against the matching local engine, with the exact
    # shipped expressions and the production-default 50-million sample limit.
    promtool, server, evaluation, expectations, scenarios, directory = prometheus_fixture
    for target in panel(filename)["targets"]:
        for timestamp in [evaluation, evaluation + 30]:
            result = subprocess.run(
                [
                    promtool,
                    "query",
                    "instant",
                    "--format=json",
                    f"--time={timestamp}",
                    server,
                    target["expr"],
                ],
                capture_output=True,
                text=True,
                timeout=150,
            )
            evidence = directory / (
                filename.replace("/", "-") + f"-{target['refId']}-{timestamp}.json"
            )
            evidence.write_text(
                json.dumps(
                    {
                        "command": result.args,
                        "exit_status": result.returncode,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "query_sha256": hashlib.sha256(target["expr"].encode()).hexdigest(),
                    },
                    indent=2,
                )
            )
            assert result.returncode == 0, result.stdout + result.stderr
            response = json.loads(result.stdout)
            assert isinstance(response, list), response
            actual = {
                tuple(sorted(sample["metric"].items())): float(sample["value"][1])
                for sample in response
            }
            expected_samples = expectations[target["refId"]]
            assert set(actual) == set(expected_samples), {
                "unexpected": set(actual) - set(expected_samples),
                "missing": set(expected_samples) - set(actual),
                "scenarios": scenarios,
            }
            for labels, expected_value in expected_samples.items():
                if expected_value == "NaN":
                    assert target["refId"] == "A", "only explicit unavailable occupancy can be NaN"
                    assert math.isnan(actual[labels]), {"labels": labels, "value": actual[labels]}
                    assert expectations["B"][labels] == 0
                    continue
                assert math.isfinite(actual[labels]) and 0 <= actual[labels] <= 100
                assert actual[labels] == pytest.approx(expected_value, abs=1e-9), {
                    "labels": labels,
                    "actual": actual[labels],
                    "expected": expected_value,
                    "scenarios": scenarios,
                }


UNKNOWN_ONLY_CASES = (
    "registered machine unknown history remains unavailable",
    "registered legacy history remains unavailable",
    "registered-only machine has no state history",
)


@pytest.mark.parametrize("filename", DASHBOARDS)
@pytest.mark.parametrize("prometheus_fixture", [UNKNOWN_ONLY_CASES], indirect=True)
def test_registered_unknown_history_keeps_both_numeric_columns(filename, prometheus_fixture):
    test_shipped_occupancy_queries_with_prometheus(filename, prometheus_fixture)
    _, _, evaluation, expectations, _, directory = prometheus_fixture
    current = panel(filename)
    assert expectations["A"] and set(expectations["A"]) == set(expectations["B"])
    nan_maps = [
        mapping
        for mapping in current["fieldConfig"]["defaults"].get("mappings", [])
        if mapping["type"] == "special" and mapping["options"]["match"] == "nan"
    ]
    assert len(nan_maps) == 1
    assert nan_maps[0]["options"]["result"]["text"] == "Unavailable"
    assert current["fieldConfig"]["defaults"]["noValue"] == "Unavailable"
    for timestamp in [evaluation, evaluation + 30]:
        responses = {}
        for ref in ["A", "B"]:
            evidence = json.loads(
                (directory / (filename.replace("/", "-") + f"-{ref}-{timestamp}.json")).read_text()
            )
            responses[ref] = json.loads(evidence["stdout"])
            assert responses[
                ref
            ], f"{ref} must retain its numeric table field when all history is unknown"
            assert all("machine" in sample["metric"] for sample in responses[ref])
        # Grafana transformDFToTable names fields Value #<refId> when both
        # populated query refs exist; joinByField now has a machine in each.
        # This checks the source-established naming precondition, not a Python
        # implementation of the Grafana renderer; root verifies the live UI.
        numeric_fields = {f"Value #{ref}" for ref in responses}
        kept = set(current["transformations"][1]["options"]["include"]["names"])
        assert numeric_fields <= kept
        names = current["transformations"][-1]["options"]["renameByName"]
        assert names["Value #A"] == "Occupancy % (observed data)"
        assert names["Value #B"] == "30-day data coverage %"
        assert all(sample["value"][1] == "NaN" for sample in responses["A"])
        assert all(float(sample["value"][1]) == 0 for sample in responses["B"])


def test_docker_publish_requires_occupancy_semantics():
    workflow = yaml.safe_load((ROOT / ".github/workflows/docker-build.yml").read_text())
    steps = workflow["jobs"]["build"]["steps"]
    names = [s.get("name") for s in steps]
    test_step = steps[names.index("Test Vast dashboards")]
    assert names.index("Test Vast dashboards") < names.index("Build Docker image")
    assert test_step["env"]["REQUIRE_PROMTOOL"] == "1"
    assert "tests/test_vast_occupancy_dashboard.py" in test_step["run"]
    assert "prometheus-3.13.1.linux-amd64/prometheus" in test_step["run"]
