"""Regression coverage for Vast provider GPU occupancy metrics."""

import copy
import importlib.util
import json
import math
import re
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
EXPORTER_PATH = ROOT / "vastai-exporter" / "vastai_exporter.py"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "vastai_host_occupancy.json"


@pytest.fixture(scope="module")
def exporter_module():
    spec = importlib.util.spec_from_file_location("vastai_exporter", EXPORTER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeProvider:
    def __init__(self, machine, instances=None):
        self.account_name = "test"
        self.machine = machine
        self.instances = instances or []

    def get_user_info(self):
        return {}

    def get_machines(self):
        return [copy.deepcopy(self.machine)]

    def get_instances(self):
        return copy.deepcopy(self.instances)


def collect(exporter_module, machine, instances=None):
    collector = exporter_module.MetricsCollector([])
    collector.clients = [FakeProvider(machine, instances)]
    return collector.collect()


def samples(metrics, metric_name):
    pattern = re.compile(rf"^{re.escape(metric_name)}\{{([^}}]*)\}} (.+)$", re.MULTILINE)
    return [(labels, float(value)) for labels, value in pattern.findall(metrics)]


def machine_sample(metrics, metric_name):
    values = samples(metrics, metric_name)
    assert len(values) == 1, values
    return values[0][1]


def occupancy_samples(metrics):
    values = samples(metrics, "vastai_machine_gpu_occupancy")
    return [value for labels, value in sorted(values, key=lambda item: int(re.search(r'gpu="(\d+)"', item[0]).group(1)))]


def test_captured_provider_occupancy_drives_gpu_metrics_and_verification(exporter_module):
    """Known provider glyphs must win over a one-rental instance response."""
    machine = json.loads(FIXTURE_PATH.read_text())["machine"]
    metrics = collect(
        exporter_module,
        machine,
        instances=[
            {
                "machine_id": machine["id"],
                "num_gpus": 1,
                "actual_status": "running",
                "is_bid": True,
            }
        ],
    )

    assert occupancy_samples(metrics) == [2.0] * 8
    assert machine_sample(metrics, "vastai_machine_gpu_rented_on_demand") == 8.0
    assert machine_sample(metrics, "vastai_machine_gpu_rented_bid_demand") == 0.0
    assert machine_sample(metrics, "vastai_machine_gpu_rented_on_reserved") == 0.0
    assert machine_sample(metrics, "vastai_machine_gpu_idle") == 0.0
    assert machine_sample(metrics, "vast_machine_Verification") == 0.0


def test_mixed_provider_glyphs_drive_consistent_individual_and_aggregate_metrics(exporter_module):
    machine = {
        "id": 7,
        "num_gpus": 4,
        "gpu_occupancy": "D R I x",
        "current_rentals_running": 3,
        "current_rentals_on_demand": 1,
        "current_rentals_resident": 1,
    }

    metrics = collect(exporter_module, machine)

    assert occupancy_samples(metrics) == [2.0, 3.0, 1.0, 0.0]
    assert machine_sample(metrics, "vastai_machine_gpu_rented_on_demand") == 1.0
    assert machine_sample(metrics, "vastai_machine_gpu_rented_bid_demand") == 1.0
    assert machine_sample(metrics, "vastai_machine_gpu_rented_on_reserved") == 1.0
    assert machine_sample(metrics, "vastai_machine_gpu_idle") == 1.0


def test_partial_on_demand_occupancy_keeps_the_remaining_slots_idle(exporter_module):
    metrics = collect(
        exporter_module,
        {
            "id": 71,
            "num_gpus": 4,
            "gpu_occupancy": "D x x x",
            "current_rentals_running": 1,
            "current_rentals_on_demand": 1,
        },
    )

    assert occupancy_samples(metrics) == [2.0, 0.0, 0.0, 0.0]
    assert machine_sample(metrics, "vastai_machine_gpu_rented_on_demand") == 1.0
    assert machine_sample(metrics, "vastai_machine_gpu_idle") == 3.0


def test_zero_running_overrides_stale_glyphs_and_resident_rental_count(exporter_module):
    machine = {
        "id": 8,
        "num_gpus": 4,
        "gpu_occupancy": "R D I R",
        "current_rentals_running": 0,
        "current_rentals_resident": 1,
    }

    metrics = collect(exporter_module, machine)

    assert occupancy_samples(metrics) == [0.0] * 4
    assert [machine_sample(metrics, name) for name in (
        "vastai_machine_gpu_rented_on_demand",
        "vastai_machine_gpu_rented_bid_demand",
        "vastai_machine_gpu_rented_on_reserved",
        "vastai_machine_gpu_idle",
    )] == [0.0, 0.0, 0.0, 4.0]


@pytest.mark.parametrize(
    "occupancy,running",
    [
        (None, None),
        ("D ? x x", 1),
        ("D D", 1),
        ("D R x x", 1),
        ("1/4", 1),
    ],
)
def test_unknown_or_contradictory_occupancy_never_claims_gpu_capacity(
    exporter_module, occupancy, running
):
    machine = {"id": 9, "num_gpus": 4, "gpu_occupancy": occupancy}
    if running is not None:
        machine["current_rentals_running"] = running

    metrics = collect(exporter_module, machine)

    assert occupancy_samples(metrics) == [-1.0] * 4
    for metric_name in (
        "vastai_machine_gpu_rented_on_demand",
        "vastai_machine_gpu_rented_bid_demand",
        "vastai_machine_gpu_rented_on_reserved",
        "vastai_machine_gpu_idle",
    ):
        assert math.isnan(machine_sample(metrics, metric_name))


@pytest.mark.parametrize(
    "verification,expected",
    [
        ("verified", 1.0),
        ("unverified", 0.0),
        ("deverified", 0.0),
        (True, 1.0),
        (False, 0.0),
        (1, 1.0),
        (0, 0.0),
        ("unknown", math.nan),
        (None, math.nan),
        (2, math.nan),
    ],
)
def test_verification_status_mapping_is_explicit(exporter_module, verification, expected):
    metrics = collect(exporter_module, {"id": 10, "num_gpus": 0, "verification": verification})
    actual = machine_sample(metrics, "vast_machine_Verification")
    if math.isnan(expected):
        assert math.isnan(actual)
    else:
        assert actual == expected
