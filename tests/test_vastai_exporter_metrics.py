# TRACEWEAVER: file-role=earnings-verification; req=REQ-EARN-001; trace=TRACE-EARN-001; ver=VER-EARN-001
# TRACEWEAVER: verifies=VER-EARN-001; req=REQ-EARN-001; trace=TRACE-EARN-001
"""Regression coverage for Vast provider occupancy and daily earnings."""

import copy
import email.message
import importlib.util
import io
import json
import math
import re
import threading
import time
import urllib.error
import urllib.parse
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


@pytest.mark.parametrize("service_fee", [0, 0.25, 25])
def test_host_earnings_are_not_adjusted_by_client_service_fee(exporter_module, service_fee):
    collector = exporter_module.MetricsCollector([])
    metrics = collector._format_metrics({
        "accounts": [{"account": "test", "balance": 100, "credit": 5, "service_fee": service_fee}],
        "machines": [{"_account": "test", "id": 1, "num_gpus": 0, "earn_hour": 26.3, "earn_day": 283.1}],
    })
    assert machine_sample(metrics, "vastai_machine_earn_hour") == 26.3
    assert machine_sample(metrics, "vastai_machine_earn_day") == 283.1
    assert machine_sample(metrics, "vastai_current_total") == 105


# Daily earnings contract is owner-approved but deliberately synthetic until
# the live provider witness closes date-range/identity/currency semantics.
EARNINGS_FIXTURE = ROOT / "tests/fixtures/vastai_host_earnings.json"
COMPONENTS = {"gpu_earn": "vastai_per_machine_gpu_earn", "sto_earn": "vastai_per_machine_sto_earn",
              "bwu_earn": "vastai_per_machine_bwu_earn", "bwd_earn": "vastai_per_machine_bwd_earn"}


class EarningsClock:
    def __init__(self, day=20738):
        self.wall = (day + 1) * 86400 + 3600
        self.mono = 10000.0

    def advance(self, seconds):
        self.wall += seconds
        self.mono += seconds


class EarningsProvider:
    """Fake dated provider; no live contract/capture claim."""
    def __init__(self, account="test", provider_id=101, response=None):
        fixture = json.loads(EARNINGS_FIXTURE.read_text())
        self.account_name, self.api_key = account, "synthetic-key"
        self.user = dict(fixture["user"], id=provider_id)
        self.machine = fixture["current_machine"]
        self.response = copy.deepcopy(fixture["response"] if response is None else response)
        self.request_day = lambda: fixture["target_day"]
        self.calls = []
        self.failure = None
        self.entered = None
        self.release = None

    def get_user_info(self):
        return copy.deepcopy(self.user)

    def get_machines(self):
        return [copy.deepcopy(self.machine)]

    def get_earnings(self, start_day, end_day):
        self.calls.append((start_day, end_day))
        expected_day = self.request_day()
        assert (start_day, end_day) == (expected_day, expected_day), (
            "earnings must request equal inclusive bounds for the previous UTC day",
            (start_day, end_day), expected_day,
        )
        if self.entered:
            self.entered.set()
            assert self.release.wait(5), "test cleanup failed to release blocked fake provider"
        if self.failure:
            raise self.failure
        return copy.deepcopy(self.response)


def daily_collector(module, providers=None, day=20738):
    clock = EarningsClock(day)
    collector = module.MetricsCollector([], wall_clock=lambda: clock.wall,
                                         monotonic_clock=lambda: clock.mono)
    providers = providers if providers is not None else [EarningsProvider()]
    for provider in providers:
        # Request truth comes from the caller clock, independently of response
        # contents: wrong/multiple response days still reach normalization.
        provider.request_day = lambda: int(clock.wall // 86400) - 1
    collector.replace_clients(providers)
    return collector, clock


def daily_values(metrics, metric):
    return {tuple(sorted(re.findall(r'(\w+)="((?:\\.|[^"\\])*)"', label))): value
            for label, value in samples(metrics, metric)}


def daily_value(metrics, metric, expected):
    values = samples(metrics, metric)
    assert len(values) == 1, (metric, values)
    assert values[0][1] == expected
    return values[0][0]


def assert_no_daily_amounts(metrics):
    assert all(not samples(metrics, metric) for metric in COMPONENTS.values())


def test_daily_contract_fixture_is_explicitly_not_a_live_capture():
    fixture = json.loads(EARNINGS_FIXTURE.read_text())
    assert fixture["provenance"]["captured_live"] is False
    assert "contract-derived" in fixture["provenance"]["kind"]
    assert fixture["response"]["per_day"][0]["day"] == fixture["target_day"]


@pytest.mark.parametrize("bounds", [(20738, 20739), (20737, 20737), (20739, 20739)])
def test_daily_fake_rejects_ranges_other_than_equal_target_day(bounds):
    provider = EarningsProvider()
    with pytest.raises(AssertionError, match="equal inclusive bounds"):
        provider.get_earnings(*bounds)


@pytest.mark.parametrize("days", [[20737], [20738, 20739]])
def test_daily_fake_leaves_wrong_or_multiple_response_days_for_normalizer(days):
    provider = EarningsProvider()
    provider.response["per_day"] = [{"day": day} for day in days]
    assert provider.get_earnings(20738, 20738)["per_day"] == [{"day": day} for day in days]


@pytest.mark.parametrize("day", [19782, 19783, 20087, 20393, 20738])
def test_daily_collector_requests_equal_previous_utc_day_bounds(exporter_module, day):
    provider = EarningsProvider()
    provider.response["per_day"][0]["day"] = day
    collector, _ = daily_collector(exporter_module, [provider], day=day)
    collector.refresh_earnings_once()
    assert provider.calls == [(day, day)]


def test_daily_earnings_endpoint_uses_epoch_days_and_bearer_auth(exporter_module, monkeypatch):
    observed = {}
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, size=-1):
            if observed.get("read"):
                return b""
            observed["read"] = True
            return json.dumps(json.loads(EARNINGS_FIXTURE.read_text())["response"]).encode()
    class Opener:
        def open(self, request, **kwargs):
            observed.update(url=request.full_url, headers=dict(request.header_items()), **kwargs)
            return Response()
    monkeypatch.setattr(exporter_module.urllib.request, "build_opener", lambda *handlers: Opener())
    monkeypatch.setattr(exporter_module.urllib.request, "urlopen", lambda *a, **k: pytest.fail("earnings must use a per-request opener"))
    client = exporter_module.VastAIClient("synthetic-key", "test")
    assert client.get_earnings(20738, 20738)["per_machine"][0]["gpu_earn"] == 10
    url = urllib.parse.urlparse(observed["url"])
    assert url._replace(query="").geturl() == "https://console.vast.ai/api/v0/users/me/machine-earnings/"
    query = urllib.parse.parse_qs(url.query)
    assert query["sday"] == ["20738"] and query["eday"] == ["20738"]
    assert query["owner"] == ["me"]
    assert "api_key" not in query
    assert observed["headers"]["Authorization"] == "Bearer synthetic-key"
    assert observed["timeout"] == 15


@pytest.mark.parametrize("redirect_code", [301, 302, 303, 307, 308])
def test_daily_client_refuses_off_origin_redirect_without_auth_forwarding_or_global_change(
    exporter_module, monkeypatch, redirect_code
):
    real_build_opener = exporter_module.urllib.request.build_opener
    existing_opener = real_build_opener()
    existing_handlers = tuple(existing_opener.handlers)
    monkeypatch.setattr(exporter_module.urllib.request, "_opener", existing_opener)
    requests = []
    installed = []

    class SyntheticHTTPS(exporter_module.urllib.request.BaseHandler):
        handler_order = 100

        def https_open(self, request):
            requests.append((request.full_url, dict(request.header_items())))
            headers = email.message.Message()
            if len(requests) == 1:
                headers["Location"] = "https://off-origin.invalid/credential-trap"
                response = exporter_module.urllib.response.addinfourl(
                    io.BytesIO(b""), headers, request.full_url, redirect_code
                )
                response.msg = "Redirect"
            else:
                response = exporter_module.urllib.response.addinfourl(
                    io.BytesIO(b'{"per_machine": []}'), headers, request.full_url, 200
                )
                response.msg = "OK"
            return response

    def build_opener(*handlers):
        # Keep the client's real redirect/error handlers. Only HTTP transport
        # is synthetic; default redirect-following will issue a second request.
        return real_build_opener(*handlers, SyntheticHTTPS())

    monkeypatch.setattr(exporter_module.urllib.request, "build_opener", build_opener)
    monkeypatch.setattr(exporter_module.urllib.request, "urlopen", lambda *a, **k: pytest.fail("earnings must use a per-request opener"))
    monkeypatch.setattr(exporter_module.urllib.request, "install_opener", lambda opener: installed.append(opener))
    result = exporter_module.VastAIClient("synthetic-bearer", "test").get_earnings(20738, 20738)

    assert result is None, "redirected earnings must remain unavailable"
    assert len(requests) == 1, "redirect followed: bearer could reach another origin"
    assert requests[0][1]["Authorization"] == "Bearer synthetic-bearer"
    url = urllib.parse.urlparse(requests[0][0])
    assert url._replace(query="").geturl() == "https://console.vast.ai/api/v0/users/me/machine-earnings/"
    assert installed == [], "earnings must not install a process-global opener"
    assert exporter_module.urllib.request._opener is existing_opener
    assert tuple(existing_opener.handlers) == existing_handlers


def test_daily_all_four_components_and_canonical_labels(exporter_module):
    provider = EarningsProvider()
    collector, clock = daily_collector(exporter_module, [provider])
    collector.refresh_earnings_once()
    assert provider.calls == [(20738, 20738)]
    metrics = collector.collect()
    for field, expected in [("gpu_earn", 10), ("sto_earn", 2), ("bwu_earn", 3), ("bwd_earn", 4)]:
        label = daily_value(metrics, COMPONENTS[field], expected)
        assert dict(re.findall(r'(\w+)="([^"\n]*)"', label)) == {
            "provider_account_id": "101", "account": "test", "machine_id": "7"}
    daily_value(metrics, "vastai_earnings_report_day_timestamp_seconds", 20738 * 86400)
    daily_value(metrics, "vastai_earnings_last_success_timestamp_seconds", clock.wall)
    daily_value(metrics, "vastai_earnings_report_valid", 1)
    daily_value(metrics, "vastai_earnings_status", 1)


@pytest.mark.parametrize("value", [0, -1.25, 2.5, 3])
def test_daily_explicit_finite_zero_and_signed_amounts(exporter_module, value):
    provider = EarningsProvider()
    for field in COMPONENTS:
        provider.response["per_machine"][0][field] = value
    collector, _ = daily_collector(exporter_module, [provider])
    collector.refresh_earnings_once()
    for metric in COMPONENTS.values():
        daily_value(collector.collect(), metric, value)


@pytest.mark.parametrize("bad", [None, True, False, "3", "bad", float("nan"), float("inf"), -float("inf")])
@pytest.mark.parametrize("field", list(COMPONENTS))
def test_daily_malformed_components_are_omitted_without_hiding_other_amounts(exporter_module, field, bad):
    provider = EarningsProvider()
    provider.response["per_machine"][0][field] = bad
    collector, _ = daily_collector(exporter_module, [provider])
    collector.refresh_earnings_once()
    metrics = collector.collect()
    assert not samples(metrics, COMPONENTS[field])
    assert sum(bool(samples(metrics, metric)) for metric in COMPONENTS.values()) == 3
    daily_value(metrics, "vastai_earnings_report_valid", 1)
    daily_value(metrics, "vastai_earnings_status", 2)


def test_daily_revised_partial_snapshot_replaces_whole_previous_snapshot(exporter_module):
    provider = EarningsProvider()
    collector, clock = daily_collector(exporter_module, [provider])
    collector.refresh_earnings_once()
    provider.response["per_machine"] = [{"machine_id": 8, "gpu_earn": -2, "sto_earn": 0}]
    clock.advance(3600)
    collector.refresh_earnings_once()
    metrics = collector.collect()
    for metric in (COMPONENTS["bwu_earn"], COMPONENTS["bwd_earn"]):
        assert not samples(metrics, metric)
    assert 'machine_id="7"' not in '\n'.join(line for line in metrics.splitlines() if line.startswith("vastai_per_machine_"))
    daily_value(metrics, COMPONENTS["gpu_earn"], -2)
    daily_value(metrics, "vastai_earnings_status", 2)


@pytest.mark.parametrize("change", ["missing-list", "not-list", "wrong-day", "no-day", "multiple-days", "seconds-date", "bool-date", "duplicate-conflict", "bad-machine-id", "bad-row"])
def test_daily_rejects_invalid_shape_date_and_duplicate_rows(exporter_module, change):
    provider = EarningsProvider()
    collector, clock = daily_collector(exporter_module, [provider])
    collector.refresh_earnings_once()
    accepted_at = clock.wall
    if change == "missing-list": del provider.response["per_machine"]
    elif change == "not-list": provider.response["per_machine"] = {}
    elif change == "wrong-day": provider.response["per_day"][0]["day"] -= 1
    elif change == "no-day": provider.response.pop("per_day")
    elif change == "multiple-days": provider.response["per_day"].append({"day": 20737})
    elif change == "seconds-date": provider.response["per_day"][0]["day"] *= 86400
    elif change == "bool-date": provider.response["per_day"][0]["day"] = True
    elif change == "duplicate-conflict": provider.response["per_machine"].append(dict(provider.response["per_machine"][0], gpu_earn=999))
    elif change == "bad-machine-id": provider.response["per_machine"][0]["machine_id"] = True
    elif change == "bad-row": provider.response["per_machine"].append(None)
    clock.advance(3600)
    collector.refresh_earnings_once()
    metrics = collector.collect()
    daily_value(metrics, COMPONENTS["gpu_earn"], 10)
    daily_value(metrics, "vastai_earnings_last_success_timestamp_seconds", accepted_at)
    daily_value(metrics, "vastai_earnings_status", 4)


def test_daily_valid_empty_and_retired_machine_rows(exporter_module):
    provider = EarningsProvider()
    provider.response["per_machine"] = []
    collector, clock = daily_collector(exporter_module, [provider])
    collector.refresh_earnings_once()
    metrics = collector.collect()
    assert_no_daily_amounts(metrics)
    daily_value(metrics, "vastai_earnings_report_valid", 1)
    daily_value(metrics, "vastai_earnings_status", 3)
    provider.response["per_machine"] = [{"machine_id": 999, "gpu_earn": 8, "sto_earn": 0, "bwu_earn": 0, "bwd_earn": 0}]
    clock.advance(3600)
    collector.refresh_earnings_once()
    assert 'machine_id="999"' in daily_value(collector.collect(), COMPONENTS["gpu_earn"], 8)


def test_daily_identical_duplicate_rows_cannot_double_amounts(exporter_module):
    provider = EarningsProvider()
    provider.response["per_machine"] *= 2
    collector, _ = daily_collector(exporter_module, [provider])
    collector.refresh_earnings_once()
    metrics = collector.collect()
    # Either deduplicate identical rows or reject the whole report; never double.
    values = samples(metrics, COMPONENTS["gpu_earn"])
    assert len(values) <= 1
    if values: assert values[0][1] == 10
    assert samples(metrics, "vastai_earnings_status"), "duplicate decision must be observable"


@pytest.mark.parametrize("identity", [None, True, False, "unknown", -1, 1.5])
def test_daily_unknown_canonical_identity_never_publishes(exporter_module, identity):
    collector, _ = daily_collector(exporter_module, [EarningsProvider(provider_id=identity)])
    collector.refresh_earnings_once()
    assert_no_daily_amounts(collector.collect())
    daily_value(collector.collect(), "vastai_earnings_status", 6)


@pytest.mark.parametrize("duplicate", ["alias", "provider-id"])
def test_daily_duplicate_configuration_is_visible_and_suppressed(exporter_module, duplicate):
    first = EarningsProvider("first", 101)
    second = EarningsProvider("first" if duplicate == "alias" else "second", 102 if duplicate == "alias" else 101)
    collector, _ = daily_collector(exporter_module, [first, second])
    collector.refresh_earnings_once()
    metrics = collector.collect()
    assert_no_daily_amounts(metrics)
    states = samples(metrics, "vastai_earnings_status")
    assert len(states) == 2 and all(v == 6 for _, v in states)


@pytest.mark.parametrize(
    "provider_id,shared_reference", [(101, False), (None, False), (101, True)],
    ids=["same-alias-same-provider", "same-alias-both-unresolved", "shared-provider-reference"],
)
def test_daily_duplicate_alias_and_identity_emit_unique_new_metric_labelsets(exporter_module, provider_id, shared_reference):
    first = EarningsProvider("same", provider_id)
    second = first if shared_reference else EarningsProvider("same", provider_id)
    collector, _ = daily_collector(exporter_module, [first, second])
    collector.refresh_earnings_once()
    metrics = collector.collect()
    assert_no_daily_amounts(metrics)
    states = samples(metrics, "vastai_earnings_status")
    assert states and all(value == 6 for _, value in states)

    identities = []
    decoder = json.JSONDecoder()
    for line in metrics.splitlines():
        if not line.startswith(tuple(COMPONENTS.values()) + ("vastai_earnings_",)):
            continue
        match = re.fullmatch(r'([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})? (.+)', line)
        assert match, line
        metric, raw_labels, raw_value = match.groups()
        if metric not in COMPONENTS.values() and not metric.startswith("vastai_earnings_"):
            continue
        labels = {}
        position = 0
        raw_labels = raw_labels or ""
        while position < len(raw_labels):
            key_match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)=', raw_labels[position:])
            assert key_match, raw_labels[position:]
            key = key_match[1]
            position += key_match.end()
            value, consumed = decoder.raw_decode(raw_labels[position:])
            assert isinstance(value, str) and key not in labels
            labels[key] = value
            position += consumed
            if position < len(raw_labels):
                assert raw_labels[position] == ","
                position += 1
        float(raw_value)
        identities.append((metric, tuple(sorted(labels.items()))))
    assert len(identities) == len(set(identities)), "duplicate new earnings metric/labelsets"


def test_daily_same_machine_id_stays_separate_per_account(exporter_module):
    first, second = EarningsProvider("first", 101), EarningsProvider("second", 102)
    second.response["per_machine"][0]["gpu_earn"] = 20
    collector, clock = daily_collector(exporter_module, [first, second])
    collector.refresh_earnings_once()
    clock.advance(2)
    collector.refresh_earnings_once()
    values = samples(collector.collect(), COMPONENTS["gpu_earn"])
    assert sorted(v for _, v in values) == [10, 20]
    assert {re.search(r'provider_account_id="(\d+)"', label)[1] for label, _ in values} == {"101", "102"}


@pytest.mark.parametrize("failure", [TimeoutError("synthetic timeout"), RuntimeError("synthetic parser failure"), urllib.error.HTTPError("synthetic", 401, "Unauthorized", {}, None), urllib.error.HTTPError("synthetic", 429, "Rate limited", {}, None), urllib.error.HTTPError("synthetic", 503, "Unavailable", {}, None)])
def test_daily_failures_do_not_extend_last_good_expiry(exporter_module, failure):
    provider = EarningsProvider()
    collector, clock = daily_collector(exporter_module, [provider])
    collector.refresh_earnings_once()
    last_good = clock.wall
    provider.failure = failure
    clock.advance(3600)
    collector.refresh_earnings_once()
    daily_value(collector.collect(), "vastai_earnings_status", 4)
    daily_value(collector.collect(), "vastai_earnings_last_success_timestamp_seconds", last_good)
    clock.advance(3601)
    assert_no_daily_amounts(collector.collect())
    daily_value(collector.collect(), "vastai_earnings_report_valid", 0)
    daily_value(collector.collect(), "vastai_earnings_status", 5)


@pytest.mark.parametrize("day", [19782, 19783, 20087, 20393, 20738])
def test_daily_utc_rollover_clears_even_warm_current_cache(exporter_module, day):
    provider = EarningsProvider()
    provider.response["per_day"][0]["day"] = day
    collector, clock = daily_collector(exporter_module, [provider], day=day)
    collector.refresh_earnings_once()
    assert provider.calls == [(day, day)]
    daily_value(collector.collect(), COMPONENTS["gpu_earn"], 10)
    clock.wall = (day + 2) * 86400
    assert_no_daily_amounts(collector.collect())
    daily_value(collector.collect(), "vastai_earnings_report_valid", 0)


def test_daily_expiry_uses_monotonic_clock_and_backward_wall_time_does_not_extend_it(exporter_module):
    collector, clock = daily_collector(exporter_module)
    collector.refresh_earnings_once()
    clock.wall -= 120
    clock.mono += 7201
    assert_no_daily_amounts(collector.collect())
    daily_value(collector.collect(), "vastai_earnings_status", 5)


def test_daily_attempt_schedule_success_failure_and_cross_account_spacing(exporter_module):
    first, second = EarningsProvider("first", 101), EarningsProvider("second", 102)
    collector, clock = daily_collector(exporter_module, [first, second])
    collector.refresh_earnings_once()
    assert sum(len(p.calls) for p in [first, second]) == 1
    clock.advance(1)
    collector.refresh_earnings_once()
    assert sum(len(p.calls) for p in [first, second]) == 1
    clock.advance(1)
    collector.refresh_earnings_once()
    assert sum(len(p.calls) for p in [first, second]) == 2
    clock.advance(3597)
    collector.refresh_earnings_once()
    assert len(first.calls) == 1
    first.failure = RuntimeError("synthetic")
    clock.advance(1)
    collector.refresh_earnings_once()
    assert len(first.calls) == 2
    clock.advance(299)
    collector.refresh_earnings_once()
    assert len(first.calls) == 2
    assert len(second.calls) == 2
    clock.advance(1)
    collector.refresh_earnings_once()
    assert len(first.calls) == 2
    clock.advance(1)
    collector.refresh_earnings_once()
    assert len(first.calls) == 3


@pytest.mark.parametrize("warm", [False, True])
def test_daily_blocked_earnings_io_does_not_block_current_scrapes_or_management(exporter_module, warm, tmp_path):
    provider = EarningsProvider()
    collector, _ = daily_collector(exporter_module, [provider])
    manager = exporter_module.AccountManager(collector)
    manager.CONFIG_FILE = str(tmp_path / "synthetic-accounts.json")
    if warm: collector.collect()
    provider.entered, provider.release = threading.Event(), threading.Event()
    worker = threading.Thread(target=collector.refresh_earnings_once, daemon=True)
    worker.start()
    try:
        assert provider.entered.wait(1)
        done = threading.Event()
        result = {}
        def scrape_and_remove():
            result["metrics"] = collector.collect()
            result["removed"] = manager.remove_account("test")
            done.set()
        caller = threading.Thread(target=scrape_and_remove, daemon=True)
        caller.start()
        assert done.wait(1), "earnings I/O held a scrape/lifecycle/management lock"
        assert machine_sample(result["metrics"], "vastai_machine_earn_day") == 283.1
        assert result["removed"]["success"] is True
    finally:
        provider.release.set()
        worker.join(2)
    assert not worker.is_alive()
    assert_no_daily_amounts(collector.collect())
    assert not samples(collector.collect(), "vastai_earnings_last_success_timestamp_seconds")


@pytest.mark.parametrize("transition", ["replace", "rollover", "stop"])
def test_daily_late_completion_cannot_republish_after_lifecycle_change(exporter_module, transition):
    old = EarningsProvider()
    collector, clock = daily_collector(exporter_module, [old])
    old.entered, old.release = threading.Event(), threading.Event()
    worker = threading.Thread(target=collector.refresh_earnings_once, daemon=True)
    worker.start()
    try:
        assert old.entered.wait(1)
        if transition == "replace": collector.replace_clients([EarningsProvider()])
        elif transition == "rollover": clock.wall += 86400
        else: collector.stop_earnings_worker()
    finally:
        old.release.set()
        worker.join(2)
    assert not worker.is_alive()
    assert_no_daily_amounts(collector.collect())


def test_daily_restart_is_unknown_and_constructor_starts_no_worker(exporter_module, monkeypatch):
    started = []
    monkeypatch.setattr(exporter_module.threading.Thread, "start", lambda self: started.append(self))
    collector, _ = daily_collector(exporter_module)
    metrics = collector.collect()
    assert started == []
    assert_no_daily_amounts(metrics)
    assert not samples(metrics, "vastai_earnings_last_success_timestamp_seconds")
    daily_value(metrics, "vastai_earnings_status", 0)


def test_daily_worker_stop_is_bounded_and_rejects_outstanding_publication(exporter_module):
    provider = EarningsProvider()
    collector, _ = daily_collector(exporter_module, [provider])
    provider.entered, provider.release = threading.Event(), threading.Event()
    collector.start_earnings_worker()
    try:
        assert provider.entered.wait(1)
        start = time.monotonic()
        collector.stop_earnings_worker()
        assert time.monotonic() - start < 2.5
    finally:
        provider.release.set()
    assert_no_daily_amounts(collector.collect())


def test_daily_metadata_labels_escape_alias_without_secret_or_day_labels(exporter_module):
    provider = EarningsProvider('alias"\\\nline')
    collector, _ = daily_collector(exporter_module, [provider])
    collector.refresh_earnings_once()
    metrics = collector.collect()
    label = daily_value(metrics, COMPONENTS["gpu_earn"], 10)
    assert 'account="alias\\"\\\\\\nline"' in label
    assert "synthetic-key" not in metrics
    assert not re.search(r'(report_day|date|day)="', label)


def test_daily_client_caps_body_and_cooperative_read_budget(exporter_module, monkeypatch):
    class Opener:
        def __init__(self, response): self.response = response
        def open(self, request, **kwargs): return self.response

    class OversizedResponse:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, size=-1):
            assert 0 < size <= 1024 * 1024 + 1, "unbounded read defeats response cap"
            return b" " * size
    monkeypatch.setattr(exporter_module.urllib.request, "build_opener", lambda *handlers: Opener(OversizedResponse()))
    monkeypatch.setattr(exporter_module.urllib.request, "urlopen", lambda *a, **k: pytest.fail("earnings must use a per-request opener"))
    assert exporter_module.VastAIClient("synthetic", "test").get_earnings(20738, 20738) is None
    ticks = iter([0, 0, 31, 31, 31, 31])
    monkeypatch.setattr(exporter_module.time, "monotonic", lambda: next(ticks, 31))
    class TrickleResponse:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, size=-1): return b" "
    monkeypatch.setattr(exporter_module.urllib.request, "build_opener", lambda *handlers: Opener(TrickleResponse()))
    assert exporter_module.VastAIClient("synthetic", "test").get_earnings(20738, 20738) is None


def test_daily_atomic_publication_never_combines_old_and_new_components(exporter_module):
    provider = EarningsProvider()
    collector, clock = daily_collector(exporter_module, [provider])
    collector.refresh_earnings_once()
    provider.response["per_machine"][0].update(gpu_earn=100, sto_earn=200, bwu_earn=300, bwd_earn=400)
    provider.entered, provider.release = threading.Event(), threading.Event()
    clock.advance(3600)
    worker = threading.Thread(target=collector.refresh_earnings_once, daemon=True)
    worker.start()
    try:
        assert provider.entered.wait(1)
        for _ in range(20):
            metrics = collector.collect()
            for field, expected in zip(COMPONENTS, [10, 2, 3, 4]):
                daily_value(metrics, COMPONENTS[field], expected)
    finally:
        provider.release.set()
        worker.join(2)
    metrics = collector.collect()
    for field, expected in zip(COMPONENTS, [100, 200, 300, 400]):
        daily_value(metrics, COMPONENTS[field], expected)


def test_daily_account_remove_readd_discards_old_generation_completion(exporter_module, monkeypatch, tmp_path):
    old = EarningsProvider()
    collector, _ = daily_collector(exporter_module, [old])
    manager = exporter_module.AccountManager(collector)
    manager.CONFIG_FILE = str(tmp_path / "synthetic-accounts.json")
    monkeypatch.setattr(exporter_module, "VastAIClient", lambda key, name: EarningsProvider(name))
    old.entered, old.release = threading.Event(), threading.Event()
    worker = threading.Thread(target=collector.refresh_earnings_once, daemon=True)
    worker.start()
    try:
        assert old.entered.wait(1)
        assert manager.remove_account("test")["success"] is True
        assert manager.add_account("test", "new-synthetic-key")["status"] == "connected"
    finally:
        old.release.set()
        worker.join(2)
    assert_no_daily_amounts(collector.collect())
    assert not samples(collector.collect(), "vastai_earnings_last_success_timestamp_seconds")


def test_daily_parser_exception_isolated_from_later_accounts(exporter_module):
    first, second = EarningsProvider("first", 101), EarningsProvider("second", 102)
    first.failure = RuntimeError("unexpected parser")
    collector, clock = daily_collector(exporter_module, [first, second])
    collector.refresh_earnings_once()
    clock.advance(2)
    collector.refresh_earnings_once()
    values = samples(collector.collect(), COMPONENTS["gpu_earn"])
    assert len(values) == 1 and 'account="second"' in values[0][0]


def test_daily_main_starts_and_stops_worker_after_account_loading(exporter_module, monkeypatch):
    events = []
    real_collector = exporter_module.MetricsCollector
    class TrackingCollector(real_collector):
        def replace_clients(self, clients):
            events.append("accounts-loaded")
            return super().replace_clients(clients)
        def start_earnings_worker(self):
            assert self.clients, "worker must start only after configured accounts are loaded"
            events.append("start")
        def stop_earnings_worker(self): events.append("stop")
    class Server:
        def __init__(self, *args): pass
        def serve_forever(self):
            assert events[-1] == "start"
            raise KeyboardInterrupt()
        def shutdown(self): events.append("server-shutdown")
    monkeypatch.setattr(exporter_module, "MetricsCollector", TrackingCollector)
    monkeypatch.setattr(exporter_module, "VastAIClient", lambda key, name: EarningsProvider(name))
    monkeypatch.setattr(exporter_module.AccountManager, "load_from_file", lambda self: [("test", "synthetic")])
    monkeypatch.setattr(exporter_module, "HTTPServer", Server)
    monkeypatch.setattr(exporter_module.sys, "argv", ["vastai_exporter.py"])
    exporter_module.main()
    assert "start" in events and "stop" in events
    assert events.index("accounts-loaded") < events.index("start") < events.index("stop")


@pytest.mark.parametrize("shape", [None, [], "not-a-report", {"per_machine": [], "per_day": []}])
def test_daily_invalid_top_level_report_cannot_refresh_success(exporter_module, shape):
    provider = EarningsProvider()
    provider.response = shape
    collector, _ = daily_collector(exporter_module, [provider])
    collector.refresh_earnings_once()
    metrics = collector.collect()
    assert_no_daily_amounts(metrics)
    assert not samples(metrics, "vastai_earnings_last_success_timestamp_seconds")
    daily_value(metrics, "vastai_earnings_status", 4)


def test_daily_collection_never_fetches_earnings_or_uses_account_summaries_as_machine_amounts(exporter_module):
    provider = EarningsProvider()
    collector, _ = daily_collector(exporter_module, [provider])
    metrics = collector.collect()
    assert provider.calls == []
    assert_no_daily_amounts(metrics)
    collector.refresh_earnings_once()
    calls = len(provider.calls)
    metrics = collector.collect()
    assert len(provider.calls) == calls
    daily_value(metrics, COMPONENTS["gpu_earn"], 10)
    daily_value(metrics, COMPONENTS["sto_earn"], 2)
    assert machine_sample(metrics, "vastai_machine_earn_day") == 283.1
    assert machine_sample(metrics, "vastai_machine_earn_hour") == 26.3
    assert machine_sample(metrics, "vastai_summary_total_gpu") == 283.1
    assert machine_sample(metrics, "vastai_current_total") == 105


@pytest.mark.parametrize("machine_id", [False, -1, 1.5, "x", "", None])
def test_daily_invalid_machine_identifier_rejects_report(exporter_module, machine_id):
    provider = EarningsProvider()
    provider.response["per_machine"][0]["machine_id"] = machine_id
    collector, _ = daily_collector(exporter_module, [provider])
    collector.refresh_earnings_once()
    metrics = collector.collect()
    assert_no_daily_amounts(metrics)
    daily_value(metrics, "vastai_earnings_status", 4)
