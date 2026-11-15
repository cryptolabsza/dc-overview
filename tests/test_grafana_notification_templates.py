"""Render the installed Telegram template with Go's real template engine."""

import json
import os
import shutil
import subprocess

import pytest
import yaml

from dc_overview.grafana_alerts import install_grafana_alerts


@pytest.fixture(scope="module")
def render_message(tmp_path_factory):
    if shutil.which("go") is None:
        pytest.skip("Go unavailable")
    directory = tmp_path_factory.mktemp("telegram-template")
    rules = install_grafana_alerts(directory)
    document = yaml.safe_load(rules.with_name("dc-overview-notifications.yml").read_text())
    template = directory / "message.tmpl"
    template.write_text(document["templates"][0]["template"])
    program = directory / "render.go"
    program.write_text('''package main
import ("encoding/json"; "os"; "text/template")
func main() {
 var data map[string]interface{}
 if err := json.NewDecoder(os.Stdin).Decode(&data); err != nil { panic(err) }
 t := template.Must(template.ParseFiles(os.Args[1]))
 if err := t.ExecuteTemplate(os.Stdout, "cryptolabs.telegram.message", data); err != nil { panic(err) }
}
''')
    binary = directory / "render"
    environment = {**os.environ, "GOCACHE": str(directory / "go-cache"), "GOTOOLCHAIN": "local"}
    compiled = subprocess.run(
        ["go", "build", "-o", str(binary), str(program)], env=environment,
        capture_output=True, text=True, timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr

    def render(firing=(), resolved=()):
        result = subprocess.run(
            [str(binary), str(template)],
            input=json.dumps({"Alerts": {"Firing": firing, "Resolved": resolved}}),
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    return render


def alert(category="", summary="", **labels):
    return {"Labels": {"alert_category": category, **labels}, "Annotations": {
        "summary": summary,
        "description": "Long technical explanation, Prometheus values, and troubleshooting steps.",
    }}


def test_mixed_notifications_are_exactly_one_line_per_alert(render_message):
    listing = alert("runpod_listing", "runpodccc98 RunPod listing status", hostname="runpodccc98")
    disk = alert(summary="High disk usage on gpu-42", alert_type="disk", mountpoint="/data")
    assert render_message([listing, disk], [listing]) == (
        "🔴 runpodccc98 — RunPod unlisted\n"
        "🔴 High disk usage on gpu-42 (/data)\n"
        "🟢 runpodccc98 — RunPod listed again"
    )
    assert render_message() == ""


@pytest.mark.parametrize("labels,identity", [
    ({"hostname": "host", "machine_id": "42", "account": "alpha"}, "host"),
    ({"machine_id": "42", "account": "alpha"}, "machine 42"),
    ({"account": "alpha", "instance": "exporter:8000"}, "account alpha"),
    ({"instance": "exporter:8000"}, "RunPod machine"),
])
def test_runpod_identity_never_uses_exporter_target(render_message, labels, identity):
    item = alert("runpod_listing", **labels)
    assert render_message([item]) == f"🔴 {identity} — RunPod unlisted"
    assert render_message(resolved=[item]) == f"🟢 {identity} — RunPod listed again"


@pytest.mark.parametrize("reason", ["MissingSeries", "Paused", "RuleDeleted", "Updated"])
@pytest.mark.parametrize("category", ["runpod_listing", "runpod_provider", "runpod_telemetry", "gpu_health"])
def test_grafana_state_changes_never_claim_recovery(render_message, reason, category):
    item = alert(category, "Host GPU is hot", hostname="host", alertname="GPU high temperature")
    item["Annotations"]["grafana_state_reason"] = reason
    assert render_message(resolved=[item]) == f"🟢 Monitoring changed ({reason}) — Host GPU is hot"


def test_vast_listing_keeps_transition_and_monitoring_wording(render_message):
    item = alert("vast_listing", "gpu-42 (machine 42, account alpha)")
    assert render_message([item]) == "🔴 Vast UNLISTED — gpu-42 (machine 42, account alpha)"
    assert render_message(resolved=[item]) == "🟢 Vast LISTED — gpu-42 (machine 42, account alpha)"
    item["Annotations"]["grafana_state_reason"] = "MissingSeries"
    assert render_message(resolved=[item]) == (
        "🟢 Vast listing monitoring changed (MissingSeries) — gpu-42 (machine 42, account alpha)"
    )


@pytest.mark.parametrize("category,summary,labels,expected", [
    ("gpu_health", "host GPU 2 is thermally throttling", {"gpu": "2"}, "host GPU 2 is thermally throttling"),
    ("", "GPU temperature high on host", {"alert_type": "temperature", "gpu": "2"}, "GPU temperature high on host (GPU 2)"),
    ("", "GPU memory errors on host", {"alert_type": "memory", "gpu": "3"}, "GPU memory errors on host (GPU 3)"),
    ("", "GPU uncorrectable errors on host", {"alert_type": "critical_event", "gpu": "4"}, "GPU uncorrectable errors on host (GPU 4)"),
    ("runpod_telemetry", "RunPod API polling has been failing", {"account": "alpha", "instance": "exporter:8000"}, "RunPod API polling has been failing (account alpha)"),
    ("runpod_provider", "host is in RunPod maintenance mode", {"hostname": "host", "alertname": "RunPod machine in maintenance mode"}, "host is in RunPod maintenance mode"),
    ("runpod_provider", "host RunPod machine sync is unavailable", {"hostname": "host", "alertname": "RunPod machine sync missing or stale"}, "host RunPod machine sync is unavailable"),
])
def test_other_alerts_use_summary_and_preserve_required_identity(render_message, category, summary, labels, expected):
    item = alert(category, summary, **labels)
    assert render_message([item]) == f"🔴 {expected}"
    assert render_message(resolved=[item]) == f"🟢 Cleared — {expected}"


@pytest.mark.parametrize("labels,expected", [
    ({"alertname": "CPU high", "instance": "host:9100"}, "CPU high — host:9100"),
    ({"alertname": "CPU high", "hostname": "host"}, "CPU high — host"),
    ({"alertname": "RunPod API failed", "account": "alpha"}, "RunPod API failed — account alpha"),
    ({}, "Alert"),
])
def test_missing_summary_is_still_useful(render_message, labels, expected):
    assert render_message([alert(**labels)]) == f"🔴 {expected}"


@pytest.mark.parametrize("notes,expected", [
    ({"runpod_note": "Network outage"}, "RunPod note: Network outage"),
    ({"runpod_maintenance_note": "Replacing switch"}, "RunPod maintenance note: Replacing switch"),
    ({"runpod_note": "Network outage", "runpod_maintenance_note": "Replacing switch"},
     "RunPod note: Network outage; maintenance note: Replacing switch"),
    ({}, "RunPod machine/maintenance note present"),
    ({"runpod_note": "Link <down> & unavailable"}, "RunPod note: Link &lt;down&gt; &amp; unavailable"),
])
def test_provider_note_prints_actual_text_with_telegram_html_escaping(render_message, notes, expected):
    item = alert("runpod_provider", "host has a RunPod provider note", hostname="host",
                 alertname="RunPod machine provider note")
    item["Annotations"].update(notes)
    assert render_message([item]) == f"🔴 host — {expected}"
    assert render_message(resolved=[item]) == f"🟢 Cleared — host — {expected}"


@pytest.mark.parametrize("reason", ["MissingSeries", "Paused", "RuleDeleted", "Updated"])
def test_provider_note_state_change_does_not_claim_note_was_cleared(render_message, reason):
    item = alert("runpod_provider", "host has a RunPod provider note", hostname="host",
                 alertname="RunPod machine provider note")
    item["Annotations"].update(
        runpod_note="Network outage", runpod_maintenance_note="Replacing switch",
        grafana_state_reason=reason,
    )
    assert render_message(resolved=[item]) == (
        f"🟢 Monitoring changed ({reason}) — host has a RunPod provider note"
    )


def test_gpu_collection_firing_and_recovery_keep_truthful_concise_wording(render_message):
    item = alert("gpu_collection", "h100x8 · GPU telemetry unavailable")
    item["Annotations"]["recovery_summary"] = "h100x8 · GPU telemetry restored"
    assert render_message([item], [item]) == (
        "🟠 h100x8 · GPU telemetry unavailable\n"
        "🟢 h100x8 · GPU telemetry restored"
    )


@pytest.mark.parametrize("reason", ["MissingSeries", "NoData", "Paused", "RuleDeleted", "Updated"])
def test_gpu_collection_state_change_never_claims_telemetry_restored(render_message, reason):
    item = alert("gpu_collection", "h100x8 · GPU telemetry unavailable")
    item["Annotations"].update(
        recovery_summary="h100x8 · GPU telemetry restored", grafana_state_reason=reason,
    )
    assert render_message(resolved=[item]) == (
        f"🟠 GPU monitoring changed ({reason}) — h100x8 · GPU telemetry unavailable"
    )
