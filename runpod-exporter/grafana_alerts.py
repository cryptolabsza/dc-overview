"""Grafana managed-alert rules for the RunPod exporter health contract.

The factory is deliberately data-only: an operator supplies the Grafana folder,
Prometheus datasource, account, and optional UID namespace before sending the
result to Grafana's provisioning API.  It does not create routes or contact
points, so existing notification routing can be retained by the caller.
"""

from __future__ import annotations

from typing import Any


DEFAULT_UID_PREFIX = "runpod"
HEALTH_STATE_SCHEMA_VERSION = 1


def build_alert_rules(
    *,
    account: str,
    folder_uid: str,
    datasource_uid: str,
    uid_prefix: str = DEFAULT_UID_PREFIX,
) -> list[dict[str, Any]]:
    """Build the RunPod alert contract for one configured account.

    ``uid_prefix`` defaults to ``runpod`` to preserve the established rule UIDs.
    Callers managing more than one account should pass a distinct prefix for
    each account (for example, ``alpha-runpod`` and ``beta-runpod``).
    """
    if not all(isinstance(value, str) and value for value in (account, folder_uid, datasource_uid, uid_prefix)):
        raise ValueError("account, folder_uid, datasource_uid, and uid_prefix must be non-empty strings")

    account_matcher = f'account="{_prometheus_label_value(account)}"'
    account_labels = {
        "account": account,
        "severity": "warning",
    }

    def account_metric(metric: str) -> str:
        return f"{metric}{{{account_matcher}}}"

    def machine_metric(metric: str) -> str:
        return account_metric(metric)

    def uid(suffix: str) -> str:
        return f"{uid_prefix}-{suffix}"

    known = machine_metric("runpod_machine_health_known")
    present = machine_metric("runpod_machine_present")
    known_join = f"and on(account,machine_id,hostname) ({known} == 1)"
    present_join = f"and on(account,machine_id,hostname) ({present} == 1)"

    return [
        _rule(
            uid=uid("machine-unlisted"),
            title="RunPod machine listing status",
            folder_uid=folder_uid,
            group="RunPod Listing",
            datasource_uid=datasource_uid,
            expression=f"(1 - {machine_metric('runpod_machine_health_listed')}) {known_join}",
            threshold=0.5,
            duration="0s",
            no_data_state="KeepLast",
            exec_error_state="KeepLast",
            labels={**account_labels, "alert_category": "runpod_listing"},
            summary=_machine_summary("RunPod listing status"),
            description=(
                "RunPod listing indicator: {{ printf \"%.0f\" $values.A.Value }} "
                "(1 = explicitly unlisted; 0 = explicitly listed). A firing notification "
                "means UNLISTED. Recovery follows an explicit LISTED observation. API failures, "
                "missing inventory entries, and stale data retain the last confirmed state; "
                "separate telemetry alerts report those gaps."
            ),
        ),
        _rule(
            uid=uid("exporter-unavailable"),
            title="RunPod exporter unavailable",
            folder_uid=folder_uid,
            group="RunPod Monitoring",
            datasource_uid=datasource_uid,
            expression='1 - (min(up{job="runpod"}) or vector(0))',
            threshold=0.5,
            duration="2m",
            no_data_state="Alerting",
            exec_error_state="Alerting",
            labels={**account_labels, "alert_category": "runpod_telemetry"},
            summary="RunPod exporter scrape is unavailable",
            description=(
                "Prometheus cannot scrape the RunPod exporter. Listing state is not being confirmed. "
                "Check the exporter service and its Prometheus target; do not interpret this as a "
                "machine being relisted."
            ),
        ),
        _rule(
            uid=uid("api-poll-failed"),
            title="RunPod API polling failed",
            folder_uid=folder_uid,
            group="RunPod Monitoring",
            datasource_uid=datasource_uid,
            expression=f"1 - {account_metric('runpod_api_poll_success')}",
            threshold=0.5,
            duration="3m",
            no_data_state="Alerting",
            exec_error_state="Alerting",
            labels={**account_labels, "alert_category": "runpod_telemetry"},
            summary="RunPod API polling has been failing",
            description=(
                "The exporter has not completed a successful RunPod API poll for the alert pending "
                "period. Last confirmed machine states are retained. Check API access and outbound DNS/HTTPS."
            ),
        ),
        _rule(
            uid=uid("api-data-stale"),
            title="RunPod API data is stale",
            folder_uid=folder_uid,
            group="RunPod Monitoring",
            datasource_uid=datasource_uid,
            expression=f"time() - {account_metric('runpod_api_last_success_timestamp_seconds')}",
            threshold=300,
            duration="1m",
            no_data_state="Alerting",
            exec_error_state="Alerting",
            labels={**account_labels, "alert_category": "runpod_telemetry"},
            summary="RunPod API data is more than five minutes old",
            description=(
                "The last complete API success is {{ printf \"%.0f\" $values.A.Value }} seconds old. "
                "Machine listing values are retained observations, not a current health confirmation."
            ),
        ),
        _rule(
            uid=uid("machine-missing"),
            title="RunPod machine missing from inventory",
            folder_uid=folder_uid,
            group="RunPod Monitoring",
            datasource_uid=datasource_uid,
            expression=f"1 - {present}",
            threshold=0.5,
            duration="2m",
            no_data_state="KeepLast",
            exec_error_state="KeepLast",
            labels={**account_labels, "alert_category": "runpod_telemetry"},
            summary=_machine_summary("is missing from RunPod inventory"),
            description=(
                "A successful API inventory omitted this previously known machine. Its last confirmed "
                "listing state has been retained. Check the RunPod host inventory; absence does not "
                "confirm relisting."
            ),
        ),
        _rule(
            uid=uid("machine-health-unknown"),
            title="RunPod machine listing telemetry unknown",
            folder_uid=folder_uid,
            group="RunPod Monitoring",
            datasource_uid=datasource_uid,
            expression=f"(1 - {known}) {present_join}",
            threshold=0.5,
            duration="5m",
            no_data_state="OK",
            exec_error_state="KeepLast",
            labels={**account_labels, "alert_category": "runpod_telemetry"},
            summary=_machine_summary("has no validated RunPod listing state"),
            description=(
                "The exporter has not obtained a valid listing boolean for this machine. No listed or "
                "unlisted transition is inferred until an explicit valid value arrives."
            ),
        ),
        _rule(
            uid=uid("machine-health-stale"),
            title="RunPod machine listing telemetry stale",
            folder_uid=folder_uid,
            group="RunPod Monitoring",
            datasource_uid=datasource_uid,
            expression=(
                f"(time() - {machine_metric('runpod_machine_health_last_success_timestamp_seconds')}) "
                f"{known_join}"
            ),
            threshold=300,
            duration="1m",
            no_data_state="KeepLast",
            exec_error_state="KeepLast",
            labels={**account_labels, "alert_category": "runpod_telemetry"},
            summary=_machine_summary("RunPod listing telemetry is stale"),
            description=(
                "The last validated machine observation is {{ printf \"%.0f\" $values.A.Value }} seconds old. "
                "The machine listing alert retains its last confirmed state until a valid update arrives."
            ),
        ),
        _rule(
            uid=uid("state-persistence-failed"),
            title="RunPod health state persistence failed",
            folder_uid=folder_uid,
            group="RunPod Monitoring",
            datasource_uid=datasource_uid,
            expression="1 - runpod_health_state_persist_success",
            threshold=0.5,
            duration="0s",
            no_data_state="Alerting",
            exec_error_state="Alerting",
            labels={**account_labels, "alert_category": "runpod_telemetry"},
            summary="RunPod monitoring cannot persist its confirmed machine states",
            description=(
                "The exporter could not load or save its protected health-state file. Check state-file "
                "permissions and available storage. Reliable transition history across restarts is not "
                "assured until this recovers."
            ),
        ),
        _rule(
            uid=uid("machine-provider-note"),
            title="RunPod machine provider note",
            folder_uid=folder_uid,
            group="RunPod Provider Status",
            datasource_uid=datasource_uid,
            expression=(
                f"({machine_metric('runpod_machine_api_note_present')} + "
                f"{machine_metric('runpod_machine_maintenance_note_present')}) {known_join}"
            ),
            threshold=0.5,
            duration="0s",
            no_data_state="KeepLast",
            exec_error_state="KeepLast",
            labels={**account_labels, "alert_category": "runpod_provider"},
            summary=_machine_summary("has a RunPod provider note"),
            description=(
                "RunPod returned a nonempty machine note or maintenance note. Review this machine in the "
                "RunPod host dashboard for the message. This observes accessible API note fields; it does "
                "not reproduce permission-restricted dashboard warning fields."
            ),
        ),
        _rule(
            uid=uid("machine-maintenance-mode"),
            title="RunPod machine in maintenance mode",
            folder_uid=folder_uid,
            group="RunPod Provider Status",
            datasource_uid=datasource_uid,
            expression=f"{machine_metric('runpod_machine_maintenance_mode')} {known_join}",
            threshold=0.5,
            duration="0s",
            no_data_state="KeepLast",
            exec_error_state="KeepLast",
            labels={**account_labels, "alert_category": "runpod_provider"},
            summary=_machine_summary("is in RunPod maintenance mode"),
            description=(
                "RunPod explicitly reports maintenanceMode=true. Confirm whether this is expected. API "
                "failures retain the last confirmed value and are reported separately."
            ),
        ),
        _rule(
            uid=uid("machine-last-sync-unavailable"),
            title="RunPod machine sync missing or stale",
            folder_uid=folder_uid,
            group="RunPod Provider Status",
            datasource_uid=datasource_uid,
            expression=(
                f"((time() - {machine_metric('runpod_machine_last_sync_timestamp_seconds')} > bool 300) "
                f"{known_join.replace(known, machine_metric('runpod_machine_last_sync_known'))}) "
                f"or on(account,machine_id,hostname) (1 - {machine_metric('runpod_machine_last_sync_known')})"
            ),
            threshold=0.5,
            duration="2m",
            no_data_state="KeepLast",
            exec_error_state="KeepLast",
            labels={**account_labels, "alert_category": "runpod_provider"},
            summary=_machine_summary("RunPod machine sync is unavailable"),
            description=(
                "RunPod returned an unknown timestamp or a machine sync timestamp more than five minutes "
                "old. This is an API telemetry observation, not proof of a port-mapping or physical-network failure."
            ),
        ),
        _rule(
            uid=uid("machine-telemetry-unavailable"),
            title="RunPod provider telemetry missing or stale",
            folder_uid=folder_uid,
            group="RunPod Provider Status",
            datasource_uid=datasource_uid,
            expression=(
                f"((time() - {machine_metric('runpod_machine_telemetry_timestamp_seconds')} > bool 300) "
                f"{known_join.replace(known, machine_metric('runpod_machine_telemetry_known'))}) "
                f"or on(account,machine_id,hostname) (1 - {machine_metric('runpod_machine_telemetry_known')})"
            ),
            threshold=0.5,
            duration="2m",
            no_data_state="KeepLast",
            exec_error_state="KeepLast",
            labels={**account_labels, "alert_category": "runpod_provider"},
            summary=_machine_summary("RunPod provider telemetry is unavailable"),
            description=(
                "RunPod returned an unknown timestamp or a provider telemetry timestamp more than five "
                "minutes old. This is an API telemetry observation, not proof of a port-mapping or physical-network failure."
            ),
        ),
        _rule(
            uid=uid("exporter-contract-unavailable"),
            title="RunPod exporter health contract unavailable",
            folder_uid=folder_uid,
            group="RunPod Monitoring",
            datasource_uid=datasource_uid,
            expression=(
                f"(max(absent({account_metric('runpod_api_poll_success')}) or "
                "absent(runpod_health_state_persist_success) or "
                "absent(runpod_health_state_schema_version) or "
                f"(runpod_health_state_schema_version != bool {HEALTH_STATE_SCHEMA_VERSION}))) or vector(0)"
            ),
            threshold=0.5,
            duration="2m",
            no_data_state="OK",
            exec_error_state="Alerting",
            labels={**account_labels, "alert_category": "runpod_telemetry"},
            summary="RunPod exporter health contract unavailable",
            description=(
                "Required account poll, durable-state, or schema metrics are absent or incompatible. "
                "This is a service-level monitoring failure; it does not imply a machine listing transition."
            ),
        ),
    ]


def _prometheus_label_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _machine_summary(suffix: str) -> str:
    """Use labels as observed, falling back without inventing a host identity."""
    target = (
        "{{ if $labels.hostname }}{{ $labels.hostname }}"
        "{{ else if $labels.machine_id }}machine {{ $labels.machine_id }}"
        "{{ else if $labels.account }}account {{ $labels.account }}"
        "{{ else }}RunPod machine{{ end }}"
    )
    return f"{target} {suffix}"


def _rule(
    *,
    uid: str,
    title: str,
    folder_uid: str,
    group: str,
    datasource_uid: str,
    expression: str,
    threshold: float,
    duration: str,
    no_data_state: str,
    exec_error_state: str,
    labels: dict[str, str],
    summary: str,
    description: str,
) -> dict[str, Any]:
    return {
        "uid": uid,
        "title": title,
        "folderUID": folder_uid,
        "ruleGroup": group,
        "condition": "C",
        "for": duration,
        "noDataState": no_data_state,
        "execErrState": exec_error_state,
        "isPaused": False,
        "annotations": {"summary": summary, "description": description},
        "labels": labels,
        "data": [
            {
                "refId": "A",
                "queryType": "",
                "relativeTimeRange": {"from": 600, "to": 0},
                "datasourceUid": datasource_uid,
                "model": {
                    "editorMode": "code",
                    "expr": expression,
                    "hide": False,
                    "instant": True,
                    "intervalMs": 1000,
                    "legendFormat": "{{ hostname }}",
                    "maxDataPoints": 43200,
                    "range": False,
                    "refId": "A",
                },
            },
            {
                "refId": "C",
                "queryType": "",
                "relativeTimeRange": {"from": 0, "to": 0},
                "datasourceUid": "__expr__",
                "model": {
                    "conditions": [
                        {
                            "evaluator": {"params": [threshold], "type": "gt"},
                            "operator": {"type": "and"},
                            "query": {"params": ["C"]},
                            "reducer": {"params": [], "type": "last"},
                            "type": "query",
                        }
                    ],
                    "datasource": {"type": "__expr__", "uid": "__expr__"},
                    "expression": "A",
                    "intervalMs": 1000,
                    "maxDataPoints": 43200,
                    "refId": "C",
                    "type": "threshold",
                },
            },
        ],
    }
