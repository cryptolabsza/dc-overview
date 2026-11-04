# Application monitoring policy traceability

## Central telemetry monitoring policy mapping

Authority: the scoped 4 November 2026 record in
[requirements.md](requirements.md), baseline `REQ-BASELINE-MON-20261104-001`;
intent registry: [.traceweaver/intent-contract.yml](.traceweaver/intent-contract.yml).
These rows map only the approved application monitoring policy work item.

| Trace | Requirement | Implementation | Verification | Validation | Status |
|---|---|---|---|---|---|
| TRACE-MON-001 | REQ-MON-001 | `src/dc_overview/app.py` | VER-MON-001: `tests/test_exporter_install_ui.py`, `tests/test_selected_worker_enrollment.py`; retained `tests/test_exporter_toggle.py`, `tests/test_operational_customer_contract.py` | VAL-MON-001: isolated outage/manual-disable scenarios | Local tests and representative validation passed; production acceptance pending |
| TRACE-MON-002 | REQ-MON-002 | `src/dc_overview/web_prometheus.py`, `src/dc_overview/app.py` | VER-MON-002: `tests/test_http_inventory.py::test_policy_metrics_follow_desired_channels_and_inventory_lifecycle` | VAL-MON-002: real local Flask/Prometheus scrape, alias/channel, absent-policy and inventory lifecycle scenarios | Local tests and representative validation passed; production acceptance pending |
| TRACE-MON-003 | REQ-MON-003 | `src/dc_overview/fleet_manager.py` | VER-MON-003: `tests/test_http_inventory.py::test_fleet_installer_uses_live_inventory_instead_of_static_workers` (initial and configured) | VAL-MON-003: both generated configurations inspected and checked | Local tests and representative validation passed; production acceptance pending |

`REQ-MON-004` and its site-rule verification remain an operations work item;
neither site inventory nor site-rule ownership is included in this repository.
The 111-contract local run and 13 real scrape/query scenarios are retained
review metadata, not a substitute for fresh CI on the published head.

### Monitoring policy code anchors

| Artifact Path | Requirement | Trace | Verification | Anchor Type | Role |
|---|---|---|---|---|---|
| src/dc_overview/app.py | REQ-MON-001 | TRACE-MON-001 | VER-MON-001 | file-role | monitoring-intent-implementation |
| src/dc_overview/app.py | REQ-MON-002 | TRACE-MON-002 | VER-MON-002 | entrypoint | prometheus_metrics |
| src/dc_overview/web_prometheus.py | REQ-MON-002 | TRACE-MON-002 | VER-MON-002 | file-role | telemetry-policy-collector |
| src/dc_overview/web_prometheus.py | REQ-MON-002 | TRACE-MON-002 | VER-MON-002 | entrypoint | collect |
| src/dc_overview/fleet_manager.py | REQ-MON-003 | TRACE-MON-003 | VER-MON-003 | file-role | application-metrics-scrape |
| src/dc_overview/fleet_manager.py | REQ-MON-003 | TRACE-MON-003 | VER-MON-003 | entrypoint | _generate_prometheus_config; _product_prometheus_config |
| tests/test_exporter_install_ui.py | REQ-MON-001 | TRACE-MON-001 | VER-MON-001 | verifies | monitoring-intent-regression |
| tests/test_selected_worker_enrollment.py | REQ-MON-001 | TRACE-MON-001 | VER-MON-001 | verifies | selected-enrollment-intent-contract |
| tests/test_http_inventory.py | REQ-MON-002 | TRACE-MON-002 | VER-MON-002 | verifies | policy-metric-regression |
| tests/test_http_inventory.py | REQ-MON-003 | TRACE-MON-003 | VER-MON-003 | verifies | application-scrape-regression |

## GPU alert quality mapping

| Requirement | Trace | Verification | Validation | Implementation | Status |
| --- | --- | --- | --- | --- | --- |
| REQ-GPUALERT-002 | TRACE-GPUALERT-002 | VER-GPUALERT-002 | VAL-GPUALERT-002 | src/dc_overview/grafana_alerts.py; src/dc_overview/web_prometheus.py; src/dc_overview/templates/grafana/provisioning/alerting/fleet-gpu-health.yml; src/dc_overview/templates/grafana/provisioning/alerting/dc-overview-notifications.yml; tests/test_gpu_collector_alerts.py; tests/test_gpu_collector_dashboard.py; tests/test_http_inventory.py | Approved scope; local verification only; deployment held |
| REQ-GPUALERT-003 | TRACE-GPUALERT-003 | VER-GPUALERT-003 | VAL-GPUALERT-003 | src/dc_overview/dashboards/DC_Exporter_Details.json; src/dc_overview/dashboards/DC_Overview.json; dashboards/DC_Exporter_Details.json; dashboards/DC_Overview.json; server/grafana/dashboards/dc-overview.json; tests/test_gpu_collector_dashboard.py | Approved scope; local verification only; deployment held |

Vast panel35 uses the same approved REQ-GPUALERT-003 behavior: `src/dc_overview/dashboards/Vast_Dashboard.json`, `dashboards/Vast_Dashboard.json`, both server Vast mirrors, `tests/test_gpu_collector_dashboard.py`, `tests/fixtures/gpu-state-pre-collector.json`, and the existing whole-dashboard preservation test in `tests/test_vast_occupancy_dashboard.py`. The original occupancy digest constants remain unchanged; only the three approved panel35 fields are restored to their captured baseline before that guard. Independent mechanical review is `.traceweaver/gpu-alerts-20261104/vast-state-review.md`.
