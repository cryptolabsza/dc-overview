# Fleet Manager bounded implementation mapping

Canonical reviewed authority and frozen profile: ../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/authority-gate.json. Status below identifies approved file scope, not requirement acceptance. Native/production validation and independent review remain pending at the parent.

## Traceability Matrix

| Trace | Requirement | Implementation | Verification | Validation | Status |
|---|---|---|---|---|---|
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `pyproject.toml` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `src/dc_overview/cli.py` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `src/dc_overview/fleet_upgrade.py` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `src/dc_overview/release_catalog.py` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `src/dc_overview/release_candidates.py` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `src/dc_overview/release_broker.py` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `src/dc_overview/release_broker_service.py` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `tests/test_release_candidates.py` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `docs/fleet-suite-authority.md` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | v3 atomic pack source candidate; native acceptance held |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `tests/test_release_broker.py` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `src/dc_overview/templates/systemd/dc-overview-release-broker.service` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `src/dc_overview/templates/systemd/dc-overview-release-broker.socket` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `docs/standard-customer-releases.md` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `.github/workflows/fleet-release-native-qa.yml` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `.github/tests/test_fleet_native_route.py` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `scripts/verify_fleet_release_native.py` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | v3 source pin corrected; automatic native recheck pending |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `docs/fleet-release-native-qa.md` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `tests/test_scoped_release_selection.py` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | Approved recovery source scope; actual native/site acceptance held |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `docs/native-service-recovery.md` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | Approved recovery operations documentation |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `scripts/fixtures/legacy-selected-state-protection.py` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved source authority |

The synthetic native fixture helper row projects only the approved source scope
under amendment `159af842…` and the root-reviewed native test integration GO.
Local15-check verification and independent frozen-body reviews are retained in
`../artifacts/ipmi-readiness-20261026/fleet-ui-20261102/execution/native-fixture/repair2/`.
Actual native execution, collector proof, public admission, customer/site
acceptance, external VM destruction and publication remain held; the source
authority status does not certify those outcomes.

## Unsupported format evidence

The two systemd units, pyproject package-data and operator documentation are manually mapped to the same approved work item. Their exact hashes, format/package checks and integration limits are retained in ../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/dc-implementation/. No whole-repo or production acceptance is inferred.

Native QA support authority is the same owner-approved step4, concretely bounded by ../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/native-qa-plan/root-decision.json and repair-cycle1-decision.json. The new workflow YAML and QA documentation use this manual mapping, exact file hashes, parsed route checks and syntax evidence in native-qa-implementation/. The reviewed published proxy commit is pinned literally. Acceptance remains held: actual fresh Linux execution, production trust, genuine future-version migration, browser acceptance and external VM destruction evidence are not claimed by local checks. Prior product authority and frozen product bytes are unchanged.

The 29 October 2026 v3 atomic pack plan at `../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/ready-to-deploy-20261028/approved-execution-20261029/discovery-consistency-definition/plan.json` supersedes only the unpublished v2 offset-listing discovery proposal. The existing FLEET source and verification rows above map the current v3 candidate. Test-first evidence and its retirement map are in `../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/ready-to-deploy-20261028/approved-execution-20261029/discovery-consistency-definition/verification-definition/`. Native route, publisher, validation and publication acceptance remain held.

The root-reviewed native preflight repair is limited to the `release_candidates.py` literal in the existing native verifier's frozen DC input map. Its authority is `../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/ready-to-deploy-20261028/approved-execution-20261029/discovery-consistency-definition/native-failure/root-repair-plan.json` under frozen `profile-v4.json` (SHA256 `d974471ff3e2e052b9da1218f463ceb6a5c7ee0026f2affc2229bae45ce9d47a`). The reviewed parser, test and source note hashes remain `bf8bd9145005901817cb4bbaa24726dbee20e7555e782e7383722e24df1d41a3`, `e4c7fab41391c810fe0169686e3551e5efa7ad6d551cc839855b0299c5e33f4a` and `4c305f686a9703f9eca5f64393e9377a91135d971a0be3109ba75df7f837015f`. Local pin coherence is verified separately; the next automatic native CI result and release acceptance remain held.

## Code Anchor Evidence

| Artifact Path | Requirement | Trace | Verification | Anchor Type | Role |
| --- | --- | --- | --- | --- | --- |
| src/dc_overview/cli.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | release-owner |
| src/dc_overview/cli.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | entrypoint | release-owner |
| src/dc_overview/fleet_upgrade.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | release-owner |
| src/dc_overview/fleet_upgrade.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | entrypoint | release-owner |
| src/dc_overview/release_catalog.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | release-owner |
| src/dc_overview/release_catalog.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | entrypoint | release-owner |
| src/dc_overview/release_candidates.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | release-owner |
| src/dc_overview/release_candidates.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | entrypoint | release-owner |
| src/dc_overview/release_broker.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | release-owner |
| src/dc_overview/release_broker.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | entrypoint | release-owner |
| src/dc_overview/release_broker_service.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | release-owner |
| src/dc_overview/release_broker_service.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | entrypoint | release-owner |
| tests/test_release_candidates.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | release-verification |
| tests/test_release_candidates.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | verifies | release-verification |
| tests/test_release_broker.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | release-verification |
| tests/test_release_broker.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | verifies | release-verification |
| scripts/verify_fleet_release_native.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | native-verification |
| scripts/verify_fleet_release_native.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | entrypoint | native-verification |
| .github/tests/test_fleet_native_route.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | native-route-verification |
| .github/tests/test_fleet_native_route.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | verifies | native-route-verification |
| .github/workflows/fleet-release-native-qa.yml | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | native-route-workflow |
| docs/fleet-release-native-qa.md | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | native-qa-documentation |
| docs/fleet-suite-authority.md | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | release-operations-documentation |
| tests/test_scoped_release_selection.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | verifies | release-verification |
| docs/native-service-recovery.md | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | file-role | recovery-operations-documentation |
| scripts/fixtures/legacy-selected-state-protection.py | REQ-FLEETUPDATE-001 | TRACE-FLEETUPDATE-001 | VER-FLEETUPDATE-001 | verifies | native-verification |


## Recovery amendment source evidence (2 November 2026)

Authority is the exact approved amendment `159af842…` and frozen contract
`91b873c5…` linked from requirements.md. Focused RED/GREEN and candidate
hashes are retained at `../artifacts/ipmi-readiness-20261026/fleet-ui-20261102/execution/build/manifest.json`.
Shared pre-code V&V is `../artifacts/ipmi-readiness-20261026/fleet-ui-20261102/execution/go/recovery-vv-root-reviewed.json`.
Native installed-wheel bootstrap, source publication, production reconciliation,
site continuity, signed admission and UI acceptance remain held.

## Central telemetry monitoring policy mapping

Authority: the scoped 4 November 2026 record in
[requirements.md](requirements.md), baseline `REQ-BASELINE-MON-20261104-001`;
intent registry: [.traceweaver/intent-contract.yml](.traceweaver/intent-contract.yml).
These rows supplement the historical Fleet mapping above without changing it.

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
