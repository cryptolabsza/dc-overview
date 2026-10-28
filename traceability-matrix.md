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
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `tests/test_release_broker.py` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `src/dc_overview/templates/systemd/dc-overview-release-broker.service` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `src/dc_overview/templates/systemd/dc-overview-release-broker.socket` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `docs/standard-customer-releases.md` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `.github/workflows/fleet-release-native-qa.yml` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `.github/tests/test_fleet_native_route.py` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `scripts/verify_fleet_release_native.py` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |
| TRACE-FLEETUPDATE-001 | REQ-FLEETUPDATE-001 | `docs/fleet-release-native-qa.md` | VER-FLEETUPDATE-001 | VAL-FLEETUPDATE-001 | approved |

## Unsupported format evidence

The two systemd units, pyproject package-data and operator documentation are manually mapped to the same approved work item. Their exact hashes, format/package checks and integration limits are retained in ../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/dc-implementation/. No whole-repo or production acceptance is inferred.

Native QA support authority is the same owner-approved step4, concretely bounded by ../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/native-qa-plan/root-decision.json and repair-cycle1-decision.json. The new workflow YAML and QA documentation use this manual mapping, exact file hashes, parsed route checks and syntax evidence in native-qa-implementation/. The reviewed published proxy commit is pinned literally. Acceptance remains held: actual fresh Linux execution, production trust, genuine future-version migration, browser acceptance and external VM destruction evidence are not claimed by local checks. Prior product authority and frozen product bytes are unchanged.

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
