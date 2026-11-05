# Approved GPU alert work — 4 November 2026

Authority: current owner message "Approve and deploy to both sights" accepts the preceding concise Watchdog plan and collector/dashboard triage proposal. The IDs below are administrative labels for those approved behaviors, not new scope.

- REQ-GPUALERT-001: Concise Telegram GPU fault/recovery messages retain host/site, TEST identity, count and evidence-supported recovery action; detailed diagnostics remain in event records. Receipt hashing binds exactly the queued Telegram payload. Unknown actions never imply reboot.
- REQ-GPUALERT-002: Detect sustained exporter collection loss (including the supplied PCIe8/NVML0 synthetic inventory) as a host collector/source-quality alert, distinct from partial inventory and confirmed hardware faults. Preserve explicit monitoring disablement, real-fault detection, stale/missing evidence handling and truthful recovery wording.
- REQ-GPUALERT-003: Dashboards distinguish synthetic collector failures from confirmed physical GPU faults and do not make unavailable monitoring green.

Implementation choices: two-minute collector persistence; 90-second count freshness; one instance per host. Valid complete source restoration is required for a restored message; Grafana missing-series/configuration resolution is described as monitoring changed, not restored. No new dependency. Preserve existing receiver credentials, customer policies, workloads, pins, unrelated dirty work, and spent synthetic acceptance budgets. No resets, reboots, source fault injection, or extra test-notification sends.

Release scope: normal tested/reviewed dev-to-main release and immutable deployment at LTX then Charlotte, preserving rollback baselines and other services. Deployment approval persists; no further generic confirmation is required. Network, CI and exact-release acceptance gates still apply.

## Registered approved scope

| Requirement | Status |
| --- | --- |
| REQ-GPUALERT-001 | Approved |
| REQ-GPUALERT-002 | Approved |
| REQ-GPUALERT-003 | Approved |

The existing source-policy collector retains inherited baseline REQ-MON-002 and REQ-MON-003 anchors. These approved baseline IDs are context for the additive REQ-GPUALERT-002 field and unchanged application scrape contract, not new scope.

| Requirement | Status |
| --- | --- |
| REQ-MON-002 | Approved |
| REQ-MON-003 | Approved |
