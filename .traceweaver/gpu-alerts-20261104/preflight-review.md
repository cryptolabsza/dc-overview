# GPU alert pre-implementation adversarial review

Status: **PASS — both bounded verification gaps resolved before implementation**. Scope and owner approval are accepted; publication remains held for network/remote freshness and normal CI. No new generic approval is needed.

Reviewed: requirements, plan, validation, authority gate, workflow profile, matrix, three new test modules and RED results. The later temporal PromQL test was included. Production source remains unchanged. RED failures establish the missing formatter, collector rule/template and dashboard behavior. The temporal test now checks sustained loss and retained recovery.

## Resolved findings

1. **DC-specific disablement is not represented by the tested aggregate policy.** Confidence 100. The requirement says “Preserve explicit monitoring disablement”; `web_prometheus.py::TelemetryMonitoringCollector.collect` emits GPU policy as `dc_exporter_enabled or dcgm_exporter_enabled`. Thus DC disabled + DCGM enabled leaves policy=1. Historical PCIe/NVML samples can persist in Prometheus after the DC target is removed. A new alert anchored on those counts can alert for an intentionally disabled collector. Add a failing scenario with DC target absent, DCGM target present, aggregate GPU policy=1 and old DCXP fault counts. Define expectation from current DC target identity where available, rather than treating aggregate policy=1 as proof DC is enabled.

2. **The promised 90-second freshness is not exercised.** Confidence 100. `test_real_promql_detects_missing_stale_and_zero_inventory_without_fanout` uses `"8 stale"` and `"0 stale"`; a Prometheus stale marker removes the series immediately. These tests cannot distinguish age-aware logic from ordinary instant queries retaining an old value for the default five-minute lookback. Add missing-sample (`_`) cases without stale markers, live target, and evaluation after 90 seconds but before five minutes. Old healthy count must produce collector failure; old disabled policy must not suppress fallback detection.

## Continuation verification

Re-read the updated test before any production mutation. It now includes DC disabled/DCGM enabled with aggregate policy=1 and no DC target, plus a fresh managed policy with no current targets. Both expect no resurrected DC collector instance. The bounded design uses current DC target identity for managed hosts and reserves PCIe fallback for hosts without current discovery exporter identity or fresh app GPU policy. This resolves finding 1 without a new policy schema.

The count and disabled-policy age cases now use missing samples (`_`) without stale markers and evaluate at three minutes, inside Prometheus's normal five-minute lookback. Old counts must alert and old disables must not hide an otherwise expected collector failure. This resolves finding 2. Separate explicit stale-marker coverage remains.

The rerun reports ten Overview tests failing against unchanged production source, including the temporal test. Both repositories' tracked production diffs remain empty. These failures are appropriate pre-implementation evidence; a passing implementation and independent final code review are still required. Existing workload, credential, spent-notification-budget, fresh-remote, CI and normal-release boundaries remain in force. This PASS authorizes the scoped implementation handoff only; it is not a code, release, runtime or deployment acceptance claim.
