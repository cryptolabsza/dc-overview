# Application monitoring policy authority

## Central telemetry monitoring policy — approved 4 November 2026

This portable record registers the three application requirements from the
owner-approved monitoring-policy plan. The owner approved implementation and testing on 4 November
2026 and subsequently authorized publication through the normal release process
and Charlotte deployment. Publication and deployment still require their own
current checks and acceptance evidence.

Authority metadata: `REQ-BASELINE-MON-20261104-001`, owner Hannes Zietsman,
approved-plan SHA256
`1ca52d740bc7e1a2933a26ed11ca1412ceb1669219f00a2a588c3899b384d50a`,
application source baseline
`1756de876bd5a72687f0b6d6047f975f5cea6ce8`.
This is a scoped projection of the approved plan, not a claim that private
operational evidence is distributed with the application.

### REQ-MON-001 — preserve configured monitoring intent

Failed or healthy connectivity, installed-state, version and watchdog
observations preserve enabled flags; failed or unknown reads preserve previously
confirmed installation. Explicit install, remove and toggle operations retain
their existing responsibility. Discovery keeps installed-and-enabled eligibility.

### REQ-MON-002 — export configured channel intent

Export current desired filesystem policy from node enablement and GPU policy
from DC OR DCGM enablement, using `server_name=monitoring_name or name` in
`dc_overview_telemetry_monitoring_enabled{server_name,telemetry}`. Unknown
installation state does not disable policy. Rename and delete leave no stale
labels. Discovery semantics remain distinct from policy.

### REQ-MON-003 — scrape application policy in every Fleet configuration

Bootstrap and configured Fleet Prometheus generation include one application
metrics job matching the existing product template, preserving managed discovery
and infrastructure jobs.

### Scope and evidence limits

`REQ-MON-004` covers the separately owned site missing-alert expressions and
their operational validation. It is outside this application repository; this
record does not transfer site-rule ownership or ship a site inventory.
The approved changes do not alter exporter binaries, host services, credentials,
database schema, GPU settings, unrelated alerts or notifications, expected-host
fallbacks, or package versions on `dev`. Existing timed maintenance silences
remain the maintenance mechanism.

Verification uses the committed tests linked in
[traceability-matrix.md](traceability-matrix.md). The reviewed application
candidate passed 111 application contracts, including both Fleet generation
cases. Representative local validation also exercised candidate Flask metrics
through a real Prometheus scrape and the separately owned expressions in 13
scenarios. These results establish local behavior; they do not claim production
deployment, notification delivery or acceptance of unrelated Fleet work.

## GPU alert quality — approved 4 November 2026

Owner instruction: “Approve and deploy to both sights”, approving the prior concise Telegram and collector/dashboard triage plan for LTX and Charlotte. Administrative identifiers below label that approved scope. Publication/deployment require fresh remote identity, tests, review, official CI/release artifacts and native site acceptance. This record is not evidence of deployment. No hardware operations, rental changes, credential changes or extra synthetic Telegram sends are authorized.

- REQ-GPUALERT-002: Host-level sustained collector coverage and truthful recovery; additive dc_exporter source intent preserves aggregate GPU policy and legacy scrapes.
- REQ-GPUALERT-003: Synthetic DRIVER-ERROR dashboard values show telemetry unavailable while real fault/passthrough states remain visible.
