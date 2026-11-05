# Fleet Manager work-item authority link

REQ-FLEETUPDATE-001 / TRACE-FLEETUPDATE-001 / VER-FLEETUPDATE-001 / VAL-FLEETUPDATE-001 are administrative labels for the exact owner-approved revision-2 plan.

Canonical authority: [../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/requirements.md](../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/requirements.md), with owner-approval.json, authority-gate.json, frozen workflow-profile.json and vv-capsule.json in that directory. This link creates no new requirement or acceptance.

## Historical 29 October 2026 discovery completeness projection (superseded)

The existing REQ-FLEETUPDATE-001 / TRACE-FLEETUPDATE-001 / VER-FLEETUPDATE-001 /
VAL-FLEETUPDATE-001 labels also cover the approved DC discovery repair in
`../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/ready-to-deploy-20261028/approved-execution-20261029/dc-discovery-source/plan.json`,
derived from its frozen authority architecture `../authority-architecture/plan-v2.json`
(SHA256 `8d0939d95e5aa9877491dcfe74b2d446d87130ce7fa2c32b3875691ea1e84459`).
The source slice is bounded to complete 100-by-ten fixed-repository listing,
91-day suite retention, at most 32 eligible families, existing signed-byte and
broker trust checks, and no partial result. The operations detail is in
`docs/fleet-suite-authority.md`. Source verification is local; native runtime,
publisher enforcement, release and deployment acceptance remain pending.

## Current 29 October 2026 atomic pack projection

The same existing FLEET IDs cover the approved v3 consistency correction in
`../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/ready-to-deploy-20261028/approved-execution-20261029/discovery-consistency-definition/plan.json`
(SHA256 `fe9516156bba64d995438a1459edfb80204aa2975e794dacbe6a8bb0af329f33`).
One fixed anonymous numeric GitHub Contents raw response must carry the whole
current index and family set. The wrapper is strict, bounded and unsigned;
existing signature, installed policy and broker highwater decisions remain.
The v2 release listing, published_at locator and asset fanout above are failed
historical evidence. The v3 source note is `docs/fleet-suite-authority.md`.
Native route, protected publisher, ten-second timing and rollout acceptance
remain held.

## 29 October 2026 native fixture pin repair

The automatic native QA run for PR 33 failed in frozen-source preflight because
the verifier retained the superseded v2 hash for `release_candidates.py`.
The exact parser pin now records the reviewed v3 source hash
`bf8bd9145005901817cb4bbaa24726dbee20e7555e782e7383722e24df1d41a3`.
This mechanical correction is bounded by the root-reviewed repair plan in
`../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/ready-to-deploy-20261028/approved-execution-20261029/discovery-consistency-definition/native-failure/root-repair-plan.json`
and frozen `profile-v4.json` (SHA256
`d974471ff3e2e052b9da1218f463ceb6a5c7ee0026f2affc2229bae45ce9d47a`).
The parser, tests and source authority note retain their reviewed bytes.
Native acceptance awaits the automatic check on the updated PR head; no manual
native dispatch or production acceptance follows from this source repair.

## Central telemetry monitoring policy — approved 4 November 2026

This portable record registers the three application requirements from the
owner-approved monitoring-policy plan. It does not revise the historical Fleet
authority above. The owner approved implementation and testing on 4 November
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

## Owner-approved per-service stable following (4 November2026)

Exact authority: `.traceweaver/auto-advance-20261104/plan.md`, SHA256 `94b783d925834004cd3f111dd2437f8ae531850f0184aaa29c52f89f84267795`; receipt `owner-approval.json`. Administrative REQ/TRACE/VER/VAL-AUTOADVANCE-001 through -008 map one-to-one to approved C1-C8 without changing their meaning. Source and verification may proceed; publication/runtime claims require their own current checks. Existing Fleet dependency holds remain.

### REQ-AUTOADVANCE-001 — approved C1

An authenticated Fleet administrator can switch one supported managed service between Pinned and Follow stable; the visible installed/selected version and mode remain distinct.

### REQ-AUTOADVANCE-002 — approved C2

Removing a pin opts only that service into verified stable candidates. Existing pins remain pinned by default. Pin current version freezes the verified installed digest; if its identity/provenance cannot be established, the operation fails without changing policy.

### REQ-AUTOADVANCE-003 — approved C3

Follow stable selects the newest admitted compatible non-prerelease version within the installed major version. No downgrade; a major upgrade requires explicit selection. No usable newer candidate leaves the current selection intact and reports why.

### REQ-AUTOADVANCE-004 — approved C4

Selection refresh occurs on Check Updates and a daily host-side check, including when no browser is open. It changes only opted-in services. Mode changes and refresh never install or restart containers. The existing Update action handles installation.

### REQ-AUTOADVANCE-005 — approved C5

Policy mutation uses the existing host owner boundary, authenticated administrator/session/CSRF/origin checks, explicit service scope, bounded fields, selection compare-and-swap, and existing lifecycle locks. A native CLI exposes the same choices. Failed persistence, stale requests, active operations, unavailable discovery or failed trust verification preserve prior selections and modes.

### REQ-AUTOADVANCE-006 — approved C6

Use verified published release/admission metadata, fixed trusted repository/channel sources and exact immutable digests. Do not replace digests with mutable :latest tags or loosen publisher/signature checks. External-owned services retain their owning lifecycle workflow; unsupported services show an explanation rather than pretending the change succeeded.

### REQ-AUTOADVANCE-007 — approved C7

Show current mode, installed version, selected target and clear failure/progress states; refreshes cannot silently re-pin or cross major versions. Re-pinning prevents a concurrent scheduled refresh from advancing afterward.

### REQ-AUTOADVANCE-008 — approved C8

TDD, independent correctness/security review, native Linux lifecycle/policy verification and real-browser checks precede release. Existing LTX data/accounts/settings and unrelated pins/runtimes remain preserved.

## GPU alert quality — approved 4 November 2026

Owner instruction: “Approve and deploy to both sights”, approving the prior concise Telegram and collector/dashboard triage plan for LTX and Charlotte. Administrative identifiers below label that approved scope. Publication/deployment require fresh remote identity, tests, review, official CI/release artifacts and native site acceptance. This record is not evidence of deployment. No hardware operations, rental changes, credential changes or extra synthetic Telegram sends are authorized.

- REQ-GPUALERT-002: Host-level sustained collector coverage and truthful recovery; additive dc_exporter source intent preserves aggregate GPU policy and legacy scrapes.
- REQ-GPUALERT-003: Synthetic DRIVER-ERROR dashboard values show telemetry unavailable while real fault/passthrough states remain visible.
