# Per-service pin removal and stable release following — candidate plan

Status: prepared for owner plan approval; no implementation or target changes.
Source request: owner approved verified stable selection advancement with manual installation, and added that users must be able to remove a pin and follow stable releases.
Scope: LTX Fleet website, reversible per-service administrator choice, trusted selection advancement, manual Update action, CI/release and LTX verification through the existing controlled routes. Existing services keep their current mode until an administrator changes it.

## Observed source boundaries

- Deployed Proxy1.6.2 source main c5e88a99b4da6fe37cacc64fc0cda5a59e3617de; upstream dev10f48b4474a1c2c771bf72449d22efddd91f0d02 contains additional unreleased release-client/auth bridge work. Do not import dev wholesale.
- Current production release_selection.py permits baseline/customer-pin/unmanaged, and release-selection docs keep selection files root-owned/read-only in Proxy. A browser toggle cannot safely be a direct file write.
- Existing DC Fleet source worktree dc-overview-fleet-service-recovery-20261102 at01011f44d93ec86027db1c0d33238b4ea90e6880 includes release_broker.py, release_catalog.py, release_candidates.py and fixed systemd socket transport. Its authority explicitly retains native/publisher/deployment holds. This is reusable source context, not accepted live infrastructure.
- Existing broker previews update a pinned identity when explicitly selecting a candidate; durable follow/pin intent and selection-only refresh are missing. Current list/preview/apply/status/recover protocol must be extended deliberately.
- Second Brain did not locate relevant current release-policy context; direct source and exact GitHub refs supplied these findings. Existing project graph covers older monitoring/exporter paths, not this feature.

## Candidate behavior and acceptance criteria

C1. An authenticated Fleet administrator can switch one supported managed service between Pinned and Follow stable; the visible installed/selected version and mode remain distinct.
C2. Removing a pin opts only that service into verified stable candidates. Existing pins remain pinned by default. Pin current version freezes the verified installed digest; if its identity/provenance cannot be established, the operation fails without changing policy.
C3. Follow stable selects the newest admitted compatible non-prerelease version within the installed major version. No downgrade; a major upgrade requires explicit selection. No usable newer candidate leaves the current selection intact and reports why.
C4. Selection refresh occurs on Check Updates and a daily host-side check, including when no browser is open. It changes only opted-in services. Mode changes and refresh never install or restart containers. The existing Update action handles installation.
C5. Policy mutation uses the existing host owner boundary, authenticated administrator/session/CSRF/origin checks, explicit service scope, bounded fields, selection compare-and-swap, and existing lifecycle locks. A native CLI exposes the same choices. Failed persistence, stale requests, active operations, unavailable discovery or failed trust verification preserve prior selections and modes.
C6. Use verified published release/admission metadata, fixed trusted repository/channel sources and exact immutable digests. Do not replace digests with mutable :latest tags or loosen publisher/signature checks. External-owned services retain their owning lifecycle workflow; unsupported services show an explanation rather than pretending the change succeeded.
C7. Show current mode, installed version, selected target and clear failure/progress states; refreshes cannot silently re-pin or cross major versions. Re-pinning prevents a concurrent scheduled refresh from advancing afterward.
C8. TDD, independent correctness/security review, native Linux lifecycle/policy verification and real-browser checks precede release. Existing LTX data/accounts/settings and unrelated pins/runtimes remain preserved.

## Numbered implementation plan

1. Write failing tests first. DC: new tests/test_release_policy.py plus existing tests/test_release_broker.py, test_release_candidates.py and test_scoped_release_selection.py. Proxy: API/client tests for the existing release bridge plus tests/test_latest_status.py. Cover pin removal/re-pinning, stable choice, same-major rule, downgrade/prerelease rejection, no eligible candidate, mode persistence, no restarts, selection races, active lifecycle locks, unauthorized/CSRF/origin rejection, interrupted publication and unrelated-service preservation.
2. Add the smallest per-service policy owner module src/dc_overview/release_policy.py. Extend src/dc_overview/release_broker.py and release_catalog.py with bounded policy read/change and selection-only refresh, reusing existing trusted candidate discovery and atomic lifecycle publication. Add CLI parity in cli.py and a daily installed systemd timer/service invoking that exact owner operation. Policy intent lives in a separate root-owned versioned record; do not add unrecognized fields to the existing selection schema. Preserve all existing source policies on first install.
3. Extend Proxy src/cryptolabs_proxy/release_client.py and the existing administrator/CSRF-protected release routes in auth.py. Add mode and target controls to landing-page/index.html and consistent status in scripts/health-api.py/updates.py where required. Browser sends only bounded service/mode/expected identity fields; it cannot supply file paths, commands or arbitrary registry URLs. No new public trust source or credential store.
4. Verify Red-Green-Refactor, focused and appropriate regression suites, independent correctness/security/API review and real Linux owner tests. Native scenarios include two competing refresh/pin requests, crash/restart, unavailable catalog, invalid admission, persistent daily refresh without a browser, and zero lifecycle calls for policy-only operations. Run real Chrome with pending and installed targets; prove unpin -> verified target -> manual update -> healthy, then re-pin -> no subsequent advance. Do not manufacture a production downgrade or extra hardware restart solely for a demo.
5. Complete the existing broker/bridge native and publisher acceptance prerequisites before activation. Publish only the reviewed required source on dev, release through main with normal versioning and GitHub CI, inspect immutable official artifacts, deploy through native LTX ownership, then verify UI persistence, exact selected digests, original history/accounts and unrelated containers. Keep automatic installation off. If prerequisite infrastructure remains held, report that specific deployment hold without claiming the feature is live.

## Dependencies, risks and decisions

No new third-party service or Python dependency is proposed. Host systemd timer and the accepted broker/bridge runtime are infrastructure changes. The existing Fleet broker source is not currently accepted on LTX; finishing that dependency is required and must not be hidden as a simple UI-only change.

Selected approach: immutable digests plus explicit persisted follow intent. A mutable :latest tag loses the selected artifact contract; a frontend-only toggle cannot cross root custody safely; duplicating a second lifecycle controller creates competing writers. Reuse and extend the existing owner and release pipeline instead.

The principal risks are choosing an untrusted/incompatible release, advancing a freshly re-pinned service, lost multi-component updates, and selection/installation confusion. Mitigations are admitted candidates, same-major/no-downgrade rules, explicit compare-and-swap plus existing locks, transactional policy publication/recovery, strict one-service scope, clear UI and native concurrency/failure tests.

## Verification and validation plan

Verification owner: main implementation chat. Every result records tested source, command/scenario, expected/actual state and evidence path under this directory. A local synthetic UI tests controls/request contracts only; actual Linux owner evidence is required for root custody, sockets, timer, atomic changes and lifecycle preservation.

Stakeholder acceptance owner/rater: Hannes Zietsman, operator requesting the behavior, independent of implementation. Observable acceptance: an administrator removes IPMI's pin in Fleet, sees Follow stable persist across reload, sees a verified compatible stable target chosen without an automatic restart, can install through Update, and can re-pin so future checks keep the version. If no genuine newer admitted release exists on LTX, pending-release installation is demonstrated on native disposable staging and LTX validates current mode/identity/preservation; no false production upgrade claim.

## Authority and publication status

Source request supports the feature intent. This plan introduces concrete files, API/root-owner behavior and scheduling details, so it remains candidate authority until explicit plan approval under project AGENTS.md section2. No production source, selection, service, credential, CI publication or deployment has changed in this planning turn. Current implementation baseline documents are read for constraints; existing Fleet-held acceptance claims are not promoted by this plan.
