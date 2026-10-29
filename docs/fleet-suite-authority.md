<!-- TRACEWEAVER: file-role=release-operations-documentation; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001 -->
# Fleet suite discovery authority — 29 October 2026

## Current v3 atomic pack source contract

The accepted source design is
`../artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/ready-to-deploy-20261028/approved-execution-20261029/discovery-consistency-definition/plan.json`
(SHA256 `fe9516156bba64d995438a1459edfb80204aa2975e794dacbe6a8bb0af329f33`).
The frozen source profile is its `profile-v3.json` (SHA256
`261f95af4fac1ff23a9d2cdc0c1255767471202e9c055f0b7706b3bc6e6faee0`).
This v3 contract replaces the release-list discovery proposal recorded below.

The customer makes one anonymous GET to
`https://api.github.com/repositories/1133295682/contents/current-pack.json?ref=fleet-suite-current`.
It requests GitHub raw media with `Cache-Control: no-cache, no-store` and
`Pragma: no-cache`. The owned session disables ambient environment and auth
credentials. Redirects, 304 responses, error bodies, release lists, serial
asset URLs and alternate hosts are not followed. A non-200 response or network
fault is unavailable. A 403/429 starts a bounded cooldown from Retry-After or
the rate-limit reset header; calls during cooldown make no network request.

The raw JSON pack contains exactly schema version 1, one base64 current signed
index and its raw 64-byte Ed25519 signature, and one to 32 families. Each
family has only exact raw manifest, admission and 64-byte admission signature
buffers encoded as canonical standard base64. Duplicate JSON keys, NaN,
unknown fields, noncanonical base64, duplicate admission identities and empty
families are refused. The body is at most 8 MiB; cumulative decoded buffers
are at most 5 MiB, counting the shared index and signature once. Each document
is at most 1 MiB. Exceeding any bound yields no partial bundle. A ten-second
single-request deadline covers streaming and decoding. This is a configured
bound, with real customer-path timing held for native evidence.

Discovery returns the same list of exact five-buffer dictionaries. The outer
pack and Git ref are transport and availability only. Installed public-key,
producer, manifest, expiry, signed current-index, revocation, compatibility
and durable highwater checks remain in the existing broker/verifier. A fresh
all-revoked index keeps a prior exact family carrier, even if its old admission
is expired, so the broker can advance highwater while offering no candidate.
An old complete pack may be observed from a replica until fresh readback; the
source does not claim linearizable newest-head delivery or unlimited anonymous
shared-IP quota.

The infrastructure publisher owns the protected data-only branch, complete
authenticated inventory, exact release-byte assembly, compare-and-swap pack
update and anonymous public readback. Customer source tests do not certify
that producer or ref. Native numeric Contents routing, protected branch,
real timing, installed trust and rollout remain separate held gates.

## Historical v2 pagination proposal — superseded by v3, not for deployment

This note records the bounded discovery contract approved in
`artifacts/ipmi-readiness-20261026/release/fleet-manager-build-20261027/ready-to-deploy-20261028/approved-execution-20261029/authority-architecture/plan-v2.json`
and its DC source slice. It describes source behavior; it is not a native GitHub,
installed trust, publisher, or deployment acceptance record.

## Discovery and availability

The customer reads only numeric repository `1133295682`, with exactly 100
releases per page and at most ten pages. A page shorter than 100 establishes
listing completeness. Ten full pages are an explicit overflow, so the supported
total is at most 999 releases. Release IDs must be distinct positive integers
across all pages. The complete list is checked before any asset is downloaded;
pagination, metadata, HTTP, time, and size failures yield no partial result.

Only nondraft releases containing the five named suite assets are candidates.
An eligible suite must have a UTC `published_at` within 91 days of discovery;
a suite timestamp more than one day in the future is refused. The 91-day
window provides the 90-day maximum admission interval plus one-day publication
allowance. Discovery checks every page without assuming list timestamp order.
At most 32 complete suite families may be eligible. Reaching the release or
family limit is fail-closed unavailability requiring a reviewed retention or
locator change before further issuance. It is not an unlimited churn promise.

The producer must publish a new suite-only release for each issuance or index
change, with actual `published_at` within 24 hours of signed index `issued_at`;
it must never retrofit an older release. The authenticated producer inventory
owns the separate limits of 16 issuance envelopes, 16 revocation carriers,
and eight live issuance envelopes per supported platform (`linux/amd64` and
`linux/arm64`). The customer conservatively counts all 32 families without
trusting unsigned subtype hints. An `any` wheel is component-specific and is
not a third deployment platform. Publisher preflight must prove listing and
family headroom before reserving or signing. These producer obligations remain
outside this DC source slice.

The existing ten-second end-to-end deadline covers every list page and asset
request. Each response is limited to 1 MiB, all list responses together to
10 MiB, and all successful response bodies together to 111,151,104 bytes
(106 MiB), including list bytes and both raw 64-byte signatures per suite.
The five-buffer return shape and fixed HTTPS GitHub host and redirect guards
stay unchanged. A native measurement may show that ten seconds is insufficient;
that would require a separate reviewed timeout change.

## Trust boundary

GitHub `published_at` is a bounded availability locator, never signed
approval or generation evidence. The broker still verifies exact Ed25519
bytes, producer, installed trust, validity, highest signed index, revocation,
and durable highwater. A newest all-revoked carrier must be discovered even
when its own older admission is expired, so the broker can advance highwater
without offering an update. Discovery does not accept or select an update.

## Verification and hold

The local source test uses a URL-driven HTTP response substitute and real
signature and broker paths. It covers the 999/1000 boundary, 91-day cutoff,
32/33 families, both platforms, late revocation, partial failures, and byte
and deadline limits. Native GitHub behavior, actual ten-second sufficiency,
installed trust, publisher inventory enforcement, release, and deployment
remain held for their separate gates.
