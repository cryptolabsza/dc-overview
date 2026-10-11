# Build release images, then promote tested aliases

The ordinary Docker workflows publish numeric release artifacts before customer
migration. A `vX.Y.Z` event must match the committed project version and checked
out source SHA. Each image receives only `X.Y.Z`, `vX.Y.Z` and
`sha-<full-source-SHA>` release tags. The three DC jobs cover DC Overview, RunPod
Exporter and Vast.ai Exporter; the proxy job covers CryptoLabs Proxy.

Main and development builds retain `main`, `dev` and `develop` discovery tags.
Their SHA tags are namespaced (`sha-main-<SHA>` / `sha-dev-<SHA>`), so branch
builds cannot overwrite the numeric release's SHA tag. PRs are build-only and
use `pr-N` / `sha-pr-N-<SHA>`. Arbitrary tag overrides are rejected. None of these
build paths writes `latest`, `stable`, minor or major aliases. Proxy metadata's
automatic `latest` generation is disabled.

After the normal Python/image artifacts exist, the release owner collects the
actual immutable manifest/index digests, assembles the approved customer
manifest, proves the installed public artifacts on disposable Linux, then
completes the LTX and Charlotte customer gates. Only after those gates pass does
the owner manually run `promote-images.yml`, giving the existing published tag,
full source SHA and each exact tested digest. Promotion is never automatically
triggered by a release, tag push or successful build.

Promotion validates the published GitHub tag/commit, committed project version,
all component repositories, both full-version tags and the release SHA tag,
manifest/config hashes, OCI source/revision/version labels and the requested
Linux platform set before writing any aliases. The ordinary workflow requests
Linux amd64; unsupported or extra runnable platforms hold. Recognized Docker
attestation entries stay in the copied index and are recorded separately.
Attestation content is preserved; the helper does not claim signature or
predicate validation.

The helper fetches the original manifest/index bytes from the same GHCR
repository and puts exactly those bytes, with their original media type, under
`latest`, `stable`, `X.Y`, and `X` (major0 omits `0`, preserving existing DC
policy). It does not rebuild, pull/tag/push a selected platform, serialize JSON
again or synthesize an index. It verifies the actual resulting alias digests
and checks for concurrent alias changes. Existing identical aliases are reused.

Registry writes are not atomic across aliases or component repositories. A
failed or uncertain write stops the loop and retains a held/partial receipt
with attempted aliases and observed readbacks; no success summary is emitted.
There is no automatic rollback, because that could overwrite another actor's
new value. Re-run the manual promotion with the same released source and tested
digests after inspecting the retained receipt. A verified receipt describes the
observed final alias values, not a guarantee that another actor cannot change
them later. Protect release tags and registry permissions through normal
organisation controls.

Actions uses the existing organisation GHCR credential in process environment
values. Build jobs use isolated Docker configurations with always cleanup;
promotion uses RegistryV2 directly and writes no Docker credentials. Python3.11
is selected for both helpers. Version bumps, commits, tags, publication and
customer acceptance remain release-owner work; nothing here changes versions
on `dev` or substitutes metadata fixtures for real Linux/customer testing.

Docker documents that `imagetools create` can wrap a single manifest as an index
unless format preservation is requested. Direct RegistryV2 GET/PUT avoids that
conversion; local SHA256 and registry readback check the exact original bytes.
See [Docker copy semantics](https://docs.docker.com/reference/cli/docker/buildx/imagetools/create/),
[RegistryV2 manifest API](https://distribution.github.io/distribution/spec/api/),
and [Docker attestation storage](https://docs.docker.com/build/metadata/attestations/attestation-storage/).

Release retries are read-only reuse operations. A repository-wide Actions
concurrency group serializes push and manual entries without cancelling a
running publication. Before any image job, a single preflight reads all three
identity tags for every owning image and verifies source/version labels,
config hashes and the exact platform set. A wholly absent product release may
build once. A complete coherent release skips every build and push, retaining
its original digest and timestamp. Missing individual identities, conflicting
bytes, or a mixture of existing and absent component images hold the entire
product. No automatic overwrite or repair is attempted.

A final readback runs even after an image job fails and retains the actual
observed per-image identities. Initial absence is only permission to build;
it is not a publication success claim. Partial first publications require
release-owner inspection and exact retained-byte recovery through normal
registry operations, or a new numeric release; rerunning cannot rebuild or
replace the old identities. A registry metadata/API failure also holds.

This serializes the normal repository producer; RegistryV2 has no atomic
create-if-absent operation for tags. External registry writers and legacy
workflows must be prevented by organisation controls before release. GitHub's
concurrency queue can replace an older pending run, while preserving the
running run with cancel-in-progress disabled; it does not promise every queued
run will execute. See [Actions concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).
