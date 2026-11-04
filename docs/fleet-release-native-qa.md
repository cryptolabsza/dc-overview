<!-- TRACEWEAVER: file-role=native-qa-documentation; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001 -->
# Fleet release native verification

The `Fleet release native verification` pull request workflow runs one sequential
integration flow in the existing `ci-build-public-ephemeral` Linux VM route for
repository `1133295682`. It requires a same-repository PR into `dev`, a read-only
job token, the exact DC PR head, and an explicitly reviewed, published proxy commit.
Root binds the recovery input to the exact reviewed protected `dev` merge
commit, refreshes every changed runtime hash in `FROZEN_PRODUCT_HASHES`, and
sets `RECOVERY_INPUTS_FROZEN = True` only after exact source review. The workflow
uses that immutable commit as `PROXY_SOURCE_SHA`. The source pin and recovery
input guards reject unresolved inputs before the proxy checkout or guest changes. This test integration is not
execution or publication approval.

The five public image inputs in `scripts/verify_fleet_release_native.py` are
immutable digests. Registry and Nginx use pinned official Linux amd64 manifests;
IPMI uses the previously approved old and new public releases. The retained
primary registry metadata readback accompanies the implementation evidence.
No registry login or publishing credential is needed.

Inside that individual fresh guest, the workflow builds and installs both
compatible wheels, checks installed bytes against frozen source hashes, and
builds two compatible proxy images from the same reviewed application source
with different metadata. These images do not stand in for legacy-runtime proof.
It first checks the vanilla packaged systemd unit with writes disabled and no
trust fixture. It then adds an explicit test-only systemd discovery adapter. The
adapter supplies locally signed synthetic admission assets to the installed
broker; policy loading, signature checks, selection, Unix socket serving, kernel
peer credentials, updater helpers, adoption owners, Docker Engine and HTTP remain
the real implementations.

The test registry listens only on guest loopback. Its temporary TLS certificate,
guest hosts entry and trust augmentation exist only in that VM. Before any fixture
trust, DNS or registry change, the script requires the guest's local rootful Docker
Engine **29.1.3**, the `io.containerd.snapshotter.v1` image store, and the exact
`/etc/docker/certs.d/ghcr.io/hosts.toml` SHA256
`5b44770a4caca465e8991cbbaaa6a50eae52bc5d349700f4ca2c240ca0458629`.
The file and its complete parent directory chain must be root-owned, nonsymlink
and have no group/other write access. The bounded regular file must have one
link and no extended attributes; unsupported metadata fails closed. The context
event exports only fixed version/store/rootless enums, the bounded-file hash,
and fixed outcomes. Unknown image or configuration changes require review.

All original public pulls and image builds finish with the original trust file.
The fixture then exclusively creates one unique public `.crt` and inserts only a
root-level `ca = ["<owned fixture certificate>"]` before the first TOML table.
The default server, existing pull/resolve mirror, its CA, and all original bytes
remain unchanged. Docker29.1.3's vendored containerd2.2.0 uses this explicit
default-server CA together with system roots; valid `hosts.toml` bypasses sibling
certificate scanning. This source mechanism explains the conditional adapter;
it does not establish the failed earlier guest's exact configuration or cause.
TLS verification stays enabled. The adapter changes no daemon configuration,
BuildKit configuration, mirror capability, source, installed image or pool setting
and performs no daemon restart.

The original inode is retained in a private root-owned guest directory. Ownership
state is registered before partial writes or renames can fail. Cleanup first
quiesces fixture consumers, then checks parent identities, owned replacement
inode/content/metadata and the protected preimage before renaming the original
inode back. Exact original bytes, uid/gid/mode and atime/mtime are restored and
checked; original **ctime cannot be restored**. Only after trust restoration may
cleanup remove the owned fixture CA. Baseline CA files are never written or
deleted. If observed custody drifts or restoration fails, cleanup does not
overwrite the unknown file or delete a potentially referenced CA; it retains the
private preimage for required external guest destruction. Independent owned
cleanup still runs. A cleanup failure emits terminal failed/held evidence and
fails the job even after a passed native-flow event. Arbitrary exception text,
configuration bytes and private paths are suppressed from evidence and chained
exceptions. Failed `native-flow` events retain only a fixed phase label:
`preflight`, `images`, `units_install`, `fixture`, `service_update`, `proxy_adopt`,
`rollback`, `interrupted_adoption`, `reset_fixture`, or `cleanup`. The script sets
these literals before their steps; phase labels never come from exception text,
arguments or callable names.

Every failed `native-flow` event also retains `source_line` and `error_kind`,
including a terminal `cleanup` failure. The line is an integer from the innermost
traceback frame whose code object is the original `NativeQA` method for that
fixed phase. An immutable allowlist captures the ten phase/method code-object
pairs when the module loads; the line must belong to that code object's line
table. Filename or function-name matches cannot supply it, and a frame from a
different trusted phase does not match. Interpret the line only against the
exact DC source head retained by preflight; for a command helper failure it
identifies the phase's caller boundary. The error kind uses ordered type checks
into fixed literals: `assertion-error`, `file-not-found`, `permission-error`,
`os-error`, `runtime-error`, or `unknown`. Missing trusted frames, invalid lines
or diagnostic collection failure retain null/`unknown`; an unknown phase also
retains null/`unknown`. An unfamiliar exception type at a valid phase line retains
that line with `unknown`. Failed `fixture` events keep the existing `fixture_line`
and `fixture_error_kind` fields as aliases of `source_line` and `error_kind`.
These fields identify an observed boundary, not an established root cause. No exception
text, arbitrary type names, arguments, locals, private paths, raw traceback or
command output is retained. The original failure and cleanup still run; this
metadata adds no retry, probe or behavior repair. All remaining native and
release acceptance limits below continue to apply.

For a failed `fixture` phase, `bootstrap_failure` adds one bounded object while
the outer line, kind and fixture aliases retain their existing meaning. Its
only fields are `bootstrap_step`, `code_label`, `source_line`, `guard_line`,
`error_kind`, `command_outcome` and `command_returncode`. The step comes from
fixed lexical markers in the original bootstrap/seed bytecode, selected by the
trusted traceback instruction offset. The collector does not read frame locals.
Steps distinguish the existing legacy inspect/updater/capabilities probes,
synthetic seed/read/custody/protection, failed-job seed, compatible installation,
owner refusal, reconciliation/replay, selection, proxy plan/adoption and health.
Untrusted or missing boundaries retain `unknown` and null values.

The code labels are `legacy-bootstrap`, `synthetic-seed`, `synthetic-helper`,
`native-command` or `unknown`. Module load captures original verifier code
objects. The helper remains byte-for-byte pinned by `PROTECTION_SHA`; its
diagnostic registration first verifies those exact bytes and complete loaded
callable code before capturing the actual callable and nested code identities.
Every traceback lookup uses exact code-object identity. A matching filename or
callable name grants no identity. The inner source line must occur in that
original code object's line table. A helper `need()` failure retains the numeric
trusted caller line as `guard_line`, rather than exporting its error text.
Interpret verifier coordinates against the exact preflight source head, and
helper coordinates against the unchanged retained helper hash.

The checked command wrapper owns an immutable pair of bounded diagnostic facts.
`command_outcome` is `nonzero-exit`, `timeout`, `spawn-error`, `none` or `unknown`;
`command_returncode` is an exact integer from -255 through 255, or null. Booleans
and out-of-range values are rejected. Only the original owned exception type
with an original command-wrapper traceback can supply command facts to the
inner object; arbitrary exception properties cannot. Command failure messages
are fixed literals, with no executable name derived from arguments. Exception
propagation and chaining remain available; only the owned facts are immutable.
Construction and collection accept exact built-in strings and return fixed
canonical outcomes; string subclasses become `unknown`. Ordinary assignment,
deletion and constructor reinitialization cannot change the owned facts.
Arbitrary Python reflection is outside this immutability promise.

No exception string or representation, argv, captured output, environment,
configuration, database content or helper private receipt is exported by this
object. Collection is best effort and cannot replace the original failed gate
or skip cleanup. These coordinates locate an observed failure boundary; they
do not prove a root cause, repair bootstrap behavior, add a retry or authorize
another native run. Full native, release and customer-site gates remain held.

At each existing broker kill boundary (`service_update` and
`interrupted_adoption`), the fixture records the auth layout, fixed phase,
actual numeric kill exit code, and before/after `systemctl show` observations of
only the fixed broker service. `ActiveState`, `SubState` and `Result` use closed
literal allowlists; unfamiliar values become `unknown`. `MainPID` is bounded
from zero through 4194304 and `ExecMainStatus` from zero through 255; invalid or
duplicate fields become null. Each read-only snapshot has a ten-second command
bound. Snapshot or evidence collection failure never replaces the kill verdict.
A nonzero kill still immediately raises the original generic command failure;
no subsequent start, lifecycle retry or successful normalization occurs.

The required injected fault is the main Python broker process, including its
in-process ThreadPool worker. Before signalling, the harness observes actual
guest `systemctl --help` support for `--kill-whom=` and records only a Boolean.
Unsupported or failed capability checks hold the gate. It requires active/running
service state, a valid nonzero MainPID, and a live kernel process identity.
It sends exactly one `systemctl kill --kill-whom=main --signal=KILL` for the fixed
broker service. A nonzero result still fails immediately; it is never retried or
normalized. No service restart or cgroup policy is changed.

The kernel identity uses PID plus `/proc/PID/stat` start-time ticks. A bounded
4096-byte parser validates the PID, state and bounded numeric fields; the process
name and raw stat text are never retained. Absence or a changed start time retires
the old identity. A zombie/dead state requires a corroborating known systemd
transition away from the old running main. MainPID change alone never establishes
death. After a zero kill exit, the harness waits at most 30 seconds for retirement
and that unit transition before the existing caller issues `start`. If automatic
restart wins, this barrier also observes a distinct live running process identity.
A subsequent separately bounded 30-second check after the existing `start`
requires a distinct live active/running broker before recovery assertions proceed.
Existing operation/recovery deadlines and all owner mapping, replay, adoption and
rollback assertions stay unchanged. Kill evidence records only the fixed
capability/retirement booleans and bounded PID/start-time numbers in addition to
the existing closed service fields and numeric exit.

These barriers establish observed main-process retirement and fresh broker
availability only when the actual native run supplies the evidence. This change
is not a proven cure for the earlier exit 1, whose cause remains unknown. It does
not test whole-cgroup failure or establish an exact owner execution micro-window.

The test-only broker child freezes the original installed `serve`,
`serve_connection`, `response`, and selected direct broker entrypoint code
objects before invoking the installed owner. An escaping exception can retain
only the innermost matching code label (`broker-serve`, `broker-connection`,
`broker-response`, `broker-init`, `broker-policy`, `broker-dispatch`,
`broker-reconcile`, or `broker-operation`), an integer from that original code
object's line table, and the fixed error category described above. Missing
trusted frames retain null/null/`unknown`. Same-name or same-filename foreign
code confers no identity. This observes escaping Python exceptions only;
SIGKILL, abrupt interpreter termination and handled exceptions may have no record.

The record uses an exclusively created fixture-owned regular file with mode
0600 in the private mode-0700 fixture root. It is reset before each layout's
socket start, opened without following symlinks, checked for owner/mode/link
custody, read with a 4096-byte bound and consumed before fixture cleanup.
The parent also requires its retained inode identity and exact closed JSON
schema before recording it. Original exceptions and cleanup remain in force
if this best-effort collection fails. No exception text, journal, traceback,
filename, argument, local, environment or credential enters these events.
The reviewed Proxy pin also freezes the newly imported
`src/cryptolabs_proxy/account_link.py` alongside the existing runtime files.

These compare-before-rename guards rely on exclusive use of a fresh single-job
guest. They are not atomic compare-and-swap against a concurrent root writer or
a credential boundary. Early preflight failures emit sanitized failed evidence
and skip cleanup over unowned paths. Script cleanup never certifies external VM
destruction, whose separate receipt remains required.

If a fixture registry push fails, its diagnostic event contains only
`case=fixture-registry-push`, one of the five literal fixture keys, `result=failed`,
an exit code bounded to -255 through 255 (or null for a command timeout),
`diagnostic_version=1`, and `diagnostic_signals`. The signals are fixed literals
selected by conservative byte markers: `certificate-untrusted`,
`certificate-name-or-time`, `client-certificate-configuration`, `tls-protocol`,
`name-resolution`, `connection-refused`, `timeout`, `registry-denied-or-auth`,
`registry-http-error`, `manifest-or-blob-invalid`, `storage-error`, or `unknown`
when no marker matches. These are observations, not established causes; Docker
message variations may remain unknown. Captured output, command arguments,
URLs, headers, environment values, keys and cookies are never copied into this
event or the generic failure. The failed event is retained before the native
flow fails and performs its existing cleanup. No retries or additional probes
are added, and the underlying push cause remains unresolved until observed.

The fixture
uses the fixed accepted image namespaces so the production parser sees its real
input contract. No push reaches the public registry. The script refuses occupied
fixture paths, existing product containers, a non-VM context or a remote Docker
endpoint. Root commands, the Docker socket, systemd units and `/etc` changes are
confined to the disposable guest. The proxy uses isolated external ports 18080
and 18443, preserving those bindings through adoption.

The new recovery/bootstrap check uses a named auth volume. After that sequence
adopts the compatible proxy, the retained flow checks the cases below. The
existing separate bind-layout compatible fixture and its interruption checks
also remain in the same sequential job; they do not stand in for legacy proof.

1. Real peer rejection, malformed framing, root-policy reload and native CLI use.
2. A scoped IPMI update, a dropped HTTPS reply and broker restart, durable owner
   mapping, replay without a second helper, and unchanged unrelated selections.
3. A raised generation floor and an operator write disable taking effect live.
4. Actual proxy A-to-B replacement, preserved service/container identities and
   auth backing storage, normal cookie renewal, session reconnect without login,
   and the fixed installed adoption recovery call.

The dropped-reply cases keep the authenticated HTTPS connection open until the
broker's operation record for that request UUID exists, then close without reading
the HTTP response. This observes accepted-request reply loss before exercising
restart and replay. A missing operation record still fails the existing bounded
wait; sending bytes alone does not establish acceptance. The earlier native timeout
identified the apply call site, so its exact inner cause remains unconfirmed until
a fresh native run observes the repaired fixture.

The named-volume case also requires an unhealthy candidate to restore the actual
original IPMI container and health. The approved IPMI images lack Docker health
metadata, so their readiness requires a bounded real HTTP 200 response from
`http://127.0.0.1:5000/health` inside the exact container. An explicit Docker
`unhealthy` status is rejected; running alone never passes. Before the
continuation/replay broker kill, the exact mapped helper must be running or its
mapped job must have a terminal result. A prelaunch mapping alone cannot satisfy
that observation. Subprocess timeouts fail with a generic error and suppressed
exception chaining, while retaining the failed outcome and cleanup.

The bind case interrupts real compatible proxy adoption after the owner retains
its plan and observes recovery after broker restart. It does not constitute a
second legacy bootstrap check. No exact Engine crash instruction boundary or
lost Engine reply is claimed.

## Packaged legacy recovery before selection and adoption

The workflow downloads the actual released DC1.8.0 and proxy1.5.4 wheels through
their immutable public HTTPS release URLs, bounds each download to 120 seconds,
and checks these SHA256 values before use:

- DC1.8.0: `72fcf2fde1d765cdfebfd2e4071261e3ff28d202f7ffb1975340e9d362969304`.
- Proxy1.5.4: `5e64f0ae59d38ebcf4885d8aa60822bc3187d5a63f9abb8bdd11927d1ffd2b47`.

It installs/imports the old pair in one guest host-tool venv, invokes old DC
release help, and creates synthetic auth data through the old proxy package.
It starts the actual serving legacy proxy image
`ghcr.io/cryptolabsza/cryptolabs-proxy@sha256:bff38744e774875287e60e1e14995b19c7eb3afbe531d07f5921d06d9b76a1fd`
without a broker socket mount. The image's stale OCI version strings are not
version proof. Both proxy fixture layouts set `PYTHONPATH=/app/src`, the copied
application source path required by their Python module probes. The pinned legacy
image does not declare that environment setting itself.
Actual updater module bytes must match the exact old wheel;
actual live capabilities must lack the new broker/recovery capabilities.
DC1.8.0 here is the host CLI/package plane; a separate old DC service OCI
container is not started or certified by this fixture.

The original IPMI service uses real 1.3.1 image
`sha256:738f11f7b432c4d9d8409154c9ca3f531a1e069999eb639a9d86433e84ac279d`.
The selected failed target is real 1.3.2 image
`sha256:dfa8a56159aab545d128b14bfb7d91cad17cac7de4f706307de508086fc56db9`.
The later successful scoped target is real 1.3.3 image
`sha256:1d616479a3842f5101615b6d97552f732de73fd424fcb844a9c643e92abc8bb1`.

The verification-only selected-state producer in
`scripts/fixtures/legacy-selected-state-protection.py` retains the bounded
selected-table/config roundtrip algorithms and records their source provenance.
All historical site PINS, customer identity values and the operational CLI
entrypoint are removed. It requires an explicit synthetic binding and creates
only a synthetic guest continuity bundle. Sync stays OFF; a deliberately
synthetic health timestamp exercises the freshness predicate. This does not
prove a real collector, customer data continuity or whole-database disaster
recovery. No production DB snapshot is taken.

The failed native record is constructed by actual old `submit_job`, using real
read-only Engine observations and the real selected snapshot/targets/sources.
Only helper create/start are intercepted during this seed step, so no seeded
update runs. The resulting job is explicitly marked failed/recovery_required as
synthetic setup. No historical ID or missing phase-success evidence is supplied,
and no incident cause or incident reproduction is claimed.

The exact compatible built wheels then replace the old pair in that same
host-tool venv. To exercise real pip provenance and the production GitHub HTTPS
origin contract, the fixture temporarily serves those exact bytes through a TLS
guest-loopback wheel mirror at 127.0.0.2:443 for `github.com`. It uses a generated
fixture certificate and genuine pip download/installation; it never edits
`direct_url.json`. This synthetic transport proves no public release or issuer
acceptance. The owned listener and exact hosts preimage are cleaned up within
the existing isolated VM; no external GitHub endpoint is changed.

With the old proxy still serving, production `InstalledOwner.capabilities`
must reject its legacy capabilities. The actual fixed host CLI then runs
`release reconcile-service --service ipmi-monitor --job <synthetic-native-id>`.
The receipt must be the only new updater-store entry; every previous file's
bytes/inode, failed job, active pointer, selection and public configuration must
remain unchanged. Receipt job/active hashes bind actual raw bytes. Discarding
the first CLI reply and repeating must retain identical receipt bytes.

Only afterward does the actual host CLI perform scoped proxy selection with
`--record-cli`. Normal `StandardAdoption` must replace the proxy and add the
existing root0600 broker socket while customer writes remain disabled. The
failed native history survives. The subsequent real signed-fixture scoped
update must bind `recovery_predecessor` to that old job and receipt; the retained
one-helper mapping, dropped HTTPS response, broker main kill/restart and real
failed-health rollback assertions still run. The real worker is not replaced by
the seed adapter. A passing run accepts only these observed fixture boundaries.

Local checks, which do not execute the guest flow:

```sh
python -m unittest discover -s .github/tests -p test_fleet_native_route.py -v
python -m py_compile scripts/verify_fleet_release_native.py
python scripts/verify_fleet_release_native.py --check-inputs-only \
  --proxy-sha ROOT_MUST_SET_REVIEWED_PROXY_SHA  # must fail closed
```

The workflow contains the exact wheel build and guest execution commands. Only
the reviewed ordinary PR route may run them; there is no manual dispatch or
provisioning fallback. The artifact contains sanitized identities and outcomes,
not private signing keys, session cookies, auth stores, raw container environments
or backup snapshots. The coordinator must retain an independent VM destruction
receipt for every outcome; script cleanup does not certify external destruction.

A passing run establishes only the observed native fixture scenarios. Production
issuer authority, real current admissions and live GitHub discovery, a genuine
future-version migration, unobserved crash windows, desktop/mobile browser
acceptance and the remaining release gates stay held. The synthetic producer key
and the same-source A/B images do not establish those claims.


The broker child also installs a test-only observation wrapper around the original
`release_broker.private_write`. It calls the original once with unchanged arguments,
returns its exact result, and observes only after a successful handled save. The
original exception and functional failure remain unchanged. Product source and
wheel bytes remain pinned, but the test process binding, timing and bounded
diagnostic I/O change: this is the original behavior under an observation wrapper,
not an unmodified runtime or a discovery-only adapter.

If the existing 90-second mapping wait fails, one passive
`owner-mapping-observation` event is attempted before normal cleanup and the same
failure is raised. It projects only closed operation/mapping states, checked store
identity/equality, and an optional exact-UUID correlated three-field failure
coordinate. It never calls status to observe progression. The private retained-inode
4096-byte slot is reset at fixture lifecycle setup; stale, partial, contended or
unavailable observations remain unknown. Captures are not guaranteed.

The fixed inspect command captures at most 1 MiB plus one overflow byte, with
four seconds for capture and the fifth second reserved for the exact child's
kill/reap, including spawn elapsed time. Regular files have explicit bounded reads;
regular-file I/O and kernel process operations have no unconditional real-time
guarantee. Raw inspect data, paths, record contents and exception strings are never
retained. A coordinate can identify only a recognized caller boundary; the actual
cause of the previous failure remains unproven. This local source work granted no
native attempt. The preceding observation's two-of-three-spent, one-held account
is historical: the original initial allowance of one and original additional
allowance of three are now fully spent. The separate current continuation cap is
described below; historical counters are unchanged.

### Scoped selection output observation

The existing bootstrap `release select` command opts into a bounded diagnostic.
If that same checked subprocess fails, `bootstrap_failure.scoped_select_diagnostic`
contains one of fifteen fixed output categories or `unknown`. Classification
requires an exact built-in integer exit code of 1, empty built-in bytes stdout,
and built-in bytes stderr of at most 512 bytes matching one complete reviewed
message, including its prefix and newline. Other output, types, line endings,
extra text and private stdout remain `unknown`. No captured output is attached to
the diagnostic slots or emitted metadata; existing subprocess capture behavior is
unchanged. Other command calls default to `unknown`; success,
unchecked calls, timeout and spawn outcomes retain their previous behavior.

The category describes observed child output. It does not identify an executed
product guard or establish a root cause. For example, `cli-provenance-rejected`
combines version and provenance checks, `recovery-required` occurs at several
sites, and the public-reference categories have repeated raise sites. Capability
refusal also combines checks. Unknown messages, import failures, tracebacks and
transitive failures may remain `unknown`; useful classification is not guaranteed.
Existing `source_line` and `guard_line` keep their caller-coordinate meanings;
this observation adds no child guard coordinate.

Projection requires the original command exception and run code frame within a
trusted scoped-select bootstrap step. The immutable slot exports only a canonical
category. Collector errors fall back to `unknown` and preserve the original
command failure and cleanup. No retry, extra subprocess, owner/status request or
product-state change is added.

The 3 November observation preparation authorizes zero native or publication
actions. Run 41573017934 attempt 1 failed at scoped selection with exit 1; its
cause remains undetermined and this change cannot diagnose that terminated run
retroactively. The current continuation cap is three, with one spent and two
unused slots held by the unknown-cause stop condition. Historical counters stay
unchanged. Observation preparation is not a diagnosed compatibility repair, and
local source tests do not establish native, release, security or client acceptance.

### Fixture-only inner recovery observation

The scoped selector now runs its original installed console script once inside
a fixture wrapper in the same host Python environment. Original arguments,
environment, stdin, captured stdout/stderr, exit status and timeout are retained.
Only that subprocess inherits one anonymous nonblocking diagnostic pipe. The
wrapper calls the original `service_recovery_dependency` once per normal call,
returns its exact result, rethrows the same exception and restores the original
module binding in `finally`. Production packages and recovery algorithms remain
unchanged; the test-process binding and bounded diagnostic I/O change.

Before a dependency exception reaches its original caller, the observer removes
only its own exact invocation frame and bare-rethrows the same exception. At the
outermost fixture dispatch, a captured contiguous prefix identifies that exact
dispatch, child and runpy invocation. Only those frame nodes are removed; original
application nodes and application-owned runpy invocations remain intact. The
interpreter renders the same exception with its current hook. The fixture never
replaces or calls `sys.excepthook`, formats exceptions itself, filters output text
or substitutes an exit code. Cause, context and suppression remain unchanged.

`bootstrap_failure.scoped_select_inner_diagnostic` contains exactly `guards`,
`condition` and `require_capability`. A guard has only a fixed `source` ID,
fixed `guard` ID and numeric `line`. The two facts are strict booleans or
`unknown`; they come only from the recognized `require(condition)` and
`service_recovery_dependency(..., require_capability=...)` frames. No messages,
exception arguments, traceback text, paths, hashes, record data or broad locals
are exported. The existing fifteen output categories keep their meanings.

Qualification checks both exact supplied wheel bytes and the frozen module
bytes at the installed distribution location, then compares full compiled function
structure before retaining loaded code-object identities. Traversal is
limited to eight exception contexts and 32 frames per exception. Foreign raise
sites or types, source/code drift, cycles, overflow, ambiguous/recovered failures
and observer faults stay unknown. A candidate is usable only when the failing
console exception retains that one dependency failure in its context chain.
Success and other output categories do not export an inner failure.

The child attempts one private record of at most 8192 bytes. A partial write,
duplicate fields, extra record, oversized/invalid input or collection failure
cannot replace the original command outcome. Both pipe endpoints are closed on
all terminal paths. No additional Engine, Docker, SQL, HTTP or CLI probe is
made. A coordinate identifies an observed trusted guard; it does not by itself
establish a unique root cause or justify changing a denial/integrity check.

Local output verification compares an actual executable directly with its wrapped
execution for uncaught RuntimeError, missing import, implicit context, explicit
cause, suppressed context and an application-owned runpy call. Byte comparisons
and interpreter versions are retained separately. A source scan of the frozen
product trees and source-qualified imports in the retained offline environment
show no product-installed custom exception hook. A real target hook or terminal
state dependency requiring broader handling stops this repair for re-planning;
the fixture is not a general interpreter or custom-hook emulator.

The separate local qualified-dependency proof uses a generated console shim and
manually assembled/extracted source-derived fixture wheels. It substitutes
`FleetConfig.load`, `select_release_components` dispatch and `UpdateEngine`.
It exercises real `CLI.main`, `_scoped_idle` and the protected dependency/private
validators, but bypasses full selector construction, lifecycle/updater locks and
earlier selector preflights. It does not attest released/native wheel artifacts
or the complete consumer path. Earlier frozen records are retained with this
successor clarification; local evidence does not establish the native cause.

The earlier three-slot accounts above are historical. The explicit owner-approved
4 November continuation has a total automatic cap of five, with two spent.
Ordinal three is one reviewed inner diagnostic; ordinals four and five require
concretely diagnosed, tested and reviewed repairs. Unknown after the diagnostic
stops progression. Source verification grants no native/publication action,
reservation, release acceptance or LTX update authority by itself.
