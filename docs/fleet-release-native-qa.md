<!-- TRACEWEAVER: file-role=native-qa-documentation; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001 -->
# Fleet release native verification

The `Fleet release native verification` pull request workflow runs one sequential
integration flow in the existing `ci-build-public-ephemeral` Linux VM route for
repository `1133295682`. It requires a same-repository PR into `dev`, a read-only
job token, the exact DC PR head, and an explicitly reviewed, published proxy commit.
The proxy input is the reviewed published commit
`5db15086c26095179f2af56bfa434c85426a6699`, with frozen runtime hashes from the
accepted source manifest. The source guard rejects an unresolved placeholder
before the proxy checkout or guest changes.

The four public image inputs in `scripts/verify_fleet_release_native.py` are
immutable digests. Registry and Nginx use pinned official Linux amd64 manifests;
IPMI uses the previously approved old and new public releases. The retained
primary registry metadata readback accompanies the implementation evidence.
No registry login or publishing credential is needed.

Inside that individual fresh guest, the workflow builds and installs both wheels,
checks installed package bytes against the frozen product hashes, and builds two
proxy images from the same reviewed application source with different metadata.
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

For both a named auth volume and a bind-mounted auth directory, the flow checks:

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

The bind case interrupts a real adoption
after the owner has retained its plan, restarts the broker and records the
observed terminal or visibly held recovery state. Timing is observed rather than
claimed to hit an exact instruction boundary. No fake Engine substitutes or
forced successful operation states are used.

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
