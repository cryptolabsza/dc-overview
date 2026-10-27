# Fleet release native verification

The `Fleet release native verification` pull request workflow runs one sequential
integration flow in the existing `ci-build-public-ephemeral` Linux VM route for
repository `1133295682`. It requires a same-repository PR into `dev`, a read-only
job token, the exact DC PR head, and an explicitly reviewed, published proxy commit.
The proxy input is the reviewed published commit
`3b1ff8e4a71da0b0392c976c1fe8c5aa5bfbc002`, with frozen runtime hashes from the
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

For a failed `fixture` phase, the same event also retains `fixture_line` and
`fixture_error_kind`. The line is an integer from the innermost traceback frame
whose code object is the original `NativeQA.fixture.__code__`, captured when the
module loads and checked against that code object's line table. Filename or
function-name matches cannot supply it. Interpret the line only against the
exact DC source head retained by preflight; for a command helper failure it
identifies the fixture caller boundary. The error kind uses ordered type checks
into fixed literals: `assertion-error`, `file-not-found`, `permission-error`,
`os-error`, `runtime-error`, or `unknown`. Missing trusted frames, invalid lines
or diagnostic collection failure retain null/`unknown`; an unfamiliar exception
type at a valid fixture line retains that line with `unknown`. These fields
identify an observed boundary, not an established root cause. No exception
text, arbitrary type names, arguments, locals, private paths, raw traceback or
command output is retained. The original failure and cleanup still run; this
metadata adds no retry, probe or behavior repair. All remaining native and
release acceptance limits below continue to apply.

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
