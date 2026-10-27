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
guest hosts entry and Docker trust directory exist only in that VM. The fixture
accepts an existing root-owned, nonsymlink registry CA directory with no group or
other write access. It exclusively creates one uniquely named fixture `.crt`,
preserves all existing entries and directory ownership/mode, and removes only its
own certificate. It removes the directory only if it created it and it is empty;
it never replaces `ca.crt` or recursively deletes the baseline CA directory.
Early preflight failures still write sanitized failed evidence and skip fixture
cleanup over unowned paths. The run remains failed and external VM destruction
is still required.

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
