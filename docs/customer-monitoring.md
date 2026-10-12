# Customer monitoring preservation

The standard installer owns its generated Prometheus job names and the `dc-managed`
HTTP inventory discovery job. Upgrades preserve other scrape jobs, global settings,
alertmanager configuration, custom rules and existing Grafana dashboards. Removing a
host updates discovery; its old job name is not evidence of product ownership.

Declare additions and exact retired job names in `fleet-config.yaml`:

```yaml
prometheus:
  customer_config_dir: /srv/customer-monitoring
  extra_scrape_configs:
    - job_name: customer-storage
      static_configs:
        - targets: ['storage.example.invalid:9100']
      authorization:
        credentials_file: /etc/prometheus/customer/storage-token
  rule_files:
    - /etc/prometheus/customer/storage-alerts.yml
  legacy_managed_jobs: ['previously-confirmed-product-worker']
grafana:
  customer_dashboard_dir: /srv/customer-dashboards
  prometheus_datasource_uid: customer-prometheus
  overwrite_product_dashboards: false
```

Customer directories must already exist at absolute paths without symlinks. The
Prometheus customer directory mounts read-only at `/etc/prometheus/customer`.
Credential, TLS and file-discovery references must stay in that namespace; credentials
must use files, including custom HTTP headers. Inline passwords, bearer tokens,
OAuth secrets, header values and credentials embedded in URLs fail preflight. Older
external file references require exact, explicit adoption by the installer; adoption
preserves references and consumer custody. The private adoption plan snapshots
effective referenced bytes for drift checks; no credential contents are published
or copied into the public monitoring subtree.

Duplicate job names, reserved product job names and known duplicate static endpoint
scrapes fail before writes. Unknown jobs remain intact. Relabeling and dynamic
third-party discovery can change addresses; their endpoint equivalence requires
operator review. Declare `legacy_managed_jobs` only after proving the exact prior
product owners. That declaration retires those jobs; it is not a wildcard or hostname
heuristic. Customer extra jobs can be reapplied unchanged, but conflicting existing
jobs require explicit adoption.

The product Prometheus configuration resides in the dedicated
`<config_dir>/prometheus` directory mounted at `/etc/prometheus`. Directory mounting
is required for atomic replacement: an individual-file bind mount can keep the old
inode visible after replacement. Preserve the original legacy configuration during
migration. DC uses `PROMETHEUS_CONFIG_PATH`, otherwise it prefers
`/etc/dc-overview/prometheus/prometheus.yml` and falls back to the legacy path.
The DC writer needs this product directory mounted writable; the customer directory
stays read-only. No Docker socket is required for web validation.

A host installer validates a candidate with `promtool` from the selected Prometheus
artifact before atomic replacement. The web writer uses synchronous server reload
validation and compares the effective loaded configuration with the declared
candidate. Docker/systemd signal delivery alone is not success: fallback reloads
require a fresh successful runtime reload timestamp. Reload failure restores the
previous exact bytes, mode and owner, then attempts a verified recovery reload.
Server-added defaults are accepted only when every declared value and list
member still matches. Before accepting reload success or restoring a failed
candidate, the writer checks that the file still contains its installed bytes.
A noncooperating customer edit during reload or recovery is retained and the
operation reports a conflict requiring forward reconciliation; it never claims
success or overwrites that edit. Recovery checks the restored file's mapping.
Unverified recovery remains an error. File discovery documents are replaced
atomically and retain their existing permissions and ownership.

Temporary promtool validation mounts contain public config/rules with directory
mode 0755 and file mode 0644 so the selected image's non-root UID can read them.
New public Prometheus config and recording-rule files use 0644. A newly created
product directory uses 0755 with UID/GID 1000, matching DC's mounted atomic writer;
the public files also use UID/GID 1000. Prometheus's non-root image can read them.
Host-created coordination locks inherit the configuration's owner and group.
Existing product directories and files must already provide this writer custody
and public read/traversal access. Preflight refuses incompatible ownership, modes
or symlinks before controller replacement; it never changes an existing customer's
ownership or permissions. Public files require GID 1000 so an unprivileged DC
writer can retain their group across atomic replacement. Existing supported file
modes and owners are retained. Customer credential files stay in the read-only customer namespace
under their declared custody; the installer does not broaden their permissions.

Effective-config verification accepts equivalent Prometheus durations at explicit
global, scrape and supported HTTP/file/DNS discovery duration fields, such as
`300s` and `5m`. It retains exact comparisons for labels, targets, job names, URLs
and filenames. The duration parser follows the [Prometheus configuration grammar](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)
and [official parser](https://github.com/prometheus/common/blob/main/model/time.go).

Grafana uses a declared Prometheus datasource UID, an existing unique default
Prometheus datasource, or the only existing Prometheus datasource. Multiple possible
datasources require an explicit UID. Existing dashboard UIDs are skipped by default,
preserving edits and datasource mappings. Explicit `overwrite_product_dashboards`
applies only to UIDs in the exact packaged product dashboards. Customer dashboard
JSON must have unique stable UIDs and cannot claim a packaged product UID. Customer
imports keep their datasource references. Product placeholders use the selected
stable Prometheus UID; custom product mappings remain intact. Custom alert resources,
receivers and datasource provisioning are outside the dashboard import helper.

The shared helpers in `dc_overview.monitoring` prepare all merges and imports before
mutation. `apply_prometheus_config` requires validation and reload callbacks that
return exactly `True`; callers must check the result. Callers that merge a previously
read configuration pass its exact bytes as `expected_previous_bytes` (or `None` for
a missing file). A changed source holds replacement for a new merge; an edit made
during validation also remains intact. The real Linux install/upgrade,
selected-artifact validation, mounted credentials and Grafana acceptance remain
separate deployment checks.

## Preserve an existing controller topology

`setup` is a fresh-controller operation. It refuses an existing DC, Prometheus,
Grafana or proxy container before loading configuration, selecting a release,
installing prerequisites or rendering replacement resources. A failed, denied or
partial Docker inspection cannot establish absence. Existing customers use the
host `configuration` commands after installing the matching public DC and proxy
packages. The running proxy must also advertise the marker-aware controller guard;
installing a new host package alone does not repair an older serving updater.

The first adoption contract supports the existing `/etc/prometheus/prometheus.yml`
**file bind**, exact separately mounted rule/discovery/credential references, and
an already-adopted product directory. Existing different directory mounts, glob
references, inherited `VolumesFrom`, automatic container removal, unsupported
runtime fields, SELinux bind relabel options and executable source overrides hold
with a named unsupported condition. These shapes require an explicit supported
mapping or upstream repair; they are never silently converted. Runtime differences
that Docker generates, such as endpoint IDs, are excluded from create declarations.
Exact data/auth/TSDB volume names, anonymous volume IDs, customer binds, static
network settings, ports, UID, commands, capabilities, resources and customer labels
come from inspection. Only DC and Prometheus may change. Grafana, its dashboards,
datasource/provisioning identities, the proxy/auth store and VPM remain untouched.

DC and Prometheus must already be running and unpaused. Paused dependencies hold;
adoption never starts a stopped service to manufacture a readiness result. The
public configuration schema supports explicit HTTP/TLS/authentication file
references, static/file/HTTP/DNS discovery and known public scrape fields. Inline
credentials, cloud discovery/signing, proxy-connect headers, credential-bearing
URLs, arbitrary header values and unknown nested contexts hold before staging.
Use the named unsupported diagnostic to obtain an upstream supported mapping.

Write a public declaration, using customer paths and exact inventory-owned job
names. `managed_jobs` permits the inventory writer to retire only those named jobs;
do not put unrelated product/customer jobs in that list. Adoption itself copies the
effective configuration unchanged and never generates a baseline over it.

```json
{
  "schema_version": 1,
  "product_directory": "/srv/dc-monitoring",
  "dc_destination": "/var/lib/dc-monitoring",
  "managed_jobs": ["dc-managed", "confirmed-old-inventory-job"],
  "session_routes": ["proxy-sso"],
  "maintenance_owners": ["customer-compose-owner", "external-watchtower-owner"],
  "public_inputs": ["/etc/dc-overview/fleet-config.yaml", "/etc/dc-overview/releases/selection.json"]
}
```

`public_inputs` freezes the public configuration and actual selection/pin files
used by this customer. Include every participating public writer/authority input.
Never put credentials into this declaration. Inspected Env and referenced file
bytes remain in an explicit private plan and recovery record. Public command output
contains image/container identities and bounded conditions, without Env or
secret-derived fingerprints.

```sh
sudo install -d -m 0700 /root/controller-adoption
sudo dc-overview configuration inspect --declaration controller.json
sudo dc-overview configuration plan --declaration controller.json --output /root/controller-adoption/plan.json
```

Planning reads the installed Engine. When changed compiled caches need proof, it
creates only a disposable isolated compiler helper at the exact retained image ID;
customer service/runtime/configuration writes remain zero. Source changes,
executable binds or unknown source evidence block same-image adoption. Normal changed CPython caches are verified using that immutable image's
interpreter, independently of the host Python version. The helper has no customer
Env, mounts, network or Docker socket; its root is readonly, UID65534, capabilities
are dropped, privilege escalation disabled, memory128MiB/CPU0.25/PIDs16 bounded, and
its private result tmpfs is1MiB. Cache inputs are at most256KiB each/8MiB total,
image source files at most1MiB, with a30s deadline. Cache code is decoded only in
that isolated helper and never executed. Different compiler code or amended
source requires a reviewed compatible public release update first. An updater no-op on the same image does not normalize amended source.

Startup/import declarations are compared with the pinned image defaults, including
root entrypoint scripts and startup environment overrides. Unverified shell or
mutable-data import locations hold. Compiler proof uses helper argv bounded to512KiB
in total, including fixed interpreter/script/output arguments and terminating NULs,
with individual arguments at most48KiB. Directory-only metadata and every cache
batch share this bound; oversized metadata holds before any helper creation.
It does not depend on Linux accepting
one oversized argument. Changed cache-parent mode/UID/GID must match bounded trusted
image metadata. Archive metadata is streamed before reading contents; malformed,
linked or unsupported extended metadata holds.

Give `/srv` (or another selected parent) independently traversable public custody.
The new product directory alone is created with UID/GID1000 and mode0755; its public
configuration/ownership files use0644, and its lock uses0600. An existing directory
must already have compatible custody and matching bytes. No parent or customer
mount is chmod'ed or chown'ed. In particular, `/etc/dc-overview` may stay0700. DC uses
its existing `PROMETHEUS_CONFIG_PATH` plus the nonsecret schema1
`PROMETHEUS_OWNERSHIP_PATH` reader; Prometheus sees the same host directory readonly
at `/etc/prometheus`. Customer references retain their original mounts and custody.
The ownership reader carries the exact inventory job names and file references,
so sanctioned monitoring updates do not need to expose private fleet configuration.
Creation modes are explicit even under a restrictive host umask. Reference files
retain exact bytes, mode, UID/GID and parent-directory custody; declared public
inputs retain the corresponding host custody.

Before applying, exclude the declared external lifecycle owners for the affected
services, retain owner-controlled disaster recovery material and its restore drill,
and prove the supported same-image persistence and declared session routes in the
maintenance rehearsal. Record those positive gates in a public proof with the
`operation_id` emitted by `plan`:

```json
{
  "schema_version": 1,
  "operation_id": "operation-id-from-plan",
  "owners_excluded": ["customer-compose-owner", "external-watchtower-owner"],
  "backup_restore_drill": true,
  "same_image_state_compatible": true,
  "session_routes_verified": ["proxy-sso"]
}
```

```sh
sudo dc-overview configuration adopt --plan /root/controller-adoption/plan.json --maintenance-proof maintenance.json
sudo dc-overview configuration recover
```

These proof fields record the operator's exercised checks; asserting `true` does
not perform a backup, prove a browser session or establish Linux acceptance. A local
cookie route requires an existing nonempty `SECRET_KEY` retained verbatim. Missing
DC `SECRET_KEY` alone does not block proxy SSO; its existing proxy session and roles
require their own authenticated continuity test. No keys or accounts are generated.

Apply takes the actual lifecycle lock, then the proxy's actual shared-auth dispatch
and operation exclusion, then the affected monitoring lock inodes, with bounded
acquisition. It stages and runs the exact retained-image promtool before an outage,
reinspects all frozen inputs, stops DC, and replaces only required topology roles.
Prometheus starts first on the same TSDB, then DC on the same data/auth mounts.
The actual predecessors remain retained and stopped. A health-checked transition
also verifies expected runtime and Prometheus's process-loaded configuration via
its existing published9090/tcp port. Shapes without one accessible published port
cannot satisfy this initial functional probe.

On failure, all candidates require positive stopped proofs before originals can
restart. Compensation restores runtime/config mappings and retains evolving
compatible data and samples. It does not rewind databases/outbox/TSDB, undo delivered
work, stop Grafana/proxy/VPM, restore shared auth or claim a cross-service transaction.
Unknown stop/restore or runtime drift leaves `forward-repair-required` and keeps
recovery exclusion. The private journal lives at
`<config_dir>/controller-recovery/operation.json` with0700/0600 custody. The durable
proxy marker survives host/helper failure; guard checks refresh its300s lease.
Every single step is bounded below that lease. A terminal receipt alone does not
release normal host lifecycle operations: explicit guard completion and durable
host publication must both finish. Recover the exact operation before retrying.

Recovery revalidates both terminal outcomes against current container identities,
runtime and intended running/paused state, readonly functional health, effective
monitoring configuration, reference/public bytes and custody, and stopped competing
writers. A saved terminal receipt alone cannot release exclusion. Any uncertainty
keeps the recovery hold and durable marker.

`already-adopted` is a pure topology no-op. Subsequent drift requires a new plan.
`adopted` verifies this bounded transition, not complete customer acceptance. Prove
Linux UID1000 traversal, atomic-replace inode visibility, ordinary monitoring
write/reload and continued scraping, retained historical samples, DC inventory and
outbox/roles, declared session continuity, unchanged Grafana queries/UIDs and the
next normal selected upgrade before accepting the deployment. Predecessor cleanup
and release/alias promotion remain separate operator work.
