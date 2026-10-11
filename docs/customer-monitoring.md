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
preserves the reference and does not read or copy its credential contents.

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
