# Standard customer release selection

A suite release is a published, post-build manifest. It identifies already-built
images by repository digest and published worker binaries/archives and the host
CLI wheel by exact URL and SHA256. The manifest is published separately from the
DC image: building an image never requires knowing that image's final digest.
The installed CLI contains the parser and component allowlists, not a mutable
list of current release digests.

Use a trusted, normally published `suite-release.json`. Test manifests and
synthetic receipts are not customer installer inputs. The version of the running
CLI must match the manifest's `dc-overview-cli.release`, and its installed
`direct_url.json` must prove the manifest URL and SHA256. The CLI does not replace
itself. Install the approved wheel using the normal package manager first:

```sh
pipx install --force 'APPROVED_CLI_WHEEL_URL#sha256=APPROVED_CLI_WHEEL_SHA256'
```

Substitute the URL and SHA256 from the approved manifest. Installing a local
copy with a different provenance URL does not satisfy this prerequisite. The
compatible, normally published `cryptolabs-proxy` setup package must also be in
that CLI's Python environment. Its shipped `updates.get_capabilities()` must
expose selection contract 1 and the exact replacement policy
`host-adoption-required-v1`. With pipx, inject the verified published wheel into
the CLI environment and expose its host command:

```sh
pipx inject --include-apps dc-overview 'APPROVED_PROXY_WHEEL_URL#sha256=APPROVED_PROXY_WHEEL_SHA256'
```

The [pipx injection flag](https://pipx.pypa.io/stable/reference/cli.html#pipx-inject)
exposes the injected package's apps on PATH. Do not assume a package version is published merely
because a compatible source checkout exists. Setup and upgrade query an existing
proxy's live updater for both capabilities, even when the host package is new.
The existing proxy must also have the releases directory mounted read-only.

If the live updater lacks that policy, first install the compatible published
proxy package and migrate the proxy with its supported host configuration flow:

```sh
cryptolabs-proxy configuration plan --declaration customer-proxy.json
sudo cryptolabs-proxy configuration adopt --declaration customer-proxy.json --plan-id REVIEWED_PLAN_ID
```

Use the supported declaration and the identity returned by the reviewed plan.
Installing a new host wheel does not patch an old running updater or its helper.
Fleet refuses release preparation and submission until the live policy matches.
The compatible generic updater holds actual proxy replacements before any
bundled service mutation; exact no-op updates and pulls remain supported. Use
host configuration plan/adopt for proxy replacement, then rerun Fleet upgrade
for the other services.

## One-time bootstrap for an old, unselected proxy

An existing old proxy may lack the live updater policy that DC requires before
release import. Install the compatible **published** host CLI and proxy wheels
first, then provision the approved public release files as host root before
proxy plan/adopt. The host wheel alone does not repair the serving updater.
This is ordinary declarative file provisioning, not an updater API, private
lifecycle helper, or permission to patch capabilities or source labels.

Use this path only when the existing proxy is unselected: no selection ID/hash
in customer/public configuration, no `selection.json`, and no
`.lifecycle-publication.json` recovery journal in the actual release directory.
If any exists, stop and reconcile through its existing owner; never overwrite
policy, pins or recovery state. Coordinate a maintenance window with other
setup/import writers and updater jobs quiesced. Proxy adoption independently
checks its existing dispatch/operation locks and refuses occupied or queued
work before stopping the proxy.

The public DC setup/status/upgrade flow uses the canonical `/etc/dc-overview`.
For this procedure keep `customer.yaml`'s `config_dir` at `/etc/dc-overview` and
`release_selection.release_selection_dir` at `/etc/dc-overview/releases`.
Ordinary status/upgrade do not automatically discover alternate configuration
roots. The complete proxy declaration must use that same release directory.

1. Obtain the trusted, normally published `suite-release.json` and verify its
   publisher and artifact receipts. Compute its **actual byte hash**, without
   reformatting it:

   ```sh
   sha256sum suite-release.json
   ```

   A SHA256 match identifies bytes; it does not establish publisher trust.
   Test manifests, test wheel URLs/digests and source checkouts are not customer
   inputs. The selected proxy candidate must be the actual published image
   matching the installed compatible host proxy package, not a fabricated
   `direct_url.json`, label, version or capability assertion.

2. Author and review a complete `customer-selection.json`. Its only top-level
   fields are `schema_version`, `selection_id`, `manifest_sha256`, and
   `components`. Use schema 1, the reviewed manifest's `baseline_id` as the
   selection ID, and the exact lowercase 64-hex byte hash above. Every manifest
   component must appear **exactly once**, with no omissions or extra names.
   Each entry has boolean `enabled` and `origin`; only `customer-pin` also has
   `pin`. The example below assumes the manifest has exactly these twelve
   components and the customer enables only DC/Prometheus/Grafana plus the
   mandatory proxy and CLI. Replace the ID and zero hash and review every entry
   against the actual manifest and `customer.yaml`; do not copy these choices
   as site policy.

   ```json
   {
     "schema_version": 1,
     "selection_id": "REVIEWED_BASELINE_ID",
     "manifest_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
     "components": {
       "cryptolabs-proxy": {"origin": "baseline", "enabled": true},
       "dc-overview-cli": {"origin": "baseline", "enabled": true},
       "dc-overview": {"origin": "baseline", "enabled": true},
       "prometheus": {"origin": "baseline", "enabled": true},
       "grafana": {"origin": "baseline", "enabled": true},
       "ipmi-monitor": {"origin": "baseline", "enabled": false},
       "vastai-exporter": {"origin": "baseline", "enabled": false},
       "runpod-exporter": {"origin": "baseline", "enabled": false},
       "vast-price-manager": {"origin": "baseline", "enabled": false},
       "node-exporter": {"origin": "baseline", "enabled": false},
       "dc-exporter": {"origin": "baseline", "enabled": false},
       "dc-watchdog-agent": {"origin": "baseline", "enabled": false}
     }
   }
   ```

   Proxy and CLI must be enabled. DC requires Prometheus/Grafana; declared
   workers require node/DC exporters; an enabled installed Watchdog requires
   its agent. Align optional roles with the customer's actual component flags,
   worker list and Watchdog install choice. Preserve reviewed origins/pins.
   `baseline` follows the approved artifact; `customer-pin` is the exact OCI
   reference or bare worker/wheel SHA256 from that manifest, including disabled
   pinned entries. A conflicting pin holds. `unmanaged` cannot be enabled.
   JSON is bounded declarative data; commands, arbitrary owners, unknown fields
   and executable policy are unsupported.

3. From the directory containing those two reviewed files, provision root-owned
   directories 0755 and new public files 0644. These Linux/coreutils commands
   refuse an existing selection/journal, symlinks or incompatible existing
   directory custody, and never overwrite an existing policy. An already
   present immutable manifest is reused only when root-owned 0644 and byte
   identical. If a guard or copy fails, stop and inspect the retained files;
   do not delete existing state just to rerun the bootstrap.

   ```sh
   sudo sh -eu <<'SH'
   umask 022
   store=/etc/dc-overview/releases
   test ! -e "$store/selection.json"
   test ! -L "$store/selection.json"
   test ! -e "$store/.lifecycle-publication.json"
   test ! -L "$store/.lifecycle-publication.json"
   for directory in /etc/dc-overview "$store" "$store/manifests"; do
     if test -e "$directory" || test -L "$directory"; then
       test ! -L "$directory"
       test -d "$directory"
       test "$(stat -c '%u:%g:%a' "$directory")" = '0:0:755'
     else
       install -d -o 0 -g 0 -m 0755 "$directory"
     fi
   done
   manifest_sha=$(sha256sum suite-release.json | cut -d ' ' -f 1)
   manifest_file="$store/manifests/$manifest_sha.json"
   set -C
   if test -e "$manifest_file" || test -L "$manifest_file"; then
     test ! -L "$manifest_file"
     test -f "$manifest_file"
     test "$(stat -c '%u:%g:%a' "$manifest_file")" = '0:0:644'
     cmp -s suite-release.json "$manifest_file"
   else
     cat suite-release.json > "$manifest_file"
   fi
   test ! -e "$store/.lifecycle-publication.json"
   test ! -L "$store/.lifecycle-publication.json"
   cat customer-selection.json > "$store/selection.json"
   test "$(stat -c '%u:%g:%a' "$store/selection.json")" = '0:0:644'
   sha256sum "$manifest_file" "$store/selection.json"
   SH
   ```

4. Inventory the old proxy's routes, domain, TLS, mounts and account authority
   into its complete supported `customer-proxy.json` declaration. Set
   `release_selection_dir` to `/etc/dc-overview/releases`; preserve the actual
   services, forwarding and certificate choices. Run the shipped host command's
   read-only plan, review its identities and preservation proof, then adopt that
   exact plan. Any policy/runtime drift requires a fresh plan; do not bypass a
   hold or replace the candidate with fixture bytes.

   ```sh
   sudo cryptolabs-proxy configuration plan --declaration customer-proxy.json
   sudo cryptolabs-proxy configuration adopt --declaration customer-proxy.json --plan-id REVIEWED_PLAN_ID
   ```

5. After successful proxy adoption, run ordinary DC setup/upgrade with the
   approved manifest. DC revalidates the installed CLI's exact public wheel
   provenance, complete selection, enabled roles, worker privileges/platforms,
   TLS/configuration and the live updater capabilities before mutation, and
   commits the public selection reference through its existing lifecycle lock
   and compare-and-swap boundary. File provisioning and proxy adoption alone
   do not establish full-suite or operator acceptance.

   ```sh
   sudo dc-overview setup --config customer.yaml --release-manifest suite-release.json
   sudo dc-overview upgrade --release-manifest suite-release.json
   ```

## Setup, status, and upgrade

Before approved selected setup, install and verify Docker Engine and Compose
from the [official Docker installation instructions](https://docs.docker.com/engine/install/).
Read-only selected preflight uses Docker and the selected Prometheus validator
before the automatic prerequisite installer runs. A missing client or
unreachable daemon cannot prove proxy runtime absence and blocks selection.
Fresh setup without a selected release retains its automatic prerequisite path;
the published proxy setup package checks existing-container adoption before its
own side effects. Every host upgrade, including ordinary channel mode, requires
the live updater's exact replacement policy before submission.

Run these commands as the normal host CLI owner; setup/import requires root:

```sh
sudo dc-overview setup --config customer.yaml --release-manifest suite-release.json
sudo dc-overview status
sudo dc-overview upgrade --release-manifest suite-release.json
```

Initial setup requires declared worker SSH keys that already reach each enabled
worker. The baseline preflight reads each platform before any suite mutation;
it also runs a read-only probe through the installer's exact noninteractive
privilege runner, checks required tools/systemd and observes the service state.
An existing worker update requires its binary and unit; a Watchdog update uses
its existing worker token without account registration. The same prerequisites
are checked again before controller replacement and each worker mutation. The
installer does not grant sudo or bootstrap password access. Unsupported architectures or
missing published worker artifacts block. The selected DC Rust exporter owner
currently supports only its published linux/amd64 binary. No latest-release
fallback is used for selected worker delivery.

Setup and upgrade resolve the same vector that status reports. Status lists
desired identity/origin separately from observed runtime identity; worker
observations remain unknown until the owner probes them. Explicit `--dev`
conflicts with a stable selection. Ordinary channel-based commands remain
available when no approved selection has been configured.

After bootstrap, ordinary import stores exact manifest bytes in root-owned
`config_dir/releases/manifests/<SHA256>.json` and atomically writes
`config_dir/releases/selection.json`. Selection links to the exact manifest
byte hash; public configuration links to the selection ID and byte hash.
The ordinary host status/upgrade commands use canonical `/etc/dc-overview`;
keep the customer configuration and release directory at the canonical paths
above. Alternate declared directories are not automatically discovered by
those commands. Proxy setup mounts the release root at
`/etc/cryptolabs/releases:ro`. Repeat
setup reconciles the mount and permanently disables Watchtower ownership for
baseline services even when login settings are unchanged.

Lifecycle reference persistence snapshots the public file, checks for concurrent
changes, and updates release/VPM references without rewriting `.secrets.yaml`.
Credential references remain under the existing secret authority.
Selection storage and the public reference publish under one lifecycle lock and
compare-and-swap boundary. An interrupted publication retains a root-owned
recovery journal: an exact unfinished candidate with unchanged public bytes
restores the prior selection, and a fully published matching reference is
finalized. Unexpected customer edits hold reconciliation and retain evidence.

## Ownership policy

Manifest component entries declare `release`, `owner`, and platform `artifacts`.
Artifacts are `oci` with immutable `reference`, or `wheel`/`binary` with immutable
published `url` and `sha256`. The only approved owners are the existing proxy
updater, host CLI, DC VPM manager, and worker installers.

Selection entries declare `enabled` and `origin`:

- `baseline` follows the approved manifest's exact artifact.
- `customer-pin` requires an exact OCI reference or bare SHA256 for a wheel or
  binary/archive. A new baseline that conflicts with that pin blocks.
- `unmanaged` may be inventoried but cannot satisfy an enabled required role.

Intentional component disables are retained. Existing unlabelled immutable
images default to customer pins; explicitly declare a baseline policy to adopt
a different approved artifact. Missing or ambiguous existing image identity
requires an explicit policy. A fresh wizard's released VPM choice follows the
baseline; choosing a custom image records a customer pin.

Proxy updates remain delegated to its existing durable helper. Successful proxy
results alone do not complete a suite. Every enabled VPM, CLI, and worker owner
must return its own verified outcome. Unreachable workers remain failed/unknown;
failed updates retain previous installed observations. Node archive checksums
are verified before extraction, and the extracted executable hash is compared
with a separate installed disk probe. Agent release tags and internal telemetry
versions are distinct; the Watchdog owner verifies artifact hash, unit, and
health rather than declaring drift from different version scopes.

In selected mode, app automatic updates, manual exporter installs/updates and
Watchdog installs/reinstalls explicitly refuse the competing latest-artifact
path. Reinstall refuses before removing the old agent. Use the authoritative
host `dc-overview upgrade` for the retained selection or
`dc-overview upgrade --release-manifest suite-release.json` for a new approved
selection; use ordinary `dc-overview setup --config customer.yaml
--release-manifest suite-release.json` for a new worker. The app reads the mounted
public policy and fails closed when required selection metadata is unreadable
or unavailable. Read-only version checks and explicit service start/stop remain
available; existing auto-update preferences are preserved for unselected mode.

Selected Watchdog updates replace the checksum-proven binary while retaining
`agent.yaml`, the unit, worker token and active/enabled/masked state. Held agents
remain held. Running agents must expose successful health and the source-defined
`dc_watchdog_agent_up` metric with the binary's telemetry version before the
installer retires recovery backups. A metric mismatch restores the old binary
and prior state. The release tag is not substituted for the telemetry version.

## Existing VPM and monitoring resources

A legacy VPM `layout` is an explicit one-time adoption input. The manager verifies
its owner, data, credentials, and recovery proof. Successful adoption persists
canonical public references and retires that input. A failed public-file save
can be recovered through the manager's read-only `is_adopted(layout)` proof;
marker presence alone is insufficient. Later setup/upgrade uses standard
install/update with the preserved data and credential custody. Adoption does
not enable automation or replace the authenticated operator acceptance gate.

Prometheus supports `extra_scrape_configs`, `rule_files`,
`customer_config_dir`, and exact `legacy_managed_jobs`. Unknown customer jobs,
global settings, and rules are retained. Customer references must be under
`/etc/prometheus/customer` and are mounted read-only; inline credential values
are rejected. Only generated product jobs and explicitly declared legacy job
names may be replaced. The product config directory is mounted as a directory
so atomic replacement does not leave Prometheus reading an old inode. The
selected Prometheus tool validates candidate config/rules; reload must report
that the effective loaded config matches the candidate, with checked recovery
on failure.

Grafana supports `customer_dashboard_dir`, `prometheus_datasource_uid`, and
`overwrite_product_dashboards` (default false). Existing datasource UIDs and
mappings are reused. Existing edited/customer dashboard UIDs are preserved by
default. Customer JSON that collides with a packaged product UID blocks before
writes. Only dashboards packaged in the selected CLI wheel are product inputs;
there is no moving GitHub branch fallback in baseline mode.

A successful local test receipt is not deployment acceptance. Published
manifest facts, actual Linux ownership/mounts, exact installed packages,
convergence of every owner, and positive authenticated VPM acceptance must be
verified on the intended customer deployment before promotion.
