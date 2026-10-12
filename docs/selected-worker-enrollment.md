# Enroll a worker in a selected fleet

Run enrollment on the existing Linux controller through the canonical `/etc/dc-overview` configuration. `setup` remains a fresh-controller command. The selected `add-machine` path uses the exact stored manifest/selection, current component policies and customer pins. It never runs controller deployment or writes static Prometheus targets.

Prerequisites:

- Install the exact approved host CLI wheel with the manifest's URL and SHA256 provenance. The live proxy must advertise selection contract 1 and `proxy_replacement_policy=host-adoption-required-v1`.
- Resolve any controller recovery or interrupted selection publication before enrollment.
- Provision the worker's SSH key through the organization's secret store. Reference its existing host path in `ssh.key_path` or `--ssh-key`; enrollment does not generate or copy a private key. Add the independently verified worker identity to `/etc/dc-overview/known_hosts` through the normal SSH trust workflow. Unknown or changed host keys hold enrollment.
- Fleet also needs its own existing registered key or canonical default key and fingerprint-verified known_hosts file readable inside the DC container namespace. A host key path does not establish that container reference. Provision these through the ordinary Fleet SSH-key UI/API or the configured organization/vault mount before enrollment; use `--ssh-key-id` for an existing registered key. Enrollment tests the container's key-authenticated SSH reachability with exact worker/user/port readback before installing. A failed check retains the registered ID for retry and never copies a key.
- The existing worker account must have verified noninteractive root privilege through the supported bounded Bash runner, systemd and installer tools. Password arguments are not accepted in selected enrollment.
- Use the current Fleet administrator login and the configured HTTPS origin. The password prompt uses the current login, independent of any old installer password. Normal TLS verification stays enabled. For a private/self-signed deployment, supply the trusted certificate/CA file reference with `--ca-file`.

## Add an additional worker

With `dc-exporter` and `node-exporter` already enabled in the selected vector:

```sh
sudo dc-overview add-machine 192.0.2.81 --name gpu-worker-01 \
  --fleet-url https://fleet.example \
  --fleet-user operator \
  --ca-file /organization-secrets/fleet-ca.pem
```

SSH user and port inherit existing configuration. Supply `--ssh-user ubuntu --ssh-port 2222` for an explicit new worker override. If the inventory already has the matching key registered, `--ssh-key-id ID` selects that existing inventory reference; it does not upload or replace a key. Resolve differing existing SSH credentials through Fleet's ordinary SSH configuration owner before retrying.

Registration uses `POST /api/servers` and exact inventory/SSH readback. Duplicate names/addresses, BMC differences and credential conflicts hold. A lost successful response or a duplicate retry retains the original ID and durable inventory/outbox state. Current Fleet administrator authentication and API registration/container-key proof precede privileged worker preflight and installation. If remote preflight is unavailable or units are unknown, the authorized registered row remains for retry; no public worker entry, installer, or installed flag is written from that failed preflight. The CLI appends only the new worker's public references under the lifecycle lock and compare-and-swap; unrelated settings, unknown YAML fields and exact secret/release files are retained. It does not write installation intent as an installed observation.

Each component is inspected independently: positively absent unit and binary use install; positively existing components use update; exact selected bytes with verified unit/state use no-op. Node's installed binary is compared with the binary extracted from the checksum-verified selected archive. Unknown or inconsistent states hold before public worker persistence or installation; an already registered identity remains intact. Existing units, watchdog token/configuration and intentional inactive/disabled/masked state are preserved by the update/no-op path. Watchdog is included when selected and configured; a positively absent agent requires the existing subscription registration authority in the organization's configured secret reference.

## Prepare the first worker in a controller-only fleet

A controller-only selected vector intentionally disables worker artifacts. Explicitly prepare that role before enrollment, without adding a fictitious server or installing a worker through upgrade:

1. Edit the existing public `/etc/dc-overview/fleet-config.yaml`, preserving all other fields. Set `components.worker_exporters: true`. Set `release_selection.components.dc-exporter.enabled: true` and `release_selection.components.node-exporter.enabled: true`, preserving each component's existing `origin` and exact `pin` if present. The public setting declares intended worker roles; the selected policies still control exact approved artifacts. A policy alone cannot override intentionally disabled configured roles.
2. Run the ordinary selected transition against the reviewed manifest:

   ```sh
   sudo dc-overview upgrade --release-manifest /root/approved-suite/suite-release.json
   ```

   This validates the ordinary controller lifecycle and exact installed CLI. With no enrolled workers, worker-owner results explicitly report `not_applicable`; no worker is installed. A conflicting pin, missing artifact, disabled policy, incompatible proxy or recovery hold must be resolved through its normal owner. Enrollment never enables a policy after failure.
3. Run the `add-machine` command above. It registers the first real worker before installing its selected components. If Watchdog is also intended, explicitly enable `components.dc_watchdog`, `watchdog.install_agent` and the `dc-watchdog-agent` selected policy in step 1, and provision its existing subscription authority before step 3.

`worker_exporters` defaults to false. Existing configurations with actual worker entries continue to require their usual exporter roles, and ordinary upgrade continues to update those workers.

## Retry and repeat

On partial delivery, the command fails truthfully while retaining the registered server and any public reference already persisted. Correct the prerequisite and repeat the same command. Successful components can become verified no-ops; failed components resume their positive install/update state. No registered server or evolved outbox is deleted to undo a remote failure. Concurrent edits cause a hold, not a silent overwrite.

After verified delivery, the existing server-check API accepts `selected_enrollment=1` only for a Fleet administrator and with the CLI's exact `expected_identity` snapshot. Selected SSH configuration/test requests use the same administrator and identity contract; ordinary requests keep their previous authorization behavior. The public snapshot binds row ID, immutable inventory identity, name/address, SSH user/port, registered key ID and effective container key path. The CLI revalidates it before each privileged stage, before worker persistence and after delivery. Drift retains evolved inventory/outbox state and reports a partial hold; it never verifies a different worker from the same row ID. Selected completion holds the existing inventory mutation transaction across its probe and observation commit. No additional operation/lease framework is introduced.

An explicit registered key must resolve to that exact readable reference; selected transports pin even a default key reference for the probe and never replace it with another default on failure. The guard checks metadata/readability without reading or hashing private-key contents. Container checks, host installation and Watchdog use the same selected file-key policy: noninteractive public-key authentication, no agent/default/config-added identities or certificates, and no password fallback. If the key becomes unavailable, the operation holds. Selected SSH uses the declared address, user, port and verified known_hosts reference directly, with ambient SSH configuration disabled; provision direct reachability for both controller host and container. An ambient ProxyJump or Host alias does not provide selected enrollment routing. Ordinary SSH paths retain their existing configuration behavior.

The selected server-check API synchronously observes units/binaries and Watchdog configuration through its strict SSH owner, retains installed status for intentionally held services, and derives enabled status from active service and live endpoint observations. Exporter version discovery uses metrics when available; its SSH fallback carries the same selected server and pinned key/trust policy, including Docker image metadata. A missing or changed key during version discovery holds completion and retains prior database observations. A rejected version connection adds no version observation. It commits observations before refreshing discovery through the sanctioned monitoring writer. Unknown service observations preserve prior flags; a discovery failure retains committed observations and reports a retryable failure. Other query values are rejected, and ordinary checks retain their previous metrics-only behavior. A held service remains inactive. Inventory/SSH owners remain the ordinary Fleet UI/API; selected artifact changes remain ordinary `upgrade`. Repeating the same add-machine command verifies the same worker and does not append another entry or replace its unit/token.

Source fixtures cover parser, API identity, CAS and delivery ordering. Actual SSH trust, Linux systemd, health/scrape behavior, Watchdog subscription registration, published artifacts and controller/worker restart still require the ordinary disposable customer rehearsal; source tests alone do not establish that acceptance.
