# Charlotte credential operations runbook

Reviewed against deployed scripts and verification receipts on **2026-09-20**.
Applies to AmericanColo / CharlotteColo (`americancolo.com`), managed by
BBmaint: `root@88.0.33.141`.

## Authority and scope

| Information | Authority | Production use |
|---|---|---|
| Server membership and BMC mapping | DC Overview | Prometheus discovery and IPMI reconciliation |
| BMC credentials | 1Password **Charlotte Colo - Device Access**, `runpodcccNN / IPMI` items | Protected BMC JSON file |
| Fleet SSH key | 1Password **DC Overview Fleet SSH Key** | Protected key file and IPMI's required key database entry |
| Per-host SSH connection details | Existing `… / SSH` vault records | `root`, port 22, shared key reference |
| Device profiles | NetBox | Profile/inventory information, not a separate password authority |

Baseline: **11 servers** (BBmaint plus CCC90–99), **10 physical BMCs**, and
**37 scrape endpoints** (33 server exporters plus four infrastructure endpoints).
BBmaint is a VM. Endpoint count is not server count.

**Vault refresh is manual/on-demand.** The applications use runtime copies and do not
fetch secrets directly from 1Password. DC Server Management credential editing is read-only in vault mode. Legacy IPMI
credential-editing paths remain: a database password override can supersede the
file until the next sync.
Maintain credentials in 1Password; do not create independent monitoring-UI passwords.

## Installations without a vault

DC Overview can act as the local credential authority without NetBox or 1Password.
Fleet setup provisions the shared internal service secret and configures both
applications. Set `FLEET_CREDENTIAL_AUTHORITY=local` consistently for an explicitly
local deployment. In Server Management, save the server's tested SSH and BMC
credentials. Changes are encrypted in transit through the durable inventory outbox;
failed delivery remains pending and retries automatically. Success means the IPMI
receiver acknowledged the exact credential revision, not that a live login test ran.
See [configuration, clear semantics and upgrade order](inventory-sync.md).

Keep Charlotte in **vault** mode. Its configured authority is not conditional on
vault availability. Local synchronization does not poll 1Password, refresh NetBox,
rotate device passwords or install public keys on the servers.

## Prerequisites

The operator scripts are deployment-specific local tooling, not commands shipped
in application releases. On the current Mac they require:

- Checkout `/Users/hanneszietsman/CrypotAI/dc-overview`.
- `sync_vault_credentials.py` and `apply_vault_runtime_remote.py` under
  `.orchestra/unified-inventory-20260920/artifacts/rollout-scripts/`.
- That task's `artifacts/credential-audit.json`: the fixed mapping of ten BMC item
  IDs. New vault items are not discovered automatically.
- Helper `/Users/hanneszietsman/CrypotAI/charlottecolo.com/scripts/charlotte_op.py`,
  1Password CLI, Python with `cryptography`, and the existing Keychain service
  `1password:charlotte-colo-netbox-bootstrap`.
- Management SSH access to BBmaint with `~/.ssh/ubuntu_key`. This operator key is
  distinct from the production fleet key being refreshed.

The helper validates the Charlotte account and vault. Its service-account token
stays on the Mac; resolved credentials travel through SSH stdin. Never print
credentials, put them in command arguments, enable shell tracing around secrets,
or save secret-bearing files in the repository.

The fleet key is pinned to item `3kmiqmndbkeocenkl44pjpo6cm` and fingerprint:

```text
SHA256:N3KytGYPaDum1fSEACaLJ8PH0Mlxc+WOLtI6zJJwHxQ
```

Before apply, confirm the expected fleet and no concurrent credential maintenance.
BBmaint must have both `fleet_key` and `fleet_key.pub`, the existing BMC cache and
IPMI database, and `/opt/cryptolabs-fleet-rollout/20260920-bugfix`.
Backup space must exceed the greater of 10 MiB or twice the database file size.

## Routine refresh

1. Confirm that vault entries contain credentials intended for the devices. For
   an empty record, test the existing device credential before saving it; preserve
   working credentials rather than rotating unnecessarily.
2. Run the dry run from the operator checkout:

   ```sh
   cd /Users/hanneszietsman/CrypotAI/dc-overview
   credential_tools=.orchestra/unified-inventory-20260920/artifacts/rollout-scripts
   python3 "$credential_tools/sync_vault_credentials.py"
   ```

   Require `dry_run: true`, ten verified BMC credentials, and the expected key
   fingerprint. This tests read-only IPMI and Redfish authentication. It does
   **not** test every SSH login, backup capacity, or complete live database state.
3. Apply:

   ```sh
   python3 "$credential_tools/sync_vault_credentials.py" --apply
   ```

   Require zero exit status and `applied: true`. The command fetches and tests
   vault values again, checks live state, creates protected backups, then updates
   the caches. SSH files are replaced atomically; the directly mounted BMC file
   is updated **in place**, retaining its inode. Active BMC database passwords are
   cleared, IPMI SSH key ID 1 is refreshed, and all ten active SSH configurations
   reference it. A metadata-only source manifest is written. No restart is required.
4. Perform every verification below. An apply receipt alone is not a health check.

## Verification and evidence

From the same shell:

```sh
python3 "$credential_tools/audit_credentials.py"
ssh -o BatchMode=yes -o ConnectTimeout=10 -i ~/.ssh/ubuntu_key \
  root@88.0.33.141 'docker exec -i cryptolabs-proxy python3 -' \
  < "$credential_tools/audit_ssh.py"
```

Success requires:

- Ten BMCs authenticate over IPMI and Redfish, match their vault entries, and
  report `credential_source: vault_runtime_file`.
- Eleven DC SSH tests return `connected: true` with key authentication.
- All ten active IPMI SSH configurations reference key ID 1, with no password or
  pasted-key overrides; active BMC database username/password overrides are empty.
- Eleven DC servers and zero pending inventory reconciliation messages.
- The expected 37 [Prometheus endpoints](https://americancolo.com/prometheus/targets)
  are healthy, and BMC sensor timestamps are fresh after the roughly five-minute
  collection cycle. Exporter health alone does not prove BMC authentication.

Sync writes `artifacts/vault-source-of-truth.json`; audit overwrites
`artifacts/credential-audit.json`. Keep dated, sanitized copies of receipts and SSH
results, plus the matching backup-directory name. Record failed checks. Never
attach vault responses, private keys, or credential backups to reports.

## Passwords, keys, inventory and releases

**BMC password changes:** retain independent OS SSH access, change the device
credential through an authorized maintenance path, test it, then update its
existing vault record and sync. Editing 1Password does not change the BMC password.
If authentication fails, recover that device before syncing; do not try shared
passwords across the fleet.

**SSH rotation:** the sync is not a rotation tool. Retain the old key and recovery
access while installing and testing the candidate public key on every intended
host. Then update the vault and review the pinned fingerprint and migration
procedure. Both scripts validate the current key identity: changing only the
wrapper fingerprint is insufficient. Remove old authorized keys only after
verification. Compare public-key identity, not serialized private-key text.

**Add/remove servers:** use DC Overview with an explicit actual BMC mapping, and
maintain the corresponding vault records. Update and review the fixed item mapping
and ten-BMC/eleven-host guards before syncing a changed fleet. Server removal does
not automatically delete vault records or revoke device access. Preserve retired
monitoring history. See [inventory reconciliation](inventory-sync.md).

**Application releases:** credential refresh does not build an image or change a
version. Application changes follow `dev` → versioned release on `main` → published
images → production Fleet Update. Image updates do not automatically refresh vault
credentials; check mounts and credential health after an application update.

## Failures and rollback

| Failure | Action |
|---|---|
| Vault unavailable or identity check fails | Stop before apply; keep working runtime copies and repair the existing Keychain/vault access. |
| BMC authentication fails | Check the exact device, username/case and vault item. Do not bypass the test. |
| Key identity or inventory differs | Review a rotation/inventory migration; do not weaken guards to force a refresh. |
| Missing `.pub` file | Derive it from the existing private key on BBmaint and verify the pinned fingerprint; do not generate a replacement key. |
| Backup or database preflight fails | Resolve the condition before retrying. Credential updates should not have started. |
| Timeout or lost connection | Outcome is uncertain. Inspect manifest, database references, backups and live authentication before retrying. |

Caught errors inside apply trigger a database rollback and an **attempt** to
restore files. This does not guarantee recovery after process termination or a
committed change. No automated post-commit rollback command has been validated.

For manual recovery, keep management SSH access open and stop other credential
writes. Select the matching protected `vault-runtime-<timestamp>-<pid>` backup and
preserve the current state first. Restore SSH files atomically, the BMC JSON
**in place**, and the source manifest consistently. If database recovery is needed,
restore only affected server configurations, key row and default-key setting in a
reviewed SQLite transaction, accounting for rows created by the operation. Do not
copy the whole backup over a live SQLite database or discard newer monitoring
history. Repeat all verification checks after recovery.

## Runtime locations on BBmaint

| Location | Purpose |
|---|---|
| `/etc/dc-overview/ssh_keys/fleet_key` and `.pub` | Vault-derived key cache; directory-mounted into both services |
| `/etc/dc-overview/secrets/ipmi-bmc-credentials.json` | BMC cache; direct file bind mount |
| `/etc/dc-overview/secrets/credential-sources.json` | Vault IDs, paths and refresh timestamp; no secrets |
| `/var/lib/docker/volumes/ipmi-monitor-data/_data/ipmi_events.db` | IPMI SSH-key cache and server references |
| `/opt/cryptolabs-fleet-rollout/20260920-bugfix/vault-runtime-*` | Root-only files and online SQLite backups |

The internal `dc-ipmi-inventory` service secret is separate and is not rotated by
this workflow. Automatic vault refresh and portable operator tooling remain outside
the implemented workflow. Local credential propagation is a separate authority mode;
DC enforces read-only credential editing while Charlotte remains vault managed.
