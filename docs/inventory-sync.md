# DC to IPMI inventory reconciliation

For Charlotte credential authority, refresh, verification and rollback, see the
[credential operations runbook](credential-operations-runbook.md). Inventory
reconciliation includes credentials in local authority mode; vault refresh remains a separate operation.

DC sends one revisioned desired-state message to the fixed internal receiver
after committing its local server mutation and durable outbox entry. The sender
never discovers BMC addresses from an OS address, and existing DC rows remain
unconfigured until an operator explicitly supplies a BMC mapping.

Fleet setup provisions a shared synchronization secret when installing IPMI. For
manual deployments, mount the same read-only secret into both containers and configure:

```text
# both containers (local installations)
FLEET_CREDENTIAL_AUTHORITY=local

# dc-overview
IPMI_INVENTORY_URL=http://ipmi-monitor:5000
DC_IPMI_INVENTORY_SECRET_FILE=/run/secrets/dc-ipmi-inventory

# ipmi-monitor
IPMI_INVENTORY_SECRET_FILE=/run/secrets/dc-ipmi-inventory
```

In local mode, Server Management is the credential authority. Save the BMC username
and password before enrolling a new BMC, and manage its SSH connection in the same
credentials dialog. Credential changes enter the durable outbox and are retried
after outages or restarts. An encrypted, authenticated snapshot carries the effective
SSH key/password and BMC credentials. The receiver applies inventory and credentials
in one transaction; DC requires a signed acknowledgement of the exact credential
revision before displaying synchronization success.

Blank BMC password fields preserve the saved password. Use the explicit clear action
to remove it. SSH key inheritance still applies when a password is cleared. These
settings update the credentials monitoring uses; they do not change passwords or
`authorized_keys` on the physical device. Test a changed device credential before
saving it here. No NetBox or 1Password connection is required in local mode.

For vault-managed deployments set `FLEET_CREDENTIAL_AUTHORITY=vault` on both services
and mount `IPMI_BMC_CREDENTIALS_FILE=/run/secrets/ipmi-bmc-credentials.json` into IPMI.
DC also detects its existing `credential-sources.json` authority manifest; IPMI detects
its configured BMC credential file. Selection is configuration-based: a vault outage
never enables local credential writes. DC credential controls become read-only;
metadata and membership reconciliation continue. Refresh vault runtime copies using
the deployment runbook. Do not switch authority modes as an outage workaround.

Upgrade IPMI Monitor before DC Overview. New senders authenticate every inventory
request with an HMAC; only metadata-only legacy requests may use the old bearer
format. Preserve the synchronization secret when updating or restoring a deployment;
local encrypted BMC data and pending bundles depend on it. Back it up in the same
protected operational store as other deployment secrets. Never rotate just one side.

`dc-ipmi-inventory` contains only the shared internal service secret. It is
mounted read-only and is not a request parameter, database value, log value, or
API response field.

DC accepts this setting only when it is exactly `http://ipmi-monitor:5000`
(with an optional trailing slash). User info, paths, query strings, fragments,
alternate schemes, ports, and hosts are rejected before a request is made. The
sender always uses the fixed path `/api/internal/inventory/reconcile`, disables
redirects, and does no network I/O when either that allowlisted destination or
the mounted secret is absent.

When both conditions are present, a daemon performs one bounded batch of up to
ten current outbox records every 60 seconds. It does not delay application
startup. Each local server change, its stable source identity, incremented
revision, and outbox row commit in one SQLite write transaction before any
delivery attempt. SQLite's `BEGIN IMMEDIATE` reservation serializes this
sequence across separate Gunicorn worker processes; network delivery occurs
after the transaction has committed.

`ipmi-bmc-credentials.json` is an organisation-vault-rendered, read-only JSON
object keyed by canonical BMC address. Each entry is exactly:

```json
{
  "10.20.0.90": {"username": "operator", "password": "vault-rendered-value"}
}
```

In vault mode, the credential file is not supplied by DC and is not copied into
reconciliation payloads, templates, or logs. A malformed configured entry or
an unreadable configured file fails closed for enrollment. Existing per-BMC
`ServerConfig` credentials keep their normal behavior.

On Charlotte, vault refresh removes active per-BMC database overrides so the
vault-rendered file supplies their credentials. Legacy overrides remain supported;
creating one in the monitoring UI can override the file again.

For an obsolete unmanaged BMC, use the internal receiver's authenticated
`/api/internal/inventory/retire-preview` endpoint with an exact `bmc_ips` list.
The default response is a preview. Applying it additionally requires
`apply: true` and `confirm_retire_count` equal to the submitted list length.
It only deprecates selected unbound records, retains all historical data, and
never runs automatically at startup.
