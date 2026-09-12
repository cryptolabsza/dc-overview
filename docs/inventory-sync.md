# DC to IPMI inventory reconciliation

DC sends one revisioned desired-state message to the fixed internal receiver
after committing its local server mutation and durable outbox entry. The sender
never discovers BMC addresses from an OS address, and existing DC rows remain
unconfigured until an operator explicitly supplies a BMC mapping.

The deployment owner should mount the same read-only service secret into both
containers and configure:

```text
# dc-overview
IPMI_INVENTORY_URL=http://ipmi-monitor:5000
DC_IPMI_INVENTORY_SECRET_FILE=/run/secrets/dc-ipmi-inventory

# ipmi-monitor
IPMI_INVENTORY_SECRET_FILE=/run/secrets/dc-ipmi-inventory
IPMI_BMC_CREDENTIALS_FILE=/run/secrets/ipmi-bmc-credentials.json
```

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

The credential file is not supplied by DC and must not be copied into
`ServerConfig`, payloads, templates, or logs. A malformed configured entry or
an unreadable configured file fails closed for enrollment. Existing per-BMC
`ServerConfig` credentials keep their normal behavior.

For an obsolete unmanaged BMC, use the internal receiver's authenticated
`/api/internal/inventory/retire-preview` endpoint with an exact `bmc_ips` list.
The default response is a preview. Applying it additionally requires
`apply: true` and `confirm_retire_count` equal to the submitted list length.
It only deprecates selected unbound records, retains all historical data, and
never runs automatically at startup.
