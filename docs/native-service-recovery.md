<!-- TRACEWEAVER: file-role=recovery-operations-documentation; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001 -->
# Native IPMI service restoration evidence

Install the reviewed exact DC Overview and CryptoLabs Proxy host wheels into
the same existing CLI environment. Keep the original proxy serving. Before
`release select --record-cli` or controller adoption, run locally as Linux root:

```sh
dc-overview release reconcile-service --service ipmi-monitor --job <exact-active-job-id>
```

The command accepts only this service and a 32-character lowercase hex native
job ID. It accepts no path, image, script, force flag or caller observation. It
resolves the serving proxy's local writable `/data/auth` mount, then holds Fleet
lifecycle, dispatch and operation exclusion in that order. It does not invoke
status, replay a worker, stop a container, clear a marker or edit job history.

It verifies exactly one trusted retained pre-job bundle below the fixed
`/var/backups/cryptolabs/ipmi132` root, its private artifact hashes, original
container/image/runtime/config/network identity, terminal helper, fresh `/health`
and read-only stable SQLite/account/link/inventory fingerprints. Missing,
ambiguous or changed evidence holds. It creates no new baseline or DB copy.

The only new durable updater record is a private `service-recovery-JOB.json`
receipt. The old desired deployment remains failed. Retry revalidates current
evidence and returns the same receipt without changing its timestamp. Private
fingerprints and configuration values never appear in the command response.

After separately approved compatible selection and proxy adoption, new native
submits require the live `native_service_recovery: 1` capability and carry the
job/receipt hash binding into their worker. Workers check before pulls and again
before the first lifecycle effect. Blocked successors retain the dependency.
Only a verified successful IPMI update retires that original dependency; archived
receipts are retained without permanently pinning future runtimes.

New jobs persist bounded intent/completion diagnostics around Engine effects.
Unknown outcomes retain only safe categories and re-observe owned IDs before
restoration. No historical phases or incident cause are synthesized.

Local source tests are not operational clearance. Exact packaged legacy
bootstrap, protected release, fresh target custody, actual signed admission and
site/browser acceptance are separate gates.
