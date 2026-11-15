# Concise alert notifications — approved 15 November 2026

Authority: the owner approved concise notifications for all alerts, explicitly requested actual RunPod note text, then instructed “Ok deploy to the two sites”. LTX and Charlotte are the two established sites. IDs below label that approved scope.

- REQ-CONCISE-001: Emit one useful concise line per configured alert; omit detailed diagnostic descriptions from Telegram while retaining them in Grafana. Preserve machine/GPU/disk/account identity, truthful listing transitions, orange GPU collector warnings and supported recovery summaries. Grafana state-reason closures describe monitoring changes, not confirmed recovery.
- REQ-CONCISE-002: Include actual accessible RunPod machine and maintenance note text. Normalize whitespace and bound each field to 512 characters with an ellipsis. Retain confirmed text across errors, missing inventory, restarts and failed saves; explicit valid empty/null clears it. Keep note text in annotations, outside condition/alert identity; support prior exporter metrics and version1 state.
- REQ-CONCISE-003: Publish the bounded patch as1.9.3 through the existing protected release path and deploy official immutable Overview/RunPod images at LTX then Charlotte using native updates. Activate only affected templates/provider-note annotations. Preserve customer intent, credentials, other components, original dirty work and rollback. No additional test-message sends or provider/workload actions.

Source verification: tests-first failures were observed before implementation in both original and fresh upstream contexts; focused tests and isolated real Grafana12.3.3/Prometheus validation passed. These are source/runtime-engine proofs, not production acceptance.
