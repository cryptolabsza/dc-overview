# Approved implementation plan

1. Write failing tests first: Watchdog compact text and per-channel durable queue/diagnostic preservation; real PromQL collector-loss/recovery/policy cases; dashboard classifications; actual Go-template recovery rendering.
2. Watchdog: add structured Telegram formatter in lib/gpu_availability.py and choose it only when enqueueing Telegram in lib/gpu_incidents.py. Preserve diagnostic messages and receipt semantics.
3. Overview: add host source-quality rule and rendering in grafana_alerts.py/fleet-gpu-health.yml; explicit source-aware dashboard state and mirrored assets; concise truthful firing/recovery template.
4. Run focused and existing notification/dashboard tests, independent review, bounded repair, source patch/hash records. No version change on dev.
5. After network/remote freshness and CI gates pass, normal publication/release and native LTX/Charlotte installation, backed-up provisioning sync, health/source/config readback and postreload evaluations. No bypass of release or native guards.

Baselines: Overview803e2a8c96cc683267bbf644e7ae02a0de771a16; Watchdog74721a2a7f68578addc0f4bd2a3050ed47b89b2a. These are last locally retained dev refs; remote freshness unavailable due GitHub DNS failure. Work is isolated in sibling source directories; canonical dirty checkout remains untouched.
