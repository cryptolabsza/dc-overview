# Watchdog GPU availability integration

Watchdog reachability and GPU collection coverage are separate. The existing
worker status response now carries `watchdog.gpu_availability` from the
customer-authenticated Watchdog agent-status endpoint. An online host, direct
health fallback, TCP connection, or database record cannot certify GPU health.

The API cache is scoped by endpoint and a credential digest. Changing credentials
invalidates cached tenant data even within its30second TTL; a late response from
an old auth context is discarded. The digest and credentials are not returned.
GPU source age continues increasing through cache reads. Retained unknown or
disabled server coverage cannot become available merely because an earlier
observation is recent. Active incidents remain visible through coverage loss.

Generated agent install/update scripts preserve existing configuration, tokens,
notification settings and unit settings. They install one owned systemd drop-in,
`40-cryptolabs-gpu-probe-state.conf`, with a private persistent state directory
and permitted write path. Binary rollback restores its prior content or absence.
Installation uses static PCI detection instead of starting another NVIDIA query.
No Grafana driver alarm or provider-listing behavior is added.

Deploy the compatible Watchdog server and additive incident/outbox schema first,
then an explicitly approved canary agent, then this display integration. The
Watchdog detector guide defines90second/3observation failure debounce, stable
source-aware recovery, channel deferral and uncertain delivery. No live rollout,
worker restart or production test message is authorized by local implementation.

When rolling an agent back, verify actual tracked helper/NVIDIA process exit
before an older collector can run; older agents do not understand the guard.
