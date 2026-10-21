# Vast.ai Prometheus Exporter

Prometheus exporter for Vast.ai host/provider metrics. Exposes account balance, machine status, reliability scores, and rental information.

## Metrics Exposed

| Metric | Type | Description |
|--------|------|-------------|
| `vastai_account_balance` | gauge | Current account balance in USD |
| `vastai_account_credit` | gauge | Current account credit in USD |
| `vastai_machine_num_gpus` | gauge | Number of GPUs on machine |
| `vastai_machine_reliability` | gauge | Machine reliability score (0-1) |
| `vastai_machine_listed` | gauge | Machine listing status (1=listed) |
| `vastai_machine_verified` | gauge | Machine verification status (1=verified) |
| `vastai_machine_disk_total_gb` | gauge | Total disk space in GB |
| `vastai_machine_disk_allocated_gb` | gauge | Allocated disk space in GB |
| `vastai_machine_inet_up_mbps` | gauge | Upload speed in Mbps |
| `vastai_machine_inet_down_mbps` | gauge | Download speed in Mbps |
| `vastai_machine_total_flops` | gauge | Total TFLOPS of machine |
| `vastai_machine_rentals_on_demand` | gauge | Current on-demand rentals |
| `vastai_machine_rentals_bid` | gauge | Current bid rentals |
| `vastai_machine_timeout` | gauge | Machine timeout status |
| `vastai_account_machines_total` | gauge | Total machines per account |
| `vastai_account_gpus_total` | gauge | Total GPUs per account |

## Previous UTC day earnings

The worker retrieves the previous completed UTC calendar day from the canonical `users/me/machine-earnings/` endpoint with equal inclusive `sday` and `eday` epoch-day bounds. Reports are as reported and revisable, with no finality guarantee. Per-day/account summaries and current `earn_day` are never allocated to machines. Retired-machine report rows are retained.

| Gauge | Meaning |
|-------|---------|
| `vastai_per_machine_gpu_earn` | Machine GPU amount |
| `vastai_per_machine_sto_earn` | Machine storage amount |
| `vastai_per_machine_bwu_earn` | Machine upload amount |
| `vastai_per_machine_bwd_earn` | Machine download amount |
| `vastai_earnings_report_day_timestamp_seconds` | Accepted report midnight UTC |
| `vastai_earnings_last_success_timestamp_seconds` | Accepted retrieval Unix time |
| `vastai_earnings_report_valid` | 1 while report day, generation and age remain valid; 0 otherwise |
| `vastai_earnings_status` | 0 awaiting, 1 valid, 2 partial, 3 valid empty, 4 refresh error, 5 expired, 6 configuration error |

Amount gauges carry `provider_account_id`, configured `account` alias and `machine_id`; account metadata omits machine ID. Unknown identity exposes alias-only status. USD display is inferred from provider host-payment documentation, rather than an explicit report currency field. Finite numeric zero and signed adjustments are retained; missing, boolean, string and non-finite components are omitted. Missing operands remove total/bandwidth values. Empty reports produce no machine zeros. Duplicate aliases or canonical accounts suppress historical values with configuration-error status.

One explicit daemon worker starts after accounts load. Reports refresh hourly, failures retry after at least five minutes, and request starts are separated by at least two seconds. The transport uses a 15-second socket timeout, a 1 MiB body limit and a 30-second cooperative read budget checked between chunks. These are not a hard end-to-end OS/DNS/network deadline. Historical I/O runs outside snapshot and management locks; existing current-metric API latency remains unchanged. Stop invalidates outstanding publication and joins for at most two seconds; a daemon may still await provider I/O after that join.

Last-good same-day data survives refresh failure only until its original two-hour monotonic expiry. UTC rollover, account replacement/removal and restart make amounts unknown. Report snapshots replace all old rows/components atomically. The Grafana history records observation time with step/point rendering and null gaps, without accounting backfill. Later corrections to older days are not replayed. Never integrate or sum repeated gauge observations; coarse long-range sampling can omit daily points.

## Telegram listing notifications

DC Overview provisions a per-machine Vast listing alert through Grafana, using
the existing Telegram contact point. A confirmed unlisted observation fires
`Vast UNLISTED`; a subsequent confirmed listed observation resolves it with
`Vast LISTED`. Messages include hostname, machine ID, and account. An initially
listed machine does not generate a startup notification. Repeated observations
do not create new transitions; Grafana's normal reminder policy still applies.

The exporter polls at most once per 60 seconds and the alert evaluates every
30 seconds. Short transitions occurring entirely between polls cannot be observed.
API failures, malformed listing fields, and absent machines retain the last
confirmed status. Separate monitoring alerts report gaps after two minutes.
Grafana rule removal, pause, and missing-series resolutions say monitoring changed,
never that a machine was listed.

Confirmed state is stored without credentials in `/data/listing-state.json`.
Keep `/data` on a persistent volume. The Fleet installer already mounts
`vastai-exporter-data`; generated Compose configurations now use that volume too.
If running the script directly, `/data` must exist and be writable.

### Activate on an existing installation

1. Upgrade the Vast exporter image and the DC Overview package together.
   Confirm `/metrics` includes `vast_machine_listing_listed` after a successful
   inventory poll and `vast_listing_state_persist_success 1`.
2. In Grafana's existing Telegram contact point, keep **Disable resolved message**
   off. Alert sync rejects receivers that suppress recovery notifications.
3. Run `dc-overview sync-alerts --config-dir <existing-config-directory>` on the
   monitoring host. The command preserves the existing managed-alert receiver.
   Supply `GRAFANA_PASSWORD` through the environment from your organisation's
   secret manager.
   When configuring a receiver for the first time, add `--receiver "<existing Telegram name>"`.
   The existing command handles backups, reload, and rollback.
4. Verify the three `vast-` rules appear under **Infrastructure Alerts / Vast Listing**
   and use the intended Telegram receiver. An installation without a configured
   Vast scrape target does not fire Vast monitoring alerts.

For an existing **Compose** exporter, inspect the current `/data` mount before
regenerating Compose:

```bash
docker inspect vastai-exporter --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}} {{.Name}} {{.Source}}{{end}}{{end}}'
```

Older Compose containers may use an anonymous Docker volume containing API-managed
accounts. Preserve that volume: set the generated Vast volume's `name` to the
exact existing volume name and `external: true` before recreating the container.
For a bind mount, retain its exact existing `source:/data` mapping instead.
Verify `/api/accounts` still contains all configured accounts afterward. Do not
switch to an empty named volume or remove the original volume during the upgrade.

## Usage

### Docker (recommended)

```bash
docker run -d \
  --name vastai-exporter \
  --restart unless-stopped \
  -p 8622:8622 \
  -v vastai-exporter-data:/data \
  -e VASTAI_API_KEY=your_api_key \
  ghcr.io/cryptolabsza/vastai-exporter:latest
```

### Multiple Accounts

```bash
docker run -d \
  --name vastai-exporter \
  --restart unless-stopped \
  -p 8622:8622 \
  -v vastai-exporter-data:/data \
  -e VASTAI_API_KEYS="Account1:KEY1,Account2:KEY2" \
  ghcr.io/cryptolabsza/vastai-exporter:latest
```

### Command Line

```bash
# Single account
python vastai_exporter.py -api-key YOUR_API_KEY

# Multiple accounts
python vastai_exporter.py -api-key Account1:KEY1 -api-key Account2:KEY2

# Custom port
python vastai_exporter.py -api-key KEY -port 9100
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `VASTAI_API_KEY` | Single API key |
| `VASTAI_API_KEYS` | Comma-separated list of `name:key` pairs |

## Getting Your API Key

1. Log in to [Vast.ai Console](https://console.vast.ai/)
2. Go to Account Settings
3. Generate or copy your API key

## Prometheus Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'vastai'
    static_configs:
      - targets: ['vastai-exporter:8622']
```

## Building

```bash
docker build -t vastai-exporter .
```

## License

MIT License - CryptoLabs
