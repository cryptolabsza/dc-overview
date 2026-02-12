# RunPod Prometheus Exporter

Prometheus exporter for RunPod host metrics. Designed for GPU hosts to track earnings, rentals, utilization, and reliability.

## Features

- **Multi-account support**: Track metrics from multiple RunPod accounts simultaneously
- **Earnings tracking**: GPU earnings, disk earnings, total earnings per machine
- **Utilization metrics**: GPUs rented, GPUs idle, active pods
- **Reliability metrics**: Uptime percentages (1w, 4w, 12w)
- **Resource metrics**: Disk space, memory, network speeds
- **Host balance**: Track pending payouts

## Quick Start

### Docker (Recommended)

```bash
# Single API key
docker run -d \
  --name runpod-exporter \
  --restart unless-stopped \
  -p 8623:8623 \
  ghcr.io/cryptolabsza/runpod-exporter:latest \
  -api-key YOUR_RUNPOD_API_KEY

# Multiple API keys (for hosts with multiple accounts)
docker run -d \
  --name runpod-exporter \
  --restart unless-stopped \
  -p 8623:8623 \
  ghcr.io/cryptolabsza/runpod-exporter:latest \
  -api-key "RunpodCCC:rpa_KEY1" \
  -api-key "Brickbox:rpa_KEY2"
```

### Direct Python

```bash
# Install and run
python3 runpod_exporter.py -api-key YOUR_API_KEY

# Multiple accounts
python3 runpod_exporter.py \
  -api-key "Account1:rpa_KEY1" \
  -api-key "Account2:rpa_KEY2"
```

### Environment Variables

```bash
# Single key
export RUNPOD_API_KEY="rpa_XXXXX"

# Multiple keys (comma-separated)
export RUNPOD_API_KEYS="Account1:rpa_KEY1,Account2:rpa_KEY2"

python3 runpod_exporter.py
```

## API Key Format

API keys can be specified in two formats:
- `rpa_XXXXX` - Uses default account name
- `AccountName:rpa_XXXXX` - Uses custom account name (recommended for multi-account)

## Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `runpod_host_balance` | Gauge | Current host balance in USD |
| `runpod_machine_gpu_total` | Gauge | Total GPUs on machine |
| `runpod_machine_gpu_rented` | Gauge | Rented GPUs on machine |
| `runpod_machine_gpu_idle` | Gauge | Idle GPUs on machine |
| `runpod_machine_gpus_in_use` | Gauge | GPUs currently used by running pods |
| `runpod_machine_listed` | Gauge | Machine listing status (1=listed) |
| `runpod_machine_verified` | Gauge | Machine verification status (1=verified) |
| `runpod_machine_uptime_percent_1w` | Gauge | Uptime % over 1 week |
| `runpod_machine_uptime_percent_4w` | Gauge | Uptime % over 4 weeks |
| `runpod_machine_uptime_percent_12w` | Gauge | Uptime % over 12 weeks |
| `runpod_machine_gpu_earnings` | Gauge | GPU earnings today |
| `runpod_machine_disk_earnings` | Gauge | Disk earnings today |
| `runpod_machine_total_earnings` | Gauge | Total earnings today |
| `runpod_machine_active_pods` | Gauge | Number of active pods |
| `runpod_machine_disk_total_gb` | Gauge | Total disk space (GB) |
| `runpod_machine_disk_reserved_gb` | Gauge | Reserved disk space (GB) |
| `runpod_machine_memory_total_gb` | Gauge | Total memory (GB) |
| `runpod_machine_download_mbps` | Gauge | Download speed (Mbps) |
| `runpod_machine_upload_mbps` | Gauge | Upload speed (Mbps) |
| `runpod_account_machines_total` | Gauge | Total machines per account |
| `runpod_account_gpus_total` | Gauge | Total GPUs per account |

### Labels

Machine metrics include these labels:
- `account` - Account name
- `machine_id` - RunPod machine ID
- `name` - Machine name
- `gpu_type` - GPU type (e.g., "NVIDIA RTX 4090")
- `location` - Machine location

## Prometheus Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'runpod'
    scrape_interval: 60s
    static_configs:
      - targets: ['runpod-exporter:8623']
```

## Endpoints

- `/metrics` - Prometheus metrics
- `/health` - Health check

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `-api-key` | - | RunPod API key (can specify multiple) |
| `-port` | 8623 | HTTP port |
| `-interval` | 60 | Cache TTL in seconds |

## Getting Your API Key

1. Go to [RunPod Console](https://www.runpod.io/console/user/settings)
2. Navigate to Settings > API Keys
3. Create a new key with "Read" permission

## Integration with DC Overview

When using DC Overview setup, RunPod exporter is configured automatically:

```yaml
# In your config.yaml
runpod:
  enabled: true
  api_keys:
    - name: "RunpodCCC"
      key: "rpa_XXXXX"
    - name: "Brickbox"
      key: "rpa_YYYYY"
```

## License

MIT License - CryptoLabs 2026
