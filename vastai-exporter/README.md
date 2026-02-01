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

## Usage

### Docker (recommended)

```bash
docker run -d \
  --name vastai-exporter \
  --restart unless-stopped \
  -p 8622:8622 \
  -e VASTAI_API_KEY=your_api_key \
  ghcr.io/cryptolabsza/vastai-exporter:latest
```

### Multiple Accounts

```bash
docker run -d \
  --name vastai-exporter \
  --restart unless-stopped \
  -p 8622:8622 \
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
