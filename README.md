# DC Overview

[![PyPI](https://img.shields.io/pypi/v/dc-overview.svg)](https://pypi.org/project/dc-overview/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io-blue)](https://github.com/cryptolabsza/dc-overview/pkgs/container/dc-overview)

**Complete GPU datacenter monitoring suite.** Deploy Prometheus, Grafana, and GPU monitoring with a single command. Features unified authentication through Fleet Management and seamless integration with [IPMI Monitor](https://github.com/cryptolabsza/ipmi-monitor).

![Dashboard](docs/images/grafana-overview.png)

## What's Included

| Component | Description | Port |
|-----------|-------------|------|
| **cryptolabs-proxy** | Unified HTTPS reverse proxy with Fleet authentication | 443 |
| **DC Overview** | Server Manager web UI for managing workers | 5001 |
| **Prometheus** | Time-series metrics database | 9090 |
| **Grafana** | Dashboards and alerting | 3000 |
| **IPMI Monitor** | BMC/IPMI server health monitoring (optional) | 5000 |
| **node_exporter** | CPU, RAM, disk metrics (on workers) | 9100 |
| **dc-exporter** | GPU VRAM temps, hotspot, power (on workers) | 9835 |
| **vastai-exporter** | Vast.ai earnings & rentals (optional) | 8622 |
| **runpod-exporter** | RunPod earnings & GPU utilization (optional) | 8623 |

---

## What's New in v1.1.1

| Feature | Description |
|---------|-------------|
| **CryptoLabs Vast.ai Exporter** | Native Vast.ai exporter built by CryptoLabs with multi-account support |
| **Multi-Account Support** | Both Vast.ai and RunPod exporters support multiple API keys with account labels |
| **Fleet Management Updates** | Health API shows update status for all services including new exporters |
| **Favicon Support** | Service icons use actual favicons for Grafana, Prometheus, RunPod, Vast.ai |
| **Improved Update Logic** | Container restart after updates now preserves original configuration |

### v1.1.1

| Feature | Description |
|---------|-------------|
| **RunPod Integration** | Track RunPod earnings, GPU utilization, and reliability with multi-account support |
| **Site Name Branding** | Customize your landing page and IPMI Monitor with your datacenter name |
| **Auto-Scaling Dashboards** | Grafana table panels automatically resize based on your server count |
| **Vast.ai/RunPod Logs** | IPMI Monitor auto-collects daemon logs when exporters are enabled |
| **Improved Dashboard Layout** | Machine column displays on the left for better readability |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    cryptolabs-proxy (Port 443)                   │
│              Unified Authentication & Reverse Proxy              │
│         Roles: admin | readwrite | readonly                      │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┬───────────────┐
          ▼                   ▼                   ▼               ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────┐ ┌─────────────┐
│  dc-overview    │ │    Grafana      │ │ Prometheus  │ │ipmi-monitor │
│  (Server Mgr)   │ │   Dashboards    │ │   Metrics   │ │ BMC Health  │
│  /dc/           │ │  /grafana/      │ │/prometheus/ │ │   /ipmi/    │
│  :5001          │ │    :3000        │ │   :9090     │ │   :5000     │
└─────────────────┘ └─────────────────┘ └─────────────┘ └─────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│   GPU Worker  │     │   GPU Worker  │     │   GPU Worker  │
│  ┌──────────┐ │     │  ┌──────────┐ │     │  ┌──────────┐ │
│  │node_exp. │ │     │  │node_exp. │ │     │  │node_exp. │ │
│  │  :9100   │ │     │  │  :9100   │ │     │  │  :9100   │ │
│  ├──────────┤ │     │  ├──────────┤ │     │  ├──────────┤ │
│  │dc-export.│ │     │  │dc-export.│ │     │  │dc-export.│ │
│  │  :9835   │ │     │  │  :9835   │ │     │  │  :9835   │ │
│  └──────────┘ │     │  └──────────┘ │     │  └──────────┘ │
└───────────────┘     └───────────────┘     └───────────────┘
   (systemd)             (systemd)             (systemd)
```

**Master Server**: Docker containers on `cryptolabs` network for easy management  
**Workers**: Native systemd services for GPU compatibility (Vast.ai, RunPod, etc.)

---

## Quick Start

### Automated Deployment (Recommended)

Deploy everything with a single command using a config file:

```bash
# Install from dev branch (latest features)
pip install git+https://github.com/cryptolabsza/cryptolabs-proxy.git@dev --break-system-packages
pip install git+https://github.com/cryptolabsza/dc-overview.git@dev --break-system-packages

# Deploy with config file (no prompts)
sudo dc-overview setup -c /path/to/config.yaml -y
```

Or install from PyPI (stable):

```bash
apt install pipx -y && pipx ensurepath
source ~/.bashrc
pipx install dc-overview
sudo dc-overview setup -c config.yaml -y
```

### Interactive Setup

For first-time users or when you don't have a config file:

```bash
sudo dc-overview setup
```

The Fleet Wizard guides you through:
1. **Site Name** - Customize your datacenter branding (e.g., "CryptoLabs", "AmericanColo")
2. **Components** - DC Overview, IPMI Monitor, Vast.ai exporter, RunPod exporter
3. **Credentials** - Fleet admin, Grafana, SSH, BMC/IPMI
4. **Servers** - Import from IPMI Monitor or enter manually
5. **SSL** - Let's Encrypt or self-signed

Then deploys everything automatically without further prompts.

> **Note:** This automatically deploys [cryptolabs-proxy](https://github.com/cryptolabsza/cryptolabs-proxy) as the unified entry point and authentication layer for all services.

---

## Configuration File

Create a YAML config for automated deployments. See [test-config.yaml](test-config.yaml) for a complete example.

```yaml
# fleet-config.yaml
site_name: My Datacenter

# Fleet Management Login (unified auth via cryptolabs-proxy)
fleet_admin_user: admin
fleet_admin_pass: YOUR_ADMIN_PASSWORD

# SSH Access (for all servers)
ssh:
  username: root
  key_path: ~/.ssh/id_rsa
  port: 22

# BMC/IPMI Access (default for all servers)
bmc:
  username: admin
  password: YOUR_BMC_PASSWORD

# SSL Configuration
ssl:
  mode: letsencrypt  # Options: letsencrypt, selfsigned
  domain: dc.example.com
  email: admin@example.com

# Components to install
components:
  dc_overview: true
  ipmi_monitor: true
  vast_exporter: false    # Set to true if using Vast.ai
  runpod_exporter: false  # Set to true if using RunPod

# Vast.ai API Keys (only needed if vast_exporter is true)
# Supports multiple accounts with labels
vast:
  api_keys:
    - name: VastMain
      key: YOUR_VAST_API_KEY
    - name: VastSecondary
      key: YOUR_SECOND_VAST_API_KEY
  # Legacy single key format also supported:
  # api_key: YOUR_VAST_API_KEY

# RunPod API Keys (only needed if runpod_exporter is true)
# Supports multiple accounts with labels
runpod:
  api_keys:
    - name: RunpodCCC
      key: YOUR_RUNPOD_API_KEY
    - name: Brickbox
      key: YOUR_SECOND_RUNPOD_API_KEY

# Servers to monitor
servers:
  - name: gpu-01
    server_ip: 192.168.1.101
    bmc_ip: 192.168.1.201

  - name: gpu-02
    server_ip: 192.168.1.102
    bmc_ip: 192.168.1.202

# Grafana settings
grafana:
  admin_password: YOUR_GRAFANA_PASSWORD
  # Home dashboard: dc-overview-main, vast-dashboard, node-exporter-full, or null
  home_dashboard: dc-overview-main

# IPMI Monitor settings (if ipmi_monitor is enabled)
ipmi_monitor:
  admin_password: YOUR_IPMI_MONITOR_PASSWORD
```

Deploy with:
```bash
sudo dc-overview setup -c fleet-config.yaml -y
```

> **Security Note:** Never commit config files with real credentials. Use placeholder values in examples and store actual credentials securely.

---

## User Permissions & Authentication

### Fleet Authentication

All services authenticate through `cryptolabs-proxy` with unified credentials:

| Role | DC Overview | Grafana | IPMI Monitor |
|------|-------------|---------|--------------|
| `admin` | Full access | Admin | Full access |
| `readwrite` | Edit servers | Editor | Edit servers |
| `readonly` | View only | Viewer | View only |

### How It Works

1. User logs into Fleet Management landing page (`https://domain/`)
2. Proxy sets authentication headers on all requests:
   - `X-Fleet-Authenticated: true`
   - `X-Fleet-Auth-User: <username>`
   - `X-Fleet-Auth-Role: <admin|readwrite|readonly>`
3. Sub-services read headers and auto-authenticate users

### Grafana Role Sync

Grafana roles are synced via API endpoint:
```bash
# Sync current user's Fleet role to Grafana
curl -X POST https://domain/dc/api/grafana/sync-role \
  -H "X-Fleet-Auth-User: admin" \
  -H "X-Fleet-Auth-Role: admin"
```

---

## CLI Commands

```bash
# Setup & Deployment
dc-overview setup              # Interactive setup wizard
dc-overview setup -c FILE -y   # Deploy from config file

# Container Management
dc-overview status                  # Show container status
dc-overview logs [-f] [SERVICE]     # View logs
dc-overview stop                    # Stop all containers
dc-overview start                   # Start all containers
dc-overview restart                 # Restart containers
dc-overview upgrade                 # Pull latest images and restart

# Worker Management
dc-overview install-exporters       # Install exporters locally
dc-overview add-machine IP          # Add a worker to monitor

# SSL/Proxy
dc-overview setup-ssl               # Configure HTTPS
```

---

## Development Workflow

### GitHub Actions

The repository uses GitHub Actions for CI/CD:

| Workflow | Trigger | Output |
|----------|---------|--------|
| `docker-build.yml` | Push to `main`, `dev`, tags | `ghcr.io/cryptolabsza/dc-overview:dev` |
| `publish.yml` | GitHub Release | PyPI package |

### Dev Branch Images

Push to `dev` branch automatically builds Docker images:
- `ghcr.io/cryptolabsza/dc-overview:dev`
- `ghcr.io/cryptolabsza/dc-overview:develop`
- `ghcr.io/cryptolabsza/dc-overview:sha-<commit>`

### Testing Dev Builds

```bash
# Install from dev branch (cryptolabs-proxy first for SSL management)
pip install git+https://github.com/cryptolabsza/cryptolabs-proxy.git@dev --break-system-packages
pip install git+https://github.com/cryptolabsza/dc-overview.git@dev --break-system-packages

# Run setup
dc-overview setup -c /path/to/test-config.yaml -y
```

---

## Deployment Flow

The `setup` command executes these steps:

1. **Prerequisites** - Install Docker, nginx, ipmitool, certbot
2. **SSH Keys** - Generate fleet key and deploy to workers
3. **Core Services** - Start Prometheus & Grafana containers
4. **Exporters** - Install node_exporter and dc-exporter on workers via SSH
5. **Prometheus Config** - Configure scrape targets
6. **Dashboards** - Import Grafana dashboards
7. **IPMI Monitor** - Deploy if enabled (with automatic Vast.ai/RunPod log collection)
8. **Vast.ai Exporter** - Deploy if enabled
9. **RunPod Exporter** - Deploy if enabled (supports multiple API keys)
10. **Reverse Proxy** - Configure cryptolabs-proxy with SSL and site branding

---

## Access URLs

After setup, access your monitoring at:

| Service | URL | Description |
|---------|-----|-------------|
| Fleet Landing | `https://domain/` | Unified login & service links |
| DC Overview | `https://domain/dc/` | Server management |
| Grafana | `https://domain/grafana/` | Dashboards |
| Prometheus | `https://domain/prometheus/` | Metrics queries |
| IPMI Monitor | `https://domain/ipmi/` | BMC health (if enabled) |

---

## Port Reference

| Service | Port | Description |
|---------|------|-------------|
| cryptolabs-proxy | 443 | HTTPS reverse proxy |
| dc-overview | 5001 | Server Manager |
| ipmi-monitor | 5000 | BMC/IPMI monitoring |
| grafana | 3000 | Dashboards |
| prometheus | 9090 | Metrics database |
| node_exporter | 9100 | System metrics |
| dc-exporter | 9835 | GPU metrics |
| dcgm-exporter | 9400 | NVIDIA DCGM |
| vastai-exporter | 8622 | Vast.ai earnings |
| runpod-exporter | 8623 | RunPod earnings |

---

## Integration with IPMI Monitor

DC Overview and IPMI Monitor share infrastructure and auto-detect each other's configuration:

```bash
# If IPMI Monitor is already installed, setup detects it:
✓ IPMI Monitor Detected!
✓ CryptoLabs Proxy Already Running!
✓ Fleet admin: admin (from existing proxy)
✓ Site name: My GPU Farm (from existing proxy)
✓ AI license key detected from existing deployment
✓ Imported 12 servers from IPMI Monitor
✓ Imported SSH keys from IPMI Monitor
```

Shared components:
- **cryptolabs-proxy** - Unified authentication, reverse proxy, and **cryptolabs-watchtower** for auto-updates
- **cryptolabs** Docker network - Service communication
- **Server list** - Imported automatically
- **SSH keys** - Shared between services

**cryptolabs-watchtower** is deployed by cryptolabs-proxy when the proxy is configured. It primarily auto-updates cryptolabs-proxy (the main entry point); other labeled containers (dc-overview, prometheus, grafana, ipmi-monitor, etc.) can also be updated. Fleet Manager UI has manual update for services.

### Cross-Tool Config Auto-Detection

Both setup commands can be run in **either order**. The second tool automatically reuses configuration from the first:

```bash
# Scenario A: dc-overview first, ipmi-monitor second
sudo dc-overview setup -c dc-config.yaml -y
sudo ipmi-monitor setup -c ipmi-config.yaml -y    # Skips credential prompts

# Scenario B: ipmi-monitor first, dc-overview second
sudo ipmi-monitor setup -c ipmi-config.yaml -y
sudo dc-overview setup -c dc-config.yaml -y        # Skips credential prompts
```

**Auto-detected from an existing proxy:**

| Value | Source |
|-------|--------|
| Fleet admin credentials | Proxy env vars (`FLEET_ADMIN_USER` / `FLEET_ADMIN_PASS`) |
| Site name | Proxy env var (`SITE_NAME`) |
| AI / Watchdog license key | Proxy env var (`WATCHDOG_API_KEY`) or `/etc/ipmi-monitor/.env` |
| Domain and SSL mode | Proxy nginx config |
| SSH keys | `/etc/ipmi-monitor/ssh_keys/` or `/etc/dc-overview/ssh_keys/` |
| Server list | IPMI Monitor database or `servers.yaml` |

**Priority order** (highest to lowest):

| Priority | Source | When used |
|----------|--------|-----------|
| 1 | Config file (`-c`) | Always takes precedence if value is present |
| 2 | Running proxy env vars | Fills in missing values from config file |
| 3 | Interactive prompt | Only if neither of the above provides a value |

> **Note:** Config file values always win. If your two config files specify different credentials, each deployment uses its own file's values. The auto-detection only fills in values **missing** from the config file — it never silently overrides what you explicitly set.

---

## Grafana Dashboards

Pre-installed dashboards (auto-scaled to fit your fleet size):

| Dashboard | Description |
|-----------|-------------|
| **DC Overview** | Fleet overview with all GPU metrics |
| **DC Exporter Details** | Detailed GPU metrics (VRAM temp, hotspot, power, PCIe errors) |
| **Node Exporter Full** | CPU, RAM, disk, network |
| **NVIDIA DCGM Exporter** | GPU performance metrics |
| **Vast Dashboard** | Vast.ai provider earnings & machine status |
| **RunPod Dashboard** | RunPod earnings, GPU utilization & reliability |
| **IPMI Monitor** | BMC/IPMI sensor data |

> **Note:** Dashboard table panels automatically scale based on your server count to ensure all machines are visible without scrolling.

---

## Manual Worker Setup

If automatic SSH deployment fails:

```bash
# On each GPU worker
pipx install dc-overview
sudo dc-overview install-exporters
```

Or install exporters individually:

```bash
# Node Exporter
wget https://github.com/prometheus/node_exporter/releases/download/v1.7.0/node_exporter-1.7.0.linux-amd64.tar.gz
tar xzf node_exporter-*.tar.gz
sudo cp node_exporter-*/node_exporter /usr/local/bin/
sudo systemctl enable --now node_exporter

# DC Exporter (GPU metrics)
curl -L https://github.com/cryptolabsza/dc-exporter-releases/releases/latest/download/dc-exporter-rs -o /usr/local/bin/dc-exporter-rs
chmod +x /usr/local/bin/dc-exporter-rs
sudo systemctl enable --now dc-exporter
```

---

## Troubleshooting

### Check Status
```bash
dc-overview status
docker ps
docker logs cryptolabs-proxy
```

### View Service Logs
```bash
dc-overview logs -f              # All services
docker logs -f dc-overview       # Server Manager
docker logs -f grafana           # Grafana
docker logs -f prometheus        # Prometheus
```

### Restart Services
```bash
dc-overview restart
# Or individually:
docker restart dc-overview grafana prometheus
```

### Update to Latest
```bash
dc-overview upgrade              # Pull and restart containers
pipx upgrade dc-overview         # Update CLI tool
```

### Test Exporter Connectivity
```bash
curl http://worker-ip:9100/metrics  # node_exporter
curl http://worker-ip:9835/metrics  # dc-exporter
```

### Nginx Config Issues
```bash
docker exec cryptolabs-proxy nginx -t  # Test config
docker exec cryptolabs-proxy nginx -s reload  # Reload
```

---

## Marketplace Exporters

### Vast.ai Exporter

CryptoLabs-built Prometheus exporter for Vast.ai host metrics.

```bash
# Single account
docker run -d --name vastai-exporter \
  -p 8622:8622 \
  ghcr.io/cryptolabsza/vastai-exporter:latest \
  -api-key YOUR_API_KEY

# Multiple accounts
docker run -d --name vastai-exporter \
  -p 8622:8622 \
  ghcr.io/cryptolabsza/vastai-exporter:latest \
  -api-key VastMain:KEY1 \
  -api-key VastSecondary:KEY2

# Using environment variable
docker run -d --name vastai-exporter \
  -p 8622:8622 \
  -e VASTAI_API_KEYS="VastMain:KEY1,VastSecondary:KEY2" \
  ghcr.io/cryptolabsza/vastai-exporter:latest
```

**Metrics exposed:**
- `vastai_account_balance` - Account balance in USD
- `vast_machine_*` - Machine status (Listed, Verified, Reliability, timeout)
- `vastai_machine_*` - Detailed metrics (disk, inet, rentals, earnings)
- `vastai_machine_gpu_occupancy` - Per-GPU occupancy state

### RunPod Exporter

CryptoLabs-built Prometheus exporter for RunPod host metrics.

```bash
# Single account
docker run -d --name runpod-exporter \
  -p 8623:8623 \
  ghcr.io/cryptolabsza/runpod-exporter:latest \
  -api-key YOUR_API_KEY

# Multiple accounts
docker run -d --name runpod-exporter \
  -p 8623:8623 \
  ghcr.io/cryptolabsza/runpod-exporter:latest \
  -api-key RunpodCCC:KEY1 \
  -api-key Brickbox:KEY2
```

**Metrics exposed:**
- `runpod_host_balance` - Host balance per account
- `runpod_machine_*` - GPU counts, earnings, uptime, listings
- `runpod_account_*` - Account-level totals

---

## Related Projects

| Project | Description |
|---------|-------------|
| [ipmi-monitor](https://github.com/cryptolabsza/ipmi-monitor) | BMC/IPMI health monitoring |
| [dc-exporter](https://github.com/cryptolabsza/dc-exporter) | GPU VRAM temperature exporter |
| [cryptolabs-proxy](https://github.com/cryptolabsza/cryptolabs-proxy) | Unified reverse proxy with auth |
| [vastai-exporter](https://github.com/cryptolabsza/dc-overview/tree/dev/vastai-exporter) | Vast.ai host metrics exporter |
| [runpod-exporter](https://github.com/cryptolabsza/dc-overview/tree/dev/runpod-exporter) | RunPod host metrics exporter |

---

## Support

- **Discord**: https://discord.gg/7yeHdf5BuC
- **Issues**: https://github.com/cryptolabsza/dc-overview/issues

---

## License

MIT License - see [LICENSE](LICENSE) for details.
