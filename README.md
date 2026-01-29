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
| **vastai-exporter** | Vast.ai earnings (optional) | 8622 |

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
pip install git+https://github.com/cryptolabsza/dc-overview.git@dev --break-system-packages

# Deploy with config file (no prompts)
sudo dc-overview quickstart -c /path/to/config.yaml -y
```

Or install from PyPI (stable):

```bash
pipx install dc-overview
sudo dc-overview quickstart -c config.yaml -y
```

### Interactive Setup

For first-time users or when you don't have a config file:

```bash
sudo dc-overview quickstart
```

The Fleet Wizard guides you through:
1. **Components** - DC Overview, IPMI Monitor, Vast.ai exporter
2. **Credentials** - Fleet admin, Grafana, SSH, BMC/IPMI
3. **Servers** - Import from IPMI Monitor or enter manually
4. **SSL** - Let's Encrypt or self-signed

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
  vast_exporter: false  # Set to true if using Vast.ai

# Vast.ai API Key (only needed if vast_exporter is true)
vast:
  api_key: YOUR_VAST_API_KEY

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
sudo dc-overview quickstart -c fleet-config.yaml -y
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
dc-overview quickstart              # Interactive setup wizard
dc-overview quickstart -c FILE -y   # Deploy from config file

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
# Install from dev branch
pip install git+https://github.com/cryptolabsza/dc-overview.git@dev --break-system-packages

# Run quickstart
dc-overview quickstart -c /path/to/test-config.yaml -y
```

---

## Deployment Flow

The `quickstart` command executes these steps:

1. **Prerequisites** - Install Docker, nginx, ipmitool, certbot
2. **SSH Keys** - Generate fleet key and deploy to workers
3. **Core Services** - Start Prometheus & Grafana containers
4. **Exporters** - Install node_exporter and dc-exporter on workers via SSH
5. **Prometheus Config** - Configure scrape targets
6. **Dashboards** - Import Grafana dashboards
7. **IPMI Monitor** - Deploy if enabled
8. **Vast.ai Exporter** - Deploy if enabled
9. **Reverse Proxy** - Configure cryptolabs-proxy with SSL

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

---

## Integration with IPMI Monitor

DC Overview and IPMI Monitor share infrastructure:

```bash
# If IPMI Monitor is already installed, quickstart detects it:
✓ IPMI Monitor Detected!
✓ CryptoLabs Proxy Already Running!
✓ Imported 12 servers from IPMI Monitor
✓ Imported SSH keys from IPMI Monitor
```

Shared components:
- **cryptolabs-proxy** - Unified authentication
- **cryptolabs** Docker network - Service communication
- **Server list** - Imported automatically
- **SSH keys** - Shared between services
- **Watchtower** - Auto-updates for all containers

---

## Grafana Dashboards

Pre-installed dashboards:

| Dashboard | Description |
|-----------|-------------|
| **DC Overview** | Fleet overview with all GPU metrics |
| **Node Exporter Full** | CPU, RAM, disk, network |
| **NVIDIA DCGM Exporter** | GPU performance metrics |
| **Vast Dashboard** | Vast.ai provider earnings |
| **IPMI Monitor** | BMC/IPMI sensor data |

---

## Manual Worker Setup

If automatic SSH deployment fails:

```bash
# On each GPU worker
pip install dc-overview
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

## Related Projects

| Project | Description |
|---------|-------------|
| [ipmi-monitor](https://github.com/cryptolabsza/ipmi-monitor) | BMC/IPMI health monitoring |
| [dc-exporter](https://github.com/cryptolabsza/dc-exporter) | GPU VRAM temperature exporter |
| [cryptolabs-proxy](https://github.com/cryptolabsza/cryptolabs-proxy) | Unified reverse proxy with auth |

---

## Support

- **Discord**: https://discord.gg/7yeHdf5BuC
- **Issues**: https://github.com/cryptolabsza/dc-overview/issues

---

## License

MIT License - see [LICENSE](LICENSE) for details.
