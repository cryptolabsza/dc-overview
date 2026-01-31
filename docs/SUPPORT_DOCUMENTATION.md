# DC Overview Support Documentation

**Complete GPU Datacenter Monitoring Suite**

Last Updated: January 2026

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Installation Methods](#installation-methods)
4. [Configuration](#configuration)
5. [Architecture](#architecture)
6. [Components](#components)
7. [User Authentication](#user-authentication)
8. [CLI Commands](#cli-commands)
9. [Grafana Dashboards](#grafana-dashboards)
10. [Troubleshooting](#troubleshooting)
11. [FAQ](#faq)
12. [Support](#support)

---

## Overview

DC Overview is a complete GPU datacenter monitoring solution that deploys Prometheus, Grafana, and GPU monitoring with a single command. It provides:

- **Fleet Management** - Unified authentication and service discovery
- **GPU Monitoring** - VRAM temperature, hotspot temperature, power, throttling
- **System Metrics** - CPU, RAM, disk, network via node_exporter
- **Visualization** - Pre-configured Grafana dashboards
- **Hardware Health** - Integration with IPMI Monitor for BMC monitoring
- **Revenue Tracking** - Vast.ai earnings integration

### What's Included

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

## Quick Start

### Automated Deployment (Recommended)

Deploy everything with a single command using a config file:

```bash
# Install from dev branch (latest features)
pip install git+https://github.com/cryptolabsza/dc-overview.git@dev --break-system-packages

# Deploy with config file (no prompts)
sudo dc-overview quickstart -c /path/to/config.yaml -y
```

### Interactive Setup

For first-time users or when you don't have a config file:

```bash
# Install
pip install dc-overview

# Run interactive wizard
sudo dc-overview quickstart
```

The Fleet Wizard guides you through:
1. **Site Name** - Customize your datacenter branding (e.g., "CryptoLabs", "AmericanColo")
2. **Components** - DC Overview, IPMI Monitor, Vast.ai exporter, RunPod exporter
3. **Credentials** - Fleet admin, Grafana, SSH, BMC/IPMI
4. **Servers** - Import from IPMI Monitor or enter manually
5. **SSL** - Let's Encrypt or self-signed

---

## Installation Methods

### Method 1: pip from Dev Branch (Latest Features)

```bash
pip install git+https://github.com/cryptolabsza/dc-overview.git@dev --break-system-packages
sudo dc-overview quickstart -c config.yaml -y
```

### Method 2: pip from PyPI (Stable)

```bash
pip install dc-overview
sudo dc-overview quickstart
```

### Method 3: pipx (Isolated Environment)

```bash
sudo apt install pipx -y
pipx install dc-overview
sudo ~/.local/bin/dc-overview quickstart
```

### Requirements

- Linux (Ubuntu 22.04+ recommended)
- Python 3.10+
- Docker and Docker Compose
- Root access for deployment
- SSH access to GPU workers

---

## Configuration

### Configuration File Format

Create a YAML config file for automated deployments:

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
  domain: monitoring.example.com
  email: admin@example.com

# Components to install
components:
  dc_overview: true
  ipmi_monitor: true
  vast_exporter: false    # Set to true if using Vast.ai
  runpod_exporter: false  # Set to true if using RunPod

# Vast.ai API Key (only needed if vast_exporter is true)
vast:
  api_key: YOUR_VAST_API_KEY

# RunPod API Keys (only needed if runpod_exporter is true)
# Supports multiple accounts with labels
runpod:
  api_keys:
    - key: YOUR_RUNPOD_API_KEY
      label: main-account
    - key: YOUR_SECOND_RUNPOD_API_KEY
      label: secondary-account

# Servers to monitor
servers:
  - name: gpu-01
    server_ip: 192.168.1.101
    bmc_ip: 192.168.1.201

  - name: gpu-02
    server_ip: 192.168.1.102
    bmc_ip: 192.168.1.202

# Grafana password
grafana:
  admin_password: YOUR_GRAFANA_PASSWORD

# IPMI Monitor password (if ipmi_monitor is enabled)
ipmi_monitor:
  admin_password: YOUR_IPMI_MONITOR_PASSWORD
```

### Configuration Files Location

After deployment, configuration files are stored in:

```
/etc/dc-overview/
├── fleet-config.yaml     # Main deployment config
├── .secrets.yaml         # Sensitive credentials (0600 permissions)
├── prometheus.yml        # Prometheus scrape config
├── recording_rules.yml   # Prometheus recording rules
├── docker-compose.yml    # Container definitions
└── ssh_keys/             # Fleet SSH keys
```

---

## Architecture

```
                    ┌─────────────────────────────────┐
                    │      cryptolabs-proxy           │
                    │   (Landing Page & Auth)         │
                    │         HTTPS :443              │
                    └─────────────────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
              ▼                    ▼                    ▼
        ┌──────────┐        ┌──────────┐        ┌──────────┐
        │  /dc/    │        │/grafana/ │        │/prometheus│
        │   DC     │        │ Grafana  │        │Prometheus │
        │ Overview │        │          │        │           │
        │  :5001   │        │  :3000   │        │  :9090    │
        └──────────┘        └──────────┘        └──────────┘
                                   │
                                   │ scrapes metrics
                                   ▼
        ┌──────────────┬──────────────┬──────────────┐
        │ GPU Worker 1 │ GPU Worker 2 │ GPU Worker N │
        │              │              │              │
        │ node_exp     │ node_exp     │ node_exp     │
        │   :9100      │   :9100      │   :9100      │
        │ dc-exporter  │ dc-exporter  │ dc-exporter  │
        │   :9835      │   :9835      │   :9835      │
        └──────────────┴──────────────┴──────────────┘
              (systemd services on each worker)
```

### Key Design Principles

1. **Single Command Setup** - `dc-overview quickstart` deploys everything
2. **Configuration Upfront** - Fleet Wizard collects all config before deployment
3. **Unified Authentication** - Single login for all services via cryptolabs-proxy
4. **Native Worker Exporters** - systemd services (not Docker) for GPU compatibility
5. **Shared Infrastructure** - Works alongside IPMI Monitor, shares proxy and network

---

## Components

### cryptolabs-proxy

The unified reverse proxy that handles:
- SSL termination (Let's Encrypt or self-signed)
- Fleet authentication (cookie-based sessions)
- Role-based access control
- Service routing

**Routes:**

| Path | Destination | Description |
|------|-------------|-------------|
| `/` | Landing page | Fleet management dashboard |
| `/dc/` | dc-overview:5001 | Server Manager |
| `/grafana/` | grafana:3000 | Dashboards |
| `/prometheus/` | prometheus:9090 | Metrics queries |
| `/ipmi/` | ipmi-monitor:5000 | BMC health (if enabled) |

### dc-exporter

GPU metrics exporter providing unique metrics not available in dcgm-exporter:

| Metric | Description |
|--------|-------------|
| `DCGM_FI_DEV_VRAM_TEMP` | VRAM/Memory temperature |
| `DCGM_FI_DEV_HOT_SPOT_TEMP` | Hotspot/Junction temperature |
| `DCGM_FI_DEV_CLOCKS_THROTTLE_REASON` | Throttle reasons |
| `GPU_ERROR_STATE` | GPU health status |

### node_exporter

Standard Prometheus exporter for system metrics:
- CPU utilization and temperature
- Memory usage
- Disk I/O and capacity
- Network throughput

---

## User Authentication

### Role Hierarchy

| Role | Description | Capabilities |
|------|-------------|--------------|
| `admin` | Full access | All operations, user management |
| `readwrite` | Edit access | Modify servers, settings, no user mgmt |
| `readonly` | View only | Dashboard viewing, no modifications |

### Authentication Flow

1. User logs into Fleet Management landing page (`https://domain/`)
2. Proxy sets authentication headers on all requests
3. Sub-services read headers and auto-authenticate users

### Grafana Role Mapping

Fleet roles automatically map to Grafana roles:

| Fleet Role | Grafana Role |
|------------|--------------|
| `admin` | Admin |
| `readwrite` | Editor |
| `readonly` | Viewer |

---

## CLI Commands

### Setup & Deployment

```bash
dc-overview quickstart              # Interactive setup wizard
dc-overview quickstart -c FILE -y   # Deploy from config file (no prompts)
```

### Container Management

```bash
dc-overview status                  # Show container status
dc-overview logs [-f] [SERVICE]     # View logs
dc-overview stop                    # Stop all containers
dc-overview start                   # Start all containers
dc-overview restart                 # Restart containers
dc-overview upgrade                 # Pull latest images and restart
```

### Worker Management

```bash
dc-overview install-exporters       # Install exporters locally
dc-overview add-machine IP          # Add a worker to monitor
```

### SSL/Proxy

```bash
dc-overview setup-ssl               # Configure HTTPS
```

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

### Accessing Dashboards

After deployment, access dashboards at:
- `https://your-domain/grafana/`

Default credentials are set during quickstart configuration.

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

### Common Issues

#### Containers won't start

```bash
# Check Docker is running
systemctl status docker

# Check port conflicts
netstat -tlnp | grep -E '443|3000|9090'

# Check logs for errors
docker logs cryptolabs-proxy
```

#### Can't access web interface

1. Verify containers are running: `docker ps`
2. Check firewall allows ports 80/443
3. Verify DNS points to your server
4. Check SSL certificate: `docker logs cryptolabs-proxy | grep -i ssl`

#### Exporters not reporting metrics

```bash
# Test from master server
curl http://worker-ip:9100/metrics  # node_exporter
curl http://worker-ip:9835/metrics  # dc-exporter

# Check exporter service on worker
systemctl status node_exporter
systemctl status dc-exporter
```

#### Prometheus not scraping targets

```bash
# Check Prometheus targets
curl http://localhost:9090/api/v1/targets

# Reload Prometheus config
docker exec prometheus kill -HUP 1

# Check config syntax
docker exec prometheus promtool check config /etc/prometheus/prometheus.yml
```

### Update to Latest

```bash
dc-overview upgrade              # Pull and restart containers
pip install --upgrade dc-overview  # Update CLI tool
```

---

## FAQ

### Q: Can I use this with Vast.ai or RunPod?

Yes! Worker exporters run as native systemd services (not Docker), making them fully compatible with GPU rental platforms. Enable the dedicated exporters to track:
- **Vast.ai**: Earnings, rental status, GPU utilization per machine
- **RunPod**: Earnings, GPU utilization, reliability metrics (supports multiple accounts)

When IPMI Monitor is also enabled with SSH, dc-overview automatically configures log collection for Vast.ai Daemon Logs and RunPod Agent Logs.

### Q: What GPUs are supported?

DC Overview supports all NVIDIA GPUs with nvidia-smi support:
- Consumer: RTX 4090, 4080, 4070, 3090, 3080, 3070
- Professional: RTX A6000, A5000, A4500, A4000
- Datacenter: H100, A100, A40, L40S, L4

### Q: Can I use this with Vast.ai or RunPod?

Yes! Worker exporters run as native systemd services (not Docker), making them fully compatible with GPU rental platforms.

### Q: How do I add more servers after initial setup?

Use the Server Manager UI at `/dc/` or run:
```bash
dc-overview add-machine IP
```

### Q: How do I change my admin password?

1. Go to Fleet Management landing page
2. Click on user settings
3. Change password

Or update the config file and redeploy:
```bash
sudo dc-overview quickstart -c config.yaml -y
```

### Q: Does this work without internet access?

Yes, after initial deployment. The system stores all data locally. Only initial Docker image pulls require internet.

### Q: How much disk space is needed?

- Master server: ~5GB for containers + metrics retention (configurable, default 30 days)
- Workers: ~100MB for exporters

---

## Support

### Resources

- **GitHub**: [github.com/cryptolabsza/dc-overview](https://github.com/cryptolabsza/dc-overview)
- **Issues**: [github.com/cryptolabsza/dc-overview/issues](https://github.com/cryptolabsza/dc-overview/issues)
- **Discord**: [Join our Discord](https://discord.gg/7yeHdf5BuC)

### Related Products

| Product | Description |
|---------|-------------|
| [IPMI Monitor](https://www.cryptolabs.co.za/ipmi-monitor-support-documentation/) | BMC/IPMI hardware monitoring with AI insights |
| [DC Exporter](https://github.com/cryptolabsza/dc-exporter-releases) | Standalone GPU metrics exporter |
| [CryptoLabs Proxy](https://github.com/cryptolabsza/cryptolabs-proxy) | Unified reverse proxy with authentication |

### Contact

- **Email**: support@cryptolabs.co.za
- **Website**: [cryptolabs.co.za](https://cryptolabs.co.za)

---

*DC Overview is open source software released under the MIT license.*

*Made with care by CryptoLabs*
