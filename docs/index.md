---
layout: default
title: DC Overview Documentation
---

# DC Overview

**Complete GPU Datacenter Monitoring Suite**

[![PyPI](https://img.shields.io/pypi/v/dc-overview.svg)](https://pypi.org/project/dc-overview/)
[![Docker Build](https://github.com/cryptolabsza/dc-overview/actions/workflows/docker-build.yml/badge.svg)](https://github.com/cryptolabsza/dc-overview/actions/workflows/docker-build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Deploy Prometheus, Grafana, and GPU monitoring with a single command. Features unified authentication through Fleet Management and seamless integration with [IPMI Monitor](https://www.cryptolabs.co.za/ipmi-monitor-support-documentation/).

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Full Documentation](https://www.cryptolabs.co.za/dc-overview-support-documentation/) | Complete guide on CryptoLabs website |
| [Architecture](ARCHITECTURE.html) | Technical architecture and component details |
| [GitHub Repository](https://github.com/cryptolabsza/dc-overview) | Source code and issues |

---

## Quick Start

### Automated Deployment (Recommended)

```bash
# Install from dev branch (latest features)
pip install git+https://github.com/cryptolabsza/dc-overview.git@dev --break-system-packages

# Deploy with config file (no prompts)
sudo dc-overview quickstart -c /path/to/config.yaml -y
```

### Interactive Setup

```bash
pip install dc-overview
sudo dc-overview quickstart
```

The Fleet Wizard guides you through all configuration options and deploys everything automatically.

---

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
        └──────────┘        └──────────┘        └──────────┘
                                   │
                                   │ scrapes metrics
                                   ▼
        ┌──────────────┬──────────────┬──────────────┐
        │ GPU Worker 1 │ GPU Worker 2 │ GPU Worker N │
        │ node_exp     │ node_exp     │ node_exp     │
        │ dc-exporter  │ dc-exporter  │ dc-exporter  │
        └──────────────┴──────────────┴──────────────┘
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
```

---

## Configuration Example

```yaml
site_name: My Datacenter  # Appears in landing page and IPMI Monitor

fleet_admin_user: admin
fleet_admin_pass: YOUR_ADMIN_PASSWORD

ssh:
  username: root
  key_path: ~/.ssh/id_rsa

bmc:
  username: admin
  password: YOUR_BMC_PASSWORD

ssl:
  mode: letsencrypt
  domain: monitoring.example.com
  email: admin@example.com

components:
  dc_overview: true
  ipmi_monitor: true
  vast_exporter: false
  runpod_exporter: false

# RunPod API Keys (supports multiple accounts)
runpod:
  api_keys:
    - key: YOUR_RUNPOD_API_KEY
      label: main-account

servers:
  - name: gpu-01
    server_ip: 192.168.1.101
    bmc_ip: 192.168.1.201

grafana:
  admin_password: YOUR_GRAFANA_PASSWORD
```

---

## Grafana Dashboards

Pre-installed dashboards (auto-scaled to fit your fleet):

| Dashboard | Description |
|-----------|-------------|
| **DC Overview** | Fleet overview with all GPU metrics |
| **DC Exporter Details** | VRAM temp, hotspot, power, PCIe errors |
| **Node Exporter Full** | CPU, RAM, disk, network |
| **NVIDIA DCGM Exporter** | GPU performance metrics |
| **Vast Dashboard** | Vast.ai provider earnings & machine status |
| **RunPod Dashboard** | RunPod earnings, GPU utilization & reliability |
| **IPMI Monitor** | BMC/IPMI sensor data |

---

## Support

- **Full Documentation**: [cryptolabs.co.za/dc-overview-support-documentation](https://www.cryptolabs.co.za/dc-overview-support-documentation/)
- **GitHub**: [github.com/cryptolabsza/dc-overview](https://github.com/cryptolabsza/dc-overview)
- **Discord**: [Join our Discord](https://discord.gg/7yeHdf5BuC)
- **Email**: support@cryptolabs.co.za

---

## Related Products

| Product | Description |
|---------|-------------|
| [IPMI Monitor](https://www.cryptolabs.co.za/ipmi-monitor-support-documentation/) | BMC/IPMI hardware monitoring with AI insights |
| [DC Exporter](https://github.com/cryptolabsza/dc-exporter-releases) | Standalone GPU metrics exporter with Grafana dashboard |
| [CryptoLabs Proxy](https://github.com/cryptolabsza/cryptolabs-proxy) | Unified reverse proxy with authentication |

---

**MIT License** · Made with care by [CryptoLabs](https://cryptolabs.co.za)
