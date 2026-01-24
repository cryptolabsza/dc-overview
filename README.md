# DC Overview

[![PyPI](https://img.shields.io/pypi/v/dc-overview.svg)](https://pypi.org/project/dc-overview/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io-blue)](https://github.com/cryptolabsza/dc-overview/pkgs/container/dc-overview)

**Complete GPU datacenter monitoring suite.** Deploy Prometheus, Grafana, and GPU monitoring with a single command. Integrates seamlessly with [IPMI Monitor](https://github.com/cryptolabsza/ipmi-monitor).

![Dashboard](docs/images/grafana-overview.png)

## What's Included

| Component | Description | Port |
|-----------|-------------|------|
| **DC Overview** | Web UI for managing workers | 5001 |
| **Prometheus** | Time-series metrics database | 9090 |
| **Grafana** | Dashboards and alerting | 3000 |
| **node_exporter** | CPU, RAM, disk metrics | 9100 |
| **dc-exporter** | GPU VRAM temps, hotspot, power | 9835 |
| **vastai-exporter** | Vast.ai earnings (optional) | 8622 |
| **cryptolabs-proxy** | HTTPS reverse proxy | 443 |

---

## Quick Start

### One Command Setup

```bash
# Install
pipx install dc-overview

# Run quickstart (does everything)
sudo dc-overview quickstart
```

The quickstart wizard will:
1. **Detect existing ipmi-monitor** and import servers/SSH keys
2. **Set up Docker containers** (dc-overview, prometheus, grafana)
3. **Configure HTTPS proxy** (cryptolabs-proxy)
4. **Install exporters** on GPU workers via SSH

### If IPMI Monitor Already Installed

DC Overview automatically detects your existing setup:

```
✓ IPMI Monitor Detected!
Found existing IPMI Monitor installation with servers and SSH keys.

Import servers and SSH keys from IPMI Monitor? [Y/n]

✓ Imported 12 servers from IPMI Monitor
✓ Imported 2 SSH keys from IPMI Monitor
✓ CryptoLabs Proxy Already Running!

Install dc-exporter on 12 servers? [Y/n]
  Installing on gpu-01 (192.168.1.101)... ✓
  Installing on gpu-02 (192.168.1.102)... ✓
  ...
```

---

## CLI Commands

```bash
# Setup & Status
dc-overview quickstart        # One-command setup wizard
dc-overview status            # Show container and exporter status

# Docker Container Management
dc-overview logs [-f]         # View container logs
dc-overview stop              # Stop all containers
dc-overview start             # Start all containers
dc-overview restart           # Restart containers
dc-overview upgrade           # Pull latest images and restart

# Worker Management
dc-overview install-exporters # Install exporters on current machine
dc-overview add-machine IP    # Add a worker to monitor

# SSL/Proxy
dc-overview setup-ssl         # Configure HTTPS reverse proxy
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     MASTER SERVER (Docker)                       │
│  ┌─────────────┐  ┌───────────┐  ┌─────────┐  ┌──────────────┐ │
│  │ dc-overview │  │prometheus │  │ grafana │  │cryptolabs-   │ │
│  │   :5001     │  │   :9090   │  │  :3000  │  │proxy :443    │ │
│  └─────────────┘  └───────────┘  └─────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────────┘
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
(Native services)     (Native services)     (Native services)
```

**Master**: Docker containers for easy management and updates  
**Workers**: Native systemd services for maximum GPU compatibility (required for Vast.ai, RunPod, etc.)

---

## Installation Options

### Ubuntu 24.04+ / Python 3.12+
```bash
sudo apt install pipx -y
pipx install dc-overview
pipx ensurepath && source ~/.bashrc
sudo dc-overview quickstart
```

### Ubuntu 22.04 / Python 3.10
```bash
pip install dc-overview
sudo dc-overview quickstart
```

### From GitHub (Development)
```bash
pipx install "git+https://github.com/cryptolabsza/dc-overview.git@dev"
sudo dc-overview quickstart
```

---

## Access URLs

After setup, access your monitoring at:

| Service | Direct | Via Proxy |
|---------|--------|-----------|
| DC Overview | `http://IP:5001` | `https://IP/dc/` |
| Grafana | `http://IP:3000` | `https://IP/grafana/` |
| Prometheus | `http://IP:9090` | `https://IP/prometheus/` |
| Landing Page | - | `https://IP/` |

---

## Port Reference

| Service | Port | Description |
|---------|------|-------------|
| dc-overview | 5001 | Web UI (configurable) |
| ipmi-monitor | 5000 | BMC/IPMI monitoring |
| grafana | 3000 | Dashboards |
| prometheus | 9090 | Metrics database |
| node_exporter | 9100 | System metrics |
| dc-exporter | 9835 | GPU metrics |
| dcgm-exporter | 9400 | NVIDIA DCGM |
| vastai-exporter | 8622 | Vast.ai earnings |
| runpod-exporter | 8623 | RunPod (planned) |
| hivefleet-exporter | 8624 | HiveFleet (planned) |

---

## Integration with IPMI Monitor

DC Overview and IPMI Monitor work together:

```bash
# Install both on the same master server
pipx install ipmi-monitor
sudo ipmi-monitor quickstart

pipx install dc-overview  
sudo dc-overview quickstart  # Automatically imports from ipmi-monitor
```

Both share:
- **cryptolabs-proxy** (unified HTTPS reverse proxy)
- **Server list** (imported from ipmi-monitor)
- **SSH keys** (copied to dc-overview)
- **Watchtower** (auto-updates for both)

---

## Manual Worker Setup

If automatic SSH deployment fails, install exporters manually on GPU workers:

```bash
# On each GPU worker
pip install dc-overview
sudo dc-overview install-exporters
```

Or install individually:

```bash
# Node Exporter (system metrics)
wget https://github.com/prometheus/node_exporter/releases/download/v1.7.0/node_exporter-1.7.0.linux-amd64.tar.gz
tar xzf node_exporter-*.tar.gz
sudo cp node_exporter-*/node_exporter /usr/local/bin/
sudo systemctl enable --now node_exporter

# DC Exporter (GPU metrics)
wget https://github.com/cryptolabsza/dc-exporter/releases/latest/download/dc-exporter-collector -O /usr/local/bin/dc-exporter
chmod +x /usr/local/bin/dc-exporter
sudo systemctl enable --now dc-exporter
```

---

## Grafana Dashboards

Pre-installed dashboards:

| Dashboard | Description |
|-----------|-------------|
| **DC Overview** | Fleet overview with all GPU metrics |
| **Node Exporter Full** | CPU, RAM, disk, network |
| **NVIDIA DCGM** | GPU performance metrics |
| **Vast Dashboard** | Vast.ai provider earnings |
| **IPMI Monitor** | BMC/IPMI sensor data |

---

## Troubleshooting

### Check container status
```bash
dc-overview status
docker ps
```

### View logs
```bash
dc-overview logs -f
dc-overview logs grafana
dc-overview logs prometheus
```

### Restart services
```bash
dc-overview restart
```

### Update to latest version
```bash
dc-overview upgrade
pipx upgrade dc-overview
```

### Check exporter connectivity
```bash
curl http://worker-ip:9100/metrics  # node_exporter
curl http://worker-ip:9835/metrics  # dc-exporter
```

---

## Related Projects

| Project | Description |
|---------|-------------|
| [ipmi-monitor](https://github.com/cryptolabsza/ipmi-monitor) | BMC/IPMI health monitoring |
| [dc-exporter](https://github.com/cryptolabsza/dc-exporter) | GPU VRAM temperature exporter |
| [cryptolabs-proxy](https://github.com/cryptolabsza/cryptolabs-proxy) | Unified reverse proxy |

---

## Support

- **Discord**: https://discord.gg/7yeHdf5BuC
- **Issues**: https://github.com/cryptolabsza/dc-overview/issues

---

## License

MIT License - see [LICENSE](LICENSE) for details.
