# DC Overview

[![PyPI](https://img.shields.io/pypi/v/dc-overview.svg)](https://pypi.org/project/dc-overview/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Complete GPU datacenter monitoring suite.** Monitor your GPU servers with Prometheus, Grafana, and optional AI-powered insights.

![Dashboard](docs/dashboard.png)

## ✨ What's Included

| Component | Description | Port |
|-----------|-------------|------|
| **Prometheus** | Time-series database for metrics | 9090 |
| **Grafana** | Beautiful dashboards and alerting | 3000 |
| **node_exporter** | CPU, RAM, disk, network metrics | 9100 |
| **dcgm-exporter** | NVIDIA GPU metrics (utilization, temp, power) | 9400 |
| **dc-exporter** | VRAM temperature, hotspot, fan speed | 9500 |
| **vastai-exporter** | Vast.ai earnings and reliability (optional) | 8622 |

---

## 🚀 Quick Start

### One Command Setup

```bash
pip install dc-overview
sudo dc-overview quickstart
```

The wizard guides you through everything:

```
╭──────────────────────────────────────────────────╮
│           DC Overview - Quick Setup              │
╰──────────────────────────────────────────────────╯

Step 1: What is this machine?
  ○ GPU Worker (has GPUs to monitor)
  ● Master Server (monitors other machines)
  ○ Both (has GPUs + monitors others)

Step 2: Setting up Monitoring Dashboard
  Set Grafana admin password: ******
  ✓ Prometheus running on port 9090
  ✓ Grafana running on port 3000

Step 3: Add Machines to Monitor
  How do you want to add servers?
    ● Import from file/paste (recommended)
    ○ Enter manually

  Paste your server list:
  global:root,mypassword
  192.168.1.101
  192.168.1.102
  192.168.1.103
  [Enter]

  Installing on 192.168.1.101... ✓
  Installing on 192.168.1.102... ✓
  Installing on 192.168.1.103... ✓
  ✓ Added 3 workers to Prometheus

Step 4: Vast.ai Integration (Optional)
  Are you a Vast.ai provider? [y/N]: y
  Vast.ai API Key: ******
  ✓ vastai-exporter running (port 8622)

✓ Setup Complete!
  Grafana: http://192.168.1.100:3000
```

---

## 📋 Import File Format

Create a simple text file to add many servers at once:

### Option 1: Global credentials (same for all)
```
global:root,mypassword
192.168.1.101
192.168.1.102
192.168.1.103
192.168.1.104
```

### Option 2: Per-server credentials
```
192.168.1.101,root,password1
192.168.1.102,ubuntu,password2
192.168.1.103,admin,password3
```

### Option 3: Mixed (global default + overrides)
```
global:root,defaultpass
192.168.1.101
192.168.1.102,ubuntu,custompass
192.168.1.103
```

---

## 🔧 Manual Installation

### On Master Server (monitoring hub)

```bash
pip install dc-overview
sudo dc-overview quickstart
# Select "Master Server"
```

### On GPU Workers

```bash
pip install dc-overview
sudo dc-overview quickstart
# Select "GPU Worker"
```

Or from the master, provide SSH credentials and the wizard installs remotely.

---

## 📊 Available Commands

```bash
dc-overview quickstart          # ⚡ One-command setup (recommended)
dc-overview status              # Check what's running
dc-overview add-machine IP      # Add another machine to monitor
dc-overview install-exporters   # Install exporters on current machine
```

---

## 🐳 Docker Alternative

If you prefer Docker Compose:

```yaml
# docker-compose.yml
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    ports: ["9090:9090"]
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports: ["3000:3000"]
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

---

## 🔗 Related Tools

| Tool | Purpose | Install |
|------|---------|---------|
| [IPMI Monitor](https://github.com/cryptolabsza/ipmi-monitor) | Server health, SEL logs, ECC errors | `pip install ipmi-monitor` |
| [dc-exporter](https://github.com/cryptolabsza/dc-exporter) | GPU VRAM temperatures | Included in quickstart |

---

## 📖 Full Suite Setup (Master + Workers)

For a complete datacenter setup with IPMI monitoring:

### 1. On Master Server
```bash
# Install dc-overview (Grafana + Prometheus)
pip install dc-overview
sudo dc-overview quickstart
# Select "Master Server", add your workers

# Install ipmi-monitor (optional - for BMC/IPMI)
pip install ipmi-monitor
sudo ipmi-monitor quickstart
```

### 2. Workers are configured automatically
The quickstart installs exporters on workers via SSH.

### 3. Import your servers
Create `servers.txt`:
```
global:root,sshpassword
192.168.1.101
192.168.1.102
192.168.1.103
```

Then paste when prompted, or run:
```bash
dc-overview add-machine 192.168.1.101 --ssh-pass mypassword
```

---

## 💬 Support

- **Discord**: https://discord.gg/7yeHdf5BuC
- **Issues**: https://github.com/cryptolabsza/dc-overview/issues

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.
