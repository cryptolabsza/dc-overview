# DC Overview

[![PyPI](https://img.shields.io/pypi/v/dc-overview.svg)](https://pypi.org/project/dc-overview/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Complete GPU datacenter monitoring suite.** Monitor your GPU servers with Prometheus, Grafana, and optional IPMI/BMC monitoring - all from a single command.

![Dashboard](docs/images/grafana-overview.png)

## ✨ What's Included

| Component | Description | Port |
|-----------|-------------|------|
| **Prometheus** | Time-series database for metrics | 9090 |
| **Grafana** | Beautiful dashboards and alerting | 3000 |
| **node_exporter** | CPU, RAM, disk, network metrics | 9100 |
| **dc-exporter** | GPU metrics (VRAM temp, hotspot, power, util, fan) | 9835 |
| **vastai-exporter** | Vast.ai earnings and reliability (optional) | 8622 |
| **IPMI Monitor** | BMC/IPMI server health monitoring (optional) | 5000 |

---

## 🚀 Quick Start (v1.1.0+)

### One Command Setup - Collect Once, Deploy Everywhere

The new unified quickstart **asks for all information upfront**, then handles everything automatically:

```bash
pip install dc-overview
sudo dc-overview quickstart
```

```
╭────────────────────────────────────────────────────────╮
│           DC Overview - Fleet Setup Wizard             │
│                                                        │
│  This wizard will collect all the information needed   │
│  to set up your datacenter monitoring.                 │
│  We'll ask everything upfront, then handle the         │
│  installation automatically.                           │
╰────────────────────────────────────────────────────────╯

STEP 1: Components to Install
  [x] DC Overview (Prometheus + Grafana + GPU dashboards)
  [ ] IPMI Monitor (BMC/IPMI server monitoring)
  [ ] Vast.ai Integration (Earnings & reliability metrics)

STEP 2: Credentials (asked once, used everywhere)
  Site name: My GPU Farm
  Grafana admin password: ******
  SSH username: root
  SSH authentication: Password / Key
  SSH password: ******
  
  (If IPMI enabled)
  BMC username: ADMIN
  BMC password: ******
  
  (If Vast.ai enabled)
  Vast.ai API Key: ******

STEP 3: Servers to Monitor
  How would you like to add servers?
    ● Import from text (recommended for many servers)
    ○ Enter servers manually
    ○ Skip for now

  Paste your server list:
  gpu-01,192.168.1.101,192.168.1.83
  gpu-02,192.168.1.102,192.168.1.85
  gpu-03,192.168.1.103,192.168.1.88
  
  ✓ Added: gpu-01 (192.168.1.101)
  ✓ Added: gpu-02 (192.168.1.102)
  ✓ Added: gpu-03 (192.168.1.103)

STEP 4: HTTPS Configuration
  Do you have a domain name? [y/N]: n
  Using self-signed certificate for IP access

STEP 5: Review & Deploy
  ✓ Configuration saved

  ━━━ Deploying DC Overview Fleet ━━━
  
  Step 1: Installing Prerequisites
    ✓ Docker installed and running
    ✓ nginx installed
    
  Step 2: Setting up SSH Keys
    ✓ SSH key generated
    Deploying to gpu-01... ✓
    Deploying to gpu-02... ✓
    Deploying to gpu-03... ✓
    
  Step 3: Starting Prometheus & Grafana
    ✓ Prometheus running on port 9090
    ✓ Grafana running on port 3000
    
  Step 4: Installing Exporters on Workers
    ✓ gpu-01 (192.168.1.101)
    ✓ gpu-02 (192.168.1.102)
    ✓ gpu-03 (192.168.1.103)
    
  Step 5: Configuring Prometheus Targets
    ✓ Prometheus configured with 4 targets
    
  Step 6: Importing Dashboards
    ✓ DC Overview
    ✓ Node Exporter Full
    ✓ NVIDIA DCGM Exporter
    
  Step 9: Setting up HTTPS Reverse Proxy
    ✓ Self-signed certificate generated
    ✓ nginx configured and running

╭────────────────────────────────────────────────────────╮
│              ✓ Deployment Complete!                    │
╰────────────────────────────────────────────────────────╯

Access Information:
  Dashboard:  https://192.168.1.100/
  Grafana:    https://192.168.1.100/grafana/
    └─ Login: admin / ******

Dashboards installed:
  • DC Overview (main dashboard)
  • Node Exporter Full (CPU/RAM/disk)
  • NVIDIA DCGM Exporter (GPU metrics)
```

### Prerequisites

- **Linux** (Ubuntu 20.04+, Debian, CentOS)
- **Python 3.9+** with pip
- **Root/sudo access** for installing services

### Installation Options

**Ubuntu 24.04+ / Python 3.12+** (uses pipx):
```bash
sudo apt install pipx -y
pipx install dc-overview
pipx ensurepath && source ~/.bashrc
sudo dc-overview quickstart
```

**Ubuntu 22.04 / Python 3.10** (direct pip):
```bash
pip install dc-overview
sudo dc-overview quickstart
```

**With IPMI Monitor integration**:
```bash
pip install dc-overview[full]
sudo dc-overview quickstart
```

> **For remote worker deployment**, set up passwordless sudo on workers:
> ```bash
> sudo bash -c 'echo "YOUR_USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/nopasswd && chmod 440 /etc/sudoers.d/nopasswd'
> ```

### Legacy Quickstart

For the previous single-machine workflow:
```bash
sudo dc-overview quickstart --legacy
```

---

## 📋 Import File Format

Create a simple text file to add many servers at once. Paste when prompted during quickstart.

### Option 1: Just Server IPs (SSH only)
```
192.168.1.101
192.168.1.102
192.168.1.103
```

### Option 2: Server IP + BMC IP (for IPMI monitoring)
```
192.168.1.101,192.168.1.83
192.168.1.102,192.168.1.85
192.168.1.103,192.168.1.88
```

### Option 3: Name, Server IP, BMC IP (recommended)
```
gpu-01,192.168.1.101,192.168.1.83
gpu-02,192.168.1.102,192.168.1.85
gpu-03,192.168.1.103,192.168.1.88
```

### Legacy Format (for --legacy quickstart)

```
global:root,mypassword
192.168.1.101
192.168.1.102
192.168.1.103
```

Or per-server credentials:
```
192.168.1.101,root,password1
192.168.1.102,ubuntu,password2
192.168.1.103,admin,password3
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
# Main commands
dc-overview quickstart          # ⚡ Unified setup wizard (asks once, deploys everywhere)
dc-overview quickstart --legacy # Old single-machine workflow
dc-overview status              # Check what's running
dc-overview add-machine IP      # Add another machine to monitor

# Exporter management
dc-overview install-exporters   # Install exporters on current machine

# Deployment commands
dc-overview deploy wizard       # Interactive deployment wizard
dc-overview deploy add          # Add workers interactively
dc-overview deploy bulk         # Bulk add workers
dc-overview deploy list         # List all workers with status
dc-overview deploy install      # Install exporters on workers
dc-overview deploy ssh-key      # Generate/deploy SSH keys
dc-overview deploy vast         # Set up Vast.ai exporter

# SSL/Reverse Proxy
dc-overview setup-ssl           # Set up reverse proxy with SSL
```

---

## 🔒 Reverse Proxy & SSL Setup

Set up a secure HTTPS frontend with a branded landing page:

### Self-Signed Certificate (Default)

```bash
# Basic setup (IP access only)
sudo dc-overview setup-ssl

# With custom site name
sudo dc-overview setup-ssl --site-name "My GPU Farm"

# Include IPMI Monitor
sudo dc-overview setup-ssl --ipmi --vastai
```

### Let's Encrypt (Free SSL)

For a valid SSL certificate (no browser warnings):

```bash
sudo dc-overview setup-ssl \
  --domain monitor.example.com \
  --letsencrypt \
  --email admin@example.com \
  --ipmi --vastai
```

### DNS Setup (Required for Domain)

Add these DNS records pointing to your server IP:

| Type | Name | Value | Purpose |
|------|------|-------|---------|
| A | `monitor.example.com` | `<server-ip>` | Main dashboard |
| A | `grafana.monitor.example.com` | `<server-ip>` | Grafana subdomain (optional) |
| A | `ipmi.monitor.example.com` | `<server-ip>` | IPMI subdomain (optional) |

### After Setup

Access your monitoring at:

```
https://<server-ip>/           # Landing page
https://<server-ip>/grafana/   # Grafana dashboards
https://<server-ip>/prometheus/# Prometheus UI
https://<server-ip>/ipmi/      # IPMI Monitor (if enabled)
```

Or with domain:
```
https://monitor.example.com/
https://grafana.monitor.example.com/  (if subdomain configured)
```

---

## 🛠️ Manual Installation (No pip/quickstart)

If you prefer full control or can't use the automatic installer, use the configuration templates in `config-templates/`.

### Directory Structure

```
config-templates/
├── docker-compose.yml              # Prometheus + Grafana stack
├── prometheus.yml                  # Scrape configuration (edit IPs)
├── recording_rules.yml             # Unified metrics (gpu:*, fleet:*)
├── nginx.conf                      # Reverse proxy with SSL
├── env-example.txt                 # Environment variables
├── grafana/provisioning/
│   └── datasources/prometheus.yml  # Auto-configure datasource
└── systemd/
    ├── node-exporter.service       # System metrics
    ├── dcgm-exporter.service       # NVIDIA GPU metrics
    └── dc-exporter.service         # VRAM/Hotspot temps
```

### Step 1: Master Server Setup

```bash
# Create directories
sudo mkdir -p /etc/dc-overview/ssl
sudo mkdir -p /root/dc-overview/grafana/provisioning/datasources
sudo mkdir -p /root/.config/dc-overview

# Copy configuration files (from this repo)
cp config-templates/docker-compose.yml /root/
cp config-templates/prometheus.yml /root/.config/dc-overview/
cp config-templates/recording_rules.yml /root/.config/dc-overview/
cp config-templates/grafana/provisioning/datasources/prometheus.yml \
   /root/dc-overview/grafana/provisioning/datasources/

# Edit prometheus.yml - replace IPs with your servers
nano /root/.config/dc-overview/prometheus.yml

# Generate self-signed SSL certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/dc-overview/ssl/server.key \
  -out /etc/dc-overview/ssl/server.crt \
  -subj "/CN=dc-overview"

# Set up Nginx reverse proxy
cp config-templates/nginx.conf /etc/nginx/sites-available/dc-overview
ln -sf /etc/nginx/sites-available/dc-overview /etc/nginx/sites-enabled/
htpasswd -c /etc/nginx/.htpasswd_prometheus admin  # Set Prometheus password
nginx -t && systemctl reload nginx

# Start monitoring stack
cd /root
docker compose up -d
```

### Step 2: Worker Server Setup (Each GPU Server)

#### Install Node Exporter (System Metrics)

```bash
# Download and install
wget https://github.com/prometheus/node_exporter/releases/download/v1.7.0/node_exporter-1.7.0.linux-amd64.tar.gz
tar xvf node_exporter-*.tar.gz
sudo cp node_exporter-*/node_exporter /usr/local/bin/
sudo useradd -rs /bin/false node_exporter

# Create service
sudo cp config-templates/systemd/node-exporter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now node-exporter

# Verify: curl http://localhost:9100/metrics
```

#### Install DCGM Exporter (GPU Metrics)

```bash
# Install DCGM (NVIDIA Data Center GPU Manager)
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt update
sudo apt install -y datacenter-gpu-manager

# Build dcgm-exporter from source
git clone https://github.com/NVIDIA/dcgm-exporter.git
cd dcgm-exporter
make binary
sudo cp cmd/dcgm-exporter/dcgm-exporter /usr/local/bin/

# Create service
sudo cp config-templates/systemd/dcgm-exporter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nvidia-dcgm dcgm-exporter

# Verify: curl http://localhost:9835/metrics
```

#### Install DC Exporter (VRAM/Hotspot Temps)

See [dc-exporter](https://github.com/cryptolabsza/dc-exporter) for installation.

```bash
# Requires: iomem=relaxed kernel parameter for direct GPU register access
# Add to /etc/default/grub: GRUB_CMDLINE_LINUX_DEFAULT="... iomem=relaxed"
# Then: sudo update-grub && reboot

# Build and install
git clone https://github.com/cryptolabsza/dc-exporter.git
cd dc-exporter
make
sudo make install
sudo systemctl enable --now dc-exporter

# Verify: curl http://localhost:9835/metrics
```

### Step 3: Update Prometheus Configuration

Edit `/root/.config/dc-overview/prometheus.yml` with your server IPs:

```yaml
scrape_configs:
  - job_name: "master"
    static_configs:
      - targets: ["192.168.1.100:9100", "192.168.1.100:9835"]

  - job_name: "worker-01"
    static_configs:
      - targets: ["192.168.1.101:9100", "192.168.1.101:9835"]

  - job_name: "dc-exporter"
    static_configs:
      - targets:
        - "192.168.1.100:9835"
        - "192.168.1.101:9835"
```

Reload Prometheus:
```bash
curl -X POST http://localhost:9090/prometheus/-/reload
```

### Step 4: Import Dashboards

Import these dashboards from `dashboards/` into Grafana:

| Dashboard | File | Description |
|-----------|------|-------------|
| DC Overview | `DC OverView-*.json` | Fleet overview with all GPU metrics |
| Node Exporter Full | `Node Exporter Full.json` | System metrics |
| NVIDIA DCGM | `NVIDIA DCGM Exporter.json` | GPU performance |
| Vast Dashboard | `Vast Dashboard.json` | Vast.ai provider metrics |

### Port Reference

| Service | Port | Metrics |
|---------|------|---------|
| Node Exporter | 9100 | `node_*` (CPU, RAM, disk) |
| DC Exporter | 9835 | `DCGM_*`, `DCXP_*` (GPU temp, VRAM, power, util) |
| DC Exporter | 9835 | `DCXP_*` (VRAM temp, hotspot, throttle) |
| Vast.ai Exporter | 8622 | `vast_machine_*` (earnings, reliability) |
| Prometheus | 9090 | Time-series DB |
| Grafana | 3000 | Dashboards |
| Nginx HTTPS | 443 | Reverse proxy |

### Recording Rules (Unified Metrics)

The `recording_rules.yml` creates unified metric names that work regardless of exporter:

```promql
# Use these in dashboards for compatibility:
gpu:core_temp:celsius       # GPU temperature
gpu:memory_temp:celsius     # VRAM temperature (DCXP or DCGM)
gpu:hotspot_temp:celsius    # Hotspot temp (DCXP or GPU temp)
gpu:power_usage:watts       # Power consumption
gpu:utilization:percent     # GPU utilization
gpu:fan_speed:percent       # Fan speed
fleet:gpu_count:total       # Total GPUs monitored
fleet:power_usage:total_watts  # Total power draw
```

---

## 🐳 Docker Alternative (Quick Reference)

Minimal docker-compose.yml for just Prometheus + Grafana:

```yaml
services:
  prometheus:
    image: prom/prometheus:latest
    ports: ["9090:9090"]
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--web.external-url=/prometheus/"

  grafana:
    image: grafana/grafana:latest
    ports: ["3000:3000"]
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    depends_on:
      - prometheus
```

For the full production setup with networking, SSL, and all features, use `config-templates/docker-compose.yml`.

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
