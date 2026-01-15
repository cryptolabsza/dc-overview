# Introducing DC-Overview: Complete GPU Datacenter Monitoring Made Simple

**Stop flying blind in your GPU datacenter. DC-Overview gives you real-time visibility into every GPU, every server, and every metric that matters.**

---

## The Problem: GPU Monitoring is Hard

If you're running a GPU datacenter - whether for AI training, rendering, or GPU-as-a-service platforms like Vast.ai or RunPod - you know the pain:

- **Temperature spikes** can damage expensive GPUs before you notice
- **VRAM temperatures** aren't exposed by standard tools
- **Multiple servers** means multiple dashboards, multiple SSH sessions, multiple headaches
- **Clients complain** about performance issues you can't diagnose
- **Revenue loss** when machines go down undetected

Traditional monitoring tools weren't built for GPU datacenters. They miss the metrics that matter most.

---

## The Solution: DC-Overview

DC-Overview is an open-source monitoring stack specifically designed for GPU datacenters. It combines:

- **Prometheus** for time-series data collection
- **Grafana** for beautiful, actionable dashboards
- **Custom exporters** for GPU-specific metrics (VRAM temps, hotspot temps, fan speeds)
- **Native installation** on GPU workers (no containers to conflict with client workloads)

![DC-Overview Dashboard](images/grafana-overview.png)
*Real-time view of your entire GPU fleet - earnings, reliability, and status at a glance*

---

## What Makes DC-Overview Different?

### 1. VRAM Temperature Monitoring

Standard GPU monitoring tools only show core temperature. But VRAM overheating is the silent killer of GPUs, especially under heavy AI workloads.

DC-Overview includes **dc-exporter**, our custom Prometheus exporter that reads VRAM temperatures directly from the GPU hardware - even for consumer GPUs like RTX 4090s.

![GPU Temperature Dashboard](images/grafana-gpu-temps.png)
*Monitor VRAM temps, hotspot temps, fan speeds, and power draw across your entire fleet*

### 2. No Containers on GPU Workers

Many GPU rental platforms (RunPod, Vast.ai) don't allow nested containers. Even if they did, running monitoring containers can interfere with client workloads.

DC-Overview installs exporters as **lightweight native systemd services** on GPU workers. Only the master server runs containers.

### 3. Secure by Default

Every installation includes:
- **HTTPS with SSL certificates** (self-signed or Let's Encrypt)
- **Nginx reverse proxy** for secure access
- **Prometheus locked to localhost** (no accidental exposure)

### 4. Works with Vast.ai and RunPod

Built-in dashboards for Vast.ai providers show:
- Pending payouts
- Income per hour/day
- Machine reliability scores
- GPU utilization across your fleet

---

## Quick Start (15 Minutes)

### Master Server (Monitoring Hub)

```bash
# Clone the repo
git clone https://github.com/cryptolabsza/dc-overview.git
cd dc-overview/server

# Configure
cp .env.example .env
nano .env  # Set your passwords

# Deploy
docker compose up -d

# Set up HTTPS
apt install -y nginx openssl
# Follow the SSL setup guide in the README
```

### GPU Workers (Exporters)

```bash
# Install node_exporter (system metrics)
bash <(curl -s https://raw.githubusercontent.com/cryptolabsza/dc-overview/main/client/install_node_exporter.sh)

# Install dcgm-exporter (GPU metrics)
bash <(curl -s https://raw.githubusercontent.com/cryptolabsza/dc-overview/main/client/install_NvidiaDCGM_Exporter.sh)

# Install dc-exporter (VRAM temps)
wget https://github.com/cryptolabsza/dc-exporter/releases/latest/download/dc-exporter-collector
wget https://github.com/cryptolabsza/dc-exporter/releases/latest/download/dc-exporter-server
# Follow installation guide
```

That's it. Your GPU datacenter is now fully monitored.

---

## Features at a Glance

| Feature | Description |
|---------|-------------|
| **GPU Metrics** | Core temp, VRAM temp, hotspot temp, power, utilization |
| **System Metrics** | CPU, RAM, disk, network via node_exporter |
| **Vast.ai Integration** | Earnings, reliability, machine status |
| **Alerting** | Grafana alerts for temperature, errors, offline machines |
| **Historical Data** | 30 days retention by default (configurable) |
| **Secure Access** | HTTPS, authentication, reverse proxy |
| **Open Source** | MIT licensed, fully customizable |

---

## Supported Hardware

| GPU Type | Core Temp | VRAM Temp | Hotspot | Fan Speed |
|----------|-----------|-----------|---------|-----------|
| RTX 4090/4080/4070 | ✅ | ✅ | ✅ | ✅ |
| RTX 3090/3080/3070 | ✅ | ✅ | ✅ | ✅ |
| RTX A6000/A5000 | ✅ | ✅ | ✅ | ✅ |
| A100/H100 (Datacenter) | ✅ | ✅ | ✅ | N/A* |

*Datacenter GPUs use chassis cooling

---

## What Our Users Say

> "Finally, a monitoring solution that shows VRAM temps. Saved me from frying a 4090 that was running hot under the heatsink."
> — GPU Datacenter Operator

> "The Vast.ai dashboard alone is worth the setup time. I can see exactly how each machine is performing."
> — Vast.ai Provider

---

## Get Started Today

DC-Overview is **free and open source**.

- **GitHub**: [github.com/cryptolabsza/dc-overview](https://github.com/cryptolabsza/dc-overview)
- **Documentation**: Full setup guide in the README
- **Support**: [Discord](https://discord.gg/cryptolabs) | support@cryptolabs.co.za

### Related Tools

- **[dc-exporter](https://github.com/cryptolabsza/dc-exporter)** - VRAM temperature exporter
- **[ipmi-monitor](https://github.com/cryptolabsza/ipmi-monitor)** - IPMI/BMC monitoring with AI insights
- **[dc-watchdog](https://github.com/cryptolabsza/dc-watchdog)** - External uptime monitoring

---

*DC-Overview is developed by [CryptoLabs](https://cryptolabs.co.za), helping GPU datacenter operators monitor, optimize, and scale their infrastructure.*
