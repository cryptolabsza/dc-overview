# DC-Overview

## Complete GPU Datacenter Monitoring

**See everything. Miss nothing. Keep your GPUs healthy and your revenue flowing.**

[Get Started Free](https://github.com/cryptolabsza/dc-overview) | [Documentation](#documentation) | [Support](#support)

---

## Your GPU Datacenter, At a Glance

![DC-Overview Dashboard](https://raw.githubusercontent.com/cryptolabsza/dc-overview/main/docs/images/grafana-overview.png)

DC-Overview is the monitoring solution built specifically for GPU datacenters. Whether you're running 4 GPUs or 400, DC-Overview gives you the visibility you need to:

- **Prevent failures** before they cost you money
- **Optimize performance** with real-time metrics
- **Maximize uptime** with intelligent alerting
- **Track revenue** with Vast.ai/RunPod integration

---

## Key Features

### GPU Health Monitoring

![GPU Temperatures](https://raw.githubusercontent.com/cryptolabsza/dc-overview/main/docs/images/grafana-gpu-temps.png)

Monitor what matters:
- **VRAM Temperature** - The metric other tools miss
- **GPU Hotspot Temperature** - Catch thermal throttling early
- **Fan Speeds** - Ensure cooling is working
- **Power Draw** - Track actual consumption
- **Thermal Throttle Events** - Know when GPUs slow down

### System Metrics

- CPU utilization and temperature
- Memory usage
- Disk I/O and capacity
- Network throughput
- Container metrics (optional)

### Vast.ai Integration

Built-in dashboard for Vast.ai providers:
- **Pending Payouts** - Track your earnings
- **Income per Hour/Day** - Revenue metrics
- **Machine Reliability** - Performance scores
- **Utilization Rates** - Maximize ROI

### Enterprise Security

- **HTTPS by default** - Self-signed or Let's Encrypt
- **Nginx reverse proxy** - Secure access control
- **Authentication** - Grafana user management
- **Internal-only services** - Prometheus never exposed publicly

---

## Architecture

```
                        ┌───────────────────────────────────────┐
                        │         cryptolabs-proxy              │
                        │    (Landing Page & Unified Auth)      │
                        │           HTTPS :443                  │
                        └───────────────────────────────────────┘
                                        │
        ┌───────────────────────────────┼───────────────────────────────┐
        ▼                               ▼                               ▼
┌───────────────┐             ┌───────────────┐             ┌───────────────┐
│   dc-overview │             │    Grafana    │             │  Prometheus   │
│  Server Mgmt  │             │  Dashboards   │             │   Metrics     │
│     /dc/      │             │   /grafana/   │             │ /prometheus/  │
└───────────────┘             └───────────────┘             └───────────────┘
                                        │
                                        │ scrapes metrics
                                        ▼
        ┌──────────────┬──────────────┬──────────────┐
        ▼              ▼              ▼              ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ GPU Worker 1 │ │ GPU Worker 2 │ │ GPU Worker N │
│              │ │              │ │              │
│ • node_exp   │ │ • node_exp   │ │ • node_exp   │
│   :9100      │ │   :9100      │ │   :9100      │
│ • dc-exporter│ │ • dc-exporter│ │ • dc-exporter│
│   :9835      │ │   :9835      │ │   :9835      │
└──────────────┘ └──────────────┘ └──────────────┘
     (systemd)       (systemd)       (systemd)
```

**No containers on GPU workers** - Native systemd services only. Works with RunPod, Vast.ai, and any environment.

All services are accessed through [cryptolabs-proxy](https://github.com/cryptolabsza/cryptolabs-proxy) which provides unified authentication and HTTPS.

---

## Quick Installation

### Automated Deployment (Recommended)

Deploy everything with a single command:

```bash
# Install from dev branch (latest features)
pip install git+https://github.com/cryptolabsza/dc-overview.git@dev --break-system-packages

# Create your config file (copy from examples)
# See: https://github.com/cryptolabsza/dc-overview/blob/main/test-config.yaml

# Deploy with config file (no prompts)
sudo dc-overview quickstart -c /path/to/config.yaml -y
```

This automatically:
- Deploys Prometheus, Grafana, and all dashboards
- Installs exporters on GPU workers via SSH
- Sets up HTTPS with Let's Encrypt or self-signed certs
- Configures unified authentication via cryptolabs-proxy

### Interactive Setup

```bash
pip install dc-overview
sudo dc-overview quickstart
```

The Fleet Wizard guides you through all configuration options.

**That's it.** Your monitoring is live at `https://your-domain/`

---

## Supported GPUs

| GPU | VRAM Temp | Hotspot | Fan | Notes |
|-----|-----------|---------|-----|-------|
| RTX 4090 | ✅ | ✅ | ✅ | Full support |
| RTX 4080/4070 | ✅ | ✅ | ✅ | Full support |
| RTX 3090/3080 | ✅ | ✅ | ✅ | Full support |
| RTX A6000 | ✅ | ✅ | ✅ | Workstation |
| A100 | ✅ | ✅ | - | Datacenter (chassis cooling) |
| H100 | ✅ | ✅ | - | Datacenter (chassis cooling) |

---

## Pricing

### Open Source (Free)

- Full monitoring stack
- All dashboards
- Community support
- Self-hosted

[Download on GitHub →](https://github.com/cryptolabsza/dc-overview)

### Managed Service (Coming Soon)

- Hosted Grafana
- No infrastructure to maintain
- Email/Telegram alerts
- Priority support

[Join Waitlist →](mailto:sales@cryptolabs.co.za?subject=DC-Overview%20Managed%20Service%20Waitlist)

---

## Documentation

- [Full Setup Guide](https://github.com/cryptolabsza/dc-overview#readme)
- [Prometheus Configuration](https://github.com/cryptolabsza/dc-overview#prometheus-configuration)
- [GPU Worker Setup](https://github.com/cryptolabsza/dc-overview#gpu-worker-setup)
- [SSL/HTTPS Setup](https://github.com/cryptolabsza/dc-overview#nginx--ssl-setup-required)
- [Troubleshooting](https://github.com/cryptolabsza/dc-overview#troubleshooting)

---

## Related Products

### dc-exporter
VRAM temperature exporter for Prometheus. The secret sauce that makes DC-Overview see what others can't.
[Learn More →](https://github.com/cryptolabsza/dc-exporter)

### ipmi-monitor
Monitor server BMCs, power status, and hardware events. AI-powered insights for proactive maintenance.
[Learn More →](https://github.com/cryptolabsza/ipmi-monitor)

### dc-watchdog
External uptime monitoring. Know when your datacenter goes offline before your customers do.
[Learn More →](https://github.com/cryptolabsza/dc-watchdog)

---

## Support

- **Discord**: [Join our community](https://discord.gg/cryptolabs)
- **Email**: support@cryptolabs.co.za
- **GitHub Issues**: [Report bugs](https://github.com/cryptolabsza/dc-overview/issues)

---

## About CryptoLabs

CryptoLabs builds infrastructure tools for GPU datacenter operators. We run our own GPU clusters and build the tools we wish existed.

[cryptolabs.co.za](https://cryptolabs.co.za)

---

*DC-Overview is open source software released under the MIT license.*
