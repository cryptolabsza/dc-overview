# DC-Overview

## Complete GPU Datacenter Monitoring

**See everything. Miss nothing. Keep your GPUs healthy and your revenue flowing.**

[Get Started](https://github.com/cryptolabsza/dc-overview) | [Documentation](#documentation) | [Support](#support)

---

## Your GPU Datacenter, At a Glance

![DC-Overview Dashboard](images/grafana-overview.png)

DC-Overview is the monitoring solution built specifically for GPU datacenters. Whether you're running 4 GPUs or 400, DC-Overview gives you the visibility you need to:

- **Prevent failures** before they cost you money
- **Optimize performance** with real-time metrics
- **Maximize uptime** with intelligent alerting
- **Track revenue** with Vast.ai/RunPod integration

---

## Key Features

### GPU Health Monitoring

![GPU Temperatures](images/grafana-gpu-temps.png)

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
┌─────────────────────────────────────────────────────────────┐
│                     MASTER SERVER                            │
│  ┌──────────┐  ┌────────────┐  ┌──────────────────────────┐ │
│  │ Grafana  │  │ Prometheus │  │ Optional: ipmi-monitor,  │ │
│  │ (UI)     │  │ (metrics)  │  │ vastai-exporter, etc.    │ │
│  └──────────┘  └────────────┘  └──────────────────────────┘ │
│       ↑              ↑                                       │
│       └──────────────┼───────────────────────────────────────┤
│                      │ scrapes metrics                       │
└──────────────────────┼───────────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ GPU Worker 1 │ │ GPU Worker 2 │ │ GPU Worker N │
│              │ │              │ │              │
│ • node_exp   │ │ • node_exp   │ │ • node_exp   │
│ • dcgm-exp   │ │ • dcgm-exp   │ │ • dcgm-exp   │
│ • dc-exporter│ │ • dc-exporter│ │ • dc-exporter│
│              │ │              │ │              │
│ Ports:       │ │ Ports:       │ │ Ports:       │
│ 9100, 9400,  │ │ 9100, 9400,  │ │ 9100, 9400,  │
│ 9500         │ │ 9500         │ │ 9500         │
└──────────────┘ └──────────────┘ └──────────────┘
```

**No containers on GPU workers** - Native systemd services only. Works with RunPod, Vast.ai, and any environment.

---

## Quick Installation

### Master Server (5 minutes)

```bash
git clone https://github.com/cryptolabsza/dc-overview.git
cd dc-overview/server
cp .env.example .env && nano .env
docker compose up -d
```

### GPU Workers (2 minutes each)

```bash
# One-liner for each exporter
curl -sSL https://install.cryptolabs.co.za/dc-overview | bash
```

### Configure Prometheus

Edit `prometheus.yml` to add your workers:
```yaml
- job_name: 'gpu-worker-01'
  static_configs:
    - targets: ['192.168.1.101:9100', '192.168.1.101:9400', '192.168.1.101:9500']
```

**That's it.** Your monitoring is live.

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
