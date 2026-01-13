# DC Overview

[![Docker Build](https://github.com/cryptolabsza/dc-overview/actions/workflows/docker-build.yml/badge.svg)](https://github.com/cryptolabsza/dc-overview/actions/workflows/docker-build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Comprehensive Prometheus & Grafana monitoring for GPU datacenters.** Pre-configured dashboards for NVIDIA GPUs, system metrics, and container monitoring.

Part of the [CryptoLabs DC Monitoring Suite](https://cryptolabs.co.za).

![Dashboard Overview](https://github.com/jjziets/DCMontoring/assets/19214485/114c2d00-cdce-4eac-9f7f-1777b9856377)

## ✨ Features

- 🎮 **GPU VRAM & Hotspot Temps** - Metrics not available in standard DCGM
- 📊 **Thermal Throttle Detection** - Know when GPUs are throttling
- 🖥️ **Machine GPU Occupancy** - Track utilization across your fleet
- 🔗 **NVLink Support** - Monitor NVLink-connected systems
- ⚠️ **PCIe AER Errors** - Track hardware errors per device
- 📈 **Historical Charts** - Detailed GPU and system usage over time
- 📱 **Telegram Alerts** - Get notified of issues instantly

## 📸 Screenshots

| Vast Dashboard | Overview | Node Exporter |
|----------------|----------|---------------|
| ![Vast](https://github.com/jjziets/DCMontoring/assets/19214485/3e200951-8ecc-404e-8267-babfbb3856eb) | ![Overview](https://github.com/jjziets/DCMontoring/assets/19214485/114c2d00-cdce-4eac-9f7f-1777b9856377) | ![Node](https://github.com/jjziets/DCMontoring/assets/19214485/95bcbabd-09da-4174-a985-3635e09aba41) |

| NVIDIA DCGM | cAdvisor | Alerts |
|-------------|----------|--------|
| ![DCGM](https://github.com/jjziets/DCMontoring/assets/19214485/fd415556-2b51-4d98-9795-bff4ab890432) | ![cAdvisor](https://github.com/jjziets/DCMontoring/assets/19214485/676b465c-23bf-4b56-930d-8abfc86da7ce) | ![Alerts](https://github.com/jjziets/DCMontoring/assets/19214485/99633c52-7b15-44be-b601-b52539a2fe6e) |

---

## 🚀 Quick Start

### Server Installation (Monitoring Server)

```bash
# Install Docker (if not installed)
curl -fsSL https://get.docker.com | sh

# Clone and deploy
git clone https://github.com/cryptolabsza/dc-overview.git
cd dc-overview/server

# Edit prometheus.yml with your server IPs
nano prometheus.yml

# Start the stack
docker compose up -d
```

### Client Installation (GPU Servers)

**Option 1: Docker Compose (Recommended for Vast.ai)**

```bash
sudo su
apt-get update && apt-get install -y gettext-base

# Download client compose file
wget -O docker-compose.yml https://raw.githubusercontent.com/cryptolabsza/dc-overview/main/client/docker-compose.yml-vast

# Start exporters
docker compose pull
sed "s/__HOST_HOSTNAME__/$(hostname)/g" docker-compose.yml | docker compose -f - up -d
```

**Option 2: Systemd Services**

```bash
# Install VRAM temperature exporter (dc-exporter)
bash -c "$(curl -fsSL https://raw.githubusercontent.com/cryptolabsza/dc-exporter/main/install.sh)"

# Install Node Exporter
wget https://raw.githubusercontent.com/cryptolabsza/dc-overview/main/client/install_node_exporter.sh
chmod +x install_node_exporter.sh && ./install_node_exporter.sh

# Install NVIDIA DCGM Exporter
wget https://raw.githubusercontent.com/cryptolabsza/dc-overview/main/client/install_NvidiaDCGM_Exporter.sh
chmod +x install_NvidiaDCGM_Exporter.sh && ./install_NvidiaDCGM_Exporter.sh
```

---

## 🌐 Nginx Reverse Proxy with SSL

For production deployments, use Nginx with Let's Encrypt SSL.

### DNS Configuration

Create A records pointing to your monitoring server:

| Subdomain | Service | Notes |
|-----------|---------|-------|
| `grafana.yourdomain.com` | Grafana dashboards | Public OK (has built-in auth) |

> ⚠️ **IMPORTANT: Prometheus should NOT be exposed publicly!**
> 
> Prometheus has no authentication by default and exposes sensitive infrastructure data.
> Access Prometheus only via:
> - `localhost:9090` on the monitoring server
> - Internal network (e.g., `192.168.1.100:9090`)
> - SSH tunnel: `ssh -L 9090:localhost:9090 user@server`
> - VPN (Tailscale, WireGuard)

### Nginx Setup

```bash
# Install Nginx and Certbot
apt update && apt install -y nginx certbot python3-certbot-nginx

# Create Nginx config (Grafana only - Prometheus stays internal!)
cat > /etc/nginx/sites-available/dc-monitoring << 'EOF'
# Grafana - OK to expose (has authentication)
server {
    listen 80;
    server_name grafana.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

# NOTE: Prometheus (port 9090) is NOT exposed publicly!
# Access via internal network or SSH tunnel only.
EOF

# Enable site
ln -s /etc/nginx/sites-available/dc-monitoring /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# Get SSL certificate for Grafana only
certbot --nginx -d grafana.yourdomain.com
```

---

## 📊 Dashboards

Import these dashboards into Grafana:

| Dashboard | Description |
|-----------|-------------|
| [DC Overview](DC_OverView.json) | Fleet-wide GPU and system overview |
| [Node Exporter Full](Node%20Exporter%20Full-1684242153326.json) | Detailed system metrics |
| [NVIDIA DCGM](NVIDIA%20DCGM%20Exporter-1684242180498.json) | GPU metrics from DCGM |
| [Vast Dashboard](Vast%20Dashboard-1692692563948.json) | Vast.ai specific metrics |
| [cAdvisor](Cadvisor%20exporter-1684242167975.json) | Container metrics |

**To import:** Grafana → Dashboards → Import → Paste JSON

---

## ⚙️ Prometheus Configuration

Edit `prometheus.yml` with your server IPs:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'gpu-server-01'
    static_configs:
      - targets: ['192.168.1.101:9100', '192.168.1.101:9400', '192.168.1.101:9200']
        labels:
          instance: 'gpu-01'

  - job_name: 'gpu-server-02'
    static_configs:
      - targets: ['192.168.1.102:9100', '192.168.1.102:9400', '192.168.1.102:9200']
        labels:
          instance: 'gpu-02'
```

### Exporter Ports

| Port | Exporter | Metrics |
|------|----------|---------|
| 9100 | node_exporter | CPU, RAM, disk, network |
| 9400 | dcgm-exporter | GPU core temp, power, memory |
| 9200 | dc-exporter | VRAM temp, hotspot temp, fan speed |
| 8080 | cAdvisor | Container metrics |

---

## 📱 Telegram Alerts

### Setup

1. Create a bot via [@BotFather](https://t.me/BotFather)
2. Get your Chat ID from `https://api.telegram.org/bot<TOKEN>/getUpdates`
3. Configure in Grafana: **Alerting → Contact Points → Add Telegram**

### Example Alert Rules

**GPU Temperature:**
```
A: DCGM_FI_DEV_GPU_TEMP
C: threshold > 80
Summary: {{ $labels.job }} GPU {{ $labels.gpu }} at {{ $values.B }}°C
```

**Disk Space:**
```
A: round((100 - ((node_filesystem_avail_bytes{mountpoint="/"} * 100) / node_filesystem_size_bytes{mountpoint="/"})))
C: threshold > 90
Summary: {{ $labels.job }} disk at {{ $values.B }}%
```

---

## 🔗 Related Projects

| Project | Description |
|---------|-------------|
| [ipmi-monitor](https://github.com/cryptolabsza/ipmi-monitor) | IPMI/Redfish SEL monitoring |
| [dc-exporter](https://github.com/cryptolabsza/dc-exporter) | VRAM temperature exporter |
| [dc-watchdog](https://github.com/cryptolabsza/dc-watchdog) | External uptime monitoring |

---

## 🆘 Troubleshooting

### Prometheus DB Locked

```bash
# Run on reboot
wget https://raw.githubusercontent.com/cryptolabsza/dc-overview/main/RemoverPrometheusDBLock.sh
chmod +x RemoverPrometheusDBLock.sh
# Add to crontab: @reboot /path/to/RemoverPrometheusDBLock.sh
```

### Grafana Can't Connect to Prometheus

Use the container's internal IP or `http://prometheus:9090` if on same Docker network.

---

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

---

<p align="center">
  Made with ❤️ by <a href="https://cryptolabs.co.za">CryptoLabs</a>
</p>
