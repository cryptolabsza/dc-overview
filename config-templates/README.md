# DC Overview Configuration Templates

This directory contains all configuration templates needed to deploy the DC Overview GPU monitoring stack.

## Directory Structure

```
config-templates/
├── docker-compose.yml        # Docker Compose for Prometheus & Grafana
├── prometheus.yml            # Prometheus scrape configuration
├── recording_rules.yml       # Prometheus recording rules for unified metrics
├── nginx.conf               # Nginx reverse proxy configuration
├── grafana/
│   └── provisioning/
│       └── datasources/
│           └── prometheus.yml   # Auto-configure Prometheus datasource
└── systemd/
    ├── node-exporter.service    # System metrics exporter
    ├── dcgm-exporter.service    # NVIDIA GPU metrics exporter
    └── dc-exporter.service      # VRAM/Hotspot temps exporter
```

## Quick Deployment Guide

### 1. Master Server Setup

```bash
# Create directories
mkdir -p /etc/dc-overview/ssl
mkdir -p /root/dc-overview

# Copy configuration files
cp docker-compose.yml prometheus.yml recording_rules.yml /root/dc-overview/
cp nginx.conf /etc/nginx/sites-available/dc-overview

# Generate self-signed SSL certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/dc-overview/ssl/server.key \
  -out /etc/dc-overview/ssl/server.crt \
  -subj "/CN=dc-overview"

# Create Prometheus basic auth
htpasswd -c /etc/nginx/.htpasswd_prometheus admin

# Enable nginx site
ln -s /etc/nginx/sites-available/dc-overview /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# Start monitoring stack
cd /root/dc-overview
docker-compose up -d
```

### 2. Worker Server Setup (Exporters Only)

On each worker server:

```bash
# Install Node Exporter
wget https://github.com/prometheus/node_exporter/releases/download/v1.7.0/node_exporter-1.7.0.linux-amd64.tar.gz
tar xvf node_exporter-*.tar.gz
cp node_exporter-*/node_exporter /usr/local/bin/
useradd -rs /bin/false node_exporter
cp systemd/node-exporter.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now node-exporter

# Install DCGM Exporter (requires NVIDIA drivers)
# See dc-exporter README for detailed instructions
```

## Configuration Variables

### prometheus.yml
- `${MASTER_IP}` - IP address of the master/monitoring server
- `${WORKER_01_IP}`, `${WORKER_02_IP}`, etc. - Worker server IPs

### docker-compose.yml
- `${GRAFANA_ADMIN_PASSWORD}` - Grafana admin password (default: DcOverview2024!)
- `${GRAFANA_ROOT_URL}` - External URL for Grafana (default: https://localhost:8443/grafana/)
- `${VASTAI_API_KEY}` - Vast.ai API key (optional)

## Port Reference

| Service | Port | Description |
|---------|------|-------------|
| Node Exporter | 9100 | System metrics (CPU, memory, disk, network) |
| DCGM Exporter | 9400 | Standard NVIDIA GPU metrics (DCGM_*) |
| DC Exporter | 9835 | VRAM/Hotspot temps, throttle reasons (DCXP_*) |
| Vast.ai Exporter | 8622 | Vast.ai earnings and machine data |
| IPMI Monitor | 5000 | BMC/IPMI monitoring |
| Prometheus | 9090 | Time-series database |
| Grafana | 3000 | Dashboards |
| Nginx HTTPS | 443 | External access point |

## Metrics Naming Convention

- **DCGM_*** - Standard NVIDIA DCGM metrics (GPU temp, power, utilization)
- **DCXP_*** - DC Exporter unique metrics (VRAM temp, hotspot temp, throttle reasons)
- **gpu:*** - Unified recording rules (e.g., `gpu:memory_temp:celsius`)
- **fleet:*** - Fleet-wide aggregates (e.g., `fleet:gpu_count:total`)
- **host:*** - Per-host aggregates (e.g., `host:power_usage:total_watts`)

## Recording Rules

The `recording_rules.yml` provides unified metric names that work regardless of which exporter provides the data:

```promql
# Use these in dashboards for maximum compatibility:
gpu:memory_temp:celsius     # VRAM temperature from DCXP or DCGM
gpu:hotspot_temp:celsius    # Hotspot temp from DCXP or GPU temp
gpu:core_temp:celsius       # GPU core temperature
gpu:power_usage:watts       # GPU power consumption
gpu:utilization:percent     # GPU utilization percentage
gpu:throttle_reason:bool    # Thermal/power throttling status
```

## Dashboards

Import these dashboards from the `../dashboards/` directory:
1. **DC Overview** - Fleet overview with all GPU metrics
2. **Node Exporter Full** - Detailed system metrics
3. **NVIDIA DCGM Exporter** - GPU performance metrics
4. **Vast Dashboard** - Vast.ai specific monitoring
5. **IPMI Monitor** - BMC/IPMI server health

## Troubleshooting

### Prometheus not connecting to Grafana
```bash
# Ensure both containers are on the same Docker network
docker network connect <network_name> prometheus
docker network ls
```

### DCGM Exporter fails to start
```bash
# Check NVIDIA drivers
nvidia-smi

# Check DCGM daemon
systemctl status nvidia-dcgm

# Check for libdcgm.so.4
ldconfig -p | grep dcgm
```

### DC Exporter shows 0 for temps
```bash
# Check kernel parameter
cat /proc/cmdline | grep iomem

# If not present, add to GRUB and reboot
# GRUB_CMDLINE_LINUX_DEFAULT="... iomem=relaxed"
```
