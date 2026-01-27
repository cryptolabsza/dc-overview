# DC Overview Configuration Templates

This directory contains reference configuration templates for manual deployment. For automated deployment, use:

```bash
dc-overview quickstart -c config.yaml -y
```

> **Note**: The quickstart command generates all necessary configuration files automatically in `/etc/dc-overview/`.

## Directory Structure

```
config-templates/
├── deployment-config.yaml    # Example YAML config for quickstart
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

## Recommended: Automated Deployment

Create a configuration file and use quickstart:

```yaml
# my-fleet-config.yaml
site_name: My Datacenter

fleet_admin_user: admin
fleet_admin_pass: SecurePassword123

ssh:
  username: root
  key_path: /root/.ssh/id_rsa
  port: 22

ssl:
  mode: letsencrypt
  domain: dc.example.com
  email: admin@example.com

components:
  dc_overview: true
  ipmi_monitor: true
  vast_exporter: false

servers:
  - name: gpu-01
    server_ip: 192.168.1.101
    bmc_ip: 192.168.1.201

grafana:
  admin_password: GrafanaPass123
```

Deploy:
```bash
dc-overview quickstart -c my-fleet-config.yaml -y
```

## Manual Deployment (Advanced)

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

# Create Docker network
docker network create cryptolabs

# Start monitoring stack
cd /root/dc-overview
docker compose up -d
```

### 2. Worker Server Setup (Exporters Only)

On each worker server:

```bash
# Install Node Exporter
wget https://github.com/prometheus/node_exporter/releases/download/v1.7.0/node_exporter-1.7.0.linux-amd64.tar.gz
tar xvf node_exporter-*.tar.gz
cp node_exporter-*/node_exporter /usr/local/bin/
cp systemd/node-exporter.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now node_exporter

# Install DC Exporter (GPU metrics)
curl -L https://github.com/cryptolabsza/dc-exporter-releases/releases/latest/download/dc-exporter-rs -o /usr/local/bin/dc-exporter-rs
chmod +x /usr/local/bin/dc-exporter-rs
cp systemd/dc-exporter.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now dc-exporter
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
