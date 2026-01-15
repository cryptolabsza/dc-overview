# CryptoLabs DC Monitoring Suite

Complete monitoring solution for GPU datacenters with AI-powered insights.

## Product Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              PRODUCT OVERVIEW                                   │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  IN-DC STACK (runs in customer datacenter)                                      │
│  ══════════════════════════════════════════                                     │
│                                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐                  │
│  │   dc-overview   │  │  ipmi-monitor   │  │   dc-exporter   │                  │
│  │   (Grafana +    │  │  (IPMI/Redfish  │  │  (VRAM temps    │                  │
│  │   Prometheus)   │  │   dashboard)    │  │   exporter)     │                  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘                  │
│         │                     │                     │                           │
│         └─────────────────────┴─────────────────────┘                           │
│                               │                                                 │
│                    Deployed ON monitoring server                                │
│                    inside the datacenter                                        │
│                                                                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  EXTERNAL MONITORING (runs OUTSIDE datacenter)                                  │
│  ═════════════════════════════════════════════                                  │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                          dc-watchdog                                    │    │
│  │                                                                         │    │
│  │   ┌──────────────────┐           ┌──────────────────────────────────┐   │    │
│  │   │  OFFSITE SERVER  │◄──────────│  AGENTS (on DC servers)          │   │    │
│  │   │  (VPS/Cloud VM)  │  "phone   │  • Ping every 30s                │   │    │
│  │   │                  │   home"   │  • MTR traceroute data           │   │    │
│  │   │  • Flask server  │           │  • Lightweight bash script       │   │    │
│  │   │  • Telegram bot  │           │                                  │   │    │
│  │   │  • Admin UI      │           │  Installed on: GPU servers,      │   │    │
│  │   │  • RCA analysis  │           │  routers, BMCs, anything with    │   │    │
│  │   │                  │           │  network access                  │   │    │
│  │   └──────────────────┘           └──────────────────────────────────┘   │    │
│  │                                                                         │    │
│  │   Purpose: Detect when DC goes offline from external perspective        │    │
│  │   Value: Know BEFORE customers complain, with network hop analysis      │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  AI SERVICE (CryptoLabs Cloud)                                                  │
│  ═════════════════════════════                                                  │
│                                                                                 │
│  ┌─────────────────┐                                                            │
│  │ ipmi-monitor-ai │  ← Receives telemetry from ipmi-monitor                    │
│  │                 │  ← Provides AI summaries, predictions, RCA                 │
│  └─────────────────┘  ← Requires paid subscription                              │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Option 1: Self-Hosted (In-DC Monitoring)

Deploy the full monitoring stack on a server inside your datacenter.

```bash
# Clone and deploy
git clone https://github.com/cryptolabsza/dc-overview.git
cd dc-overview
cp .env.example .env
# Edit .env with your API keys and passwords
nano .env
docker compose up -d
```

### Environment Variables (.env)

Create a `.env` file (gitignored) with your secrets:

```bash
# .env.example - Copy to .env and fill in your values

# Grafana
GRAFANA_ADMIN_PASS=your_secure_password

# Vast.ai (optional - for vastai-exporter)
VAST_API_KEY=your_vast_api_key

# dc-watchdog (optional - for uptime monitoring)
TELEGRAM_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_chat_id
WATCHDOG_API_KEY=your_secret_api_key
ADMIN_PASS=your_admin_password

# IPMI Monitor (optional)
IPMI_USER=admin
IPMI_PASS=your_ipmi_password
```

> ⚠️ **IMPORTANT:** Never commit `.env` to git! It contains secrets.

### Docker Compose (Full Stack)

```yaml
# docker-compose.yml
services:
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./grafana/datasources:/etc/grafana/provisioning/datasources
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASS:-admin}
      - GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-piechart-panel
    restart: always

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    # Internal only - NOT exposed publicly
    ports:
      - "127.0.0.1:9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.retention.time=30d"
    restart: always

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    restart: unless-stopped
    network_mode: host
    pid: host
    volumes:
      - "/:/host:ro,rslave"
    command: ["--path.rootfs=/host"]

  cadvisor:
    image: gcr.io/cadvisor/cadvisor:v0.47.1
    container_name: cadvisor
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - "/:/rootfs:ro"
      - "/var/run:/var/run:ro"
      - "/sys:/sys:ro"
      - "/var/lib/docker/:/var/lib/docker:ro"
      - "/dev/disk/:/dev/disk:ro"
    privileged: true
    devices:
      - "/dev/kmsg:/dev/kmsg"

  vastai-exporter:
    image: jjziets/vastai-exporter:latest
    container_name: vastai-exporter
    restart: unless-stopped
    ports:
      - "127.0.0.1:8622:8622"
    command: ["-api-key", "${VAST_API_KEY}"]

  watchtower:
    image: containrrr/watchtower
    container_name: watchtower
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - WATCHTOWER_CLEANUP=true
      - WATCHTOWER_POLL_INTERVAL=86400
    command: --label-enable

volumes:
  grafana-data:
  prometheus-data:
```

### Grafana Datasource Configuration

Grafana is pre-configured to connect to Prometheus via **Docker network DNS**:

```
Prometheus URL: http://prometheus:9090
```

> ⚠️ **Why `http://prometheus:9090` instead of `localhost`?**  
> Grafana runs inside a Docker container. Using `localhost:9090` would look for Prometheus inside Grafana's own container.  
> The Docker network DNS name `prometheus` resolves to the Prometheus container.

### Grafana Datasource Provisioning

Create `grafana/datasources/prometheus.yml`:

```yaml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
```

### Prometheus Configuration

Create `prometheus.yml` to scrape all exporters:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  # Master server
  - job_name: 'master'
    static_configs:
      - targets: ['<MASTER_IP>:9090', '<MASTER_IP>:9100', '<MASTER_IP>:8080']
        labels:
          instance: 'master'

  # IPMI Monitor (SEL events, BMC status)
  - job_name: 'ipmi-monitor'
    scrape_interval: 60s
    static_configs:
      - targets: ['<MASTER_IP>:5000']
        labels:
          instance: 'ipmi-monitor'

  # Vast.ai exporter (if using Vast.ai)
  - job_name: 'vastai'
    scrape_interval: 60s
    static_configs:
      - targets: ['vastai-exporter:8622']
        labels:
          instance: 'vastai'

  # GPU Worker 1
  - job_name: 'gpu-worker-01'
    static_configs:
      - targets: ['<WORKER1_IP>:9100', '<WORKER1_IP>:9400', '<WORKER1_IP>:9500']
        labels:
          instance: 'gpu-worker-01'

  # GPU Worker 2
  - job_name: 'gpu-worker-02'
    static_configs:
      - targets: ['<WORKER2_IP>:9100', '<WORKER2_IP>:9400', '<WORKER2_IP>:9500']
        labels:
          instance: 'gpu-worker-02'
```

**Exporter ports:**
- `9090` - Prometheus self-monitoring
- `9100` - node_exporter (CPU, RAM, disk)
- `8080` - cAdvisor (containers)
- `5000` - ipmi-monitor (IPMI/SEL)
- `9400` - dcgm-exporter (NVIDIA GPU)
- `9500` - dc-exporter (VRAM temps)
- `8622` - vastai-exporter (Vast.ai)

---

### Option 2: External Uptime Monitoring (dc-watchdog)

Deploy the server on a VPS outside your DC, agents on your DC servers.

**On your VPS (offsite):**
```bash
git clone https://github.com/cryptolabsza/dc-watchdog.git
cd dc-watchdog
cp .env.example .env
# Edit .env with your Telegram bot token and secrets
nano .env
docker compose up -d
```

**dc-watchdog .env:**
```bash
TELEGRAM_TOKEN=your_telegram_bot_token
CHAT_ID=your_chat_id
API_KEY=your_secret_api_key
ADMIN_PASS=your_admin_password
```

**On each DC server (agents):**
```bash
curl -sSL https://raw.githubusercontent.com/cryptolabsza/dc-watchdog/main/install-agent.sh | bash
```

---

## Nginx Reverse Proxy with SSL

For production, use Nginx as a reverse proxy with Let's Encrypt SSL certificates.

### DNS Configuration

Create A records pointing to your servers:

| Subdomain | Points To | Service | Notes |
|-----------|-----------|---------|-------|
| `grafana.yourdomain.com` | `<monitoring-server-ip>` | Grafana dashboards | Public OK (has auth) |
| `ipmi.yourdomain.com` | `<monitoring-server-ip>` | IPMI Monitor | Public OK (has auth) |
| `watchdog.yourdomain.com` | `<offsite-vps-ip>` | dc-watchdog server | Public (agents call home) |

> ⚠️ **IMPORTANT:** Prometheus should **NOT** be exposed publicly!
> It has no authentication by default and exposes sensitive infrastructure data.
> Access Prometheus only via:
> - `localhost:9090` on the monitoring server
> - Internal network (e.g., `192.168.1.100:9090`)
> - VPN (Tailscale, WireGuard)

**Example DNS entries:**
```
# For in-DC monitoring server (public IP or behind NAT with port forwarding)
grafana.cryptolabs.co.za     A    203.0.113.10
ipmi.cryptolabs.co.za        A    203.0.113.10

# For external watchdog server (MUST be offsite/different location)
watchdog.cryptolabs.co.za    A    198.51.100.20

# Prometheus - NO PUBLIC DNS! Access internally only:
# http://192.168.1.100:9090 (internal network)
# http://localhost:9090 (on monitoring server)
```

### Nginx Installation

```bash
# Install Nginx and Certbot
apt update && apt install -y nginx certbot python3-certbot-nginx

# Create Nginx config directory
mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
```

### Nginx Configuration

Create `/etc/nginx/sites-available/dc-monitoring`:

```nginx
# Grafana
server {
    listen 80;
    server_name grafana.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support for Grafana Live
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

# IPMI Monitor
server {
    listen 80;
    server_name ipmi.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# NOTE: Prometheus is NOT exposed publicly!
# Access via internal network: http://192.168.1.100:9090
# Or via SSH tunnel: ssh -L 9090:localhost:9090 user@monitoring-server
```

For the **dc-watchdog server** (on offsite VPS), create `/etc/nginx/sites-available/dc-watchdog`:

```nginx
# dc-watchdog
server {
    listen 80;
    server_name watchdog.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Enable Sites and SSL

```bash
# Enable the sites
ln -s /etc/nginx/sites-available/dc-monitoring /etc/nginx/sites-enabled/
ln -s /etc/nginx/sites-available/dc-watchdog /etc/nginx/sites-enabled/

# Test configuration
nginx -t

# Reload Nginx
systemctl reload nginx

# Get SSL certificates for public-facing services only
certbot --nginx -d grafana.yourdomain.com
certbot --nginx -d ipmi.yourdomain.com
# Note: watchdog.yourdomain.com runs on a DIFFERENT server (offsite VPS)

# Auto-renewal (already set up by certbot, but verify)
certbot renew --dry-run
```

### All-in-One Docker Compose with Traefik (Auto-SSL)

For a complete stack with automatic SSL certificates:

```yaml
# docker-compose.yml with Traefik
services:
  traefik:
    image: traefik:v2.10
    container_name: traefik
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik/acme.json:/acme.json
    command:
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge=true"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
      - "--certificatesresolvers.letsencrypt.acme.email=${ACME_EMAIL}"
      - "--certificatesresolvers.letsencrypt.acme.storage=/acme.json"
      - "--entrypoints.web.http.redirections.entrypoint.to=websecure"

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/datasources:/etc/grafana/provisioning/datasources
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASS}
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.grafana.rule=Host(`${GRAFANA_DOMAIN}`)"
      - "traefik.http.routers.grafana.entrypoints=websecure"
      - "traefik.http.routers.grafana.tls.certresolver=letsencrypt"
      - "traefik.http.services.grafana.loadbalancer.server.port=3000"

  ipmi-monitor:
    image: ghcr.io/cryptolabsza/ipmi-monitor:latest
    container_name: ipmi-monitor
    restart: unless-stopped
    volumes:
      - ipmi-data:/app/data
    environment:
      - IPMI_USER=${IPMI_USER}
      - IPMI_PASS=${IPMI_PASS}
      - ADMIN_PASS=${ADMIN_PASS}
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.ipmi.rule=Host(`${IPMI_DOMAIN}`)"
      - "traefik.http.routers.ipmi.entrypoints=websecure"
      - "traefik.http.routers.ipmi.tls.certresolver=letsencrypt"
      - "traefik.http.services.ipmi.loadbalancer.server.port=5000"

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    # NOT exposed via Traefik - internal only!
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.retention.time=30d"

  vastai-exporter:
    image: jjziets/vastai-exporter:latest
    container_name: vastai-exporter
    restart: unless-stopped
    command: ["-api-key", "${VAST_API_KEY}"]
    # Internal only - Prometheus scrapes via Docker network

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    restart: unless-stopped
    network_mode: host
    pid: host
    volumes:
      - "/:/host:ro,rslave"
    command: ["--path.rootfs=/host"]

  cadvisor:
    image: gcr.io/cadvisor/cadvisor:v0.47.1
    container_name: cadvisor
    restart: unless-stopped
    volumes:
      - "/:/rootfs:ro"
      - "/var/run:/var/run:ro"
      - "/sys:/sys:ro"
      - "/var/lib/docker/:/var/lib/docker:ro"
    privileged: true

volumes:
  grafana-data:
  prometheus-data:
  ipmi-data:
```

**.env for Traefik setup:**
```bash
# Domains
GRAFANA_DOMAIN=grafana.yourdomain.com
IPMI_DOMAIN=ipmi.yourdomain.com
ACME_EMAIL=admin@yourdomain.com

# Credentials (NEVER commit these!)
GRAFANA_ADMIN_PASS=your_secure_password
IPMI_USER=admin
IPMI_PASS=your_ipmi_password
ADMIN_PASS=your_admin_password
VAST_API_KEY=your_vast_api_key
```

> ⚠️ **Security Note:** All secrets are loaded from `.env` which must be gitignored.
> Prometheus is NOT exposed publicly - access via internal network or SSH tunnel only.

---

## Port Reference

### In-DC Monitoring Server

| Port | Service | Access | Notes |
|------|---------|--------|-------|
| 80/443 | Nginx/Traefik | Public | SSL termination |
| 3000 | Grafana | Internal | Proxied via Nginx |
| 5000 | IPMI Monitor | Internal | Proxied via Nginx |
| 9090 | Prometheus | **Internal only** | ⚠️ Never expose publicly! |
| 8080 | cAdvisor | Internal | Container metrics |

### GPU Servers (Exporters)

| Port | Service | Scraped By |
|------|---------|------------|
| 9100 | node_exporter | Prometheus |
| 9400 | dcgm-exporter | Prometheus |
| 9500 | dc-exporter (VRAM temps) | Prometheus |

---

## DC Exporter (GPU Server Agent)

Install dc-exporter on each GPU server to expose VRAM temperatures and additional metrics.

### Quick Install

```bash
# Download the latest release
wget https://github.com/cryptolabsza/dc-exporter/releases/latest/download/dc-exporter-collector
wget https://github.com/cryptolabsza/dc-exporter/releases/latest/download/dc-exporter-server
wget https://github.com/cryptolabsza/dc-exporter/releases/latest/download/config.ini

# Install binaries
chmod +x dc-exporter-collector dc-exporter-server
sudo mv dc-exporter-collector dc-exporter-server /usr/local/bin/
sudo mkdir -p /etc/dc-exporter
sudo mv config.ini /etc/dc-exporter/

# Create systemd service
sudo tee /etc/systemd/system/dc-exporter.service > /dev/null << 'EOF'
[Unit]
Description=DC Exporter - GPU and System Metrics
After=network.target

[Service]
Type=simple
WorkingDirectory=/etc/dc-exporter
ExecStart=/bin/bash -c "/usr/local/bin/dc-exporter-collector --no-console & /usr/local/bin/dc-exporter-server"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable dc-exporter
sudo systemctl start dc-exporter

# Verify
curl http://localhost:9500/metrics | grep dc_exporter
```

### Check Version

```bash
# Command line
dc-exporter-collector -v
# Output: dc-exporter version 1.0.0 (built Jan 14 2026)

# Via Prometheus metrics
curl -s http://localhost:9500/metrics | grep dc_exporter_build_info
# Output: dc_exporter_build_info{version="1.0.0",build_date="Jan 14 2026"} 1
```

### Supported GPUs

| GPU Type | VRAM Temp | Hotspot Temp | Fan Speed | Method |
|----------|-----------|--------------|-----------|--------|
| A100/H100 (Datacenter) | ✅ | ✅ | N/A* | NVML API |
| RTX 4090/4080/4070 | ✅ | ✅ | ✅ | PCIe BAR |
| RTX 3090/3080/3070 | ✅ | ✅ | ✅ | PCIe BAR |
| RTX A6000/A5000 | ✅ | ✅ | ✅ | NVML API |

\* A100-SXM4 and H100 use chassis cooling, no per-GPU fan.

### Configuration

Edit `/etc/dc-exporter/config.ini` to enable/disable metrics:

```ini
[agent]
machine_id=auto
interval=5

[gpu]
enabled=1
DCGM_FI_DEV_VRAM_TEMP
DCGM_FI_DEV_HOT_SPOT_TEMP
DCGM_FI_DEV_FAN_SPEED
DCGM_FI_DEV_CLOCKS_THROTTLE_REASON
GPU_AER_TOTAL_ERRORS
GPU_AER_ERROR_STATE
# Uncomment if not using dcgm-exporter:
#DCGM_FI_DEV_GPU_TEMP
#DCGM_FI_DEV_POWER_USAGE

[system]
enabled=1
SYS_LOAD_AVG
SYS_CPU_USAGE
SYS_MEM_USED

[ipmi]
enabled=1
IPMI_INLET_TEMP
IPMI_EXHAUST_TEMP
```

### Exposed Metrics

| Metric | Description |
|--------|-------------|
| `dc_exporter_build_info` | Version and build date |
| `dc_exporter_gpu_available` | 1 if GPUs available, 0 if VM passthrough |
| `dc_exporter_gpu_count` | Number of GPUs detected |
| `DCGM_FI_DEV_VRAM_TEMP` | VRAM/HBM temperature |
| `DCGM_FI_DEV_HOT_SPOT_TEMP` | GPU hotspot temperature |
| `DCGM_FI_DEV_FAN_SPEED` | Fan speed percentage |
| `GPU_AER_TOTAL_ERRORS` | PCIe AER error count |

### Master Server (Additional Exporters)

| Port | Service | Description |
|------|---------|-------------|
| 5000 | ipmi-monitor | IPMI/Redfish metrics (SEL events, power status, BMC reachability) |
| 8622 | vastai-exporter | Vast.ai metrics (earnings, reliability, etc.) |
| 8080 | cAdvisor | Container metrics |

### IPMI Monitor Metrics

The ipmi-monitor exposes Prometheus metrics at `/metrics`:

| Metric | Description |
|--------|-------------|
| `ipmi_server_reachable` | BMC reachability (1=up, 0=down) |
| `ipmi_server_power_on` | Server power status |
| `ipmi_events_total` | Total IPMI/SEL events collected |
| `ipmi_events_critical_24h` | Critical events in last 24 hours |
| `ipmi_events_warning_24h` | Warning events in last 24 hours |
| `ipmi_total_servers` | Total monitored servers |
| `ipmi_reachable_servers` | Number of reachable servers |

### dc-watchdog (Offsite VPS)

| Port | Service | Access |
|------|---------|--------|
| 80/443 | Nginx | Public |
| 5001 | dc-watchdog | Internal (proxied) |

---

## Firewall Configuration

### In-DC Monitoring Server

```bash
# Allow HTTP/HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# Allow Prometheus scraping from internal network only
ufw allow from 192.168.1.0/24 to any port 9090
ufw allow from 192.168.1.0/24 to any port 9100

# Deny direct access to internal services
ufw deny 3000/tcp
ufw deny 5000/tcp
```

### dc-watchdog Offsite Server

```bash
# Allow HTTP/HTTPS for web UI
ufw allow 80/tcp
ufw allow 443/tcp

# Allow agent pings from anywhere (or restrict to DC IPs)
# Agents call home via HTTP(S)
```

---

## Repository Links

| Repo | Description | Releases |
|------|-------------|----------|
| [dc-overview](https://github.com/cryptolabsza/dc-overview) | Prometheus/Grafana dashboards | Public |
| [dc-exporter](https://github.com/cryptolabsza/dc-exporter/releases) | GPU VRAM temp exporter | [v1.0.0](https://github.com/cryptolabsza/dc-exporter/releases/tag/v1.0.0) |
| [dc-watchdog](https://github.com/cryptolabsza/dc-watchdog) | External uptime monitoring | Private |
| [ipmi-monitor](https://github.com/cryptolabsza/ipmi-monitor) | IPMI/Redfish dashboard | Public |
| [ipmi-monitor-ai](https://github.com/cryptolabsza/ipmi-monitor-ai) | AI processing service | Private |

---

## Support

- **Documentation**: [docs.cryptolabs.co.za](https://docs.cryptolabs.co.za)
- **Discord**: [Join our community](https://discord.gg/cryptolabs)
- **Email**: support@cryptolabs.co.za

---

*Made with ❤️ by [CryptoLabs](https://cryptolabs.co.za)*
