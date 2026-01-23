# DC Overview v1.1 Development Brief

## Project Goal

Pivot DC Overview from native installation to **Docker-based deployment** (like IPMI Monitor), using the new **shared `cryptolabs-proxy`** for reverse proxy and fleet management landing page.

**End State**: Both `ipmi-monitor` and `dc-overview` can be installed on the same server, share a unified reverse proxy, and cross-import server/SSH configurations.

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────────┐
│                         cryptolabs-proxy                            │
│   ┌─────────────────────────────────────────────────────────────┐  │
│   │  Nginx (ghcr.io/cryptolabsza/cryptolabs-proxy:latest)       │  │
│   │  - Port 80/443                                               │  │
│   │  - Fleet Management Landing Page (/)                         │  │
│   │  - Routes: /ipmi/ /dc/ /grafana/ /prometheus/                │  │
│   │  - Health API: /api/health, /api/services                    │  │
│   └─────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│  ipmi-monitor    │ │  dc-overview     │ │  grafana         │
│  Container       │ │  (Flask app)     │ │  Container       │
│  Port 5000       │ │  Port 5001       │ │  Port 3000       │
│  /ipmi/          │ │  /dc/            │ │  /grafana/       │
└──────────────────┘ └──────────────────┘ └──────────────────┘
                              │
                     ┌────────┴────────┐
                     ▼                 ▼
            ┌──────────────┐   ┌──────────────┐
            │ prometheus   │   │ watchtower   │
            │ Port 9090    │   │ Auto-updates │
            └──────────────┘   └──────────────┘
```

---

## Phase 1: Docker-Based Deployment

### 1.1 Create Dockerfile for DC Overview

**New File**: `Dockerfile`

```dockerfile
FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/cryptolabsza/dc-overview"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    openssh-client \
    sshpass \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python package
COPY . /app/
RUN pip install --no-cache-dir .

# Create data directory
RUN mkdir -p /data /app/ssh_keys

# Expose port
EXPOSE 5001

# Environment variables
ENV DC_OVERVIEW_DATA=/data
ENV FLASK_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5001/api/health || exit 1

# Start application
CMD ["gunicorn", "-b", "0.0.0.0:5001", "-w", "2", "dc_overview.app:app"]
```

### 1.2 Create Flask Web Application

**New File**: `src/dc_overview/app.py`

The web app should provide:
- Dashboard showing monitored servers
- Prometheus targets management
- Grafana integration status
- SSH key management
- API endpoints for health/status

```python
# Key endpoints needed:
# GET  /                      - Dashboard
# GET  /api/health            - Health check
# GET  /api/servers           - List monitored servers
# POST /api/servers           - Add server
# GET  /api/prometheus/targets - Prometheus targets
# POST /api/exporters/install - Install exporters on remote server
# GET  /metrics               - Prometheus metrics endpoint
```

### 1.3 Update `quickstart.py` for Docker Deployment

**Modify**: `src/dc_overview/quickstart.py`

Key changes:
1. Check for and install Docker (like ipmi-monitor)
2. Use `cryptolabs-proxy` instead of native nginx
3. Generate `docker-compose.yml` for all services
4. **NEW**: Check if `ipmi-monitor` is already installed and offer to import SSH keys/servers

```python
def run_quickstart():
    check_root()
    
    # Check Docker
    if not check_docker_installed():
        # ... offer to install
    
    # Check for existing ipmi-monitor installation
    ipmi_config = detect_ipmi_monitor()
    if ipmi_config:
        import_from_ipmi = questionary.confirm(
            "IPMI Monitor detected. Import SSH keys and server IPs?",
            default=True
        ).ask()
        
        if import_from_ipmi:
            ssh_keys, servers = import_ipmi_config(ipmi_config)
            # Pre-populate wizard with imported data
    
    # Continue with wizard...
```

### 1.4 Docker Compose Template

**New File**: `src/dc_overview/templates/docker-compose.yml.j2`

```yaml
version: '3.8'

services:
  dc-overview:
    image: ghcr.io/cryptolabsza/dc-overview:{{ docker_tag }}
    container_name: dc-overview
    restart: unless-stopped
    volumes:
      - dc_data:/data
      - ./ssh_keys:/app/ssh_keys:ro
    environment:
      - APPLICATION_ROOT=/dc
      - GRAFANA_URL=http://grafana:3000
      - PROMETHEUS_URL=http://prometheus:9090
    networks:
      - cryptolabs
    labels:
      - "com.centurylinklabs.watchtower.enable=true"

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.retention.time=30d"
      - "--web.external-url=/prometheus/"
      - "--web.route-prefix=/prometheus/"
    networks:
      - cryptolabs
    labels:
      - "com.centurylinklabs.watchtower.enable=true"

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
      - ./grafana/dashboards:/var/lib/grafana/dashboards:ro
    environment:
      - GF_SECURITY_ADMIN_PASSWORD={{ grafana_password }}
      - GF_SERVER_ROOT_URL=%(protocol)s://%(domain)s/grafana/
      - GF_SERVER_SERVE_FROM_SUB_PATH=true
    networks:
      - cryptolabs
    labels:
      - "com.centurylinklabs.watchtower.enable=true"

  {% if use_cryptolabs_proxy %}
  cryptolabs-proxy:
    image: ghcr.io/cryptolabsza/cryptolabs-proxy:{{ proxy_tag }}
    container_name: cryptolabs-proxy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./ssl:/etc/nginx/ssl:ro
    networks:
      - cryptolabs
    labels:
      - "com.centurylinklabs.watchtower.enable=true"
  {% endif %}

  watchtower:
    image: containrrr/watchtower
    container_name: watchtower
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - WATCHTOWER_CLEANUP=true
      - WATCHTOWER_POLL_INTERVAL=300
      - WATCHTOWER_LABEL_ENABLE=true
    networks:
      - cryptolabs

networks:
  cryptolabs:
    name: cryptolabs
    driver: bridge

volumes:
  dc_data:
  prometheus_data:
  grafana_data:
```

---

## Phase 2: Cross-Import Between Products

### 2.1 DC Overview: Import from IPMI Monitor

**Function**: `import_ipmi_config()`

```python
def detect_ipmi_monitor() -> Optional[Dict]:
    """Detect if ipmi-monitor is installed."""
    ipmi_config_dir = Path("/etc/ipmi-monitor")
    
    if not ipmi_config_dir.exists():
        return None
    
    # Check for running container
    result = subprocess.run(
        ["docker", "inspect", "ipmi-monitor"],
        capture_output=True
    )
    
    if result.returncode != 0:
        return None
    
    return {
        "config_dir": ipmi_config_dir,
        "db_path": ipmi_config_dir / "data" / "ipmi_monitor.db",
        "ssh_keys_dir": ipmi_config_dir / "ssh_keys"
    }


def import_ipmi_config(ipmi_config: Dict) -> Tuple[List, List]:
    """Import SSH keys and servers from IPMI Monitor."""
    import sqlite3
    
    ssh_keys = []
    servers = []
    
    db_path = ipmi_config["db_path"]
    
    if db_path.exists():
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Import servers (for Prometheus targets)
        cursor.execute("""
            SELECT name, bmc_ip, ssh_username, ssh_port, ssh_key_id 
            FROM servers
        """)
        
        for row in cursor.fetchall():
            servers.append({
                "name": row[0],
                "ip": row[1],  # Use BMC IP as server IP for prometheus
                "ssh_user": row[2],
                "ssh_port": row[3],
                "ssh_key_id": row[4]
            })
        
        # Import SSH keys
        cursor.execute("SELECT id, name, key_path FROM ssh_keys")
        for row in cursor.fetchall():
            ssh_keys.append({
                "id": row[0],
                "name": row[1],
                "path": row[2]
            })
        
        conn.close()
    
    # Copy SSH keys to DC Overview directory
    ssh_keys_dir = ipmi_config["ssh_keys_dir"]
    if ssh_keys_dir.exists():
        dc_ssh_dir = Path("/etc/dc-overview/ssh_keys")
        dc_ssh_dir.mkdir(parents=True, exist_ok=True)
        
        for key_file in ssh_keys_dir.iterdir():
            shutil.copy2(key_file, dc_ssh_dir / key_file.name)
    
    return ssh_keys, servers
```

### 2.2 IPMI Monitor: Import from DC Overview

**Add to ipmi-monitor's quickstart.py**:

```python
def detect_dc_overview() -> Optional[Dict]:
    """Detect if DC Overview is installed."""
    dc_config_dir = Path("/etc/dc-overview")
    
    if not dc_config_dir.exists():
        return None
    
    # Check for config file
    config_file = dc_config_dir / "fleet_config.yaml"
    if not config_file.exists():
        return None
    
    return {
        "config_dir": dc_config_dir,
        "config_file": config_file,
        "ssh_keys_dir": dc_config_dir / "ssh_keys"
    }


def import_dc_overview_config(dc_config: Dict) -> Tuple[List, List]:
    """Import SSH credentials and server IPs from DC Overview.
    
    Returns:
        Tuple of (ssh_keys, servers)
        - servers have IP (from Prometheus targets) but need BMC IP added
    """
    import yaml
    
    ssh_keys = []
    servers = []
    
    config_file = dc_config["config_file"]
    
    if config_file.exists():
        with open(config_file) as f:
            config = yaml.safe_load(f)
        
        # Get SSH credentials
        ssh_config = config.get("ssh", {})
        if ssh_config.get("key_path"):
            ssh_keys.append({
                "name": "dc-overview-key",
                "path": ssh_config["key_path"]
            })
        
        # Get server list (for BMC IP collection)
        for server in config.get("servers", []):
            servers.append({
                "name": server.get("name"),
                "server_ip": server.get("server_ip"),
                "bmc_ip": None,  # User must provide
                "ssh_user": ssh_config.get("username", "root"),
                "ssh_port": ssh_config.get("port", 22)
            })
    
    return ssh_keys, servers
```

**Quickstart Integration**:

```python
def run_quickstart():
    # ... existing code ...
    
    # Check for DC Overview
    dc_config = detect_dc_overview()
    if dc_config:
        console.print("[green]✓[/green] DC Overview detected")
        
        import_from_dc = questionary.confirm(
            "Import server IPs and SSH keys from DC Overview?",
            default=True
        ).ask()
        
        if import_from_dc:
            ssh_keys, servers = import_dc_overview_config(dc_config)
            
            console.print(f"  Imported {len(ssh_keys)} SSH keys")
            console.print(f"  Imported {len(servers)} servers")
            console.print("\n[yellow]⚠[/yellow] You'll need to provide BMC IP for each server\n")
            
            # For each imported server, ask for BMC details
            for server in servers:
                bmc_ip = questionary.text(
                    f"BMC IP for {server['name']} ({server['server_ip']}):",
                    validate=lambda x: looks_like_ip(x) or "Invalid IP",
                ).ask()
                server["bmc_ip"] = bmc_ip
```

---

## Phase 3: Exporter Installation

### 3.1 Remote Exporter Installation

DC Overview should install these exporters on worker nodes:
- **node_exporter** (port 9100) - CPU, RAM, disk
- **dc-exporter** (port 9835) - GPU VRAM, hotspot temps
- **dcgm-exporter** (optional, port 9400) - NVIDIA DCGM metrics

```python
def install_exporters_on_remote(
    host: str,
    ssh_user: str,
    ssh_key: str,
    ssh_port: int = 22,
    has_gpu: bool = True
) -> bool:
    """Install all exporters on a remote host via SSH."""
    
    ssh_cmd = [
        "ssh", "-i", ssh_key,
        "-o", "StrictHostKeyChecking=no",
        "-p", str(ssh_port),
        f"{ssh_user}@{host}"
    ]
    
    # Script to install exporters
    install_script = """
    # Install node_exporter
    if ! systemctl is-active node_exporter >/dev/null 2>&1; then
        cd /tmp
        curl -sLO https://github.com/prometheus/node_exporter/releases/download/v1.7.0/node_exporter-1.7.0.linux-amd64.tar.gz
        tar xzf node_exporter-1.7.0.linux-amd64.tar.gz
        cp node_exporter-1.7.0.linux-amd64/node_exporter /usr/local/bin/
        
        cat > /etc/systemd/system/node_exporter.service << 'EOF'
[Unit]
Description=Node Exporter
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable --now node_exporter
    fi
    
    # Install dc-exporter if GPU present
    if nvidia-smi >/dev/null 2>&1; then
        pip3 install dc-overview 2>/dev/null || pip install dc-overview
        dc-overview install-exporters --no-node-exporter
    fi
    """
    
    result = subprocess.run(
        ssh_cmd + ["bash", "-c", install_script],
        capture_output=True, text=True, timeout=300
    )
    
    return result.returncode == 0
```

---

## Phase 4: Unified Proxy Integration

### 4.1 Update `cryptolabs-proxy`

The proxy's `/api/services` endpoint should detect both services:

```python
# In cryptolabs-proxy health-api.py
SERVICES = {
    'ipmi-monitor': {'container': 'ipmi-monitor', 'port': 5000, 'path': '/ipmi/'},
    'dc-overview': {'container': 'dc-overview', 'port': 5001, 'path': '/dc/'},
    'grafana': {'container': 'grafana', 'port': 3000, 'path': '/grafana/'},
    'prometheus': {'container': 'prometheus', 'port': 9090, 'path': '/prometheus/'},
}
```

### 4.2 Landing Page Service Detection

The landing page should show:
- **Running Services**: Direct links to access
- **Not Installed**: "Get DC Overview" / "Get IPMI Monitor" buttons with links

```javascript
// In cryptolabs-proxy landing-page/index.html
const DEFAULT_SERVICES = {
    'ipmi-monitor': {
        displayName: 'IPMI Monitor',
        icon: '🖥️',
        description: 'Monitor server hardware health via IPMI/BMC',
        path: '/ipmi/',
        productUrl: 'https://github.com/cryptolabsza/ipmi-monitor',
        docsUrl: 'https://cryptolabs.co.za/ipmi-monitor/'
    },
    'dc-overview': {
        displayName: 'DC Overview',
        icon: '📊',
        description: 'GPU datacenter monitoring with Prometheus & Grafana',
        path: '/dc/',
        productUrl: 'https://github.com/cryptolabsza/dc-overview',
        docsUrl: 'https://www.cryptolabs.co.za/dc-overview/'
    },
    // ... grafana, prometheus
};
```

---

## Phase 5: Future Exporters

### 5.1 Planned Exporters

| Exporter | Port | Status | Description |
|----------|------|--------|-------------|
| node_exporter | 9100 | ✅ Ready | CPU, RAM, disk |
| dc-exporter | 9835 | ✅ Ready | GPU VRAM, hotspot |
| dcgm-exporter | 9400 | ✅ Ready | NVIDIA DCGM |
| vastai-exporter | 8622 | ✅ Ready | Vast.ai earnings |
| runpod-exporter | 8623 | 🔜 Planned | RunPod metrics |
| hivefleet-exporter | 8624 | 🔜 Planned | HiveFleet metrics |

### 5.2 Exporter Installation Matrix

```
┌────────────────────────────────────────────────────────────┐
│                    DC Overview Quickstart                   │
├────────────────────────────────────────────────────────────┤
│  Machine Role Selection:                                    │
│                                                            │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │  Master Server  │  │  GPU Worker     │                  │
│  │  (this machine) │  │  (remote)       │                  │
│  └────────┬────────┘  └────────┬────────┘                  │
│           │                    │                           │
│           ▼                    ▼                           │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │ Prometheus      │  │ node_exporter   │                  │
│  │ Grafana         │  │ dc-exporter     │                  │
│  │ cryptolabs-proxy│  │ dcgm-exporter?  │                  │
│  │ dc-overview app │  │ vastai-exporter?│                  │
│  └─────────────────┘  └─────────────────┘                  │
│                                                            │
│  [If IPMI Monitor installed]                               │
│  ┌─────────────────┐                                       │
│  │ Import SSH keys │                                       │
│  │ Import server   │                                       │
│  │ IPs for targets │                                       │
│  └─────────────────┘                                       │
└────────────────────────────────────────────────────────────┘
```

---

## Implementation Checklist

### Phase 1: Docker Deployment
- [ ] Create `Dockerfile`
- [ ] Create `src/dc_overview/app.py` (Flask web app)
- [ ] Create `templates/docker-compose.yml.j2`
- [ ] Update `quickstart.py` to use Docker
- [ ] Create GitHub Actions for Docker builds
- [ ] Test quickstart with Docker deployment

### Phase 2: Cross-Import
- [ ] Implement `detect_ipmi_monitor()` in dc-overview
- [ ] Implement `import_ipmi_config()` in dc-overview
- [ ] Implement `detect_dc_overview()` in ipmi-monitor
- [ ] Implement `import_dc_overview_config()` in ipmi-monitor
- [ ] Add BMC IP prompt for imported servers

### Phase 3: Exporters
- [ ] Verify remote exporter installation works
- [ ] Add GPU detection before dc-exporter install
- [ ] Add Vast.ai detection for vastai-exporter
- [ ] Create install scripts for each exporter

### Phase 4: Proxy Integration
- [ ] Update cryptolabs-proxy to detect dc-overview
- [ ] Add dc-overview route to nginx.conf
- [ ] Test landing page service detection
- [ ] Test cross-promotion display

### Phase 5: Documentation
- [ ] Update README.md
- [ ] Update docs/index.md
- [ ] Add quickstart screenshots
- [ ] Document cross-import feature

---

## Testing Plan

### Test Scenario 1: Fresh DC Overview Install
```bash
pipx install "git+https://github.com/cryptolabsza/dc-overview.git@dev"
sudo ~/.local/bin/dc-overview quickstart
```

Expected: Full wizard, Docker deployment, cryptolabs-proxy landing page

### Test Scenario 2: DC Overview After IPMI Monitor
```bash
# IPMI Monitor already installed
pipx install "git+https://github.com/cryptolabsza/dc-overview.git@dev"
sudo ~/.local/bin/dc-overview quickstart
```

Expected: Detects ipmi-monitor, offers import, reuses proxy

### Test Scenario 3: IPMI Monitor After DC Overview
```bash
# DC Overview already installed
pipx install "git+https://github.com/cryptolabsza/ipmi-monitor.git@dev"
sudo ~/.local/bin/ipmi-monitor quickstart
```

Expected: Detects dc-overview, imports SSH keys/IPs, prompts for BMC details

---

## Repository Structure (After Changes)

```
dc-overview/
├── Dockerfile                    # NEW
├── pyproject.toml               # Updated: add gunicorn dependency
├── src/dc_overview/
│   ├── app.py                   # NEW: Flask web application
│   ├── cli.py                   # Updated: minor changes
│   ├── quickstart.py            # Major update: Docker deployment
│   ├── cross_import.py          # NEW: Import from ipmi-monitor
│   └── templates/
│       ├── docker-compose.yml.j2 # NEW
│       └── dashboard.html        # NEW
├── dashboards/                  # Existing Grafana dashboards
├── .github/workflows/
│   ├── publish.yml              # Existing
│   └── docker-build.yml         # NEW
└── docs/
    └── index.md                 # Updated
```

---

## Questions for Discussion

1. **Port Assignment**: Should dc-overview use port 5001 to avoid conflict with ipmi-monitor on 5000?

2. **Database Sharing**: Should both products share a common config database, or keep separate?

3. **SSH Key Storage**: Use shared `/etc/cryptolabs/ssh_keys/` or per-product directories?

4. **Prometheus Configuration**: When dc-overview imports from ipmi-monitor, should it auto-add the IPMI Monitor metrics endpoint?

5. **Grafana Dashboard Provisioning**: Should dashboards be bundled in Docker image or downloaded on first run?

---

*Brief created: 2026-01-23*
*Target: DC Overview v1.1.0*
*Related: ipmi-monitor v1.1.0, cryptolabs-proxy v1.0.0*
