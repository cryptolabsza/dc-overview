# DC Overview v1.1 Development Brief

> **Note**: This document is the historical development brief. For current architecture documentation, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Project Goal

Pivot DC Overview from native installation to **Docker-based deployment** (like IPMI Monitor), using the new **shared `cryptolabs-proxy`** for reverse proxy and fleet management landing page.

**End State**: Both `ipmi-monitor` and `dc-overview` can be installed on the same server, share a unified reverse proxy, and cross-import server/SSH configurations.

**Status**: ✅ IMPLEMENTED - See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for current state.

---

## Quick Start (After Implementation)

```bash
# Install via pipx (recommended)
pipx install "git+https://github.com/cryptolabsza/dc-overview.git@dev"

# Run quickstart (does everything)
sudo ~/.local/bin/dc-overview quickstart

# Or if on PATH:
sudo dc-overview quickstart
```

**CLI Commands:**
```bash
dc-overview quickstart      # One-command setup
dc-overview status          # Check container status
dc-overview logs [-f]       # View logs
dc-overview stop            # Stop containers
dc-overview start           # Start containers
dc-overview upgrade         # Pull latest image & restart
dc-overview restart         # Restart containers
```

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

## Phase 1: Docker-Based Deployment ✅ IMPLEMENTED

### 1.1 Dockerfile ✅

**File**: `Dockerfile`

```dockerfile
FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/cryptolabsza/dc-overview"
LABEL org.opencontainers.image.description="DC Overview - GPU Datacenter Monitoring Suite"

# Build arguments for version info
ARG GIT_COMMIT=unknown
ARG GIT_BRANCH=unknown
ARG BUILD_TIME=unknown

ENV GIT_COMMIT=${GIT_COMMIT}
ENV GIT_BRANCH=${GIT_BRANCH}
ENV BUILD_TIME=${BUILD_TIME}

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    sshpass \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .
RUN pip install --no-cache-dir .

# Create data directories
RUN mkdir -p /data /app/ssh_keys

# Default port (configurable via environment variable)
ENV DC_OVERVIEW_PORT=5001
ENV DC_OVERVIEW_DATA=/data
ENV FLASK_ENV=production

EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${DC_OVERVIEW_PORT}/api/health || exit 1

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${DC_OVERVIEW_PORT} --workers 1 --threads 4 dc_overview.app:app"]
```

### 1.2 Flask Web Application ✅

**File**: `src/dc_overview/app.py`

The Flask app provides:
- ✅ Dashboard showing server status (total servers, online count, GPUs)
- ✅ Server management page (add/remove/check connectivity)
- ✅ Exporter installation controls (install via SSH)
- ✅ Settings page (SSH keys, integration URLs)
- ✅ Authentication (password-based login)

**API Endpoints Implemented:**
```python
GET  /                              # Dashboard (login required)
GET  /api/health                    # Health check (no auth)
GET  /api/servers                   # List monitored servers
POST /api/servers                   # Add server
DELETE /api/servers/<id>            # Remove server
GET  /api/servers/<id>/check        # Check server connectivity
POST /api/servers/<id>/install-exporters  # Install exporters via SSH
GET  /api/prometheus/targets        # Prometheus targets (authenticated)
GET  /api/prometheus/targets.json   # File-based service discovery (no auth)
GET  /api/ssh-keys                  # List SSH keys
GET  /metrics                       # Prometheus metrics endpoint

# Web Routes
GET  /login                         # Login page
POST /login                         # Handle login
GET  /logout                        # Logout
GET  /servers                       # Server management page
GET  /settings                      # Settings page
```

**Database Models:**
- `Server` - GPU worker servers (name, IP, SSH config, exporter status)
- `SSHKey` - SSH keys for worker authentication
- `AppSettings` - Key-value application settings

### 1.3 Quickstart Flow ✅

**File**: `src/dc_overview/quickstart.py`

The quickstart wizard follows this flow:

```
┌─────────────────────────────────────────────────────────────────────┐
│                     dc-overview quickstart                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Step 1: Detect Environment                                         │
│    • Hostname, IP, GPU count                                        │
│    • Check if IPMI Monitor installed                                │
│                                                                     │
│  Step 2: Select Role                                                │
│    ○ GPU Worker (has GPUs to monitor)                               │
│    ○ Master Server (monitors other machines)                        │
│    ○ Both (has GPUs + monitors others)                              │
│                                                                     │
│  Step 3: Worker Setup (if worker/both)                              │
│    • Install node_exporter (port 9100)                              │
│    • Install dc-exporter (port 9835)                                │
│    [Native systemd services - NOT Docker]                           │
│                                                                     │
│  Step 4: Master Setup (if master/both)                              │
│    • Check/install Docker                                           │
│    • Detect ipmi-monitor → offer import                             │
│    • Configure DC Overview port (default 5001)                      │
│    • Set Grafana password                                           │
│    • Setup cryptolabs-proxy? (Y/n)                                  │
│      - Domain name?                                                 │
│      - Let's Encrypt?                                               │
│      - External HTTPS port?                                         │
│    • Enable Watchtower auto-updates? (Y/n)                          │
│    • Generate configs (docker-compose, prometheus, nginx)           │
│    • Pull images & start containers                                 │
│                                                                     │
│  Step 5: Add Workers (if master/both)                               │
│    • Import from file/paste                                         │
│    • Enter IPs manually                                             │
│    • Install exporters via SSH                                      │
│                                                                     │
│  Step 6: Vast.ai Integration (Optional)                             │
│    • API key input                                                  │
│    • Start vastai-exporter container                                │
│                                                                     │
│  Step 7: Summary                                                    │
│    • Display access URLs                                            │
│    • Show credentials                                               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Key Functions Implemented:**
- `check_docker_installed()` - Check Docker availability
- `install_docker()` - Install via get.docker.com script
- `detect_ipmi_monitor()` - Find existing IPMI Monitor installation
- `import_ipmi_config()` - Import SSH keys and servers from IPMI Monitor
- `setup_master_docker()` - Full Docker-based master setup
- `install_exporters_remote()` - Install exporters via SSH/Paramiko
- `generate_self_signed_cert()` - Create SSL certificate

### 1.4 Docker Compose Template ✅

**File**: `src/dc_overview/templates/docker-compose.yml.j2`

Key features:
- Configurable DC Overview port via `dc_port` variable
- Optional cryptolabs-proxy (HTTPS reverse proxy)
- Optional Watchtower (auto-updates)
- Optional vastai-exporter integration
- Uses `cryptolabs` Docker network for service communication

### 1.5 GitHub Actions Workflow ✅

**File**: `.github/workflows/docker-build.yml`

Builds and pushes to `ghcr.io/cryptolabsza/dc-overview:latest` on:
- Push to `main`, `master`, `develop`, `dev` branches
- Tags matching `v*`

Multi-platform: `linux/amd64`, `linux/arm64`

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
        pipx install dc-overview
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

### Phase 1: Docker Deployment ✅ COMPLETE
- [x] Create `Dockerfile`
- [x] Create `requirements.txt` (for Docker builds)
- [x] Create `src/dc_overview/app.py` (Flask web app with full UI)
- [x] Create `templates/docker-compose.yml.j2`
- [x] Create `templates/prometheus.yml.j2`
- [x] Create `templates/nginx.conf.j2`
- [x] Update `quickstart.py` to use Docker
- [x] Add Docker management CLI commands (`status`, `logs`, `stop`, `start`, `upgrade`, `restart`)
- [x] Create GitHub Actions for Docker builds (`.github/workflows/docker-build.yml`)
- [ ] Test quickstart with Docker deployment (pending image build)

### Phase 2: Cross-Import ✅ COMPLETE
- [x] Implement `detect_ipmi_monitor()` in dc-overview
- [x] Implement `import_ipmi_config()` in dc-overview
- [ ] Implement `detect_dc_overview()` in ipmi-monitor (future)
- [ ] Implement `import_dc_overview_config()` in ipmi-monitor (future)
- [ ] Add BMC IP prompt for imported servers (future)

### Phase 3: Exporters ✅ COMPLETE
- [x] Native exporter installation for workers (node_exporter, dc-exporter)
- [x] Remote exporter installation via SSH (Paramiko)
- [x] GPU detection before dc-exporter install
- [x] Vast.ai exporter integration (Docker container)
- [ ] RunPod exporter (port 8623) - needs development
- [ ] HiveFleet exporter (port 8624) - needs development

### Phase 4: Proxy Integration ✅ COMPLETE
- [x] Update `cryptolabs-proxy/scripts/health-api.py` with dc-overview port 5001
- [x] Create dc-overview nginx.conf.j2 template
- [x] Grafana provisioning templates (datasources, dashboards)
- [ ] Test landing page service detection (pending deployment)

### Phase 5: CLI Parity with ipmi-monitor ✅ COMPLETE
- [x] `quickstart` command
- [x] `status` command (shows Docker container status)
- [x] `logs` command (Docker logs)
- [x] `stop` command (docker compose down)
- [x] `start` command (docker compose up -d)
- [x] `upgrade` command (pull latest + restart)
- [x] `restart` command

### Phase 6: Documentation (Pending)
- [ ] Update README.md
- [ ] Update docs/index.md
- [ ] Add quickstart screenshots
- [ ] Document cross-import feature

---

## Testing Plan

### Pre-requisite: Build Docker Image

Before testing quickstart, build the Docker image locally (or push to dev branch to trigger workflow):

```bash
cd /Users/hanneszietsman/CrypotAI/dc-overview
docker build -t ghcr.io/cryptolabsza/dc-overview:latest .
```

### Test Scenario 1: Fresh DC Overview Install
```bash
# Install from local repo
pipx install /Users/hanneszietsman/CrypotAI/dc-overview --force

# Or from GitHub (after pushing to dev)
pipx install "git+https://github.com/cryptolabsza/dc-overview.git@dev" --force

# Run quickstart
sudo ~/.local/bin/dc-overview quickstart
```

**Expected Flow:**
1. Shows environment detection (hostname, IP, GPU count)
2. Asks for machine role (worker/master/both)
3. If master: checks Docker, asks for port/passwords
4. Generates docker-compose.yml, prometheus.yml
5. Pulls images, starts containers
6. Shows access URLs

### Test Scenario 2: DC Overview After IPMI Monitor
```bash
# With IPMI Monitor already installed at /etc/ipmi-monitor
sudo ~/.local/bin/dc-overview quickstart
```

**Expected:**
- Detects ipmi-monitor → "[green]✓[/green] IPMI Monitor detected"
- Asks "Include IPMI Monitor in reverse proxy?" → adds /ipmi/ route
- Imports SSH keys and servers if confirmed

### Test Scenario 3: CLI Commands
```bash
# After quickstart completes
dc-overview status      # Shows container status
dc-overview logs -f     # Follow logs
dc-overview stop        # Stop containers
dc-overview start       # Start containers
dc-overview upgrade     # Pull latest + restart
```

---

## Repository Structure (Current)

```
dc-overview/
├── Dockerfile                    # ✅ Docker image definition
├── requirements.txt              # ✅ Python deps for Docker
├── pyproject.toml               # ✅ Updated with Flask, gunicorn deps
├── src/dc_overview/
│   ├── __init__.py              # Version info
│   ├── app.py                   # ✅ Flask web application (full UI)
│   ├── cli.py                   # ✅ CLI with Docker commands
│   ├── quickstart.py            # ✅ Docker-based setup wizard
│   └── templates/
│       ├── docker-compose.yml.j2 # ✅ Docker compose template
│       ├── prometheus.yml.j2     # ✅ Prometheus config template
│       ├── nginx.conf.j2         # ✅ Nginx reverse proxy template
│       └── grafana/
│           └── provisioning/
│               ├── datasources/prometheus.yml  # ✅
│               └── dashboards/default.yml      # ✅
├── dashboards/                   # Grafana dashboard JSON files
├── .github/workflows/
│   ├── publish.yml              # PyPI publishing
│   └── docker-build.yml         # ✅ Docker image build
└── docs/
    └── index.md
```

---

## Decisions Made

1. **Port Assignment**: ✅ DC Overview uses port **5001** (configurable in quickstart). IPMI Monitor uses 5000.

2. **Database Sharing**: ✅ Keep **separate databases** per product. Cross-import via detection functions.

3. **SSH Key Storage**: ✅ Per-product directories (`/etc/dc-overview/ssh_keys/`, `/etc/ipmi-monitor/ssh_keys/`). Keys copied during import.

4. **Prometheus Configuration**: ✅ Auto-detects IPMI Monitor and adds to prometheus.yml if present.

5. **Grafana Dashboard Provisioning**: ✅ Dashboards bundled in package (`dc_overview/dashboards/`) and copied to Grafana volume during setup.

6. **Exporter Strategy**: 
   - **Master node**: Docker containers (dc-overview, prometheus, grafana, proxy)
   - **GPU Workers**: Native systemd services (node_exporter, dc-exporter) for compatibility with Vast.ai/RunPod platforms

---

## Port Assignments

| Service | Port | Notes |
|---------|------|-------|
| ipmi-monitor | 5000 | Default, configurable |
| dc-overview | 5001 | Default, configurable in quickstart |
| grafana | 3000 | Standard |
| prometheus | 9090 | Standard |
| node_exporter | 9100 | Standard |
| dc-exporter | 9835 | Custom GPU metrics |
| dcgm-exporter | 9400 | NVIDIA DCGM |
| vastai-exporter | 8622 | Vast.ai earnings |
| runpod-exporter | 8623 | Reserved (future) |
| hivefleet-exporter | 8624 | Reserved (future) |

---

*Brief created: 2026-01-23*
*Last updated: 2026-01-23*
*Target: DC Overview v1.1.0*
*Related: ipmi-monitor v1.1.0, cryptolabs-proxy v1.0.0*
