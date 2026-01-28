# DC Overview - Architecture & Handover Documentation

*Last Updated: January 2026*

This document provides comprehensive technical documentation for developers working on DC Overview. It covers system architecture, component interactions, user permissions, deployment flow, and development workflows.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [Component Details](#component-details)
4. [User Permissions & Authentication](#user-permissions--authentication)
5. [Deployment Flow](#deployment-flow)
6. [Configuration System](#configuration-system)
7. [Key Source Files](#key-source-files)
8. [Development Workflow](#development-workflow)
9. [Testing Environment](#testing-environment)
10. [API Reference](#api-reference)
11. [Known Issues & TODOs](#known-issues--todos)

---

## System Overview

DC Overview is a GPU datacenter monitoring suite that provides:

- **Fleet Management** - Unified authentication and service discovery
- **Server Management** - Web UI for managing GPU workers
- **Metrics Collection** - Prometheus-based time-series database
- **Visualization** - Grafana dashboards for GPU and system metrics
- **Hardware Health** - Integration with IPMI Monitor for BMC monitoring
- **Revenue Tracking** - Vast.ai/RunPod exporter integration

### Design Principles

1. **Single Command Setup** - `dc-overview quickstart` deploys everything
2. **Configuration Upfront** - Fleet Wizard collects all config before deployment
3. **Unified Authentication** - Single login for all services via cryptolabs-proxy
4. **Native Worker Exporters** - systemd services (not Docker) for GPU compatibility
5. **Shared Infrastructure** - Works alongside IPMI Monitor, shares proxy and network

---

## Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         INTERNET / USERS                                 │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ HTTPS :443
┌─────────────────────────────────────────────────────────────────────────┐
│                        cryptolabs-proxy                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │  Nginx + Auth Service                                                ││
│  │  - Unified Fleet Authentication (admin/readwrite/readonly)           ││
│  │  - Routes: / /dc/ /grafana/ /prometheus/ /ipmi/                     ││
│  │  - SSL termination (Let's Encrypt or self-signed)                   ││
│  │  - Sets X-Fleet-Auth-* headers on authenticated requests            ││
│  └─────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    Docker Network: cryptolabs
                                    │
        ┌───────────────┬───────────┼───────────┬───────────────┐
        ▼               ▼           ▼           ▼               ▼
┌─────────────┐ ┌─────────────┐ ┌─────────┐ ┌─────────────┐ ┌───────────┐
│ dc-overview │ │   Grafana   │ │Promethe-│ │ipmi-monitor │ │ vastai-   │
│   :5001     │ │   :3000     │ │us :9090 │ │   :5000     │ │ exporter  │
│   /dc/      │ │  /grafana/  │ │/prometh/│ │   /ipmi/    │ │  :8622    │
│             │ │             │ │         │ │             │ │           │
│ Flask App   │ │ Dashboards  │ │ TSDB    │ │ BMC Health  │ │ Earnings  │
│ Server Mgmt │ │ Alerting    │ │ Scrapes │ │ AI Insights │ │ Metrics   │
└─────────────┘ └─────────────┘ └─────────┘ └─────────────┘ └───────────┘
        │               │           │
        └───────────────┴───────────┘
                    │
                    │ Prometheus scrapes :9100, :9835
                    │ SSH for exporter installation
                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          GPU WORKERS                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
│  │   gpu-worker-01 │  │   gpu-worker-02 │  │   gpu-worker-N  │         │
│  │                 │  │                 │  │                 │         │
│  │ ┌─────────────┐ │  │ ┌─────────────┐ │  │ ┌─────────────┐ │         │
│  │ │node_exporter│ │  │ │node_exporter│ │  │ │node_exporter│ │         │
│  │ │   :9100     │ │  │ │   :9100     │ │  │ │   :9100     │ │         │
│  │ └─────────────┘ │  │ └─────────────┘ │  │ └─────────────┘ │         │
│  │ ┌─────────────┐ │  │ ┌─────────────┐ │  │ ┌─────────────┐ │         │
│  │ │ dc-exporter │ │  │ │ dc-exporter │ │  │ │ dc-exporter │ │         │
│  │ │   :9835     │ │  │ │   :9835     │ │  │ │   :9835     │ │         │
│  │ └─────────────┘ │  │ └─────────────┘ │  │ └─────────────┘ │         │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘         │
│       (systemd)            (systemd)            (systemd)               │
└─────────────────────────────────────────────────────────────────────────┘
```

### Docker Network

All services run on the `cryptolabs` Docker network (external network):

```bash
docker network create cryptolabs
```

This allows:
- Service-to-service communication using container names
- Shared network between dc-overview, ipmi-monitor, and proxy
- No port exposure needed for internal services

---

## Component Details

### cryptolabs-proxy

**Image**: `ghcr.io/cryptolabsza/cryptolabs-proxy:dev`

The unified reverse proxy handles:
- SSL termination (Let's Encrypt or self-signed)
- Fleet authentication (cookie-based sessions)
- Role-based access control
- Service routing

**Routes**:
| Path | Destination | Auth Required |
|------|-------------|---------------|
| `/` | Landing page | No (shows login) |
| `/login` | Auth endpoint | No |
| `/dc/` | dc-overview:5001 | Yes |
| `/grafana/` | grafana:3000 | Yes |
| `/prometheus/` | prometheus:9090 | Yes |
| `/ipmi/` | ipmi-monitor:5000 | Yes |

**Auth Headers Set**:
```
X-Fleet-Authenticated: true
X-Fleet-Auth-User: <username>
X-Fleet-Auth-Role: <admin|readwrite|readonly>
X-Fleet-Auth-Token: <session-token>
```

### dc-overview (Server Manager)

**Image**: `ghcr.io/cryptolabsza/dc-overview:dev`
**Port**: 5001
**Path**: `/dc/`

Flask web application for managing GPU workers:
- Server list management (add/remove/check connectivity)
- Exporter installation via SSH
- Integration settings
- Prometheus target generation

**Key Features**:
- Reads Fleet auth headers for auto-authentication
- API for server CRUD operations
- SSH key management
- Grafana role sync endpoint

### Prometheus

**Image**: `prom/prometheus:latest`
**Port**: 9090
**Path**: `/prometheus/`

Configuration stored at `/etc/dc-overview/prometheus.yml`:
- Scrapes all worker exporters
- Recording rules for unified GPU metrics
- IPMI Monitor scrape target
- Vast.ai exporter scrape target

### Grafana

**Image**: `grafana/grafana:latest`
**Port**: 3000
**Path**: `/grafana/`

Provisioned dashboards:
- DC Overview (fleet summary)
- Node Exporter Full
- NVIDIA DCGM Exporter
- Vast Dashboard
- IPMI Monitor

### Worker Exporters

**node_exporter** (port 9100):
- System metrics (CPU, RAM, disk, network)
- Installed as systemd service

**dc-exporter** (port 9835):
- GPU metrics (VRAM temp, hotspot temp, power, throttling)
- Binary: `/usr/local/bin/dc-exporter-rs`
- Installed as systemd service

---

## User Permissions & Authentication

### Role Hierarchy

| Role | Description | Capabilities |
|------|-------------|--------------|
| `admin` | Full access | All operations, user management |
| `readwrite` | Edit access | Modify servers, settings, no user mgmt |
| `readonly` | View only | Dashboard viewing, no modifications |

### Authentication Flow

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Browser   │────▶│ cryptolabs-proxy│────▶│   Sub-service   │
│             │     │                 │     │ (dc-overview,   │
│             │     │ 1. Check cookie │     │  grafana, etc.) │
│             │     │ 2. Validate     │     │                 │
│             │     │ 3. Set headers  │     │ Reads headers:  │
│             │     │    X-Fleet-*    │     │ - Auto login    │
│             │     │                 │     │ - Apply role    │
└─────────────┘     └─────────────────┘     └─────────────────┘
```

### DC Overview Auth Implementation

Location: `src/dc_overview/app.py` (lines 162-199)

```python
PROXY_AUTH_HEADER_FLAG = 'X-Fleet-Authenticated'
PROXY_AUTH_HEADER_USER = 'X-Fleet-Auth-User'
PROXY_AUTH_HEADER_ROLE = 'X-Fleet-Auth-Role'

def is_proxy_authenticated():
    if request.headers.get(PROXY_AUTH_HEADER_FLAG) == 'true':
        username = request.headers.get(PROXY_AUTH_HEADER_USER)
        proxy_role = request.headers.get(PROXY_AUTH_HEADER_ROLE, 'readonly')
        role = proxy_role if proxy_role in ['admin', 'readwrite', 'readonly'] else 'readonly'
        session['authenticated'] = True
        session['username'] = username
        session['role'] = role
        return True
    return False
```

### Grafana Role Mapping

Fleet roles map to Grafana roles:

| Fleet Role | Grafana Role |
|------------|--------------|
| `admin` | `Admin` |
| `readwrite` | `Editor` |
| `readonly` | `Viewer` |

**Manual sync required** via API:
```python
# POST /api/grafana/sync-role
# Syncs current user's Fleet role to Grafana org role
```

---

## Deployment Flow

### Quickstart Command

Entry point: `cli.py` → `run_fleet_quickstart()`

```
dc-overview quickstart [-c CONFIG] [-y]
```

### Deployment Steps

The `FleetManager.deploy()` method executes:

| Step | Function | Description |
|------|----------|-------------|
| 1 | `_install_prerequisites()` | Docker, nginx, ipmitool, certbot |
| 2 | `_setup_ssh_keys()` | Generate fleet key, deploy to workers |
| 3 | `_deploy_prometheus_grafana()` | Start core containers |
| 4 | `_deploy_to_workers()` | Install exporters via SSH |
| 5 | `_configure_prometheus_targets()` | Update scrape config |
| 6 | `_import_dashboards()` | Load Grafana dashboards |
| 7 | `_deploy_ipmi_monitor()` | Optional IPMI Monitor |
| 8 | `_deploy_vast_exporter()` | Optional Vast.ai exporter |
| 9 | `_setup_reverse_proxy()` | Deploy cryptolabs-proxy |

### Exporter Installation Script

Executed on workers via SSH (fleet_manager.py lines 564-622):

```bash
#!/bin/bash
# Install node_exporter
curl -sLO https://github.com/prometheus/node_exporter/releases/download/v1.7.0/...
systemctl enable --now node_exporter

# Install dc-exporter
curl -L https://github.com/cryptolabsza/dc-exporter-releases/releases/latest/download/dc-exporter-rs -o /usr/local/bin/dc-exporter-rs
systemctl enable --now dc-exporter
```

---

## Configuration System

### Configuration Files

| File | Location | Purpose |
|------|----------|---------|
| `fleet-config.yaml` | `/etc/dc-overview/` | Main deployment config |
| `.secrets.yaml` | `/etc/dc-overview/` | Sensitive credentials |
| `prometheus.yml` | `/etc/dc-overview/` | Prometheus scrape config |
| `recording_rules.yml` | `/etc/dc-overview/` | Prometheus recording rules |
| `docker-compose.yml` | `/etc/dc-overview/` | Container definitions |

### FleetConfig Data Classes

Location: `src/dc_overview/fleet_config.py`

```python
@dataclass
class FleetConfig:
    site_name: str
    fleet_admin_user: str
    fleet_admin_pass: str
    ssh: SSHConfig
    bmc: BMCConfig
    ssl: SSLConfig
    components: ComponentConfig
    servers: List[Server]
    grafana: GrafanaConfig
    prometheus: PrometheusConfig
    vast: VastConfig
    ipmi_monitor: IPMIMonitorConfig
```

### Server Configuration

```python
@dataclass
class Server:
    name: str
    server_ip: str
    bmc_ip: Optional[str] = None
    ssh_user: Optional[str] = None
    ssh_port: int = 22
    ssh_key_path: Optional[str] = None
    has_gpu: bool = False
    exporters_installed: bool = False
```

---

## Key Source Files

### Core Modules

| File | Purpose |
|------|---------|
| `cli.py` | CLI command definitions |
| `fleet_wizard.py` | Interactive configuration collection |
| `fleet_manager.py` | Deployment orchestration (main logic) |
| `fleet_config.py` | Configuration data classes |
| `app.py` | Flask web application (Server Manager) |
| `ssh_manager.py` | SSH key generation and remote execution |
| `exporters.py` | Exporter installation logic |
| `prerequisites.py` | System dependency installer |
| `reverse_proxy.py` | Nginx/SSL configuration |

### Templates

| File | Purpose |
|------|---------|
| `templates/docker-compose.yml.j2` | Container definitions |
| `templates/prometheus.yml.j2` | Initial Prometheus config |
| `templates/nginx.conf.j2` | Reverse proxy config |
| `templates/landing.html.j2` | Fleet landing page |

### Dashboards

Location: `dashboards/` or `src/dc_overview/dashboards/`

| File | Dashboard |
|------|-----------|
| `DC_Overview.json` | Fleet GPU overview |
| `Node_Exporter_Full.json` | System metrics |
| `NVIDIA_DCGM_Exporter.json` | GPU performance |
| `Vast_Dashboard.json` | Vast.ai earnings |
| `IPMI_Monitor.json` | BMC health |

---

## Development Workflow

### GitHub Actions

#### docker-build.yml

Triggers on:
- Push to `main`, `master`, `dev`, `develop`
- Version tags (`v*`)
- Pull requests

Builds:
- Multi-arch images (linux/amd64, linux/arm64)
- Registry: `ghcr.io/cryptolabsza/dc-overview`

Tags:
- Version tags: `v1.0.0`, `1.0.0`, `1.0`, `latest`, `stable`
- Branch tags: `main`, `dev`, `develop`
- PR tags: `pr-{number}`
- SHA tags: `sha-{commit}`

#### publish.yml

Triggers on:
- GitHub releases
- Manual dispatch

Publishes to PyPI.

### Local Development

```bash
# Clone repository
git clone https://github.com/cryptolabsza/dc-overview.git
cd dc-overview

# Install in development mode
pip install -e .

# Run CLI
dc-overview --help

# Build Docker image locally
docker build -t ghcr.io/cryptolabsza/dc-overview:dev .
```

### Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Production releases |
| `dev` | Development/testing |
| `feature/*` | Feature branches |

---

## Testing Environment

### Dev Fleet

| Node | SSH Command | Notes |
|------|-------------|-------|
| master | `ssh root@41.193.204.66 -p 100 -i ~/.ssh/ubuntu_key` | Main deployment target |
| wk01 | `ssh root@41.193.204.66 -p 101 -i ~/.ssh/ubuntu_key` | Has other services - DON'T interfere |
| wk03 | `ssh root@41.193.204.66 -p 103 -i ~/.ssh/ubuntu_key` | Safe to modify |

### Test Deployment

```bash
# On master node:
pip install git+https://github.com/cryptolabsza/dc-overview.git@dev --break-system-packages
dc-overview quickstart -c /root/test-config.yaml -y
```

### Test Configuration

Create a test config file (e.g., `/root/test-config.yaml`):

```yaml
site_name: MyDatacenter
fleet_admin_user: admin
fleet_admin_pass: YOUR_ADMIN_PASSWORD
ssh:
  username: root
  key_path: ~/.ssh/id_rsa
  port: 22
bmc:
  username: admin
  password: YOUR_BMC_PASSWORD
ssl:
  mode: letsencrypt  # Options: letsencrypt, selfsigned
  domain: monitoring.example.com
  email: admin@example.com
components:
  dc_overview: true
  ipmi_monitor: true
  vast_exporter: false
servers:
  - name: server1
    server_ip: 192.168.1.100
    bmc_ip: 192.168.1.10
  - name: server2
    server_ip: 192.168.1.101
    bmc_ip: 192.168.1.11
grafana:
  admin_password: YOUR_GRAFANA_PASSWORD
ipmi_monitor:
  admin_password: YOUR_IPMI_MONITOR_PASSWORD
```

> **Security Note:** Never commit config files with real credentials. Use placeholder values in documentation.

### Cleanup Commands

```bash
# Remove dc-overview containers and volumes (safe)
docker rm -f dc-overview prometheus grafana
docker volume rm dc-overview-data prometheus-data grafana-data

# Remove exporters on workers
systemctl stop node_exporter dc-exporter
rm /usr/local/bin/node_exporter /usr/local/bin/dc-exporter-rs
```

---

## API Reference

### DC Overview API Endpoints

#### Health Check
```
GET /api/health
Response: {"status": "ok", "version": "1.1.0"}
```

#### Server Management
```
GET  /api/servers                      # List all servers
POST /api/servers                      # Add server
     Body: {"name": "...", "server_ip": "...", "ssh_user": "root"}
DELETE /api/servers/<id>               # Remove server
GET  /api/servers/<id>/check           # Check connectivity
POST /api/servers/<id>/install-exporters  # Install exporters
```

#### SSH Keys
```
GET  /api/ssh-keys                     # List SSH keys
POST /api/ssh-keys                     # Add SSH key
     Body: {"name": "...", "key_path": "..."}
POST /api/servers/<id>/ssh-key         # Assign key to server
     Body: {"ssh_key_id": 1}
```

#### Grafana Integration
```
POST /api/grafana/sync-role            # Sync Fleet role to Grafana
GET  /api/grafana/test-connection      # Test Grafana connectivity
```

#### Prometheus Targets
```
GET /api/prometheus/targets            # Get scrape targets (authenticated)
GET /api/prometheus/targets.json       # File-based discovery (no auth)
```

---

## Known Issues & TODOs

### Current Gaps

1. **Grafana Role Auto-Sync**
   - Role sync requires manual API call
   - TODO: Implement automatic sync on proxy authentication

2. **Error Handling**
   - SSH failures could use better retry logic
   - Exporter installation errors need clearer messages

3. **Health Checks**
   - No comprehensive fleet health check endpoint
   - Individual service health checks exist

### Future Improvements

1. **RunPod Exporter** (port 8623)
2. **HiveFleet Exporter** (port 8624)
3. **Automatic Grafana user provisioning**
4. **WebSocket support for real-time updates**
5. **Bulk exporter installation with progress**

---

## Quick Reference

### Container Names
```
dc-overview
prometheus
grafana
cryptolabs-proxy
ipmi-monitor
vastai-exporter
```

### Config Paths
```
/etc/dc-overview/           # Main config directory
/etc/dc-overview/ssh_keys/  # Fleet SSH keys
/etc/cryptolabs-proxy/      # Proxy config
/etc/ipmi-monitor/          # IPMI Monitor config
```

### Docker Network
```
docker network ls | grep cryptolabs
docker network inspect cryptolabs
```

### Useful Commands
```bash
# Check all services
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# View proxy logs
docker logs -f cryptolabs-proxy

# Reload prometheus config
docker exec prometheus kill -HUP 1

# Test nginx config
docker exec cryptolabs-proxy nginx -t
```

---

*This document should be updated as the system evolves. For questions, contact the development team via Discord or GitHub issues.*
