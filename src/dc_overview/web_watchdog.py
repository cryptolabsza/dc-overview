"""
DC Watchdog agent management for the web application.

Functions for checking agent status, installing/removing agents,
fetching API key, and communicating with the dc-watchdog server.
"""

import http.client
import json
import logging
import os
import re
import subprocess
import time

import yaml
import requests as http_requests

from .proxy import get_proxy_config
from .ssh_helpers import build_ssh_cmd
from .web_exporters import check_exporter

logger = logging.getLogger(__name__)

# DC Watchdog API integration
WATCHDOG_URL = os.environ.get('WATCHDOG_URL', 'https://watchdog.cryptolabs.co.za')

# Cache for watchdog API results (avoid hammering the API)
_watchdog_api_cache = {'ts': 0, 'data': None}
_WATCHDOG_CACHE_TTL = 30  # seconds


def get_watchdog_api_key() -> str:
    """Get DC Watchdog API key from environment, proxy API, or config files.
    
    Searches in order:
    1. WATCHDOG_API_KEY environment variable
    2. /data/auth/watchdog_api_key (shared volume from cryptolabs-proxy)
    3. Proxy internal API at http://172.30.0.10:8080/internal/api/config/watchdog_api_key
    4. /etc/dc-overview/.secrets.yaml
    5. /etc/dc-overview/fleet-config.yaml
    """
    # 1. Check environment variable first
    api_key = os.environ.get('WATCHDOG_API_KEY', '')
    if api_key:
        return api_key
    
    # 2. Check shared fleet-auth-data volume
    shared_key_path = '/data/auth/watchdog_api_key'
    if os.path.exists(shared_key_path):
        try:
            with open(shared_key_path) as f:
                api_key = f.read().strip()
                if api_key:
                    return api_key
        except PermissionError:
            logger.warning(f"Permission denied reading {shared_key_path} - proxy may need rebuild to fix file permissions")
        except Exception:
            pass
    
    # 3. Ask the proxy directly via internal API
    api_key = get_proxy_config('watchdog_api_key')
    if api_key:
        return api_key
    
    # 4. Check .secrets.yaml
    secrets_path = '/etc/dc-overview/.secrets.yaml'
    if os.path.exists(secrets_path):
        try:
            with open(secrets_path) as f:
                secrets = yaml.safe_load(f) or {}
                api_key = secrets.get('watchdog_api_key') or secrets.get('ipmi_ai_license')
                if api_key:
                    return api_key
        except Exception:
            pass
    
    # 5. Check fleet-config.yaml (legacy location)
    config_paths = ['/etc/dc-overview/fleet-config.yaml', '/etc/dc-overview/config.yaml']
    for config_path in config_paths:
        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    cfg = yaml.safe_load(f) or {}
                    api_key = cfg.get('watchdog', {}).get('api_key', '')
                    if not api_key:
                        api_key = cfg.get('ipmi_monitor', {}).get('ai_license_key', '')
                    if api_key:
                        return api_key
            except Exception:
                pass
    
    return ''


def get_site_id() -> str:
    """Get the site_id for this deployment (multi-site support).
    
    Derives site_id from fleet config domain or master_ip.
    Consistent with what's written to agent.yaml during deployment.
    """
    config_paths = ['/etc/dc-overview/fleet-config.yaml', '/etc/dc-overview/config.yaml']
    for config_path in config_paths:
        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    cfg = yaml.safe_load(f) or {}
                    domain = cfg.get('domain', '')
                    if domain:
                        return domain
                    master_ip = cfg.get('master_ip', '')
                    if master_ip:
                        return master_ip
            except Exception:
                pass
    
    # Fallback: use hostname
    import socket
    return socket.gethostname()


def get_watchdog_agents_from_api() -> dict:
    """Fetch per-agent status from the dc-watchdog server API.
    
    Returns a dict keyed by worker_id (lowercase) with agent info,
    or empty dict if unavailable. Uses cached results for 30s.
    """
    now = time.time()
    
    if _watchdog_api_cache['data'] is not None and (now - _watchdog_api_cache['ts']) < _WATCHDOG_CACHE_TTL:
        return _watchdog_api_cache['data']
    
    api_key = get_watchdog_api_key()
    if not api_key:
        return {}
    
    try:
        resp = http_requests.get(
            f'{WATCHDOG_URL}/api/agents/status',
            params={'api_key': api_key},
            timeout=5
        )
        if resp.ok:
            data = resp.json()
            agents_map = {}
            for agent in data.get('agents', []):
                wid = (agent.get('worker_id') or '').lower()
                if wid:
                    agents_map[wid] = agent
            
            _watchdog_api_cache['ts'] = now
            _watchdog_api_cache['data'] = agents_map
            return agents_map
    except Exception as e:
        logger.debug(f"Could not fetch watchdog agent status: {e}")
    
    return _watchdog_api_cache.get('data') or {}


def check_watchdog_health_port(ip, port=9878):
    """Check the dc-watchdog-agent health endpoint via HTTP.
    
    The agent exposes /health on port 9878 with JSON status.
    Returns dict with status or None if unreachable.
    """
    try:
        conn = http.client.HTTPConnection(ip, port, timeout=3)
        conn.request("GET", "/health")
        resp = conn.getresponse()
        if resp.status == 200:
            data = json.loads(resp.read().decode())
            return {
                'running': True,
                'installed': True,
                'status': 'running',
                'version': data.get('version'),
                'last_heartbeat_ok': data.get('last_heartbeat_ok', False),
                'heartbeat_count': data.get('heartbeat_count', 0),
                'uptime_seconds': data.get('uptime_seconds', 0),
                'source': 'health_port'
            }
        conn.close()
    except Exception:
        pass
    return None


def check_watchdog_agent(server):
    """Check if dc-watchdog-agent is running for this server.
    
    Uses a consistent, fast checking strategy (no SSH):
    1. Primary: Query the dc-watchdog server API (HTTP, cached, bulk)
    2. Secondary: Probe the agent's local health port (9878)
    3. Last resort: Use database cached state
    """
    # Method 1: Check via dc-watchdog server API
    agents_map = get_watchdog_agents_from_api()
    if agents_map:
        server_name_lower = server.name.lower()
        agent_info = agents_map.get(server_name_lower)
        
        if agent_info:
            is_online = agent_info.get('online', False)
            version = agent_info.get('version') or None
            last_seen = agent_info.get('last_seen', '')
            
            if is_online:
                # Agent is actively reporting - definitely installed and running
                return {
                    'running': True,
                    'installed': True,
                    'status': 'running',
                    'version': version,
                    'last_seen': last_seen,
                    'source': 'watchdog_api'
                }
            # Agent is offline on the watchdog server - don't trust as "installed"
            # because it may have been removed locally. Fall through to health port
            # check below to verify it's actually on the machine.
    
    # Method 2: Probe the agent's local health port
    health_result = check_watchdog_health_port(server.server_ip)
    if health_result:
        return health_result
    
    # Check TCP port to distinguish "not listening" from "not reachable"
    port_check = check_exporter(server.server_ip, 9878)
    if port_check.get('running'):
        return {
            'running': True,
            'installed': True,
            'status': 'running',
            'version': None,
            'source': 'health_port_tcp'
        }
    
    # Method 3: Fall back to database cached state
    db_installed = getattr(server, 'watchdog_agent_installed', False)
    db_enabled = getattr(server, 'watchdog_agent_enabled', False)
    db_version = getattr(server, 'watchdog_agent_version', None)
    
    if db_installed:
        return {
            'running': db_enabled,
            'installed': True,
            'status': 'running (cached)' if db_enabled else 'stopped (cached)',
            'version': db_version,
            'source': 'database'
        }
    return {'running': False, 'installed': False, 'status': 'not_installed', 'version': None, 'source': 'none'}


def toggle_watchdog_service(server, enabled: bool) -> bool:
    """Start or stop dc-watchdog-agent service on a server via SSH."""
    try:
        cmd, env = build_ssh_cmd(server, timeout=10)
        
        if enabled:
            cmd.append('systemctl start dc-watchdog-agent')
        else:
            cmd.append('systemctl stop dc-watchdog-agent')
        
        run_env = {**os.environ, **env} if env else None
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15, env=run_env)
        return result.returncode == 0
    except Exception as e:
        logger.error(f"Error toggling watchdog agent on {server.name}: {e}")
        return False


def get_watchdog_latest_release() -> dict:
    """Query GitHub API for the latest dc-watchdog agent release.
    
    Returns dict with 'version' and 'tag', or empty dict if unreachable.
    Uses a 10-minute cache.
    """
    from datetime import datetime
    
    cache_key = '_watchdog_release_cache'
    cache = getattr(get_watchdog_latest_release, cache_key, None)
    if cache and (datetime.utcnow() - cache['fetched_at']).total_seconds() < 600:
        return cache['data']
    
    try:
        import requests as req
        resp = req.get(
            'https://api.github.com/repos/cryptolabsza/dc-watchdog/releases/latest',
            headers={'Accept': 'application/vnd.github.v3+json'},
            timeout=10
        )
        if resp.ok:
            data = resp.json()
            tag = data.get('tag_name', '')
            version = tag.lstrip('v') if tag else ''
            result = {'version': version, 'tag': tag, 'name': data.get('name', '')}
            setattr(get_watchdog_latest_release, cache_key, {
                'data': result, 'fetched_at': datetime.utcnow()
            })
            return result
    except Exception as e:
        logger.warning(f"Could not fetch latest watchdog release: {e}")
    
    return {}


def install_watchdog_agent_remote(server, api_key: str) -> tuple:
    """Install DC Watchdog Go agent on a remote server via SSH.
    
    Downloads the Go binary from the latest GitHub release. No bash fallback -
    the Go binary is required for health endpoint, Prometheus metrics, etc.
    
    Security: Requests a worker-specific token from dc-watchdog when possible.
    """
    GITHUB_REPO = "cryptolabsza/dc-watchdog"
    
    try:
        # Step 1: Request a worker token from dc-watchdog
        import requests as req
        
        worker_token = None
        try:
            token_resp = req.post(
                f'{WATCHDOG_URL}/api/worker/register',
                json={'worker_id': server.name},
                params={'api_key': api_key},
                timeout=30
            )
            
            if token_resp.ok:
                token_data = token_resp.json()
                if token_data.get('success'):
                    worker_token = token_data.get('worker_token')
                    logger.info(f"Worker token obtained for {server.name}")
                else:
                    return False, token_data.get('error', 'Failed to get worker token')
            else:
                logger.warning(f"Could not get worker token (status {token_resp.status_code}), using API key")
        except req.RequestException as e:
            logger.warning(f"Could not reach dc-watchdog for token: {e}, using API key")
        
        latest = get_watchdog_latest_release()
        latest_ver = latest.get('version', 'unknown')
        logger.info(f"Installing watchdog agent on {server.name} (latest release: {latest_ver})")
        
        # Step 2: Build SSH command and deploy the Go agent
        cmd, ssh_env = build_ssh_cmd(server, timeout=60)
        
        auth_key = worker_token if worker_token else api_key
        
        install_script = f'''
set -e

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/dc-watchdog"
GITHUB_REPO="{GITHUB_REPO}"

echo "[+] Installing DC-Watchdog Agent (Go binary)..."

# Stop existing agent if running
systemctl stop dc-watchdog-agent 2>/dev/null || true

# Create directories
mkdir -p "$CONFIG_DIR"

# Install dependencies (mtr for network diagnostics)
echo "[+] Installing dependencies..."
if command -v apt-get &> /dev/null; then
    apt-get update -qq 2>/dev/null || true
    apt-get install -y -qq mtr-tiny curl 2>/dev/null || true
elif command -v yum &> /dev/null; then
    yum install -y -q mtr curl 2>/dev/null || true
elif command -v dnf &> /dev/null; then
    dnf install -y -q mtr curl 2>/dev/null || true
fi

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)  ARCH_SUFFIX="linux-amd64" ;;
    aarch64) ARCH_SUFFIX="linux-arm64" ;;
    *)
        echo "INSTALL_FAILED: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Download Go agent binary
echo "[+] Downloading Go agent for $ARCH_SUFFIX..."
DOWNLOAD_OK=false

# Primary: Download from DC Watchdog server
AGENT_URL="{WATCHDOG_URL}/agent/dc-watchdog-agent-$ARCH_SUFFIX"
if curl -fsSL "$AGENT_URL" -o "$INSTALL_DIR/dc-watchdog-agent.tmp" 2>/dev/null; then
    if [ -s "$INSTALL_DIR/dc-watchdog-agent.tmp" ]; then
        mv "$INSTALL_DIR/dc-watchdog-agent.tmp" "$INSTALL_DIR/dc-watchdog-agent"
        chmod +x "$INSTALL_DIR/dc-watchdog-agent"
        if "$INSTALL_DIR/dc-watchdog-agent" -version 2>/dev/null; then
            DOWNLOAD_OK=true
            echo "[+] Go agent downloaded from watchdog server"
        fi
    fi
fi

# Fallback: Try GitHub releases
if [ "$DOWNLOAD_OK" = "false" ]; then
    echo "[+] Trying GitHub releases (latest)..."
    RELEASE_URL="https://github.com/$GITHUB_REPO/releases/latest/download/dc-watchdog-agent-$ARCH_SUFFIX"
    if curl -fsSL "$RELEASE_URL" -o "$INSTALL_DIR/dc-watchdog-agent.tmp" 2>/dev/null; then
        if [ -s "$INSTALL_DIR/dc-watchdog-agent.tmp" ]; then
            mv "$INSTALL_DIR/dc-watchdog-agent.tmp" "$INSTALL_DIR/dc-watchdog-agent"
            chmod +x "$INSTALL_DIR/dc-watchdog-agent"
            if "$INSTALL_DIR/dc-watchdog-agent" -version 2>/dev/null; then
                DOWNLOAD_OK=true
                echo "[+] Go agent downloaded from GitHub releases"
            fi
        fi
    fi
fi

rm -f "$INSTALL_DIR/dc-watchdog-agent.tmp" 2>/dev/null

if [ "$DOWNLOAD_OK" = "false" ]; then
    echo "INSTALL_FAILED: Could not download Go agent binary from watchdog server or GitHub releases"
    exit 1
fi

# Detect GPU availability
HAS_GPU=false
if command -v nvidia-smi &> /dev/null; then
    if timeout 5 nvidia-smi -L &> /dev/null; then
        HAS_GPU=true
    fi
fi

if [ "$HAS_GPU" = "true" ]; then
    MONITOR_LEVEL="standard"
else
    MONITOR_LEVEL="basic"
fi

# Create YAML configuration for Go agent
echo "[+] Creating configuration..."
cat > "$CONFIG_DIR/agent.yaml" << YAMLEOF
# DC-Watchdog Agent Configuration
server_url: "{WATCHDOG_URL}"
api_key: "{auth_key}"
worker_name: "{server.name}"
heartbeat_interval: 30s
level: $MONITOR_LEVEL

health_port: 9878

gpu:
  enabled: $HAS_GPU
  check_driver_health: true
  detect_vm_passthrough: true
  timeout_seconds: 5

network:
  mtr:
    enabled: true
    interval: 10
    hops: 15

raid:
  enabled: true
  interval: 1
  alert_on_degraded: true

log_level: info
YAMLEOF
chmod 600 "$CONFIG_DIR/agent.yaml"

# Clean up any old bash fallback agent
rm -f /opt/dc-watchdog/dc-watchdog-agent.sh 2>/dev/null

# Create systemd service
echo "[+] Creating systemd service..."
cat > /etc/systemd/system/dc-watchdog-agent.service << 'SVCEOF'
[Unit]
Description=DC-Watchdog Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/dc-watchdog-agent -config /etc/dc-watchdog/agent.yaml
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal
MemoryLimit=128M

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable dc-watchdog-agent
systemctl restart dc-watchdog-agent

# Verify agent starts and stays running
sleep 3
if ! systemctl is-active --quiet dc-watchdog-agent; then
    echo "INSTALL_FAILED: Agent crashed on startup"
    journalctl -u dc-watchdog-agent -n 5 --no-pager 2>/dev/null || true
    exit 1
fi

sleep 3
if ! systemctl is-active --quiet dc-watchdog-agent; then
    echo "INSTALL_FAILED: Agent crashed after startup"
    journalctl -u dc-watchdog-agent -n 5 --no-pager 2>/dev/null || true
    exit 1
fi

VERSION=$("$INSTALL_DIR/dc-watchdog-agent" -version 2>&1 | head -1 || echo "unknown")
echo "AGENT_VERSION=$VERSION"
echo "INSTALL_SUCCESS"
'''
        cmd.append(install_script)
        
        run_env = {**os.environ, **ssh_env} if ssh_env else None
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180, env=run_env)
        
        if result.returncode == 0 and 'INSTALL_SUCCESS' in result.stdout:
            for line in result.stdout.splitlines():
                if line.startswith('AGENT_VERSION='):
                    version_str = line.split('=', 1)[1].strip()
                    ver_match = re.search(r'(\d+\.\d+\.\d+)', version_str)
                    if ver_match:
                        server.watchdog_agent_version = ver_match.group(1)
            return True, None
        else:
            error = result.stderr.strip() or result.stdout.strip() or 'Unknown error'
            return False, error[:300]
    except subprocess.TimeoutExpired:
        return False, 'SSH connection timed out (180s)'
    except Exception as e:
        logger.exception(f"Error installing watchdog agent on {server.name}")
        return False, str(e)[:200]


def remove_watchdog_agent_remote(server) -> bool:
    """Remove DC Watchdog agent from a remote server via SSH."""
    try:
        cmd, env = build_ssh_cmd(server, timeout=15)
        
        remove_script = '''
systemctl stop dc-watchdog-agent 2>/dev/null || true
systemctl disable dc-watchdog-agent 2>/dev/null || true
rm -f /etc/systemd/system/dc-watchdog-agent.service
rm -f /usr/local/bin/dc-watchdog-agent
rm -rf /etc/dc-watchdog
rm -rf /opt/dc-watchdog
systemctl daemon-reload
echo "REMOVE_SUCCESS"
'''
        cmd.append(remove_script)
        
        run_env = {**os.environ, **env} if env else None
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=run_env)
        return result.returncode == 0 and 'REMOVE_SUCCESS' in result.stdout
    except Exception as e:
        logger.error(f"Error removing watchdog agent on {server.name}: {e}")
        return False
