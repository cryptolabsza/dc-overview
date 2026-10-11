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
import shlex
import subprocess
import time

import yaml
import requests as http_requests

from .proxy import get_proxy_config
from .ssh_helpers import build_ssh_cmd, privileged_remote_command, remote_failure_message
from .web_exporters import check_exporter

logger = logging.getLogger(__name__)

# DC Watchdog API integration
WATCHDOG_URL = os.environ.get('WATCHDOG_URL', 'https://watchdog.cryptolabs.co.za')


def watchdog_remote_runner(*, sudo=False):
    """Static component runner shared with its readonly privilege proof."""
    command = 'timeout --signal=TERM --kill-after=30s 120s bash -s'
    return 'sudo -n -- ' + command if sudo else command


def watchdog_update_prerequisites():
    """Match the supported local unit layout without changing mask or custody."""
    return '''[ -s /etc/dc-watchdog/agent.yaml ]
[ -e /etc/systemd/system/dc-watchdog-agent.service ] || [ -L /etc/systemd/system/dc-watchdog-agent.service ]
[ -s /usr/local/bin/dc-watchdog-agent ]
'''

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
    
    # An unreachable health port cannot establish that the service was removed.
    return {'running': bool(getattr(server, 'watchdog_agent_enabled', False)),
            'installed': bool(getattr(server, 'watchdog_agent_installed', False)),
            'status': 'unknown', 'version': getattr(server, 'watchdog_agent_version', None),
            'source': 'database'}


def toggle_watchdog_service(server, enabled: bool) -> bool:
    """Start or stop dc-watchdog-agent service on a server via SSH."""
    try:
        cmd, env = build_ssh_cmd(server, timeout=10)
        
        if enabled:
            cmd.append(privileged_remote_command(server, 'systemctl start dc-watchdog-agent'))
        else:
            cmd.append(privileged_remote_command(server, 'systemctl stop dc-watchdog-agent'))
        
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


def _register_watchdog_worker(req, endpoint, name, api_key):
    response = req.post(f'{endpoint}/api/worker/register', json={'worker_id':name},
                        params={'api_key':api_key}, timeout=30)
    if not response.ok:
        return None
    value = response.json()
    token = value.get('worker_token')
    return token if value.get('success') and isinstance(token, str) and token.strip() else None


def install_watchdog_agent_remote(server, api_key: str, *, selected_artifact=None, watchdog_url=None, mode='install') -> tuple:
    """Install DC Watchdog Go agent on a remote server via SSH.
    
    Downloads the Go binary from the latest GitHub release. No bash fallback -
    the Go binary is required for health endpoint, Prometheus metrics, etc.
    
    Security: Requires a worker-specific token before any remote mutation.
    """
    GITHUB_REPO = "cryptolabsza/dc-watchdog"
    if mode not in ('install', 'update'):
        return False, 'Invalid Watchdog lifecycle mode.'
    if selected_artifact is None:
        from .worker_lifecycle import selected_worker_mutation_refusal
        refusal = selected_worker_mutation_refusal()
        if refusal:
            return False, refusal
    
    try:
        endpoint = watchdog_url or WATCHDOG_URL
        if not re.fullmatch(r'https://[A-Za-z0-9.-]+(?::[0-9]+)?', endpoint):
            raise ValueError('invalid watchdog endpoint')
        if selected_artifact is not None:
            from .exporters import validate_selected_worker_artifact
            validate_selected_worker_artifact('dc-watchdog-agent', selected_artifact)
        # Step 1: Request a worker token from dc-watchdog
        import requests as req
        
        worker_token = None
        try:
            if mode == 'update':
                # Existing agent.yaml owns the worker-specific token. Updating
                # its binary must not re-register or replace that custody.
                worker_token = ''
            else:
                worker_token = _register_watchdog_worker(req, endpoint, server.name, api_key)
                if worker_token is None:
                    return False, 'Worker registration did not return a valid token.'
        except (req.RequestException, ValueError, TypeError, AttributeError):
            return False, 'Worker registration unavailable; no remote changes were made.'
        
        latest = get_watchdog_latest_release() if selected_artifact is None else {}
        latest_ver = selected_artifact['release'] if selected_artifact is not None else latest.get('version', 'unknown')
        logger.info(f"Installing watchdog agent on {server.name} (latest release: {latest_ver})")
        
        # Step 2: Build SSH command and deploy the Go agent
        cmd, ssh_env = build_ssh_cmd(server, timeout=60)
        
        auth_key = worker_token
        
        install_script = rf'''
set -Eeuo pipefail
MODE={shlex.quote(mode)}

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/dc-watchdog"
GITHUB_REPO="{GITHUB_REPO}"

echo "[+] Installing DC-Watchdog Agent (Go binary)..."

# Keep downloads and backups private; do not stop the live agent until validated.
STAGE=$(mktemp -d)
changed=0
was_active=0
was_enabled=0
enabled_state=not-found
finish() {{
    status=$?
    trap - EXIT HUP INT TERM
    if [ "$status" != 0 ] && [ "$changed" = 1 ]; then
        recovery_failed=0
        systemctl stop dc-watchdog-agent >/dev/null 2>&1 || true
        files=("$INSTALL_DIR/dc-watchdog-agent")
        if [ "$MODE" = install ]; then files+=("$CONFIG_DIR/agent.yaml" /etc/systemd/system/dc-watchdog-agent.service); fi
        for file in "${{files[@]}}"; do
            name=$(basename "$file")
            rm -f "$file" || recovery_failed=1
            if [ -e "$STAGE/$name.old" ] || [ -L "$STAGE/$name.old" ]; then cp -a "$STAGE/$name.old" "$file" || recovery_failed=1; fi
        done
        systemctl daemon-reload || recovery_failed=1
        if [ "$MODE" = install ]; then
            case "$enabled_state" in
                enabled) systemctl enable dc-watchdog-agent || recovery_failed=1;;
                masked) systemctl mask dc-watchdog-agent || recovery_failed=1;;
                disabled|not-found) systemctl disable dc-watchdog-agent || recovery_failed=1;;
            esac
        fi
        if [ "$was_active" = 1 ]; then systemctl start dc-watchdog-agent || recovery_failed=1; systemctl is-active --quiet dc-watchdog-agent || recovery_failed=1; fi
        if [ "$recovery_failed" = 0 ]; then echo 'previous installation restored' >&2; else echo 'rollback incomplete' >&2; fi
    fi
    rm -rf "$STAGE"
    exit "$status"
}}
trap finish EXIT
trap 'exit 1' HUP INT TERM
state=$(systemctl is-active dc-watchdog-agent) || [ "$state" = inactive ] || [ "$state" = failed ]
[ "$state" != active ] || was_active=1
state=$(systemctl is-enabled dc-watchdog-agent) || [ "$state" = disabled ] || [ "$state" = not-found ] || [ "$state" = masked ] || [ "$state" = masked-runtime ]
enabled_state=$state
[ "$state" != enabled ] || was_enabled=1
for file in "$INSTALL_DIR/dc-watchdog-agent" "$CONFIG_DIR/agent.yaml" /etc/systemd/system/dc-watchdog-agent.service; do
    if [ -e "$file" ] || [ -L "$file" ]; then cp -a "$file" "$STAGE/$(basename "$file").old"; fi
done
if [ "$MODE" = update ]; then
    {watchdog_update_prerequisites()}
fi

# Install dependencies (mtr for network diagnostics)
echo "[+] Installing dependencies..."
if [ "$MODE" = update ]; then :
elif command -v apt-get &> /dev/null; then
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
AGENT_URL="{endpoint}/agent/dc-watchdog-agent-$ARCH_SUFFIX"
if curl -fsSL "$AGENT_URL" -o "$STAGE/candidate" 2>/dev/null; then
    if [ -s "$STAGE/candidate" ]; then
        chmod +x "$STAGE/candidate"
        if "$STAGE/candidate" -version 2>/dev/null; then
            DOWNLOAD_OK=true
            echo "[+] Go agent downloaded from watchdog server"
        fi
    fi
fi

# Fallback: Try GitHub releases
if [ "$DOWNLOAD_OK" = "false" ]; then
    echo "[+] Trying GitHub releases (latest)..."
    RELEASE_URL="https://github.com/$GITHUB_REPO/releases/latest/download/dc-watchdog-agent-$ARCH_SUFFIX"
    if curl -fsSL "$RELEASE_URL" -o "$STAGE/candidate" 2>/dev/null; then
        if [ -s "$STAGE/candidate" ]; then
            chmod +x "$STAGE/candidate"
            if "$STAGE/candidate" -version 2>/dev/null; then
                DOWNLOAD_OK=true
                echo "[+] Go agent downloaded from GitHub releases"
            fi
        fi
    fi
fi

if [ "$DOWNLOAD_OK" = "false" ]; then
    echo "INSTALL_FAILED: Could not download Go agent binary from watchdog server or GitHub releases"
    exit 1
fi

changed=1
if [ "$was_active" = 1 ]; then systemctl stop dc-watchdog-agent; fi
mkdir -p "$CONFIG_DIR"
cp "$STAGE/candidate" "$INSTALL_DIR/dc-watchdog-agent"
chmod 755 "$INSTALL_DIR/dc-watchdog-agent"

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
if [ "$MODE" = install ]; then
echo "[+] Creating configuration..."
cat > "$CONFIG_DIR/agent.yaml" << YAMLEOF
# DC-Watchdog Agent Configuration
server_url: "{endpoint}"
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
fi

systemctl daemon-reload
if [ "$MODE" = install ]; then
    systemctl enable dc-watchdog-agent
    systemctl restart dc-watchdog-agent
elif [ "$was_active" = 1 ]; then
    systemctl start dc-watchdog-agent
fi

# Verify agent starts and stays running
if [ "$MODE" = install ] || [ "$was_active" = 1 ]; then
sleep 3
if ! systemctl is-active --quiet dc-watchdog-agent; then
    echo "INSTALL_FAILED: Agent crashed on startup"
    exit 1
fi

sleep 3
if ! systemctl is-active --quiet dc-watchdog-agent; then
    echo "INSTALL_FAILED: Agent crashed after startup"
    exit 1
fi
fi

VERSION=$("$INSTALL_DIR/dc-watchdog-agent" -version 2>&1 | head -1 || echo "unknown")
echo "AGENT_VERSION=$VERSION"
if [ "$MODE" = install ] || [ "$was_active" = 1 ]; then
    # Released agent exposes health JSON and this metric with its telemetry
    # version, which is deliberately distinct from the release tag.
    telemetry=$(printf '%s' "$VERSION" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    port=$(sed -nE 's/^health_port:[[:space:]]*([0-9]+)[[:space:]]*$/\1/p' "$CONFIG_DIR/agent.yaml")
    port=${{port:-9878}}
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
    curl -fsS --max-time 5 "http://127.0.0.1:$port/health" | grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"'
    curl -fsS --max-time 5 "http://127.0.0.1:$port/metrics" | grep -F "dc_watchdog_agent_up{{version=\"$telemetry\"" >/dev/null
fi
# Retire old fallback only after the replacement is verified.
rm -f /opt/dc-watchdog/dc-watchdog-agent.sh 2>/dev/null || true
echo "INSTALL_SUCCESS"
'''
        if selected_artifact is not None:
            download_start = install_script.index('# Primary: Download from DC Watchdog server')
            download_end = install_script.index('changed=1', download_start)
            platform_arch = {'linux/amd64':'linux-amd64', 'linux/arm64':'linux-arm64'}[selected_artifact['platform']]
            approved_download = (
                '[ "$ARCH_SUFFIX" = ' + shlex.quote(platform_arch) + ' ]\n'
                + 'curl -fsSL ' + shlex.quote(selected_artifact['url']) + ' -o "$STAGE/candidate"\n'
                + 'candidate_sha=$(sha256sum "$STAGE/candidate")\n[ "${candidate_sha%% *}" = ' + shlex.quote(selected_artifact['sha256']) + ' ]\n'
                + 'chmod +x "$STAGE/candidate"\n"$STAGE/candidate" -version >/dev/null\n\n'
            )
            install_script = install_script[:download_start] + approved_download + install_script[download_end:]
        cmd.append(watchdog_remote_runner(sudo=(server.ssh_user or 'root') != 'root'))
        
        run_env = {**os.environ, **ssh_env} if ssh_env else None
        result = subprocess.run(cmd, input=install_script, capture_output=True, text=True, timeout=180, env=run_env)
        
        if result.returncode == 0 and 'INSTALL_SUCCESS' in result.stdout:
            for line in result.stdout.splitlines():
                if line.startswith('AGENT_VERSION='):
                    version_str = line.split('=', 1)[1].strip()
                    ver_match = re.search(r'(\d+\.\d+\.\d+)', version_str)
                    if ver_match:
                        server.watchdog_agent_version = ver_match.group(1)
            return True, None
        else:
            return False, remote_failure_message(result)
    except subprocess.TimeoutExpired:
        return False, 'SSH connection timed out (180s)'
    except Exception as e:
        logger.error('Error installing watchdog agent on %s', server.name)
        return False, 'Watchdog installation unavailable.'


def remove_watchdog_agent_remote(server) -> bool:
    """Remove DC Watchdog agent from a remote server via SSH."""
    try:
        cmd, env = build_ssh_cmd(server, timeout=15)
        
        remove_script = '''
set -e
systemctl stop dc-watchdog-agent 2>/dev/null || true
systemctl disable dc-watchdog-agent 2>/dev/null || true
rm -f /etc/systemd/system/dc-watchdog-agent.service
rm -f /usr/local/bin/dc-watchdog-agent
rm -rf /etc/dc-watchdog
rm -rf /opt/dc-watchdog
systemctl daemon-reload
echo "REMOVE_SUCCESS"
'''
        cmd.append(privileged_remote_command(server, 'bash -s'))
        
        run_env = {**os.environ, **env} if env else None
        result = subprocess.run(cmd, input=remove_script, capture_output=True, text=True, timeout=30, env=run_env)
        return result.returncode == 0 and 'REMOVE_SUCCESS' in result.stdout
    except Exception as e:
        logger.error(f"Error removing watchdog agent on {server.name}: {e}")
        return False
