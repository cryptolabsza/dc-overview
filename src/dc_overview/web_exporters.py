"""
Exporter management helpers for the web application.

Functions for checking, installing, removing, toggling, and updating
Prometheus exporters on remote servers via SSH.

Note: This module is for the web UI (app.py). The CLI exporter logic
lives in dc_overview.exporters.
"""

import logging
import os
import socket
import subprocess

from .ssh_helpers import build_ssh_cmd

logger = logging.getLogger(__name__)


def check_exporter(ip, port):
    """Check if an exporter is running on given port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))
        sock.close()
        return {'running': result == 0, 'port': port}
    except Exception as e:
        return {'running': False, 'port': port, 'error': str(e)}


def install_exporter_remote(server, exporter_name):
    """Install an exporter on a remote server via SSH."""
    try:
        if exporter_name == 'node_exporter':
            script = """
            if ! systemctl is-active node_exporter >/dev/null 2>&1; then
                cd /tmp
                curl -sLO https://github.com/prometheus/node_exporter/releases/download/v1.10.2/node_exporter-1.10.2.linux-amd64.tar.gz
                tar xzf node_exporter-1.10.2.linux-amd64.tar.gz
                cp node_exporter-1.10.2.linux-amd64/node_exporter /usr/local/bin/
                useradd -r -s /bin/false node_exporter 2>/dev/null || true
                cat > /etc/systemd/system/node_exporter.service << 'EOF'
[Unit]
Description=Node Exporter
After=network.target

[Service]
Type=simple
User=node_exporter
ExecStart=/usr/local/bin/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOF
                systemctl daemon-reload
                systemctl enable node_exporter
                systemctl start node_exporter
            fi
            """
        elif exporter_name == 'dc_exporter':
            script = """
            # Download dc-exporter-rs (Rust version)
            curl -L https://github.com/cryptolabsza/dc-exporter-releases/releases/latest/download/dc-exporter-rs -o /usr/local/bin/dc-exporter-rs
            chmod +x /usr/local/bin/dc-exporter-rs
            
            # Create systemd service
            cat > /etc/systemd/system/dc-exporter.service << 'EOF'
[Unit]
Description=DC Exporter - GPU Metrics for Prometheus (Rust)
Documentation=https://github.com/cryptolabsza/dc-exporter-rs
After=network.target nvidia-persistenced.service

[Service]
Type=simple
ExecStart=/usr/local/bin/dc-exporter-rs --port 9835
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable dc-exporter
            systemctl start dc-exporter
            """
        else:
            return False
        
        cmd, env = build_ssh_cmd(server, timeout=10, batch_mode=False)
        cmd.append(f'bash -c "{script}"')
        
        run_env = {**os.environ, **env} if env else None
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=run_env)
        return result.returncode == 0
    except Exception:
        return False


def remove_exporter_remote(server, exporter_name):
    """Remove an exporter from a remote server via SSH."""
    try:
        if exporter_name == 'node_exporter':
            script = """
            systemctl stop node_exporter 2>/dev/null || true
            systemctl disable node_exporter 2>/dev/null || true
            rm -f /etc/systemd/system/node_exporter.service
            rm -f /usr/local/bin/node_exporter
            systemctl daemon-reload
            echo "node_exporter removed"
            """
        elif exporter_name == 'dc_exporter':
            script = """
            systemctl stop dc-exporter 2>/dev/null || true
            systemctl disable dc-exporter 2>/dev/null || true
            rm -f /etc/systemd/system/dc-exporter.service
            rm -f /usr/local/bin/dc-exporter-collector
            rm -f /usr/local/bin/dc-exporter-server
            rm -rf /etc/dc-exporter
            systemctl daemon-reload
            echo "dc-exporter removed"
            """
        elif exporter_name == 'dcgm_exporter':
            script = """
            systemctl stop dcgm-exporter 2>/dev/null || true
            systemctl disable dcgm-exporter 2>/dev/null || true
            rm -f /etc/systemd/system/dcgm-exporter.service
            systemctl daemon-reload
            docker rm -f dcgm-exporter 2>/dev/null || true
            echo "dcgm-exporter removed"
            """
        else:
            return False
        
        cmd, env = build_ssh_cmd(server, timeout=10, batch_mode=False)
        cmd.append(f'bash -c "{script}"')
        
        run_env = {**os.environ, **env} if env else None
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=run_env)
        return result.returncode == 0
    except Exception:
        return False


def toggle_exporter_service(server, exporter: str, enabled: bool) -> tuple:
    """Start or stop an exporter service on a remote server via SSH.
    
    Returns (success: bool, error: str or None)
    """
    service_names = {
        'node_exporter': 'node_exporter',
        'dc_exporter': 'dc-exporter',
        'dcgm_exporter': 'dcgm-exporter'
    }
    
    service = service_names.get(exporter)
    if not service:
        return False, f'Unknown exporter: {exporter}'
    
    try:
        ssh_cmd, env = build_ssh_cmd(server, timeout=10)
        
        if exporter == 'dcgm_exporter':
            if enabled:
                ssh_cmd.append(f"docker start {service} 2>&1 || echo 'not found'")
            else:
                ssh_cmd.append(f"docker stop {service} 2>&1 || echo 'not found'")
        else:
            action = 'start' if enabled else 'stop'
            ssh_cmd.append(f"systemctl {action} {service} 2>&1")
        
        run_env = {**os.environ, **env} if env else None
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30, env=run_env)
        
        if result.returncode != 0:
            error_msg = (result.stderr or result.stdout or '').strip()
            logger.warning(f"Failed to {('start' if enabled else 'stop')} {service} on {server.name}: {error_msg}")
            return False, error_msg or f'SSH command exited with code {result.returncode}'
        
        return True, None
        
    except subprocess.TimeoutExpired:
        return False, 'SSH command timed out'
    except Exception as e:
        logger.error(f"Exception toggling {service} on {server.name}: {e}")
        return False, str(e)


def update_exporter_remote(server, exporter: str, version: str, branch: str = 'main') -> tuple:
    """Update an exporter on a remote server to a specific version.
    
    Returns:
        tuple: (success: bool, error_message: str or None)
    """
    from .exporters import get_exporter_download_url
    
    download_url = get_exporter_download_url(exporter, version, branch)
    if not download_url:
        return False, f"Could not get download URL for {exporter} v{version}"
    
    try:
        ssh_cmd, ssh_env = build_ssh_cmd(server, timeout=15, extra_opts=['-o', 'ServerAliveInterval=10'])
        
        if exporter == 'node_exporter':
            update_script = f'''
set -e
cd /tmp
curl -sL "{download_url}" -o node_exporter.tar.gz
tar xzf node_exporter.tar.gz
systemctl stop node_exporter 2>/dev/null || true
cp node_exporter-*/node_exporter /usr/local/bin/
chmod +x /usr/local/bin/node_exporter
systemctl start node_exporter
rm -rf node_exporter*
echo "UPDATE_SUCCESS"
'''
            ssh_cmd.append(update_script)
            
        elif exporter == 'dc_exporter':
            update_script = f'''
set -e
systemctl stop dc-exporter 2>/dev/null || true
curl -sL "{download_url}" -o /usr/local/bin/dc-exporter-rs
chmod +x /usr/local/bin/dc-exporter-rs
systemctl start dc-exporter
echo "UPDATE_SUCCESS"
'''
            ssh_cmd.append(update_script)
            
        elif exporter == 'dcgm_exporter':
            update_script = f'''
set -e
docker stop dcgm-exporter 2>/dev/null || true
docker rm dcgm-exporter 2>/dev/null || true
docker pull {download_url}
docker run -d --name dcgm-exporter --gpus all -p 9400:9400 --restart unless-stopped {download_url}
echo "UPDATE_SUCCESS"
'''
            ssh_cmd.append(update_script)
        else:
            return False, f"Unknown exporter type: {exporter}"
        
        logger.info(f"[Exporter Update] Running: ssh -p {server.ssh_port or 22} {server.ssh_user or 'root'}@{server.server_ip}")
        run_env = {**os.environ, **ssh_env} if ssh_env else None
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=180, env=run_env)
        
        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip() or f"SSH command failed with code {result.returncode}"
            logger.error(f"[Exporter Update] Failed for {server.server_ip}: {error_msg[:200]}")
            return False, error_msg[:200]
        
        if 'UPDATE_SUCCESS' in result.stdout:
            logger.info(f"[Exporter Update] Successfully updated {exporter} on {server.server_ip}")
            return True, None
        else:
            return False, f"Update script did not complete successfully: {result.stdout[:200]}"
        
    except subprocess.TimeoutExpired:
        return False, "SSH connection timed out (180s)"
    except Exception as e:
        logger.exception(f"[Exporter Update] Exception updating {exporter} on {server.server_ip}")
        return False, str(e)[:200]
