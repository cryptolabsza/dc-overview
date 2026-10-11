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

from .exporters import (
    DC_EXPORTER_CALLER_TIMEOUT_SECONDS,
    build_dc_exporter_install_script,
    build_node_exporter_install_script,
    dc_exporter_remote_bash_command,
)
from .ssh_helpers import build_ssh_cmd, privileged_remote_command, remote_failure_message

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


SERVICE_NAMES = {
    'node_exporter': 'node_exporter',
    'dc_exporter': 'dc-exporter',
    'dcgm_exporter': 'dcgm-exporter',
}


def _run_dc_exporter_remote(server, script):
    """Run a delivery script through bounded Bash, independent of login shell."""
    cmd, env = build_ssh_cmd(
        server,
        timeout=15,
        batch_mode=False,
        extra_opts=['-o', 'ServerAliveInterval=10'],
    )
    cmd.append(privileged_remote_command(server, dc_exporter_remote_bash_command()))
    run_env = {**os.environ, **env} if env else None
    return subprocess.run(
        cmd,
        input=script,
        capture_output=True,
        text=True,
        timeout=DC_EXPORTER_CALLER_TIMEOUT_SECONDS,
        env=run_env,
    )


class ServiceCheckUnavailable(RuntimeError):
    """Discovery did not produce a complete trustworthy observation."""


def check_services_installed(server):
    """Check which exporter services actually exist on a remote host via SSH.

    Runs a single SSH command that queries systemctl for each service unit file
    and checks for docker containers for dcgm-exporter.

    Returns dict mapping exporter key to
    {'installed': bool, 'active': bool}.
    """
    result = {
        'node_exporter': {'installed': False, 'active': False},
        'dc_exporter': {'installed': False, 'active': False},
        'dcgm_exporter': {'installed': False, 'active': False},
    }

    script = '''
set -e
for svc in node_exporter dc-exporter; do
    load=$(systemctl show "$svc" --property=LoadState --value)
    state=$(systemctl show "$svc" --property=ActiveState --value)
    printf '%s:%s:%s\\n' "$svc" "$state" "$load"
done
if ! command -v docker >/dev/null 2>&1; then
    docker_state=missing
elif docker_state=$(docker inspect -f '{{.State.Status}}' dcgm-exporter 2>&1); then
    :
else
    case "$docker_state" in
        *"No such object"*|*"No such container"*) docker_state=missing ;;
        *) exit 1 ;;
    esac
fi
printf 'dcgm-exporter:%s:docker\\n' "$docker_state"
'''

    try:
        cmd, env = build_ssh_cmd(server, timeout=10)
        import shlex
        cmd.append(privileged_remote_command(server, 'bash -c ' + shlex.quote(script)))

        run_env = {**os.environ, **env} if env else None
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20, env=run_env)

        if proc.returncode != 0:
            raise ServiceCheckUnavailable(remote_failure_message(proc))

        svc_to_key = {
            'node_exporter': 'node_exporter',
            'dc-exporter': 'dc_exporter',
            'dcgm-exporter': 'dcgm_exporter',
        }

        observed = set()
        for line in proc.stdout.strip().splitlines():
            parts = line.strip().split(':')
            if len(parts) != 3:
                raise ServiceCheckUnavailable('Incomplete service discovery response.')
            svc_name, state, enabled = parts[0], parts[1], parts[2]
            exp_key = svc_to_key.get(svc_name)
            if not exp_key or exp_key in observed:
                raise ServiceCheckUnavailable('Invalid service discovery response.')
            observed.add(exp_key)

            if exp_key == 'dcgm_exporter':
                if enabled != 'docker' or state not in ('missing', 'running', 'created', 'restarting', 'paused', 'exited', 'dead', 'removing'):
                    raise ServiceCheckUnavailable('Unknown container state.')
                result[exp_key]['installed'] = state != 'missing'
                result[exp_key]['active'] = state == 'running'
            else:
                if enabled not in ('loaded', 'not-found', 'masked', 'error', 'bad-setting', 'merged', 'stub') or state not in ('active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading', 'maintenance', 'refreshing'):
                    raise ServiceCheckUnavailable('Unknown systemd state.')
                is_known = enabled != 'not-found'
                result[exp_key]['installed'] = is_known
                result[exp_key]['active'] = state == 'active'

        if observed != set(result):
            raise ServiceCheckUnavailable('Incomplete service discovery response.')
    except subprocess.TimeoutExpired:
        raise ServiceCheckUnavailable(remote_failure_message(timed_out=True)) from None
    except ServiceCheckUnavailable:
        raise
    except Exception:
        raise ServiceCheckUnavailable('Service discovery unavailable.') from None

    return result


def install_exporter_remote(server, exporter_name, *, return_error=False):
    """Install an exporter on a remote server via SSH.

    Always performs a fresh download regardless of existing files.
    Cleans up temporary files after installation.
    """
    from .worker_lifecycle import selected_worker_mutation_refusal
    refusal = selected_worker_mutation_refusal()
    if refusal:
        return (False, refusal) if return_error else False
    try:
        if exporter_name == 'dc_exporter':
            script = build_dc_exporter_install_script(mode='install')
            result = _run_dc_exporter_remote(server, script)
            success = (
                result.returncode == 0
                and 'DC_EXPORTER_INSTALL_SUCCESS' in result.stdout
            )
            error = None if success else remote_failure_message(result)
            return (success, error) if return_error else success

        if exporter_name == 'node_exporter':
            script = build_node_exporter_install_script()
        else:
            return (False, 'Unsupported exporter.') if return_error else False
        
        result = _run_dc_exporter_remote(server, script)
        success = result.returncode == 0 and 'NODE_EXPORTER_INSTALL_SUCCESS' in result.stdout
        error = None if success else remote_failure_message(result)
    except subprocess.TimeoutExpired:
        success, error = False, remote_failure_message(timed_out=True)
    except Exception:
        success, error = False, 'Exporter installation could not be verified.'
    return (success, error) if return_error else success


def remove_exporter_remote(server, exporter_name):
    """Remove an exporter from a remote server via SSH."""
    try:
        if exporter_name == 'node_exporter':
            script = """
            set -e
            systemctl stop node_exporter 2>/dev/null || true
            systemctl disable node_exporter 2>/dev/null || true
            rm -f /etc/systemd/system/node_exporter.service
            rm -f /usr/local/bin/node_exporter
            systemctl daemon-reload
            echo "node_exporter removed"
            """
        elif exporter_name == 'dc_exporter':
            script = """
            set -e
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
            set -e
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
        import shlex
        cmd.append(privileged_remote_command(server, 'bash -c ' + shlex.quote(script)))
        
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
                ssh_cmd.append(privileged_remote_command(server, f"docker start {service}"))
            else:
                ssh_cmd.append(privileged_remote_command(server, f"docker stop {service}"))
        else:
            action = 'start' if enabled else 'stop'
            ssh_cmd.append(privileged_remote_command(server, f"systemctl {action} {service}"))
        
        run_env = {**os.environ, **env} if env else None
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30, env=run_env)
        
        if result.returncode != 0:
            error_msg = remote_failure_message(result)
            logger.warning(f"Failed to {('start' if enabled else 'stop')} {service} on {server.name}: {error_msg}")
            return False, error_msg or f'SSH command exited with code {result.returncode}'
        
        return True, None
        
    except subprocess.TimeoutExpired:
        return False, 'SSH command timed out'
    except Exception as e:
        logger.error("Exception toggling %s on %s", service, server.name)
        return False, 'Remote service operation unavailable.'


def update_exporter_remote(server, exporter: str, version: str, branch: str = 'main') -> tuple:
    """Update an exporter on a remote server to a specific version.
    
    Returns:
        tuple: (success: bool, error_message: str or None)
    """
    from .worker_lifecycle import selected_worker_mutation_refusal
    refusal = selected_worker_mutation_refusal()
    if refusal:
        return False, refusal
    from .exporters import get_exporter_download_url

    if exporter == 'dc_exporter':
        try:
            update_script = build_dc_exporter_install_script(version, mode='update')
        except ValueError as exc:
            return False, str(exc)
    else:
        download_url = get_exporter_download_url(exporter, version, branch)
        if not download_url:
            return False, f"Could not get download URL for {exporter} v{version}"
    
    try:
        if exporter == 'dc_exporter':
            result = _run_dc_exporter_remote(server, update_script)
        else:
            ssh_cmd, ssh_env = build_ssh_cmd(
                server,
                timeout=15,
                extra_opts=['-o', 'ServerAliveInterval=10'],
            )

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
            import shlex
            ssh_cmd.append(privileged_remote_command(server, 'bash -c ' + shlex.quote(update_script)))

        elif exporter == 'dcgm_exporter':
            update_script = f'''
set -e
docker stop dcgm-exporter 2>/dev/null || true
docker rm dcgm-exporter 2>/dev/null || true
docker pull {download_url}
docker run -d --name dcgm-exporter --gpus all -p 9400:9400 --restart unless-stopped {download_url}
echo "UPDATE_SUCCESS"
'''
            import shlex
            ssh_cmd.append(privileged_remote_command(server, 'bash -c ' + shlex.quote(update_script)))
        else:
            if exporter != 'dc_exporter':
                return False, f"Unknown exporter type: {exporter}"

        logger.info(f"[Exporter Update] Running: ssh -p {server.ssh_port or 22} {server.ssh_user or 'root'}@{server.server_ip}")
        if exporter != 'dc_exporter':
            run_env = {**os.environ, **ssh_env} if ssh_env else None
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=240,
                env=run_env,
            )
        
        if result.returncode != 0:
            error_msg = remote_failure_message(result)
            logger.error(f"[Exporter Update] Failed for {server.server_ip}: {error_msg[:200]}")
            return False, error_msg[:200]
        
        success_marker = (
            'DC_EXPORTER_INSTALL_SUCCESS'
            if exporter == 'dc_exporter'
            else 'UPDATE_SUCCESS'
        )
        if success_marker in result.stdout:
            logger.info(f"[Exporter Update] Successfully updated {exporter} on {server.server_ip}")
            return True, None
        else:
            return False, 'Update could not be verified.'
        
    except subprocess.TimeoutExpired:
        return False, f"SSH connection timed out ({DC_EXPORTER_CALLER_TIMEOUT_SECONDS}s)"
    except Exception as e:
        logger.error('[Exporter Update] Operation unavailable for %s', server.server_ip)
        return False, 'Exporter update unavailable.'
