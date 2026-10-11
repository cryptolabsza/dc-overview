"""
SSH helper functions for remote server management.

Provides building SSH commands, checking connectivity,
and resolving SSH key paths.
"""

import logging
import os
import shlex
import subprocess

logger = logging.getLogger(__name__)


def privileged_remote_command(server, command):
    """Select direct root execution or fail-fast noninteractive sudo."""
    return command if (server.ssh_user or 'root') == 'root' else f'sudo -n -- {command}'


def remote_failure_message(result=None, *, timed_out=False):
    """Return an operator diagnostic without echoing remote output or credentials."""
    if timed_out:
        return 'Remote operation timed out; verify service state before retrying.'
    output = ((getattr(result, 'stderr', '') or '') + (getattr(result, 'stdout', '') or '')).lower()
    if 'sudo' in output or 'permission denied' in output:
        return 'Remote permission denied; root or passwordless sudo is required.'
    if 'rollback incomplete' in output:
        return 'Installation failed; automatic recovery was incomplete. Check the remote service.'
    if 'rollback' in output or 'previous installation restored' in output:
        return 'Installation failed; the previous installation was restored.'
    code = getattr(result, 'returncode', None)
    return f'Remote operation failed (exit {code}).' if isinstance(code, int) and code else 'Remote operation could not be verified.'


def resolve_ssh_key_path(server):
    """Resolve the SSH key path for a server, with fallback to default fleet key.
    
    Priority:
    1. Server's explicitly associated SSH key (from database)
    2. Default fleet key at /etc/dc-overview/ssh_keys/fleet_key
    3. Default user key at ~/.ssh/id_rsa
    """
    if server.ssh_key and server.ssh_key.key_path:
        key_path = server.ssh_key.key_path
        if os.path.exists(key_path):
            return key_path
        logger.warning(f"SSH key for {server.name} not found at {key_path}, trying defaults")
    
    default_keys = ['/etc/dc-overview/ssh_keys/fleet_key',
                    os.path.expanduser('~/.ssh/id_rsa')]
    for key_path in default_keys:
        if os.path.exists(key_path):
            return key_path
    
    return None


def build_ssh_cmd(server, timeout=10, batch_mode=True, extra_opts=None):
    """Build a complete SSH command for a server, handling both key and password auth.
    
    Returns (cmd_prefix, env) where:
    - cmd_prefix: list of command parts (may include 'sshpass' for password auth)
    - env: dict of extra environment variables (for SSHPASS)
    
    Usage:
        cmd, env = build_ssh_cmd(server)
        cmd.append('echo ok')
        result = subprocess.run(cmd, capture_output=True, text=True, env={**os.environ, **env})
    """
    env = {}
    cmd = []
    
    ssh_key_path = resolve_ssh_key_path(server)
    ssh_password = getattr(server, 'ssh_password', None)
    
    if ssh_key_path:
        cmd = [
            'ssh',
            '-o', f'ConnectTimeout={timeout}',
            '-o', 'StrictHostKeyChecking=no',
        ]
        if batch_mode:
            cmd.extend(['-o', 'BatchMode=yes'])
        cmd.extend(['-p', str(server.ssh_port or 22)])
        cmd.extend(['-i', ssh_key_path])
    elif ssh_password:
        cmd = [
            'sshpass', '-e',
            'ssh',
            '-o', f'ConnectTimeout={timeout}',
            '-o', 'StrictHostKeyChecking=no',
            '-p', str(server.ssh_port or 22),
        ]
        env['SSHPASS'] = ssh_password
    else:
        cmd = [
            'ssh',
            '-o', f'ConnectTimeout={timeout}',
            '-o', 'StrictHostKeyChecking=no',
        ]
        if batch_mode:
            cmd.extend(['-o', 'BatchMode=yes'])
        cmd.extend(['-p', str(server.ssh_port or 22)])
    
    if extra_opts:
        cmd.extend(extra_opts)
    
    # Sanitize user and IP to prevent injection
    safe_user = shlex.quote(server.ssh_user or "root")
    safe_ip = shlex.quote(server.server_ip)
    cmd.append(f'{safe_user}@{safe_ip}')
    
    return cmd, env


def check_ssh_connection(server):
    """Test SSH connection to a server. Supports both key and password auth."""
    try:
        cmd, env = build_ssh_cmd(server, timeout=5)
        cmd.append('echo ok')
        
        run_env = {**os.environ, **env} if env else None
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, env=run_env)
        return {'connected': result.returncode == 0}
    except Exception as e:
        return {'connected': False, 'error': str(e)}
