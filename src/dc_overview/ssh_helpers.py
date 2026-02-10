"""
SSH helper functions for remote server management.

Provides building SSH commands, checking connectivity,
and resolving SSH key paths.
"""

import logging
import os
import subprocess

logger = logging.getLogger(__name__)


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
    
    cmd.append(f'{server.ssh_user or "root"}@{server.server_ip}')
    
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
