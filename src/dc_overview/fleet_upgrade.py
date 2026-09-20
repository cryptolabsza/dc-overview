"""Use Fleet's durable updater from the host CLI without a second lifecycle owner."""
import json
import re
import subprocess
import time


def _updater(*arguments):
    command = ['docker', 'exec', 'cryptolabs-proxy', 'env', 'PYTHONPATH=/app/src',
               'python3', '-m', 'cryptolabs_proxy.updates', *arguments]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            value = json.loads(result.stdout)
            return value if isinstance(value, dict) else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        pass
    return None


def run_fleet_upgrade(branch, timeout=1800):
    if branch not in ('main', 'dev'):
        raise ValueError('Expected main or dev channel')
    job = _updater('submit', '--branch', branch, '--service', 'all', '--action', 'update')
    job_id = job.get('id') if job else None
    if not isinstance(job_id, str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}', job_id):
        raise RuntimeError('Fleet updater unavailable. Install the current proxy updater before upgrading; no services were replaced by this CLI.')
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = _updater('status', job_id)
        if result and result.get('state') in ('completed', 'failed', 'interrupted'):
            return result
        time.sleep(2)
    raise RuntimeError(f'Fleet update {job_id} is still unconfirmed. Check its status in Fleet before retrying.')
