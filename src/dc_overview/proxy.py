"""
Proxy communication helpers for the cryptolabs-proxy internal API.

The proxy (source of truth) exposes /internal/api/config on port 8080,
accessible only from the internal Docker network (172.30.0.0/16).
"""

import json
import logging
import os

logger = logging.getLogger(__name__)

PROXY_URL = 'http://172.30.0.10:8080'


def _get_internal_api_token() -> str:
    """Get the shared secret for authenticating with the proxy's internal API.
    
    The token is passed via the INTERNAL_API_TOKEN environment variable, which is
    set during container deployment by the quickstart scripts. This is intentionally
    NOT read from a file on the shared volume to prevent token leakage.
    """
    return os.environ.get('INTERNAL_API_TOKEN', '')


def get_proxy_config(key: str = None):
    """Fetch shared config from the cryptolabs-proxy internal API.
    
    Sensitive keys require a valid bearer token.
    
    Args:
        key: Specific config key to fetch, or None for all config.
    
    Returns:
        dict (all config) or str (single value) or None on failure.
    """
    token = _get_internal_api_token()
    try:
        import urllib.request
        if key:
            url = f'{PROXY_URL}/internal/api/config/{key}'
        else:
            url = f'{PROXY_URL}/internal/api/config'
        req = urllib.request.Request(url, method='GET')
        req.add_header('Accept', 'application/json')
        if token:
            req.add_header('Authorization', f'Bearer {token}')
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            if key:
                return data.get('value')
            return data
    except Exception:
        return None


def push_proxy_config(updates: dict) -> bool:
    """Push config values to the cryptolabs-proxy internal API.
    
    Requires a valid bearer token. Passwords and secrets are rejected server-side.
    
    Args:
        updates: dict of key-value pairs to set.
    
    Returns:
        True on success, False on failure.
    """
    token = _get_internal_api_token()
    if not token:
        logger.warning("Cannot push config to proxy: INTERNAL_API_TOKEN not set")
        return False
    try:
        import urllib.request
        payload = json.dumps(updates).encode()
        req = urllib.request.Request(
            f'{PROXY_URL}/internal/api/config',
            data=payload,
            method='POST'
        )
        req.add_header('Content-Type', 'application/json')
        req.add_header('Authorization', f'Bearer {token}')
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            return data.get('success', False)
    except Exception:
        return False
