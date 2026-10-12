"""Inventory discovery updates with explicit monitoring ownership and recovery."""
import json
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

from .monitoring import (apply_prometheus_config, atomic_write_bytes, merge_prometheus_config,
                         validate_known_discovery_targets)

logger = logging.getLogger(__name__)
IPMI_CONFIG_PATH = '/etc/ipmi-monitor/servers.yaml'


def build_discovery_targets(servers):
    """Use one inventory for every exporter; preserve explicit legacy aliases."""
    targets = []
    exporters = (('node_exporter', 'node', 9100), ('dc_exporter', 'dc', 9835),
                 ('dcgm_exporter', 'dcgm', 9400), ('watchdog_agent', 'watchdog', 9878))
    for server in servers:
        name = server.monitoring_name or server.name
        address = server.server_ip
        if ':' in address:
            address = f'[{address}]'
        for field, label, port in exporters:
            if getattr(server, field + '_installed') and getattr(server, field + '_enabled'):
                targets.append({'targets': [f'{address}:{port}'], 'labels': {
                    'instance': name, 'job': name, 'exporter': label,
                }})
    return targets


def _configuration_path():
    explicit = os.environ.get('PROMETHEUS_CONFIG_PATH')
    if explicit:
        path = Path(explicit)
        if not path.is_absolute() or '..' in path.parts:
            raise ValueError('Prometheus config path must be absolute')
        return path
    canonical = Path('/etc/dc-overview/prometheus/prometheus.yml')
    return canonical if canonical.is_file() else Path('/etc/dc-overview/prometheus.yml')


def _adopted_ownership():
    explicit = os.environ.get('PROMETHEUS_OWNERSHIP_PATH')
    if not explicit:
        return None
    path = Path(explicit)
    if not path.is_absolute() or '..' in path.parts or path.is_symlink():
        raise ValueError('monitoring ownership requires a safe absolute file')
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or set(data) != {'schema_version', 'managed_jobs', 'file_references'} or data['schema_version'] != 1:
        raise ValueError('monitoring ownership schema_version 1 required')
    for key in ('managed_jobs', 'file_references'):
        if not isinstance(data[key], list) or any(not isinstance(v, str) for v in data[key]):
            raise ValueError('monitoring ownership lists required')
    return data


def _declared_legacy_jobs():
    adopted = _adopted_ownership()
    if adopted is not None:
        return adopted['managed_jobs']
    path = Path('/etc/dc-overview/fleet-config.yaml')
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text()) or {}
    section = data.get('prometheus') or {}
    names = section.get('legacy_managed_jobs', [])
    if not isinstance(names, list) or any(not isinstance(name, str) for name in names):
        raise ValueError('legacy monitoring ownership must be a list of exact names')
    return names


def update_prometheus_targets(servers, data_dir: str):
    """Atomically update compatibility file-SD using the live discovery contract."""
    try:
        servers = list(servers)
        targets = build_discovery_targets(servers)
        validate_known_discovery_targets({'scrape_configs': []}, targets)
        atomic_write_bytes(Path(data_dir) / 'prometheus_targets.json', json.dumps(targets, indent=2).encode())
        if _configuration_path().exists():
            return update_prometheus_yml_targets(servers)
        return True
    except Exception:
        # Configuration errors can contain inline secrets; do not emit exception
        # strings/configuration contents into application logs.
        logger.warning('Prometheus target update failed; prior configuration retained')
        return False


def update_prometheus_yml_targets(servers, *, config_path=None, legacy_managed_jobs=None,
                                  adopted_file_references=(), reload_callback=None):
    """Inventory owns dc-managed and only explicitly adopted legacy job names.

    Unknown static jobs survive deletion/rename. A known duplicate endpoint with
    live inventory fails before mutation until its original owner is declared.
    """
    try:
        path = Path(config_path) if config_path is not None else _configuration_path()
        if not path.exists():
            return True
        previous_bytes = path.read_bytes()
        previous = yaml.safe_load(previous_bytes) or {}
        generated = {'scrape_configs': [{
            'job_name': 'dc-managed', 'http_sd_configs': [{
                'url': 'http://dc-overview:5001/api/prometheus/discovery', 'refresh_interval': '30s',
            }],
        }]}
        legacy = _declared_legacy_jobs() if legacy_managed_jobs is None else legacy_managed_jobs
        # recording_rules.yml is the shipped product rule reference, not an
        # implicit grant to arbitrary historical external credential files.
        ownership = _adopted_ownership()
        adopted = tuple(adopted_file_references) + tuple(ownership['file_references'] if ownership else []) + ('/etc/prometheus/recording_rules.yml',)
        candidate = merge_prometheus_config(previous, generated, legacy_managed_jobs=legacy,
                                             adopted_file_references=adopted)
        validate_known_discovery_targets(candidate, build_discovery_targets(servers))
        reload = reload_callback or (lambda: reload_prometheus(expected_config=yaml.safe_load(path.read_text())))
        # Web containers do not gain a Docker socket merely to run promtool. The
        # synchronous server reload validates the actual mounted candidate, and
        # its effective-config response must match. Structural merge ran above.
        return apply_prometheus_config(path, candidate, validate_candidate=lambda _: True,
            reload_config=reload, expected_previous_bytes=previous_bytes)
    except Exception:
        logger.warning('Prometheus configuration update failed; inspect reload/recovery status')
        return False


def sync_ipmi_monitor_targets(servers, config_path: str = None):
    """Deprecated compatibility shim; DC no longer writes IPMI configuration."""
    logger.debug('IPMI YAML sync is disabled; use the inventory reconciliation API')


def _declared_matches(expected, loaded):
    """Prometheus adds defaults; every declared value must still match."""
    from .monitoring import declared_configuration_matches
    return declared_configuration_matches(expected, loaded)


def _loaded_configuration_matches(expected):
    for prefix in ('http://prometheus:9090/prometheus', 'http://prometheus:9090'):
        try:
            response = requests.get(prefix + '/api/v1/status/config', timeout=5)
            response.raise_for_status()
            payload = response.json()
            if response.status_code == 200 and payload.get('status') == 'success':
                loaded = yaml.safe_load(payload['data']['yaml'])
                return _declared_matches(expected, loaded)
        except (requests.RequestException, ValueError, KeyError, TypeError):
            continue
    return False


def _fresh_reload_proof(started):
    for prefix in ('http://prometheus:9090/prometheus', 'http://prometheus:9090'):
        try:
            response = requests.get(prefix + '/api/v1/status/runtimeinfo', timeout=5)
            response.raise_for_status()
            payload = response.json()
            data = payload['data']
            stamp = datetime.fromisoformat(data['lastConfigTime'].replace('Z', '+00:00'))
            if response.status_code == 200 and payload.get('status') == 'success' and data['reloadConfigSuccess'] is True and stamp >= started:
                return True
        except (requests.RequestException, ValueError, KeyError, TypeError):
            continue
    return False


def reload_prometheus(*, expected_config=None):
    """Return actual reload success; command delivery alone is not validation.

    HTTP lifecycle reload is synchronous. Docker/systemctl fallbacks additionally
    require a fresh successful runtime reload timestamp. If an expected mapping
    is supplied, effective loaded configuration must match (detects stale mounts).
    """
    for url in ('http://prometheus:9090/prometheus/-/reload', 'http://prometheus:9090/-/reload'):
        try:
            response = requests.post(url, timeout=5)
            response.raise_for_status()
            if response.status_code == 200:
                return expected_config is None or _loaded_configuration_matches(expected_config)
        except requests.RequestException:
            continue
    for command in (['docker', 'exec', 'prometheus', 'kill', '-HUP', '1'],
                    ['systemctl', 'reload', 'prometheus']):
        try:
            started = datetime.now(timezone.utc)
            result = subprocess.run(command, capture_output=True, timeout=10)
            if result.returncode == 0 and _fresh_reload_proof(started):
                return expected_config is None or _loaded_configuration_matches(expected_config)
        except (OSError, subprocess.SubprocessError):
            continue
    logger.warning('Prometheus reload failed or runtime acceptance is unverified')
    return False
