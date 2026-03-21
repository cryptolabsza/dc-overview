"""
Prometheus and IPMI-monitor target management for the web application.

Functions for updating Prometheus targets files, syncing the IPMI-monitor
servers.yaml, and reloading Prometheus.
"""

import json
import logging
import subprocess

import requests
import yaml
from pathlib import Path

logger = logging.getLogger(__name__)

# Job names that belong to infrastructure, not managed servers.
# These are never added or removed by the sync logic.
_INFRA_JOB_NAMES = frozenset({
    'prometheus', 'vastai', 'runpod', 'ipmi-monitor', 'cadvisor',
    'node-exporter', 'grafana', 'dc-overview',
})

IPMI_CONFIG_PATH = '/etc/ipmi-monitor/servers.yaml'


def update_prometheus_targets(servers, data_dir: str):
    """Update Prometheus targets file for file-based service discovery.
    
    Only includes exporters that are both installed AND enabled.
    
    Args:
        servers: List of Server model instances.
        data_dir: Path to the application data directory.
    """
    try:
        targets_file = Path(data_dir) / 'prometheus_targets.json'
        targets = []
        
        for server in servers:
            if server.node_exporter_installed and server.node_exporter_enabled:
                targets.append({
                    'targets': [f"{server.server_ip}:9100"],
                    'labels': {'instance': server.name, 'job': 'node-exporter'}
                })
            if server.dc_exporter_installed and server.dc_exporter_enabled:
                targets.append({
                    'targets': [f"{server.server_ip}:9835"],
                    'labels': {'instance': server.name, 'job': 'dc-exporter'}
                })
            if server.dcgm_exporter_installed and server.dcgm_exporter_enabled:
                targets.append({
                    'targets': [f"{server.server_ip}:9400"],
                    'labels': {'instance': server.name, 'job': 'dcgm-exporter'}
                })
            if server.watchdog_agent_installed and server.watchdog_agent_enabled:
                targets.append({
                    'targets': [f"{server.server_ip}:9878"],
                    'labels': {'instance': server.name, 'job': 'dc-watchdog-agent'}
                })
        
        targets_file.write_text(json.dumps(targets, indent=2))
        
        # Also update the main prometheus.yml if it exists
        prometheus_yml = Path('/etc/dc-overview/prometheus.yml')
        if prometheus_yml.exists():
            update_prometheus_yml_targets(servers)

        # Sync IPMI monitor config
        sync_ipmi_monitor_targets(servers)
            
    except Exception:
        logger.debug("Non-critical: failed to update targets", exc_info=True)


def _build_server_targets(server):
    """Build the list of scrape targets for a single server."""
    targets = []
    if server.node_exporter_installed and server.node_exporter_enabled:
        targets.append(f"{server.server_ip}:9100")
    if server.dc_exporter_installed and server.dc_exporter_enabled:
        targets.append(f"{server.server_ip}:9835")
    if server.dcgm_exporter_installed and server.dcgm_exporter_enabled:
        targets.append(f"{server.server_ip}:9400")
    return targets


def update_prometheus_yml_targets(servers):
    """Sync prometheus.yml scrape configs to match the current server list.

    - Updates targets for servers that already have a job entry.
    - Adds a new scrape_config for servers that are missing.
    - Removes scrape_configs for servers that have been deleted (but
      preserves infrastructure jobs like 'prometheus', 'vastai', etc.).
    """
    prometheus_yml = Path('/etc/dc-overview/prometheus.yml')
    if not prometheus_yml.exists():
        return
    
    try:
        with open(prometheus_yml, 'r') as f:
            config = yaml.safe_load(f)
        
        if not config or 'scrape_configs' not in config:
            return
        
        server_map = {s.name: s for s in servers}
        
        # 1. Update existing entries and remove deleted servers
        kept_configs = []
        for sc in config['scrape_configs']:
            job = sc.get('job_name', '')
            
            if job in _INFRA_JOB_NAMES:
                kept_configs.append(sc)
                continue
            
            if job in server_map:
                targets = _build_server_targets(server_map[job])
                if targets:
                    sc['static_configs'] = [
                        {'labels': {'instance': job}, 'targets': targets}
                    ]
                    kept_configs.append(sc)
                # If no targets (nothing enabled), drop the entry
            # else: server deleted — don't keep the config
        
        # 2. Add new servers not yet in the config
        existing_jobs = {sc.get('job_name') for sc in kept_configs}
        for name, server in server_map.items():
            if name not in existing_jobs:
                targets = _build_server_targets(server)
                if targets:
                    kept_configs.append({
                        'job_name': name,
                        'static_configs': [
                            {'labels': {'instance': name}, 'targets': targets}
                        ],
                    })
        
        config['scrape_configs'] = kept_configs
        
        with open(prometheus_yml, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        reload_prometheus()
        
    except Exception:
        logger.debug("Failed to update prometheus.yml", exc_info=True)


def sync_ipmi_monitor_targets(servers, config_path: str = None):
    """Sync the IPMI-monitor servers.yaml with the current server list.

    - Adds entries for servers that are missing (name + server_ip only,
      so IPMI-monitor can at least do SSH-based monitoring).
    - Removes entries for servers that were deleted from dc-overview.
    - Preserves existing IPMI fields (bmc_ip, ipmi_user, ipmi_pass) for
      servers that already have them.
    """
    cfg_path = Path(config_path or IPMI_CONFIG_PATH)
    if not cfg_path.exists():
        return
    
    try:
        with open(cfg_path, 'r') as f:
            ipmi_config = yaml.safe_load(f) or {}
        
        existing_entries = {s['name']: s for s in ipmi_config.get('servers', [])}
        server_names = {s.name for s in servers}
        
        new_entries = []
        for server in servers:
            if server.name in existing_entries:
                entry = existing_entries[server.name]
                entry['server_ip'] = server.server_ip
                new_entries.append(entry)
            else:
                new_entries.append({
                    'name': server.name,
                    'server_ip': server.server_ip,
                })
        
        ipmi_config['servers'] = new_entries
        
        with open(cfg_path, 'w') as f:
            yaml.dump(ipmi_config, f, default_flow_style=False)
        
    except Exception:
        logger.debug("Failed to sync IPMI monitor config", exc_info=True)


def reload_prometheus():
    """Reload Prometheus configuration via HTTP lifecycle API with fallbacks.

    Tries in order:
      1. HTTP POST to prometheus:9090/prometheus/-/reload  (sub-path deploy)
      2. HTTP POST to prometheus:9090/-/reload             (root deploy)
      3. docker exec prometheus kill -HUP 1                (host with docker)
      4. systemctl reload prometheus                       (bare-metal)
    """
    for url in (
        "http://prometheus:9090/prometheus/-/reload",
        "http://prometheus:9090/-/reload",
    ):
        try:
            resp = requests.post(url, timeout=5)
            resp.raise_for_status()
            logger.debug("Prometheus reloaded via %s", url)
            return
        except (requests.ConnectionError, requests.Timeout, requests.HTTPError):
            continue

    try:
        subprocess.run(['docker', 'exec', 'prometheus', 'kill', '-HUP', '1'],
                      capture_output=True, timeout=10)
        logger.debug("Prometheus reloaded via docker exec")
        return
    except Exception:
        pass

    try:
        subprocess.run(['systemctl', 'reload', 'prometheus'],
                      capture_output=True, timeout=10)
        logger.debug("Prometheus reloaded via systemctl")
    except Exception:
        logger.warning("Failed to reload Prometheus via all methods")
