"""
Prometheus target management for the web application.

Functions for updating Prometheus targets files and reloading
the Prometheus configuration.
"""

import json
import logging
import subprocess

import yaml
from pathlib import Path

logger = logging.getLogger(__name__)


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
            
    except Exception:
        pass  # Non-critical operation


def update_prometheus_yml_targets(servers):
    """Update the prometheus.yml scrape targets to match enabled exporters."""
    prometheus_yml = Path('/etc/dc-overview/prometheus.yml')
    if not prometheus_yml.exists():
        return
    
    try:
        with open(prometheus_yml, 'r') as f:
            config = yaml.safe_load(f)
        
        if not config or 'scrape_configs' not in config:
            return
        
        for server in servers:
            for scrape_config in config['scrape_configs']:
                if scrape_config.get('job_name') == server.name:
                    targets = []
                    if server.node_exporter_installed and server.node_exporter_enabled:
                        targets.append(f"{server.server_ip}:9100")
                    if server.dc_exporter_installed and server.dc_exporter_enabled:
                        targets.append(f"{server.server_ip}:9835")
                    if server.dcgm_exporter_installed and server.dcgm_exporter_enabled:
                        targets.append(f"{server.server_ip}:9400")
                    
                    if targets and scrape_config.get('static_configs'):
                        scrape_config['static_configs'][0]['targets'] = targets
                    break
        
        with open(prometheus_yml, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        reload_prometheus()
        
    except Exception:
        pass


def reload_prometheus():
    """Reload Prometheus configuration."""
    try:
        subprocess.run(['docker', 'exec', 'prometheus', 'kill', '-HUP', '1'],
                      capture_output=True, timeout=10)
    except Exception:
        try:
            subprocess.run(['systemctl', 'reload', 'prometheus'],
                          capture_output=True, timeout=10)
        except Exception:
            pass
