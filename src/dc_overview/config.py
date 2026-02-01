"""
DC Overview Configuration - Manage prometheus.yml and targets

Also includes CryptoLabs Alert System configuration for push notifications
to the CryptoLabs app, email, and web browser (v1.1.0+).
"""

import os
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

import yaml

logger = logging.getLogger(__name__)


# =============================================================================
# CryptoLabs Alert System Configuration (v1.1.0+)
# =============================================================================

@dataclass
class NotificationConfig:
    """Configuration for CryptoLabs Alert System notifications.
    
    This prepares DC Overview for future integration with the CryptoLabs
    Alert API, allowing push notifications to the CryptoLabs app, email,
    and web browser when deployment or monitoring issues occur.
    """
    # Master enable/disable for notifications
    enabled: bool = False
    
    # CryptoLabs API key for authentication with Alert API
    # Users will link their CryptoLabs account to get this key
    cryptolabs_api_key: str = ""
    
    # Alert API endpoint
    alert_endpoint: str = "https://ipmi-ai.cryptolabs.co.za/api/v1/alerts/send"
    
    # Rate limiting - minimum minutes between alerts of same type for same server
    rate_limit_minutes: int = 5
    
    # Which alert types to send
    alert_types: Dict[str, bool] = field(default_factory=lambda: {
        'exporter_down': True,
        'exporter_failed': True,
        'deployment_failed': True,
        'worker_unreachable': True,
        'high_temperature': True,
        'gpu_error': True,
        'container_unhealthy': True,
    })
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NotificationConfig':
        """Create NotificationConfig from dictionary."""
        if not data:
            return cls()
        
        config = cls()
        config.enabled = data.get('enabled', False)
        config.cryptolabs_api_key = data.get('cryptolabs_api_key', '')
        config.alert_endpoint = data.get('alert_endpoint', config.alert_endpoint)
        config.rate_limit_minutes = data.get('rate_limit_minutes', 5)
        
        # Merge alert types
        if 'alert_types' in data:
            config.alert_types.update(data['alert_types'])
        
        return config
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'enabled': self.enabled,
            'cryptolabs_api_key': self.cryptolabs_api_key,
            'alert_endpoint': self.alert_endpoint,
            'rate_limit_minutes': self.rate_limit_minutes,
            'alert_types': self.alert_types,
        }
    
    def is_alert_type_enabled(self, alert_type: str) -> bool:
        """Check if a specific alert type is enabled."""
        return self.enabled and self.alert_types.get(alert_type, False)


class PrometheusConfig:
    """Manage Prometheus configuration and scrape targets."""
    
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.config_file = config_dir / "prometheus.yml"
        self.targets_file = config_dir / "targets.yaml"
        self.targets: List[Dict[str, Any]] = []
        self._prometheus_config: Dict[str, Any] = {}
    
    @classmethod
    def load(cls, config_dir: Path) -> "PrometheusConfig":
        """Load configuration from directory."""
        instance = cls(config_dir)
        
        # Load targets
        if instance.targets_file.exists():
            with open(instance.targets_file) as f:
                data = yaml.safe_load(f) or {}
                instance.targets = data.get("targets", [])
        
        # Load prometheus config
        if instance.config_file.exists():
            with open(instance.config_file) as f:
                instance._prometheus_config = yaml.safe_load(f) or {}
        
        return instance
    
    def add_target(self, ip: str, name: str, ports: List[int]):
        """Add a new scrape target."""
        # Check for duplicates
        for target in self.targets:
            if target.get("ip") == ip:
                # Update existing
                target["name"] = name
                target["ports"] = ports
                return
        
        self.targets.append({
            "name": name,
            "ip": ip,
            "ports": ports,
        })
    
    def remove_target(self, ip: str):
        """Remove a target by IP."""
        self.targets = [t for t in self.targets if t.get("ip") != ip]
    
    def save(self):
        """Save configuration to files."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Save targets
        with open(self.targets_file, "w") as f:
            yaml.dump({"targets": self.targets}, f, default_flow_style=False)
        
        # Generate and save prometheus.yml
        self._generate_prometheus_config()
        with open(self.config_file, "w") as f:
            yaml.dump(self._prometheus_config, f, default_flow_style=False, sort_keys=False)
    
    def _generate_prometheus_config(self):
        """Generate prometheus.yml from targets."""
        self._prometheus_config = {
            "global": {
                "scrape_interval": "15s",
                "evaluation_interval": "15s",
            },
            "scrape_configs": []
        }
        
        # Add self-monitoring
        self._prometheus_config["scrape_configs"].append({
            "job_name": "prometheus",
            "static_configs": [{
                "targets": ["localhost:9090"],
                "labels": {"instance": "master"}
            }]
        })
        
        # Add targets
        for target in self.targets:
            job_name = target.get("name", target.get("ip", "unknown"))
            ip = target.get("ip")
            ports = target.get("ports", [9100, 9835])
            
            targets = [f"{ip}:{port}" for port in ports]
            
            self._prometheus_config["scrape_configs"].append({
                "job_name": job_name,
                "static_configs": [{
                    "targets": targets,
                    "labels": {"instance": job_name}
                }]
            })
    
    def get_prometheus_yml(self) -> str:
        """Get prometheus.yml content as string."""
        self._generate_prometheus_config()
        return yaml.dump(self._prometheus_config, default_flow_style=False, sort_keys=False)


class Config:
    """General DC Overview configuration."""
    
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.config_file = config_dir / "config.yaml"
        self._data: Dict[str, Any] = {
            "mode": "worker",
            "master": {
                "prometheus_port": 9090,
                "grafana_port": 3000,
                "grafana_password": None,
            },
            "exporters": {
                "node_exporter": True,
                "dc_exporter": True,  # Provides DCGM-compatible metrics + VRAM/hotspot temps
            },
            "vast_api_key": None,
            # CryptoLabs Alert System (v1.1.0+)
            "notifications": {},
        }
        self._notifications: Optional[NotificationConfig] = None
    
    @classmethod
    def load(cls, config_dir: Path) -> "Config":
        """Load configuration from file."""
        instance = cls(config_dir)
        
        if instance.config_file.exists():
            with open(instance.config_file) as f:
                data = yaml.safe_load(f) or {}
                instance._data.update(data)
        
        # Load notifications config
        instance._notifications = NotificationConfig.from_dict(
            instance._data.get("notifications", {})
        )
        
        # Also check environment variables for notification settings
        if os.environ.get('NOTIFICATIONS_ENABLED'):
            instance._notifications.enabled = os.environ['NOTIFICATIONS_ENABLED'].lower() == 'true'
        if os.environ.get('CRYPTOLABS_API_KEY'):
            instance._notifications.cryptolabs_api_key = os.environ['CRYPTOLABS_API_KEY']
        if os.environ.get('ALERT_ENDPOINT'):
            instance._notifications.alert_endpoint = os.environ['ALERT_ENDPOINT']
        
        return instance
    
    def save(self):
        """Save configuration to file."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Include notifications in saved data
        if self._notifications:
            self._data["notifications"] = self._notifications.to_dict()
        
        with open(self.config_file, "w") as f:
            yaml.dump(self._data, f, default_flow_style=False, sort_keys=False)
        
        # Secure the file (may contain API keys)
        os.chmod(self.config_file, 0o600)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self._data.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set a configuration value."""
        self._data[key] = value
    
    @property
    def mode(self) -> str:
        return self._data.get("mode", "worker")
    
    @property
    def is_master(self) -> bool:
        return self.mode == "master"
    
    @property
    def grafana_port(self) -> int:
        return self._data.get("master", {}).get("grafana_port", 3000)
    
    @property
    def prometheus_port(self) -> int:
        return self._data.get("master", {}).get("prometheus_port", 9090)
    
    @property
    def notifications(self) -> NotificationConfig:
        """Get notification configuration (CryptoLabs Alert System v1.1.0+)."""
        if self._notifications is None:
            self._notifications = NotificationConfig()
        return self._notifications
