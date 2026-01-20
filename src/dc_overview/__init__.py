"""
DC Overview - GPU Datacenter Monitoring Suite

A comprehensive monitoring solution for GPU datacenters with:
- Prometheus metrics collection
- Grafana dashboards  
- Node, GPU, and VRAM temperature exporters
- IPMI/BMC monitoring integration
- Vast.ai integration
- Automated fleet deployment

Quick Start:
    pip install dc-overview
    sudo dc-overview quickstart
"""

__version__ = "1.1.0"
__author__ = "CryptoLabs"
__email__ = "info@cryptolabs.co.za"

# Export main classes for programmatic use
from .fleet_config import FleetConfig, Server
from .fleet_wizard import FleetWizard, run_fleet_wizard
from .fleet_manager import FleetManager, deploy_fleet
from .ssh_manager import SSHManager
from .prerequisites import PrerequisitesInstaller, ensure_prerequisites

__all__ = [
    "FleetConfig",
    "Server", 
    "FleetWizard",
    "FleetManager",
    "SSHManager",
    "PrerequisitesInstaller",
    "run_fleet_wizard",
    "deploy_fleet",
    "ensure_prerequisites",
]
