"""
DC Overview Service Manager - systemd service installation
"""

import os
import subprocess
from pathlib import Path
from typing import Dict, Any

DC_OVERVIEW_SERVICE = """[Unit]
Description=DC Overview - GPU Datacenter Monitoring Suite
Documentation=https://github.com/cryptolabsza/dc-overview
After=network.target docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory={config_dir}
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
ExecReload=/usr/bin/docker compose restart

[Install]
WantedBy=multi-user.target
"""


class ServiceManager:
    """Manage systemd services for DC Overview."""
    
    def __init__(self, mode: str = "worker"):
        self.mode = mode
        self.service_name = "dc-overview"
        self.service_file = f"/etc/systemd/system/{self.service_name}.service"
    
    def install_all(self, config: Dict[str, Any]):
        """Install all services based on mode."""
        if os.geteuid() != 0:
            raise PermissionError("Installing services requires root privileges")
        
        if self.mode == "master":
            self._install_master_service(config)
        else:
            self._install_worker_services(config)
    
    def _install_master_service(self, config: Dict[str, Any]):
        """Install master service (docker compose wrapper)."""
        config_dir = config.get("_config_dir", Path.home() / ".config" / "dc-overview")
        
        service_content = DC_OVERVIEW_SERVICE.format(
            config_dir=str(config_dir)
        )
        
        with open(self.service_file, "w") as f:
            f.write(service_content)
        
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", self.service_name], check=True)
        
        print(f"Master service installed: {self.service_file}")
        print(f"Start with: sudo systemctl start {self.service_name}")
    
    def _install_worker_services(self, config: Dict[str, Any]):
        """Install worker services (exporters)."""
        from .exporters import ExporterInstaller
        
        installer = ExporterInstaller()
        exporters = config.get("exporters", {})
        
        if exporters.get("node_exporter", True):
            installer.install_node_exporter()
        
        if exporters.get("dcgm_exporter", True):
            installer.install_dcgm_exporter()
        
        if exporters.get("dc_exporter", True):
            installer.install_dc_exporter()
    
    def uninstall(self):
        """Remove DC Overview services."""
        if os.geteuid() != 0:
            raise PermissionError("Uninstalling services requires root privileges")
        
        # Stop and disable main service
        subprocess.run(["systemctl", "stop", self.service_name], capture_output=True)
        subprocess.run(["systemctl", "disable", self.service_name], capture_output=True)
        
        if os.path.exists(self.service_file):
            os.remove(self.service_file)
        
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        print(f"Service uninstalled")
    
    def status(self) -> str:
        """Get service status."""
        if not os.path.exists(self.service_file):
            return "Not installed"
        
        try:
            result = subprocess.run(
                ["systemctl", "is-active", self.service_name],
                capture_output=True,
                text=True
            )
            status = result.stdout.strip()
            
            if status == "active":
                return "✓ Running"
            elif status == "inactive":
                return "○ Stopped"
            elif status == "failed":
                return "✗ Failed"
            else:
                return status
        except Exception:
            return "Unknown"
    
    def start(self):
        """Start the service."""
        subprocess.run(["systemctl", "start", self.service_name], check=True)
    
    def stop(self):
        """Stop the service."""
        subprocess.run(["systemctl", "stop", self.service_name], check=True)
    
    def restart(self):
        """Restart the service."""
        subprocess.run(["systemctl", "restart", self.service_name], check=True)
