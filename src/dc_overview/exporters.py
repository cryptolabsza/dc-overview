"""
DC Overview Exporter Installer - Install Prometheus exporters as systemd services
"""

import os
import subprocess
import urllib.request
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Latest versions
NODE_EXPORTER_VERSION = "1.7.0"
DCGM_EXPORTER_VERSION = "3.3.5-3.4.1"
DC_EXPORTER_VERSION = "1.0.0"

# Download URLs
NODE_EXPORTER_URL = f"https://github.com/prometheus/node_exporter/releases/download/v{NODE_EXPORTER_VERSION}/node_exporter-{NODE_EXPORTER_VERSION}.linux-amd64.tar.gz"
DC_EXPORTER_URL = f"https://github.com/cryptolabsza/dc-exporter/releases/download/v{DC_EXPORTER_VERSION}/dc-exporter-collector"
DC_EXPORTER_SERVER_URL = f"https://github.com/cryptolabsza/dc-exporter/releases/download/v{DC_EXPORTER_VERSION}/dc-exporter-server"


# Systemd service templates
NODE_EXPORTER_SERVICE = """[Unit]
Description=Node Exporter
Documentation=https://github.com/prometheus/node_exporter
After=network.target

[Service]
Type=simple
User=node_exporter
Group=node_exporter
ExecStart=/usr/local/bin/node_exporter
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

DCGM_EXPORTER_SERVICE = """[Unit]
Description=NVIDIA DCGM Exporter
Documentation=https://github.com/NVIDIA/dcgm-exporter
After=network.target nvidia-dcgm.service
Requires=nvidia-dcgm.service

[Service]
Type=simple
ExecStart=/usr/local/bin/dcgm-exporter -a :9400
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

DC_EXPORTER_SERVICE = """[Unit]
Description=DC Exporter - GPU VRAM Temperature Exporter
Documentation=https://github.com/cryptolabsza/dc-exporter
After=network.target

[Service]
Type=simple
WorkingDirectory=/etc/dc-exporter
ExecStart=/bin/bash -c "/usr/local/bin/dc-exporter-collector --no-console & /usr/local/bin/dc-exporter-server"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

DC_EXPORTER_CONFIG = """[agent]
machine_id=auto
interval=5

[gpu]
enabled=1
DCGM_FI_DEV_VRAM_TEMP
DCGM_FI_DEV_HOT_SPOT_TEMP
DCGM_FI_DEV_FAN_SPEED
DCGM_FI_DEV_CLOCKS_THROTTLE_REASON
GPU_AER_TOTAL_ERRORS
GPU_AER_ERROR_STATE

[system]
enabled=1
SYS_LOAD_AVG
SYS_CPU_USAGE
SYS_MEM_USED

[ipmi]
enabled=0
"""


class ExporterInstaller:
    """Install Prometheus exporters as native systemd services."""
    
    def __init__(self):
        if os.geteuid() != 0:
            raise PermissionError("ExporterInstaller requires root privileges")
    
    def install_node_exporter(self) -> bool:
        """Install node_exporter."""
        console.print("\n[bold]Installing node_exporter...[/bold]")
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                # Download
                task = progress.add_task("Downloading node_exporter...", total=None)
                
                with tempfile.TemporaryDirectory() as tmpdir:
                    tarball = Path(tmpdir) / "node_exporter.tar.gz"
                    
                    urllib.request.urlretrieve(NODE_EXPORTER_URL, tarball)
                    progress.update(task, description="Extracting...")
                    
                    with tarfile.open(tarball, "r:gz") as tar:
                        tar.extractall(tmpdir)
                    
                    # Find and move binary
                    for item in Path(tmpdir).iterdir():
                        if item.is_dir() and "node_exporter" in item.name:
                            binary = item / "node_exporter"
                            if binary.exists():
                                progress.update(task, description="Installing...")
                                subprocess.run(["cp", str(binary), "/usr/local/bin/"], check=True)
                                subprocess.run(["chmod", "+x", "/usr/local/bin/node_exporter"], check=True)
                                break
                
                # Create user
                progress.update(task, description="Creating service user...")
                subprocess.run(
                    ["useradd", "-r", "-s", "/bin/false", "node_exporter"],
                    capture_output=True
                )
                
                # Install service
                progress.update(task, description="Installing systemd service...")
                with open("/etc/systemd/system/node_exporter.service", "w") as f:
                    f.write(NODE_EXPORTER_SERVICE)
                
                subprocess.run(["systemctl", "daemon-reload"], check=True)
                subprocess.run(["systemctl", "enable", "node_exporter"], check=True)
                subprocess.run(["systemctl", "start", "node_exporter"], check=True)
            
            console.print("[green]✓[/green] node_exporter installed (port 9100)")
            return True
            
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to install node_exporter: {e}")
            return False
    
    def install_dcgm_exporter(self, vastai_mode: bool = None) -> bool:
        """Install dcgm-exporter via Docker.
        
        Args:
            vastai_mode: If True, use --runtime=nvidia instead of --gpus all.
                        If None, auto-detect Vast.ai hosts.
        """
        console.print("\n[bold]Installing dcgm-exporter...[/bold]")
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Checking NVIDIA drivers...", total=None)
                
                # Check for nvidia-smi
                result = subprocess.run(["nvidia-smi", "-L"], capture_output=True)
                if result.returncode != 0:
                    console.print("[yellow]⚠[/yellow] NVIDIA drivers not found. Skipping dcgm-exporter.")
                    return False
                
                # Check for Docker
                progress.update(task, description="Checking Docker...")
                result = subprocess.run(["which", "docker"], capture_output=True)
                if result.returncode != 0:
                    console.print("[yellow]⚠[/yellow] Docker not found. Install Docker first.")
                    return False
                
                # Auto-detect Vast.ai host if not specified
                if vastai_mode is None:
                    vastai_mode = os.path.exists("/var/lib/vastai_kaalia") or \
                                  os.path.exists("/etc/systemd/system/vastai.service")
                
                # Check if already running
                progress.update(task, description="Checking existing containers...")
                result = subprocess.run(
                    ["docker", "ps", "-q", "-f", "name=dcgm-exporter"],
                    capture_output=True, text=True
                )
                if result.stdout.strip():
                    console.print("[green]✓[/green] dcgm-exporter already running")
                    return True
                
                # Remove old container if exists
                subprocess.run(
                    ["docker", "rm", "-f", "dcgm-exporter"],
                    capture_output=True
                )
                
                # Start dcgm-exporter container
                progress.update(task, description="Starting dcgm-exporter container...")
                
                # Use --runtime=nvidia for Vast.ai hosts (required)
                # Use --gpus all for standard Docker hosts
                if vastai_mode:
                    docker_cmd = [
                        "docker", "run", "-d",
                        "--name", "dcgm-exporter",
                        "--runtime=nvidia",  # Required for Vast.ai hosts
                        "-p", "9400:9400",
                        "--restart", "unless-stopped",
                        "nvidia/dcgm-exporter:3.3.5-3.4.1-ubuntu22.04"
                    ]
                    console.print("[dim]Using --runtime=nvidia (Vast.ai mode)[/dim]")
                else:
                    docker_cmd = [
                        "docker", "run", "-d",
                        "--name", "dcgm-exporter",
                        "--gpus", "all",
                        "-p", "9400:9400",
                        "--restart", "unless-stopped",
                        "nvidia/dcgm-exporter:3.3.5-3.4.1-ubuntu22.04"
                    ]
                    console.print("[dim]Using --gpus all (standard mode)[/dim]")
                
                result = subprocess.run(docker_cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    console.print(f"[red]✗[/red] Failed to start dcgm-exporter: {result.stderr}")
                    return False
            
            console.print("[green]✓[/green] dcgm-exporter installed (port 9400)")
            return True
            
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to install dcgm-exporter: {e}")
            return False
    
    def install_dc_exporter(self) -> bool:
        """Install dc-exporter for VRAM temperatures."""
        console.print("\n[bold]Installing dc-exporter...[/bold]")
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Downloading dc-exporter...", total=None)
                
                # Download binaries
                urllib.request.urlretrieve(
                    DC_EXPORTER_URL, 
                    "/usr/local/bin/dc-exporter-collector"
                )
                urllib.request.urlretrieve(
                    DC_EXPORTER_SERVER_URL, 
                    "/usr/local/bin/dc-exporter-server"
                )
                
                subprocess.run(["chmod", "+x", "/usr/local/bin/dc-exporter-collector"], check=True)
                subprocess.run(["chmod", "+x", "/usr/local/bin/dc-exporter-server"], check=True)
                
                # Create config directory and file
                progress.update(task, description="Creating configuration...")
                os.makedirs("/etc/dc-exporter", exist_ok=True)
                
                with open("/etc/dc-exporter/config.ini", "w") as f:
                    f.write(DC_EXPORTER_CONFIG)
                
                # Install service
                progress.update(task, description="Installing systemd service...")
                with open("/etc/systemd/system/dc-exporter.service", "w") as f:
                    f.write(DC_EXPORTER_SERVICE)
                
                subprocess.run(["systemctl", "daemon-reload"], check=True)
                subprocess.run(["systemctl", "enable", "dc-exporter"], check=True)
                subprocess.run(["systemctl", "start", "dc-exporter"], check=True)
            
            console.print("[green]✓[/green] dc-exporter installed (port 9500)")
            return True
            
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to install dc-exporter: {e}")
            return False
    
    def uninstall_all(self):
        """Uninstall all exporters."""
        services = ["node_exporter", "dcgm-exporter", "dc-exporter"]
        
        for service in services:
            try:
                subprocess.run(["systemctl", "stop", service], capture_output=True)
                subprocess.run(["systemctl", "disable", service], capture_output=True)
                
                service_file = f"/etc/systemd/system/{service}.service"
                if os.path.exists(service_file):
                    os.remove(service_file)
                
                console.print(f"[green]✓[/green] Uninstalled {service}")
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] Could not uninstall {service}: {e}")
        
        subprocess.run(["systemctl", "daemon-reload"], check=True)
    
    @staticmethod
    def check_status() -> dict:
        """Check status of all exporters."""
        status = {}
        services = [
            ("node_exporter", 9100),
            ("dcgm-exporter", 9400),
            ("dc-exporter", 9500),
        ]
        
        for name, port in services:
            try:
                # First check systemd service
                result = subprocess.run(
                    ["systemctl", "is-active", name],
                    capture_output=True,
                    text=True
                )
                if result.stdout.strip() == "active":
                    status[name] = {
                        "status": "active",
                        "port": port,
                        "running": True
                    }
                    continue
                
                # For dcgm-exporter, also check Docker container
                if name == "dcgm-exporter":
                    docker_result = subprocess.run(
                        ["docker", "ps", "-q", "-f", "name=dcgm-exporter"],
                        capture_output=True, text=True
                    )
                    if docker_result.returncode == 0 and docker_result.stdout.strip():
                        status[name] = {
                            "status": "active (docker)",
                            "port": port,
                            "running": True
                        }
                        continue
                
                status[name] = {
                    "status": result.stdout.strip() or "not installed",
                    "port": port,
                    "running": False
                }
            except Exception:
                status[name] = {
                    "status": "not installed",
                    "port": port,
                    "running": False
                }
        
        return status
