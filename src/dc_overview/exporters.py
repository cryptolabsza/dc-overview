"""
DC Overview Exporter Installer - Install Prometheus exporters as systemd services

Includes:
- Version detection from metrics endpoints and SSH
- GitHub release checking for updates
- Remote installation and update via SSH
"""

import os
import re
import json
import subprocess
import urllib.request
import urllib.error
import tarfile
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Latest versions (defaults, used as fallback when GitHub API is rate limited)
NODE_EXPORTER_VERSION = "1.10.2"
DC_EXPORTER_RS_VERSION = "0.2.5"
DCGM_EXPORTER_VERSION = "3.3.8-3.6.0"

# Fallback versions when GitHub API fails
FALLBACK_VERSIONS = {
    'node_exporter': NODE_EXPORTER_VERSION,
    'dc_exporter': DC_EXPORTER_RS_VERSION,
    'dcgm_exporter': DCGM_EXPORTER_VERSION,
}

# Version cache - check GitHub once per hour, not per server
import time
_VERSION_CACHE = {
    'versions': {},      # exporter -> version
    'last_update': 0,    # timestamp of last GitHub check
    'ttl': 3600,         # cache TTL in seconds (1 hour)
}

def _get_cached_versions() -> Dict[str, Optional[str]]:
    """Get latest versions from cache, refreshing from GitHub if stale."""
    now = time.time()
    
    # If cache is fresh, return cached versions
    if _VERSION_CACHE['versions'] and (now - _VERSION_CACHE['last_update']) < _VERSION_CACHE['ttl']:
        return _VERSION_CACHE['versions']
    
    # Cache is stale - try to refresh from GitHub
    new_versions = {}
    for exporter, repo in EXPORTER_REPOS.items():
        release = get_latest_github_release(repo, 'main')
        if release:
            new_versions[exporter] = release.get('version')
        else:
            # GitHub failed - use fallback or previous cached value
            new_versions[exporter] = _VERSION_CACHE['versions'].get(exporter) or FALLBACK_VERSIONS.get(exporter)
    
    # Update cache
    _VERSION_CACHE['versions'] = new_versions
    _VERSION_CACHE['last_update'] = now
    
    return new_versions

# GitHub repositories for each exporter
EXPORTER_REPOS = {
    'node_exporter': 'prometheus/node_exporter',
    'dc_exporter': 'cryptolabsza/dc-exporter-releases',
    'dcgm_exporter': 'NVIDIA/dcgm-exporter'
}

# Exporter ports
EXPORTER_PORTS = {
    'node_exporter': 9100,
    'dc_exporter': 9835,
    'dcgm_exporter': 9400
}

# Download URLs
NODE_EXPORTER_URL = f"https://github.com/prometheus/node_exporter/releases/download/v{NODE_EXPORTER_VERSION}/node_exporter-{NODE_EXPORTER_VERSION}.linux-amd64.tar.gz"

# DC Exporter RS (Rust version) - preferred
# Using dc-exporter-releases repo for public binary distribution
# Note: Both main and dev branches use the same 'latest' release URL since
# dc-exporter-releases doesn't have separate dev releases
DC_EXPORTER_RS_URL = "https://github.com/cryptolabsza/dc-exporter-releases/releases/latest/download/dc-exporter-rs"
DC_EXPORTER_RS_DEB_URL = f"https://github.com/cryptolabsza/dc-exporter-releases/releases/latest/download/dc-exporter-rs_{DC_EXPORTER_RS_VERSION}_amd64.deb"


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
Description=DC Exporter - GPU Metrics for Prometheus (Rust)
Documentation=https://github.com/cryptolabsza/dc-exporter-rs
After=network.target nvidia-persistenced.service

[Service]
Type=simple
ExecStart=/usr/local/bin/dc-exporter-rs --port 9835
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

# Legacy run script (deprecated, kept for backwards compatibility)
DC_EXPORTER_RUN_SCRIPT = '''#!/bin/bash
# This script is deprecated. Use dc-exporter-rs instead.
exec /usr/local/bin/dc-exporter-rs --port 9835
'''

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
        """Install dc-exporter-rs (Rust version) for GPU metrics.
        
        Provides DCGM-compatible metrics (DCGM_FI_*) plus unique metrics:
        - DCGM_FI_DEV_VRAM_TEMP - VRAM temperature
        - DCGM_FI_DEV_HOT_SPOT_TEMP - Hotspot/Junction temperature  
        - DCGM_FI_DEV_CLOCKS_THROTTLE_REASON - Throttle reasons
        - GPU_AER_TOTAL_ERRORS - PCIe AER errors
        - GPU_ERROR_STATE - GPU state (OK/Warning/Error/VM_Passthrough)
        
        Downloads from: https://github.com/cryptolabsza/dc-exporter-rs
        """
        console.print("\n[bold]Installing dc-exporter-rs...[/bold]")
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Setting up dc-exporter-rs...", total=None)
                
                # Create config directory
                os.makedirs("/etc/dc-exporter", exist_ok=True)
                
                # Stop any existing old dc-exporter service
                subprocess.run(["systemctl", "stop", "dc-exporter"], capture_output=True)
                subprocess.run(["systemctl", "stop", "gddr6-metrics-exporter"], capture_output=True)
                
                # Download dc-exporter-rs binary
                progress.update(task, description="Downloading dc-exporter-rs...")
                binary_path = "/usr/local/bin/dc-exporter-rs"
                
                try:
                    urllib.request.urlretrieve(DC_EXPORTER_RS_URL, binary_path)
                    subprocess.run(["chmod", "+x", binary_path], check=True)
                    console.print(f"[dim]Downloaded from {DC_EXPORTER_RS_URL}[/dim]")
                except Exception as e:
                    console.print(f"[yellow]⚠[/yellow] Failed to download: {e}")
                    console.print("[dim]Trying alternative method...[/dim]")
                    
                    # Try curl as fallback
                    result = subprocess.run(
                        ["curl", "-L", "-o", binary_path, DC_EXPORTER_RS_URL],
                        capture_output=True
                    )
                    if result.returncode != 0:
                        console.print("[red]✗[/red] Failed to download dc-exporter-rs")
                        console.print(f"[dim]Download manually from: {DC_EXPORTER_RS_URL}[/dim]")
                        return False
                    subprocess.run(["chmod", "+x", binary_path], check=True)
                
                # Verify binary works
                progress.update(task, description="Verifying binary...")
                try:
                    result = subprocess.run(
                        [binary_path, "--version"],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        version = result.stdout.strip().split('\n')[0] if result.stdout else "unknown"
                        console.print(f"[dim]Version: {version}[/dim]")
                    else:
                        # Try --help as fallback
                        result = subprocess.run(
                            [binary_path, "--help"],
                            capture_output=True, text=True, timeout=10
                        )
                except Exception as e:
                    console.print(f"[yellow]⚠[/yellow] Could not verify binary: {e}")
                
                # Remove old services and binaries
                progress.update(task, description="Cleaning up old installations...")
                # Remove old gddr6-metrics-exporter
                subprocess.run(["systemctl", "disable", "gddr6-metrics-exporter"], capture_output=True)
                subprocess.run(["rm", "-f", "/etc/systemd/system/gddr6-metrics-exporter.service"], capture_output=True)
                # Remove old dc-exporter files
                subprocess.run(["rm", "-rf", "/opt/dc-exporter"], capture_output=True)
                subprocess.run(["rm", "-f", "/usr/local/bin/dc-exporter-c"], capture_output=True)
                subprocess.run(["rm", "-f", "/usr/local/bin/dc-exporter-collector"], capture_output=True)
                subprocess.run(["rm", "-f", "/usr/local/bin/dc-exporter-server"], capture_output=True)
                
                # Install systemd service
                progress.update(task, description="Installing systemd service...")
                with open("/etc/systemd/system/dc-exporter.service", "w") as f:
                    f.write(DC_EXPORTER_SERVICE)
                
                subprocess.run(["systemctl", "daemon-reload"], check=True)
                subprocess.run(["systemctl", "enable", "dc-exporter"], check=True)
                subprocess.run(["systemctl", "restart", "dc-exporter"], check=True)
                
                # Wait and verify service is running
                progress.update(task, description="Verifying service...")
                import time
                time.sleep(2)
                
                result = subprocess.run(
                    ["systemctl", "is-active", "dc-exporter"],
                    capture_output=True, text=True
                )
                if result.stdout.strip() != "active":
                    console.print("[yellow]⚠[/yellow] Service may not be running correctly")
                    console.print("[dim]Check: journalctl -u dc-exporter -n 20[/dim]")
            
            console.print("[green]✓[/green] dc-exporter-rs installed (port 9835)")
            console.print("[dim]  Metrics: DCGM_FI_* + VRAM/Hotspot temps + Throttle reasons[/dim]")
            console.print("[dim]  Verify: curl http://localhost:9835/metrics | head[/dim]")
            return True
            
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to install dc-exporter-rs: {e}")
            return False
    
    def _compile_dc_exporter_from_source(self) -> bool:
        """Try to compile dc-exporter from bundled source."""
        try:
            # Check for required dependencies
            result = subprocess.run(["which", "gcc"], capture_output=True)
            if result.returncode != 0:
                console.print("[dim]gcc not found, installing...[/dim]")
                subprocess.run(["apt-get", "update", "-qq"], capture_output=True)
                subprocess.run(["apt-get", "install", "-y", "-qq", "gcc", "libpci-dev"], capture_output=True)
            
            # Copy bundled source from package
            try:
                import dc_overview
                pkg_path = Path(dc_overview.__file__).parent / "dc_exporter" / "dc-exporter.c"
                if pkg_path.exists():
                    import shutil
                    shutil.copy(pkg_path, "/opt/dc-exporter/dc-exporter.c")
                    console.print("[dim]Using bundled source[/dim]")
                else:
                    console.print("[dim]Bundled source not found[/dim]")
                    return False
            except Exception as e:
                console.print(f"[dim]Could not locate bundled source: {e}[/dim]")
                return False
            
            # Compile
            result = subprocess.run(
                ["gcc", "-O2", "-Wall", "-o", "/opt/dc-exporter/dc-exporter-c", 
                 "/opt/dc-exporter/dc-exporter.c", "-lpci", "-lnvidia-ml",
                 "-I/usr/local/cuda/include"],
                capture_output=True,
                text=True,
                cwd="/opt/dc-exporter"
            )
            
            if result.returncode == 0 and Path("/opt/dc-exporter/dc-exporter-c").exists():
                subprocess.run(["chmod", "+x", "/opt/dc-exporter/dc-exporter-c"], check=True)
                console.print("[dim]Compiled from source[/dim]")
                return True
            else:
                console.print(f"[dim]Compilation failed: {result.stderr[:100]}[/dim]")
                
        except Exception as e:
            console.print(f"[dim]Source compilation failed: {e}[/dim]")
        
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
            ("dc-exporter", 9835),
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


# =============================================================================
# VERSION DETECTION FUNCTIONS
# =============================================================================

def get_version_from_metrics(server_ip: str, exporter: str, timeout: int = 5) -> Optional[str]:
    """
    Get exporter version from its metrics endpoint.
    
    Args:
        server_ip: IP address of the server
        exporter: One of 'node_exporter', 'dc_exporter', 'dcgm_exporter'
        timeout: Request timeout in seconds
        
    Returns:
        Version string or None if not available
    """
    port = EXPORTER_PORTS.get(exporter)
    if not port:
        return None
    
    try:
        url = f"http://{server_ip}:{port}/metrics"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            metrics = response.read().decode('utf-8')
            
            if exporter == 'node_exporter':
                # Parse: node_exporter_build_info{...version="1.7.0"...}
                match = re.search(r'node_exporter_build_info\{[^}]*version="([^"]+)"', metrics)
                if match:
                    return match.group(1)
                    
            elif exporter == 'dc_exporter':
                # Parse: DCXP_BUILD_INFO or look for version in any metric
                match = re.search(r'dc_exporter_build_info\{[^}]*version="([^"]+)"', metrics)
                if match:
                    return match.group(1)
                # Try to find version in any DCXP metric
                match = re.search(r'DCXP_VERSION\{[^}]*\}\s+([0-9.]+)', metrics)
                if match:
                    return match.group(1)
                # Check if metrics are present (exporter is working)
                if 'DCXP_GPU_SUPPORTED' in metrics or 'DCXP_FI_DEV' in metrics:
                    return "running"  # Version unknown but exporter is active
                    
            elif exporter == 'dcgm_exporter':
                # Parse: dcgm_exporter_build_info{...version="3.3.5-3.4.1"...}
                match = re.search(r'dcgm_exporter_build_info\{[^}]*version="([^"]+)"', metrics)
                if match:
                    return match.group(1)
                # Check if DCGM metrics present
                if 'DCGM_FI_' in metrics:
                    return "running"
                    
    except Exception:
        pass
    
    return None


def _build_exporter_ssh_cmd(server_ip: str, ssh_user: str = 'root',
                            ssh_port: int = 22, ssh_key_path: Optional[str] = None,
                            ssh_password: Optional[str] = None,
                            timeout: int = 5) -> tuple:
    """Build SSH command for exporter operations, supporting both key and password auth.
    
    Returns (cmd_prefix, env_dict) where env_dict contains SSHPASS if password auth.
    """
    env = {}
    
    if ssh_key_path:
        ssh_cmd = [
            'ssh',
            '-o', f'ConnectTimeout={timeout}',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'BatchMode=yes',
            '-p', str(ssh_port)
        ]
        ssh_cmd.extend(['-i', ssh_key_path])
    elif ssh_password:
        ssh_cmd = [
            'sshpass', '-e',
            'ssh',
            '-o', f'ConnectTimeout={timeout}',
            '-o', 'StrictHostKeyChecking=no',
            '-p', str(ssh_port)
        ]
        env['SSHPASS'] = ssh_password
    else:
        ssh_cmd = [
            'ssh',
            '-o', f'ConnectTimeout={timeout}',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'BatchMode=yes',
            '-p', str(ssh_port)
        ]
    
    ssh_cmd.append(f'{ssh_user}@{server_ip}')
    return ssh_cmd, env


def get_version_from_ssh(server_ip: str, exporter: str, ssh_user: str = 'root',
                         ssh_port: int = 22, ssh_key_path: Optional[str] = None,
                         ssh_password: Optional[str] = None,
                         timeout: int = 10) -> Optional[str]:
    """
    Get exporter version by running --version on the remote server via SSH.
    
    Args:
        server_ip: IP address of the server
        exporter: One of 'node_exporter', 'dc_exporter', 'dcgm_exporter'
        ssh_user: SSH username
        ssh_port: SSH port
        ssh_key_path: Path to SSH key (optional)
        ssh_password: SSH password for password-based auth (optional)
        timeout: Command timeout
        
    Returns:
        Version string or None if not available
    """
    binary_paths = {
        'node_exporter': '/usr/local/bin/node_exporter',
        'dc_exporter': '/usr/local/bin/dc-exporter-rs',
        'dcgm_exporter': None  # Docker-based, use docker inspect
    }
    
    binary = binary_paths.get(exporter)
    
    try:
        ssh_cmd, env = _build_exporter_ssh_cmd(server_ip, ssh_user, ssh_port, ssh_key_path, ssh_password, timeout=5)
        
        if exporter == 'dcgm_exporter':
            # For Docker-based dcgm-exporter, get image tag
            ssh_cmd.append("docker inspect dcgm-exporter --format '{{.Config.Image}}' 2>/dev/null || echo ''")
        else:
            ssh_cmd.append(f"{binary} --version 2>/dev/null || echo ''")
        
        run_env = {**os.environ, **env} if env else None
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout, env=run_env)
        
        if result.returncode == 0 and result.stdout.strip():
            output = result.stdout.strip()
            
            if exporter == 'node_exporter':
                # Parse: node_exporter, version 1.7.0 (branch: ...)
                match = re.search(r'version\s+([0-9.]+)', output)
                if match:
                    return match.group(1)
                    
            elif exporter == 'dc_exporter':
                # Parse: dc-exporter-rs 0.1.0 or similar
                match = re.search(r'([0-9]+\.[0-9]+\.[0-9]+)', output)
                if match:
                    return match.group(1)
                    
            elif exporter == 'dcgm_exporter':
                # Parse Docker image tag: nvidia/dcgm-exporter:3.3.5-3.4.1-ubuntu22.04
                match = re.search(r':([0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+\.[0-9]+)', output)
                if match:
                    return match.group(1)
                    
    except Exception:
        pass
    
    return None


def get_exporter_version(server_ip: str, exporter: str, ssh_user: str = 'root',
                        ssh_port: int = 22, ssh_key_path: Optional[str] = None,
                        ssh_password: Optional[str] = None) -> Optional[str]:
    """
    Get exporter version, trying metrics endpoint first then SSH fallback.
    
    Args:
        server_ip: IP address of the server
        exporter: One of 'node_exporter', 'dc_exporter', 'dcgm_exporter'
        ssh_user: SSH username
        ssh_port: SSH port
        ssh_key_path: Path to SSH key (optional)
        ssh_password: SSH password for password-based auth (optional)
        
    Returns:
        Version string or None if not available
    """
    # Try metrics endpoint first (faster, doesn't require SSH)
    version = get_version_from_metrics(server_ip, exporter)
    if version and version != "running":
        return version
    
    # Fall back to SSH
    version = get_version_from_ssh(server_ip, exporter, ssh_user, ssh_port, ssh_key_path, ssh_password)
    if version:
        return version
    
    # If metrics showed "running" but we couldn't get version
    if version == "running":
        return "unknown"
    
    return None


def get_all_exporter_versions(server_ip: str, ssh_user: str = 'root',
                              ssh_port: int = 22, ssh_key_path: Optional[str] = None,
                              ssh_password: Optional[str] = None) -> Dict[str, Optional[str]]:
    """
    Get versions of all exporters on a server.
    
    Returns:
        Dictionary mapping exporter name to version (or None if not installed)
    """
    return {
        'node_exporter': get_exporter_version(server_ip, 'node_exporter', ssh_user, ssh_port, ssh_key_path, ssh_password),
        'dc_exporter': get_exporter_version(server_ip, 'dc_exporter', ssh_user, ssh_port, ssh_key_path, ssh_password),
        'dcgm_exporter': get_exporter_version(server_ip, 'dcgm_exporter', ssh_user, ssh_port, ssh_key_path, ssh_password),
    }


# =============================================================================
# GITHUB RELEASE FUNCTIONS
# =============================================================================

def get_latest_github_release(repo: str, branch: str = 'main') -> Optional[Dict[str, Any]]:
    """
    Get the latest release from a GitHub repository.
    
    Args:
        repo: GitHub repository in 'owner/repo' format
        branch: Branch to check ('main' or 'dev') - affects pre-release filtering
        
    Returns:
        Dictionary with 'version', 'tag', 'url', 'published_at' or None
    """
    try:
        # GitHub API for releases
        url = f"https://api.github.com/repos/{repo}/releases"
        req = urllib.request.Request(url)
        req.add_header('Accept', 'application/vnd.github.v3+json')
        req.add_header('User-Agent', 'dc-overview')
        
        # Add GitHub token if available (increases rate limit from 60 to 5000 req/hour)
        github_token = os.environ.get('GITHUB_TOKEN')
        if github_token:
            req.add_header('Authorization', f'token {github_token}')
        
        with urllib.request.urlopen(req, timeout=10) as response:
            releases = json.loads(response.read().decode('utf-8'))
            
            if not releases:
                return None
            
            for release in releases:
                # Skip pre-releases unless using dev branch
                if release.get('prerelease') and branch == 'main':
                    continue
                
                tag = release.get('tag_name', '')
                version = tag.lstrip('v')
                
                return {
                    'version': version,
                    'tag': tag,
                    'url': release.get('html_url'),
                    'published_at': release.get('published_at'),
                    'prerelease': release.get('prerelease', False),
                    'assets': release.get('assets', [])
                }
                
    except Exception:
        pass
    
    return None


def get_latest_exporter_version(exporter: str, branch: str = 'main') -> Optional[str]:
    """
    Get the latest available version for an exporter.
    Uses a 1-hour cache to avoid GitHub API rate limiting.
    
    Args:
        exporter: One of 'node_exporter', 'dc_exporter', 'dcgm_exporter'
        branch: Branch to check ('main' or 'dev')
        
    Returns:
        Version string or None
    """
    # Use cached versions (refreshes from GitHub once per hour)
    cached = _get_cached_versions()
    version = cached.get(exporter)
    
    if version:
        return version
    
    # Ultimate fallback
    return FALLBACK_VERSIONS.get(exporter)


def get_all_latest_versions(branch: str = 'main') -> Dict[str, Optional[str]]:
    """
    Get the latest available versions for all exporters.
    Uses a 1-hour cache to minimize GitHub API calls.
    
    Args:
        branch: Branch to check ('main' or 'dev')
        
    Returns:
        Dictionary mapping exporter name to latest version
    """
    # Use the cache directly - it handles GitHub API and fallbacks
    return _get_cached_versions()


def check_for_updates(server_ip: str, ssh_user: str = 'root', ssh_port: int = 22,
                     ssh_key_path: Optional[str] = None, ssh_password: Optional[str] = None,
                     branch: str = 'main') -> Dict[str, Dict[str, Any]]:
    """
    Check if any exporters on a server have updates available.
    
    Returns:
        Dictionary with update info per exporter:
        {
            'node_exporter': {
                'installed': '1.6.0',
                'latest': '1.7.0',
                'update_available': True
            },
            ...
        }
    """
    installed = get_all_exporter_versions(server_ip, ssh_user, ssh_port, ssh_key_path, ssh_password)
    latest = get_all_latest_versions(branch)
    
    result = {}
    for exporter in EXPORTER_REPOS.keys():
        inst_ver = installed.get(exporter)
        lat_ver = latest.get(exporter)
        
        update_available = False
        if inst_ver and lat_ver and inst_ver not in ('running', 'unknown'):
            # Simple version comparison (works for semver)
            try:
                inst_parts = [int(x) for x in inst_ver.split('.')[:3]]
                lat_parts = [int(x) for x in lat_ver.split('.')[:3]]
                update_available = lat_parts > inst_parts
            except ValueError:
                # Non-numeric version parts, do string comparison
                update_available = lat_ver != inst_ver
        
        result[exporter] = {
            'installed': inst_ver,
            'latest': lat_ver,
            'update_available': update_available
        }
    
    return result


def get_exporter_download_url(exporter: str, version: str = None, branch: str = 'main') -> Optional[str]:
    """
    Get the download URL for an exporter binary.
    
    Args:
        exporter: One of 'node_exporter', 'dc_exporter', 'dcgm_exporter'
        version: Specific version (or None for latest)
        branch: Branch ('main' or 'dev')
        
    Returns:
        Download URL or None
    """
    if not version:
        version = get_latest_exporter_version(exporter, branch)
    
    if not version:
        return None
    
    if exporter == 'node_exporter':
        return f"https://github.com/prometheus/node_exporter/releases/download/v{version}/node_exporter-{version}.linux-amd64.tar.gz"
    elif exporter == 'dc_exporter':
        # dc-exporter-rs: always use 'latest' download URL since dc-exporter-releases
        # repo uses tagged releases (v0.2.1, etc.) not branch-specific releases
        # The 'latest' endpoint automatically serves the newest stable release
        return "https://github.com/cryptolabsza/dc-exporter-releases/releases/latest/download/dc-exporter-rs"
    elif exporter == 'dcgm_exporter':
        # Docker image, return image tag
        return f"nvidia/dcgm-exporter:{version}-ubuntu22.04"
    
    return None
