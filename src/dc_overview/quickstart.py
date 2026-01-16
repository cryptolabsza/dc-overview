"""
DC Overview QuickStart - One command setup for everything

The client runs:
    pip install dc-overview
    sudo dc-overview quickstart

And answers a few questions. That's it.
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

import questionary
from questionary import Style
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.prompt import Prompt
import yaml

console = Console()

custom_style = Style([
    ('qmark', 'fg:cyan bold'),
    ('question', 'bold'),
    ('answer', 'fg:cyan'),
    ('pointer', 'fg:cyan bold'),
    ('highlighted', 'fg:cyan bold'),
    ('selected', 'fg:green'),
])


def check_root():
    """Check if running as root."""
    if os.geteuid() != 0:
        console.print("[red]Error:[/red] This command requires root privileges.")
        console.print("Run with: [cyan]sudo dc-overview quickstart[/cyan]")
        sys.exit(1)


def detect_gpus() -> int:
    """Detect number of NVIDIA GPUs."""
    try:
        result = subprocess.run(
            ["nvidia-smi", "-L"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return len([l for l in result.stdout.split('\n') if 'GPU' in l])
    except Exception:
        pass
    return 0


def get_local_ip() -> str:
    """Get the local IP address."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def install_package(package: str) -> bool:
    """Install a system package."""
    try:
        # Try apt first (Debian/Ubuntu)
        result = subprocess.run(
            ["apt-get", "install", "-y", "-qq", package],
            capture_output=True, timeout=120
        )
        return result.returncode == 0
    except Exception:
        return False


def run_quickstart():
    """Main quickstart wizard - does everything."""
    check_root()
    
    console.print()
    console.print(Panel(
        "[bold cyan]DC Overview - Quick Setup[/bold cyan]\n\n"
        "This will set up GPU datacenter monitoring on this machine.\n"
        "Just answer a few questions and everything will be configured.\n\n"
        "[dim]Press Ctrl+C to cancel at any time.[/dim]",
        border_style="cyan"
    ))
    console.print()
    
    # Detect environment
    gpu_count = detect_gpus()
    local_ip = get_local_ip()
    hostname = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
    
    console.print(f"[dim]Detected: {hostname} ({local_ip}) with {gpu_count} GPUs[/dim]\n")
    
    # ============ Step 1: What is this machine? ============
    console.print("[bold]Step 1: What is this machine?[/bold]\n")
    
    if gpu_count > 0:
        default_role = "GPU Worker (has GPUs to monitor)"
    else:
        default_role = "Master Server (monitors other machines)"
    
    role = questionary.select(
        "Select this machine's role:",
        choices=[
            questionary.Choice("GPU Worker (has GPUs to monitor)", value="worker"),
            questionary.Choice("Master Server (monitors other machines)", value="master"),
            questionary.Choice("Both (has GPUs + monitors others)", value="both"),
        ],
        default=default_role,
        style=custom_style
    ).ask()
    
    if not role:
        return
    
    # ============ Step 2: Install exporters (worker/both) ============
    if role in ["worker", "both"]:
        console.print("\n[bold]Step 2: Installing GPU Monitoring[/bold]\n")
        install_exporters()
    
    # ============ Step 3: Set up master (master/both) ============
    if role in ["master", "both"]:
        console.print("\n[bold]Step 3: Setting up Monitoring Dashboard[/bold]\n")
        setup_master()
    
    # ============ Step 4: Add other machines to monitor ============
    if role in ["master", "both"]:
        console.print("\n[bold]Step 4: Add Machines to Monitor[/bold]\n")
        add_machines_wizard()
    
    # ============ Step 5: Vast.ai Integration ============
    console.print("\n[bold]Step 5: Vast.ai Integration (Optional)[/bold]\n")
    console.print("[dim]If you're a Vast.ai provider, this tracks your earnings and reliability.[/dim]")
    
    setup_vast = questionary.confirm(
        "Are you a Vast.ai provider?",
        default=False,
        style=custom_style
    ).ask()
    
    if setup_vast:
        setup_vastai_exporter()
    
    # ============ Done! ============
    show_summary(role, local_ip)


def install_exporters():
    """Install all monitoring exporters as systemd services."""
    exporters = [
        ("node_exporter", "CPU, RAM, disk metrics", 9100),
        ("dcgm-exporter", "NVIDIA GPU metrics", 9400),
        ("dc-exporter", "VRAM temperatures", 9500),
    ]
    
    for name, desc, port in exporters:
        with Progress(SpinnerColumn(), TextColumn(f"Installing {name}..."), console=console) as progress:
            progress.add_task("", total=None)
            
            success = install_single_exporter(name)
            
            if success:
                console.print(f"[green]✓[/green] {name} installed (port {port}) - {desc}")
            else:
                console.print(f"[yellow]⚠[/yellow] {name} - install manually or skip")


def install_single_exporter(name: str) -> bool:
    """Install a single exporter."""
    if name == "node_exporter":
        return install_node_exporter()
    elif name == "dcgm-exporter":
        return install_dcgm_exporter()
    elif name == "dc-exporter":
        return install_dc_exporter()
    return False


def install_node_exporter() -> bool:
    """Install node_exporter."""
    try:
        # Check if already installed
        result = subprocess.run(["systemctl", "is-active", "node_exporter"], capture_output=True)
        if result.returncode == 0:
            return True
        
        # Download and install
        import urllib.request
        import tarfile
        import tempfile
        
        version = "1.7.0"
        url = f"https://github.com/prometheus/node_exporter/releases/download/v{version}/node_exporter-{version}.linux-amd64.tar.gz"
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tarball = Path(tmpdir) / "node_exporter.tar.gz"
            urllib.request.urlretrieve(url, tarball)
            
            with tarfile.open(tarball, "r:gz") as tar:
                tar.extractall(tmpdir)
            
            # Find and install binary
            for item in Path(tmpdir).iterdir():
                if item.is_dir() and "node_exporter" in item.name:
                    binary = item / "node_exporter"
                    if binary.exists():
                        subprocess.run(["cp", str(binary), "/usr/local/bin/"], check=True)
                        subprocess.run(["chmod", "+x", "/usr/local/bin/node_exporter"], check=True)
                        break
        
        # Create user
        subprocess.run(["useradd", "-r", "-s", "/bin/false", "node_exporter"], capture_output=True)
        
        # Create service
        service = """[Unit]
Description=Node Exporter
After=network.target

[Service]
Type=simple
User=node_exporter
ExecStart=/usr/local/bin/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
"""
        Path("/etc/systemd/system/node_exporter.service").write_text(service)
        
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "node_exporter"], check=True)
        subprocess.run(["systemctl", "start", "node_exporter"], check=True)
        
        return True
    except Exception:
        return False


def install_dcgm_exporter() -> bool:
    """Install DCGM exporter."""
    try:
        # Check if nvidia-smi exists
        result = subprocess.run(["nvidia-smi", "-L"], capture_output=True)
        if result.returncode != 0:
            return False  # No GPUs
        
        # Check if already running
        result = subprocess.run(["systemctl", "is-active", "dcgm-exporter"], capture_output=True)
        if result.returncode == 0:
            return True
        
        # Try to install datacenter-gpu-manager
        subprocess.run(["apt-get", "update", "-qq"], capture_output=True, timeout=60)
        result = subprocess.run(
            ["apt-get", "install", "-y", "-qq", "datacenter-gpu-manager"],
            capture_output=True, timeout=120
        )
        
        if result.returncode == 0:
            subprocess.run(["systemctl", "enable", "nvidia-dcgm"], capture_output=True)
            subprocess.run(["systemctl", "start", "nvidia-dcgm"], capture_output=True)
        
        # For now, just note that dcgm-exporter needs manual setup
        # (it's complex to install without Docker)
        return False
        
    except Exception:
        return False


def install_dc_exporter() -> bool:
    """Install dc-exporter for VRAM temps."""
    try:
        # Check if already running
        result = subprocess.run(["systemctl", "is-active", "dc-exporter"], capture_output=True)
        if result.returncode == 0:
            return True
        
        import urllib.request
        
        # Download binaries
        base_url = "https://github.com/cryptolabsza/dc-exporter/releases/latest/download"
        
        urllib.request.urlretrieve(f"{base_url}/dc-exporter-collector", "/usr/local/bin/dc-exporter-collector")
        urllib.request.urlretrieve(f"{base_url}/dc-exporter-server", "/usr/local/bin/dc-exporter-server")
        
        subprocess.run(["chmod", "+x", "/usr/local/bin/dc-exporter-collector"], check=True)
        subprocess.run(["chmod", "+x", "/usr/local/bin/dc-exporter-server"], check=True)
        
        # Create config
        os.makedirs("/etc/dc-exporter", exist_ok=True)
        config = """[agent]
machine_id=auto
interval=5

[gpu]
enabled=1
DCGM_FI_DEV_VRAM_TEMP
DCGM_FI_DEV_HOT_SPOT_TEMP
DCGM_FI_DEV_FAN_SPEED
"""
        Path("/etc/dc-exporter/config.ini").write_text(config)
        
        # Create service
        service = """[Unit]
Description=DC Exporter - GPU VRAM Temperature
After=network.target

[Service]
Type=simple
WorkingDirectory=/etc/dc-exporter
ExecStart=/bin/bash -c "/usr/local/bin/dc-exporter-collector --no-console & /usr/local/bin/dc-exporter-server"
Restart=always

[Install]
WantedBy=multi-user.target
"""
        Path("/etc/systemd/system/dc-exporter.service").write_text(service)
        
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "dc-exporter"], check=True)
        subprocess.run(["systemctl", "start", "dc-exporter"], check=True)
        
        return True
    except Exception:
        return False


def setup_master():
    """Set up master monitoring server (Prometheus + Grafana)."""
    console.print("[dim]Installing Prometheus and Grafana...[/dim]\n")
    
    # Check if Docker is available (easier setup)
    docker_available = subprocess.run(["which", "docker"], capture_output=True).returncode == 0
    
    if docker_available:
        console.print("[dim]Docker detected - using containerized setup (recommended)[/dim]")
        setup_master_docker()
    else:
        console.print("[dim]Docker not found - installing natively[/dim]")
        setup_master_native()


def setup_master_docker():
    """Set up master with Docker (easier)."""
    config_dir = Path("/etc/dc-overview")
    config_dir.mkdir(parents=True, exist_ok=True)
    
    # Ask for Grafana password
    grafana_pass = questionary.password(
        "Set Grafana admin password:",
        validate=lambda x: len(x) >= 4 or "Password too short",
        style=custom_style
    ).ask() or "admin"
    
    # Create docker-compose.yml
    compose = f"""version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.retention.time=30d"

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD={grafana_pass}

volumes:
  prometheus-data:
  grafana-data:
"""
    (config_dir / "docker-compose.yml").write_text(compose)
    
    # Create initial prometheus.yml
    local_ip = get_local_ip()
    prometheus_yml = f"""global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'local'
    static_configs:
      - targets: ['{local_ip}:9100', '{local_ip}:9400', '{local_ip}:9500']
        labels:
          instance: 'master'
"""
    (config_dir / "prometheus.yml").write_text(prometheus_yml)
    
    # Start services
    with Progress(SpinnerColumn(), TextColumn("Starting monitoring services..."), console=console) as progress:
        progress.add_task("", total=None)
        
        result = subprocess.run(
            ["docker", "compose", "up", "-d"],
            cwd=config_dir,
            capture_output=True
        )
    
    if result.returncode == 0:
        console.print("[green]✓[/green] Prometheus running on port 9090")
        console.print("[green]✓[/green] Grafana running on port 3000")
        console.print(f"[dim]  Login: admin / {grafana_pass}[/dim]")
    else:
        console.print(f"[red]Error starting services:[/red] {result.stderr.decode()[:200]}")


def setup_master_native():
    """Set up master natively (no Docker)."""
    console.print("[yellow]Native installation requires manual setup.[/yellow]")
    console.print("Install Docker for automatic setup: [cyan]curl -fsSL https://get.docker.com | sh[/cyan]")
    console.print("Then run: [cyan]sudo dc-overview quickstart[/cyan] again")


def add_machines_wizard():
    """Wizard to add other machines to monitor."""
    console.print("[dim]Add the IP addresses of GPU machines you want to monitor.[/dim]")
    console.print("[dim]You can add more later with: dc-overview add-machine[/dim]\n")
    
    machines = []
    config_dir = Path("/etc/dc-overview")
    
    while True:
        add_more = questionary.confirm(
            "Add a machine to monitor?" if not machines else "Add another machine?",
            default=len(machines) == 0,
            style=custom_style
        ).ask()
        
        if not add_more:
            break
        
        ip = questionary.text(
            "Machine IP address:",
            validate=lambda x: len(x) > 0,
            style=custom_style
        ).ask()
        
        if not ip:
            break
        
        name = questionary.text(
            "Name for this machine:",
            default=f"gpu-{len(machines)+1:02d}",
            style=custom_style
        ).ask()
        
        # Test connection
        console.print(f"[dim]Testing connection to {ip}...[/dim]")
        
        reachable = test_machine_connection(ip)
        
        if reachable:
            console.print(f"[green]✓[/green] {name} ({ip}) - reachable")
            machines.append({"name": name, "ip": ip})
        else:
            console.print(f"[yellow]⚠[/yellow] {name} ({ip}) - not reachable (adding anyway)")
            
            # Ask if they want to set up SSH access
            setup_ssh = questionary.confirm(
                "Set up SSH access to install exporters remotely?",
                default=True,
                style=custom_style
            ).ask()
            
            if setup_ssh:
                setup_remote_machine(ip, name)
            
            machines.append({"name": name, "ip": ip})
    
    # Update prometheus.yml with new machines
    if machines:
        update_prometheus_targets(machines)
        console.print(f"\n[green]✓[/green] Added {len(machines)} machines to monitoring")


def test_machine_connection(ip: str, port: int = 9100) -> bool:
    """Test if a machine's exporter is reachable."""
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def setup_remote_machine(ip: str, name: str):
    """Set up a remote machine via SSH."""
    console.print(f"\n[bold]Setting up {name} ({ip})[/bold]")
    
    ssh_user = questionary.text(
        "SSH username:",
        default="root",
        style=custom_style
    ).ask()
    
    ssh_port = questionary.text(
        "SSH port:",
        default="22",
        style=custom_style
    ).ask()
    
    ssh_pass = questionary.password(
        "SSH password:",
        style=custom_style
    ).ask()
    
    if not ssh_pass:
        console.print("[dim]Skipping remote setup - no password provided[/dim]")
        return
    
    # Install exporters remotely
    with Progress(SpinnerColumn(), TextColumn(f"Installing exporters on {name}..."), console=console) as progress:
        progress.add_task("", total=None)
        
        # Use sshpass to run commands
        install_cmd = "pip3 install dc-overview --break-system-packages && dc-overview install-exporters"
        
        result = subprocess.run(
            f"sshpass -p '{ssh_pass}' ssh -o StrictHostKeyChecking=no -p {ssh_port} {ssh_user}@{ip} '{install_cmd}'",
            shell=True,
            capture_output=True,
            timeout=300
        )
    
    if result.returncode == 0:
        console.print(f"[green]✓[/green] Exporters installed on {name}")
    else:
        console.print(f"[yellow]⚠[/yellow] Could not install automatically. Install manually on {name}:")
        console.print(f"  [cyan]pip install dc-overview && sudo dc-overview install-exporters[/cyan]")


def update_prometheus_targets(machines: List[Dict[str, str]]):
    """Update prometheus.yml with new targets."""
    config_dir = Path("/etc/dc-overview")
    prometheus_file = config_dir / "prometheus.yml"
    
    if not prometheus_file.exists():
        return
    
    # Read existing config
    with open(prometheus_file) as f:
        config = yaml.safe_load(f)
    
    # Add new targets
    for machine in machines:
        job = {
            "job_name": machine["name"],
            "static_configs": [{
                "targets": [
                    f"{machine['ip']}:9100",
                    f"{machine['ip']}:9400",
                    f"{machine['ip']}:9500",
                ],
                "labels": {"instance": machine["name"]}
            }]
        }
        config["scrape_configs"].append(job)
    
    # Save
    with open(prometheus_file, "w") as f:
        yaml.dump(config, f, default_flow_style=False)
    
    # Reload Prometheus
    subprocess.run(["docker", "exec", "prometheus", "kill", "-HUP", "1"], capture_output=True)


def setup_vastai_exporter():
    """Set up Vast.ai exporter."""
    console.print("\n[dim]Get your API key from: https://cloud.vast.ai/account/[/dim]")
    
    api_key = questionary.password(
        "Vast.ai API Key:",
        style=custom_style
    ).ask()
    
    if not api_key:
        console.print("[dim]Skipping Vast.ai setup[/dim]")
        return
    
    # Check if Docker available
    if subprocess.run(["which", "docker"], capture_output=True).returncode != 0:
        console.print("[yellow]Docker required for Vast.ai exporter[/yellow]")
        return
    
    with Progress(SpinnerColumn(), TextColumn("Starting Vast.ai exporter..."), console=console) as progress:
        progress.add_task("", total=None)
        
        # Stop existing
        subprocess.run(["docker", "rm", "-f", "vastai-exporter"], capture_output=True)
        
        # Start new
        result = subprocess.run([
            "docker", "run", "-d",
            "--name", "vastai-exporter",
            "--restart", "unless-stopped",
            "-p", "8622:8622",
            "jjziets/vastai-exporter:latest",
            "-api-key", api_key
        ], capture_output=True)
    
    if result.returncode == 0:
        console.print("[green]✓[/green] Vast.ai exporter running on port 8622")
        
        # Add to Prometheus
        config_dir = Path("/etc/dc-overview")
        prometheus_file = config_dir / "prometheus.yml"
        
        if prometheus_file.exists():
            with open(prometheus_file) as f:
                config = yaml.safe_load(f)
            
            config["scrape_configs"].append({
                "job_name": "vastai",
                "scrape_interval": "60s",
                "static_configs": [{
                    "targets": ["localhost:8622"],
                    "labels": {"instance": "vastai"}
                }]
            })
            
            with open(prometheus_file, "w") as f:
                yaml.dump(config, f, default_flow_style=False)
            
            subprocess.run(["docker", "exec", "prometheus", "kill", "-HUP", "1"], capture_output=True)
    else:
        console.print(f"[red]Error:[/red] {result.stderr.decode()[:100]}")


def show_summary(role: str, local_ip: str):
    """Show setup summary."""
    console.print()
    console.print(Panel(
        "[bold green]✓ Setup Complete![/bold green]",
        border_style="green"
    ))
    
    table = Table(title="Your Monitoring Setup", show_header=False)
    table.add_column("", style="dim")
    table.add_column("")
    
    table.add_row("This Machine", f"{role}")
    table.add_row("IP Address", local_ip)
    
    if role in ["master", "both"]:
        table.add_row("Grafana", f"http://{local_ip}:3000")
        table.add_row("Prometheus", f"http://{local_ip}:9090")
    
    if role in ["worker", "both"]:
        table.add_row("Node Exporter", f"http://{local_ip}:9100/metrics")
        table.add_row("DC Exporter", f"http://{local_ip}:9500/metrics")
    
    console.print(table)
    
    console.print("\n[bold]Next Steps:[/bold]")
    
    if role in ["master", "both"]:
        console.print(f"  1. Open Grafana: [cyan]http://{local_ip}:3000[/cyan]")
        console.print("  2. Import dashboards from Grafana.com (ID: 1860 for node, 12239 for DCGM)")
        console.print("  3. Add more machines: [cyan]dc-overview add-machine[/cyan]")
    
    if role == "worker":
        console.print("  1. On your master server, add this machine:")
        console.print(f"     [cyan]dc-overview add-machine {local_ip}[/cyan]")
    
    console.print()


if __name__ == "__main__":
    run_quickstart()
