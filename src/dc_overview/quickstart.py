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
        default_role = "worker"
    else:
        default_role = "master"
    
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
    
    # ============ Step 6: SSL/Reverse Proxy (master only) ============
    if role in ["master", "both"]:
        console.print("\n[bold]Step 6: HTTPS Access (Recommended)[/bold]\n")
        console.print("[dim]Set up a secure reverse proxy to access Grafana via HTTPS.[/dim]")
        console.print("[dim]This ensures all traffic is encrypted and only port 443 is exposed.[/dim]\n")
        
        setup_ssl = questionary.confirm(
            "Set up HTTPS reverse proxy?",
            default=True,
            style=custom_style
        ).ask()
        
        if setup_ssl:
            setup_reverse_proxy_wizard(local_ip)
    
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
    
    # Save password for later use
    (config_dir / ".grafana_pass").write_text(grafana_pass)
    
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
        
        # Configure Grafana
        configure_grafana(grafana_pass)
    else:
        console.print(f"[red]Error starting services:[/red] {result.stderr.decode()[:200]}")


def configure_grafana(password: str):
    """Configure Grafana with Prometheus datasource and dashboards."""
    import time
    import urllib.request
    import json
    
    console.print("[dim]Configuring Grafana...[/dim]")
    
    # Wait for Grafana to start
    time.sleep(5)
    
    grafana_url = "http://localhost:3000"
    auth = f"admin:{password}"
    auth_bytes = auth.encode('utf-8')
    
    import base64
    auth_header = base64.b64encode(auth_bytes).decode('utf-8')
    
    # Add Prometheus datasource
    try:
        datasource_data = json.dumps({
            "name": "Prometheus",
            "type": "prometheus",
            "url": "http://prometheus:9090",
            "access": "proxy",
            "isDefault": True
        }).encode('utf-8')
        
        req = urllib.request.Request(
            f"{grafana_url}/api/datasources",
            data=datasource_data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {auth_header}"
            },
            method="POST"
        )
        
        urllib.request.urlopen(req, timeout=10)
        console.print("[green]✓[/green] Prometheus datasource added")
    except Exception as e:
        console.print(f"[dim]Datasource may already exist[/dim]")
    
    # Import dashboards from jjziets/DCMontoring GitHub repo
    # These are the official GPU datacenter monitoring dashboards
    dashboards = [
        ("DC Overview", "https://raw.githubusercontent.com/jjziets/DCMontoring/main/DC_OverView.json"),
        ("Node Exporter Full", "https://raw.githubusercontent.com/jjziets/DCMontoring/main/Node%20Exporter%20Full-1684242153326.json"),
        ("NVIDIA DCGM Exporter", "https://raw.githubusercontent.com/jjziets/DCMontoring/main/NVIDIA%20DCGM%20Exporter-1684242180498.json"),
        ("Vast Dashboard", "https://raw.githubusercontent.com/jjziets/DCMontoring/main/Vast%20Dashboard-1692692563948.json"),
    ]
    
    for name, url in dashboards:
        try:
            # Download dashboard JSON
            dashboard_json = urllib.request.urlopen(url, timeout=30).read().decode('utf-8')
            dashboard_obj = json.loads(dashboard_json)
            
            # Use import API with datasource input mapping
            import_data = json.dumps({
                "dashboard": dashboard_obj,
                "overwrite": True,
                "inputs": [{
                    "name": "DS_PROMETHEUS",
                    "type": "datasource",
                    "pluginId": "prometheus",
                    "value": "Prometheus"
                }],
                "folderId": 0
            }).encode('utf-8')
            
            req = urllib.request.Request(
                f"{grafana_url}/api/dashboards/import",
                data=import_data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Basic {auth_header}"
                },
                method="POST"
            )
            
            urllib.request.urlopen(req, timeout=30)
            console.print(f"[green]✓[/green] {name} dashboard imported")
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] {name} dashboard: {str(e)[:50]}")
    
    # Auto-detect optional exporters
    detect_and_configure_optional_exporters(grafana_url, auth_header)


def detect_and_configure_optional_exporters(grafana_url: str, auth_header: str):
    """Detect Vast exporter and IPMI Monitor and configure them if present."""
    import urllib.request
    import json
    
    config_path = Path("/etc/dc-overview/prometheus.yml")
    if not config_path.exists():
        return
    
    prometheus_config = config_path.read_text()
    config_updated = False
    
    # Check for Vast.ai exporter (typically on port 8622)
    vastai_exporter_running = test_machine_connection("localhost", 8622)
    if vastai_exporter_running and "vastai" not in prometheus_config:
        console.print("[green]✓[/green] Vast.ai exporter detected - adding to monitoring")
        # Add to prometheus config
        vastai_config = """
  # Vast.ai Earnings Exporter (auto-detected)
  - job_name: 'vastai'
    static_configs:
      - targets: ['localhost:8622']
"""
        prometheus_config = prometheus_config.rstrip() + vastai_config
        config_path.write_text(prometheus_config)
        config_updated = True
    
    # Check for IPMI Monitor exporter (typically on port 5000 or 9150)
    ipmi_ports = [5000, 9150]
    ipmi_running = any(test_machine_connection("localhost", p) for p in ipmi_ports)
    if ipmi_running and "ipmi" not in prometheus_config.lower():
        console.print("[green]✓[/green] IPMI Monitor detected - adding to monitoring")
        # Find which port
        ipmi_port = next((p for p in ipmi_ports if test_machine_connection("localhost", p)), 5000)
        ipmi_config = f"""
  # IPMI Monitor (auto-detected)
  - job_name: 'ipmi-monitor'
    static_configs:
      - targets: ['localhost:{ipmi_port}']
    metrics_path: '/metrics'
"""
        prometheus_config = prometheus_config.rstrip() + ipmi_config
        config_path.write_text(prometheus_config)
        config_updated = True
        
        # Try to import IPMI Monitor dashboard if available
        try:
            ipmi_dashboard_url = "https://raw.githubusercontent.com/cryptolabsza/ipmi-monitor/main/grafana/dashboards/ipmi-monitor.json"
            dashboard_json = urllib.request.urlopen(ipmi_dashboard_url, timeout=10).read().decode('utf-8')
            import_data = json.dumps({
                "dashboard": json.loads(dashboard_json),
                "overwrite": True,
                "inputs": [{"name": "DS_PROMETHEUS", "type": "datasource", "pluginId": "prometheus", "value": "Prometheus"}],
                "folderId": 0
            }).encode('utf-8')
            req = urllib.request.Request(
                f"{grafana_url}/api/dashboards/import",
                data=import_data,
                headers={"Content-Type": "application/json", "Authorization": f"Basic {auth_header}"},
                method="POST"
            )
            urllib.request.urlopen(req, timeout=30)
            console.print("[green]✓[/green] IPMI Monitor dashboard imported")
        except Exception:
            console.print("[dim]IPMI Monitor dashboard: import manually if needed[/dim]")
    
    # Reload Prometheus if config changed
    if config_updated:
        try:
            subprocess.run(["docker", "exec", "prometheus", "kill", "-HUP", "1"], capture_output=True)
            console.print("[dim]Prometheus config reloaded[/dim]")
        except Exception:
            pass


def setup_master_native():
    """Set up master natively (no Docker)."""
    console.print("[yellow]Native installation requires manual setup.[/yellow]")
    console.print("Install Docker for automatic setup: [cyan]curl -fsSL https://get.docker.com | sh[/cyan]")
    console.print("Then run: [cyan]sudo dc-overview quickstart[/cyan] again")


def add_machines_wizard():
    """Wizard to add other machines to monitor."""
    console.print(Panel(
        "[bold]Adding GPU Workers[/bold]\n\n"
        "Choose how to add workers:\n"
        "  • [cyan]Import file[/cyan] - Paste or load a simple text file\n"
        "  • [cyan]Enter manually[/cyan] - Type IPs one by one",
        border_style="cyan"
    ))
    console.print()
    
    method = questionary.select(
        "How do you want to add workers?",
        choices=[
            questionary.Choice("Import from file/paste (recommended for many servers)", value="import"),
            questionary.Choice("Enter IPs manually", value="manual"),
        ],
        style=custom_style
    ).ask()
    
    if method == "import":
        machines = import_servers_from_text()
    else:
        machines = add_machines_manual()
    
    if not machines:
        console.print("[yellow]No workers added.[/yellow]")
        return
    
    # Update prometheus.yml with new machines
    update_prometheus_targets(machines)
    console.print(f"\n[green]✓[/green] Added {len(machines)} workers to Prometheus")


def import_servers_from_text() -> List[Dict]:
    """Import servers from a simple text format."""
    console.print(Panel(
        "[bold]Import Format[/bold]\n\n"
        "[cyan]Option 1: Global credentials + IPs[/cyan]\n"
        "  global:root,mypassword\n"
        "  192.168.1.101\n"
        "  192.168.1.102\n"
        "  192.168.1.103\n\n"
        "[cyan]Option 2: Per-server credentials[/cyan]\n"
        "  192.168.1.101,root,pass1\n"
        "  192.168.1.102,root,pass2\n"
        "  192.168.1.103,ubuntu,pass3\n\n"
        "[dim]Paste your list below, then press Enter twice.[/dim]",
        border_style="cyan"
    ))
    
    console.print("\n[bold]Paste your server list:[/bold]")
    
    lines = []
    while True:
        line = questionary.text("", style=custom_style).ask()
        if not line or line.strip() == "":
            break
        lines.append(line.strip())
    
    if not lines:
        return []
    
    return parse_server_list(lines)


def parse_server_list(lines: List[str]) -> List[Dict]:
    """Parse server list in various formats."""
    machines = []
    global_user = None
    global_pass = None
    global_key = None
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        # Check for global credentials
        if line.lower().startswith("global:"):
            parts = line[7:].split(",")
            if len(parts) >= 2:
                global_user = parts[0].strip()
                global_pass = parts[1].strip()
            elif len(parts) == 1 and parts[0].startswith("/"):
                global_user = "root"
                global_key = parts[0].strip()
            continue
        
        # Parse server line
        parts = [p.strip() for p in line.split(",")]
        
        if len(parts) == 1:
            # Just IP - use global credentials
            ip = parts[0]
            user = global_user or "root"
            password = global_pass
            key_path = global_key
        elif len(parts) == 2:
            # IP, user - use global password
            ip, user = parts[0], parts[1]
            password = global_pass
            key_path = global_key
        elif len(parts) >= 3:
            # IP, user, password
            ip, user, password = parts[0], parts[1], parts[2]
            key_path = None
        else:
            continue
        
        # Validate IP format (basic check)
        if not ip or not any(c.isdigit() for c in ip):
            continue
        
        name = f"gpu-{len(machines)+1:02d}"
        
        # Test if exporters already running
        if test_machine_connection(ip):
            console.print(f"[green]✓[/green] {name} ({ip}) - exporters already running")
            machines.append({"name": name, "ip": ip})
            continue
        
        # Try to install exporters remotely
        console.print(f"[dim]Installing on {ip}...[/dim]", end=" ")
        
        success = install_exporters_remote(
            ip=ip,
            user=user,
            password=password,
            key_path=key_path,
            port=22
        )
        
        if success:
            console.print(f"[green]✓[/green]")
        else:
            console.print(f"[yellow]⚠ manual install needed[/yellow]")
        
        machines.append({"name": name, "ip": ip})
    
    return machines


def add_machines_manual() -> List[Dict]:
    """Add machines by entering IPs manually with shared credentials."""
    console.print("\n[bold]SSH Credentials[/bold] (used for all workers)\n")
    
    ssh_user = questionary.text(
        "SSH username:",
        default="root",
        style=custom_style
    ).ask()
    
    auth_method = questionary.select(
        "Authentication method:",
        choices=[
            questionary.Choice("Password", value="password"),
            questionary.Choice("SSH Key", value="key"),
        ],
        style=custom_style
    ).ask()
    
    ssh_password = None
    ssh_key = None
    
    if auth_method == "password":
        ssh_password = questionary.password(
            "SSH password:",
            style=custom_style
        ).ask()
    else:
        ssh_key = questionary.text(
            "SSH key path:",
            default="~/.ssh/id_rsa",
            style=custom_style
        ).ask()
        ssh_key = os.path.expanduser(ssh_key)
    
    ssh_port = questionary.text(
        "SSH port:",
        default="22",
        style=custom_style
    ).ask()
    
    # Get list of worker IPs
    console.print("\n[bold]Worker IP Addresses[/bold]")
    console.print("[dim]Enter one IP per line, or comma-separated. Blank line to finish.[/dim]\n")
    
    ips = []
    
    while True:
        ip = questionary.text(
            f"  Worker {len(ips)+1}:",
            style=custom_style
        ).ask()
        
        if not ip or ip.strip() == "":
            break
        
        # Handle comma-separated input
        for single_ip in ip.replace(",", " ").split():
            single_ip = single_ip.strip()
            if single_ip:
                ips.append(single_ip)
    
    if not ips:
        return []
    
    console.print(f"\n[dim]Adding {len(ips)} workers...[/dim]\n")
    
    machines = []
    
    for i, ip in enumerate(ips):
        name = f"gpu-{i+1:02d}"
        
        # Test if exporters already running
        if test_machine_connection(ip):
            console.print(f"[green]✓[/green] {name} ({ip}) - exporters already running")
            machines.append({"name": name, "ip": ip})
            continue
        
        # Try to install exporters remotely
        console.print(f"[dim]Installing on {ip}...[/dim]", end=" ")
        
        success = install_exporters_remote(
            ip=ip,
            user=ssh_user,
            password=ssh_password,
            key_path=ssh_key,
            port=int(ssh_port)
        )
        
        if success:
            console.print(f"[green]✓[/green]")
        else:
            console.print(f"[yellow]⚠ manual install needed[/yellow]")
        
        machines.append({"name": name, "ip": ip})
    
    return machines


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


def install_exporters_remote(ip: str, user: str, password: str = None, key_path: str = None, port: int = 22) -> bool:
    """Install exporters on a remote machine via SSH."""
    try:
        import paramiko
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect
        if password:
            client.connect(ip, port=port, username=user, password=password, timeout=10)
        else:
            key = paramiko.RSAKey.from_private_key_file(key_path)
            client.connect(ip, port=port, username=user, pkey=key, timeout=10)
        
        # Install pip if needed, then dc-overview
        commands = [
            "which pip3 || apt-get update -qq && apt-get install -y -qq python3-pip",
            "pip3 install dc-overview --break-system-packages -q 2>/dev/null || pip3 install dc-overview -q",
            "dc-overview install-exporters",
        ]
        
        for cmd in commands:
            stdin, stdout, stderr = client.exec_command(cmd, timeout=120)
            exit_code = stdout.channel.recv_exit_status()
            if exit_code != 0 and "install-exporters" in cmd:
                # Failed on the important command
                client.close()
                return False
        
        client.close()
        return True
        
    except Exception as e:
        return False


def setup_remote_machine(ip: str, name: str):
    """Set up a remote machine via SSH (legacy function)."""
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
    
    success = install_exporters_remote(ip, ssh_user, password=ssh_pass, port=int(ssh_port))
    
    if success:
        console.print(f"[green]✓[/green] Exporters installed on {name}")
    else:
        console.print(f"[yellow]⚠[/yellow] Could not install automatically. Install manually on {name}:")
        console.print(f"  [cyan]pip install dc-overview && sudo dc-overview quickstart[/cyan]")


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


def setup_reverse_proxy_wizard(local_ip: str):
    """Interactive setup for SSL reverse proxy."""
    from .reverse_proxy import setup_reverse_proxy
    
    console.print()
    
    # Ask about domain
    has_domain = questionary.confirm(
        "Do you have a domain name pointing to this server?",
        default=False,
        style=custom_style
    ).ask()
    
    domain = None
    email = None
    use_letsencrypt = False
    
    if has_domain:
        domain = questionary.text(
            "Enter your domain name:",
            validate=lambda x: len(x) > 3 and '.' in x,
            style=custom_style
        ).ask()
        
        if domain:
            console.print("\n[bold yellow]⚠️  Let's Encrypt Requirements:[/bold yellow]")
            console.print("   • Port [cyan]80[/cyan] must be open (for certificate verification)")
            console.print("   • Port [cyan]443[/cyan] must be open (for HTTPS)")
            console.print("   • DNS must point to this server's IP")
            console.print("   • Both ports must stay open for [bold]auto-renewal[/bold] (every 90 days)\n")
            
            use_letsencrypt = questionary.confirm(
                "Use Let's Encrypt? (requires ports 80 + 443 open)",
                default=False,  # Default to No since it has requirements
                style=custom_style
            ).ask()
            
            if use_letsencrypt:
                email = questionary.text(
                    "Email for certificate expiry notifications:",
                    validate=lambda x: '@' in x,
                    style=custom_style
                ).ask()
            else:
                console.print("\n[dim]Using self-signed certificate instead.[/dim]")
                console.print("[dim]You can switch to Let's Encrypt later with: dc-overview setup-ssl --letsencrypt[/dim]\n")
    
    if not domain:
        console.print("\n[dim]Using self-signed certificate for IP-only access.[/dim]")
        console.print("[dim]Browser will show a security warning - this is normal for internal networks.[/dim]\n")
    
    # Ask about site name
    site_name = questionary.text(
        "Site name for landing page:",
        default="GPU Monitoring",
        style=custom_style
    ).ask() or "GPU Monitoring"
    
    # Check if IPMI Monitor is installed
    ipmi_installed = Path("/usr/local/bin/ipmi-monitor").exists() or \
                     subprocess.run(["which", "ipmi-monitor"], capture_output=True).returncode == 0
    
    ipmi_enabled = False
    if ipmi_installed:
        ipmi_enabled = questionary.confirm(
            "Include IPMI Monitor in reverse proxy?",
            default=True,
            style=custom_style
        ).ask()
    
    # Run setup
    console.print()
    with Progress(SpinnerColumn(), TextColumn("Setting up HTTPS..."), console=console) as progress:
        progress.add_task("", total=None)
        
        try:
            setup_reverse_proxy(
                domain=domain,
                email=email,
                site_name=site_name,
                ipmi_enabled=ipmi_enabled,
                prometheus_enabled=False,  # Disabled by default (no auth)
                use_letsencrypt=use_letsencrypt,
            )
        except Exception as e:
            console.print(f"[red]Error setting up SSL:[/red] {e}")
            return
    
    console.print("[green]✓[/green] HTTPS reverse proxy configured!")
    
    if domain:
        console.print(f"  Access: [cyan]https://{domain}/[/cyan]")
    else:
        console.print(f"  Access: [cyan]https://{local_ip}/[/cyan]")
    
    console.print("  [dim]Accept the certificate warning if using self-signed[/dim]")


def show_summary(role: str, local_ip: str):
    """Show setup summary."""
    console.print()
    console.print(Panel(
        "[bold green]✓ Setup Complete![/bold green]",
        border_style="green"
    ))
    
    # Check if SSL is configured
    ssl_configured = Path("/etc/nginx/sites-enabled/dc-overview").exists()
    
    table = Table(title="Your Monitoring Setup", show_header=False)
    table.add_column("", style="dim")
    table.add_column("")
    
    table.add_row("This Machine", f"{role}")
    table.add_row("IP Address", local_ip)
    
    if role in ["master", "both"]:
        if ssl_configured:
            table.add_row("Dashboard", f"https://{local_ip}/ (HTTPS)")
            table.add_row("Grafana", f"https://{local_ip}/grafana/")
        else:
            table.add_row("Grafana", f"http://{local_ip}:3000")
            table.add_row("Prometheus", f"http://{local_ip}:9090")
    
    if role in ["worker", "both"]:
        table.add_row("Node Exporter", f"http://{local_ip}:9100/metrics")
        table.add_row("DC Exporter", f"http://{local_ip}:9500/metrics")
    
    console.print(table)
    
    console.print("\n[bold]Next Steps:[/bold]")
    
    if role in ["master", "both"]:
        if ssl_configured:
            console.print(f"  1. Open Dashboard: [cyan]https://{local_ip}/[/cyan]")
            console.print("     (Accept the certificate warning if using self-signed)")
        else:
            console.print(f"  1. Open Grafana: [cyan]http://{local_ip}:3000[/cyan]")
        console.print("  2. Add more workers: [cyan]dc-overview add-machine[/cyan]")
        if not ssl_configured:
            console.print("  3. Set up HTTPS: [cyan]sudo dc-overview setup-ssl[/cyan]")
        console.print("\n[dim]Dashboards auto-imported: DC Overview, Node Exporter, DCGM, Vast[/dim]")
    
    if role == "worker":
        console.print("  1. On your master server, add this machine:")
        console.print(f"     [cyan]dc-overview add-machine {local_ip}[/cyan]")
    
    console.print()


if __name__ == "__main__":
    run_quickstart()
