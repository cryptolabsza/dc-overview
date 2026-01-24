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
import json
import secrets
import shutil
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
        ("dc-exporter", "GPU metrics (VRAM, hotspot, power, util)", 9835),
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
    """Install dc-exporter for VRAM/hotspot temps and GPU metrics."""
    try:
        # Check if already running on correct port
        result = subprocess.run(["systemctl", "is-active", "dc-exporter"], capture_output=True)
        if result.returncode == 0:
            # Verify it's serving on port 9835
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex(('127.0.0.1', 9835)) == 0:
                    sock.close()
                    return True
                sock.close()
            except Exception:
                pass
        
        import urllib.request
        
        # Create installation directory
        os.makedirs("/opt/dc-exporter", exist_ok=True)
        
        # Download the collector binary
        base_url = "https://github.com/cryptolabsza/dc-exporter/releases/latest/download"
        urllib.request.urlretrieve(f"{base_url}/dc-exporter-collector", "/opt/dc-exporter/dc-exporter-c")
        subprocess.run(["chmod", "+x", "/opt/dc-exporter/dc-exporter-c"], check=True)
        
        # Create the run script (Python HTTP server on port 9835)
        run_script = '''#!/bin/bash
cd /opt/dc-exporter

# Kill any existing process on port 9835
fuser -k 9835/tcp 2>/dev/null || true
sleep 1

# Run the exporter in a loop to update metrics
(
    while true; do
        ./dc-exporter-c >/dev/null 2>&1 || true
        sleep 10
    done
) &

# Serve the metrics file via HTTP with SO_REUSEADDR
exec python3 -c "
import http.server
import socketserver
import socket

class ReuseAddrTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class MetricsHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == \\"/metrics\\" or self.path == \\"/\\":
            self.send_response(200)
            self.send_header(\\"Content-type\\", \\"text/plain\\")
            self.end_headers()
            try:
                with open(\\"metrics.txt\\", \\"r\\") as f:
                    self.wfile.write(f.read().encode())
            except FileNotFoundError:
                self.wfile.write(b\\"# No metrics yet\\\\n\\")
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        pass

PORT = 9835
with ReuseAddrTCPServer((\\"\\"\\", PORT), MetricsHandler) as httpd:
    print(f\\"DC Exporter serving on port {PORT}\\")
    httpd.serve_forever()
"
'''
        Path("/opt/dc-exporter/run.sh").write_text(run_script)
        subprocess.run(["chmod", "+x", "/opt/dc-exporter/run.sh"], check=True)
        
        # Create service
        service = """[Unit]
Description=DC Exporter - VRAM/Hotspot Temperature Metrics
After=network.target

[Service]
Type=simple
ExecStart=/opt/dc-exporter/run.sh
Restart=always
RestartSec=5
WorkingDirectory=/opt/dc-exporter

[Install]
WantedBy=multi-user.target
"""
        Path("/etc/systemd/system/dc-exporter.service").write_text(service)
        
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "dc-exporter"], check=True)
        subprocess.run(["systemctl", "restart", "dc-exporter"], check=True)
        
        return True
    except Exception:
        return False


def setup_master():
    """Set up master monitoring server (Prometheus + Grafana) via Docker."""
    console.print("[dim]Setting up monitoring stack via Docker...[/dim]\n")
    
    # Check Docker
    if not check_docker_installed():
        console.print("[yellow]Docker is not installed.[/yellow]")
        install = questionary.confirm(
            "Install Docker now?",
            default=True,
            style=custom_style
        ).ask()
        
        if install:
            if not install_docker():
                console.print("[red]Cannot continue without Docker.[/red]")
                return
        else:
            console.print("[red]Cannot continue without Docker.[/red]")
            console.print("[dim]Install Docker manually: https://docs.docker.com/engine/install/[/dim]")
            return
    else:
        console.print("[green]✓[/green] Docker is installed")
    
    setup_master_docker()


def check_docker_installed() -> bool:
    """Check if Docker is installed and running."""
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        if result.returncode != 0:
            return False
        result = subprocess.run(["docker", "info"], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def install_docker() -> bool:
    """Install Docker using the official convenience script."""
    console.print("\n[bold]Installing Docker...[/bold]\n")
    try:
        with Progress(SpinnerColumn(), TextColumn("Downloading Docker installer..."), console=console) as progress:
            progress.add_task("", total=None)
            subprocess.run(
                ["curl", "-fsSL", "https://get.docker.com", "-o", "/tmp/get-docker.sh"],
                check=True, capture_output=True
            )
        with Progress(SpinnerColumn(), TextColumn("Installing Docker (this may take a few minutes)..."), console=console) as progress:
            progress.add_task("", total=None)
            subprocess.run(["sh", "/tmp/get-docker.sh"], check=True, capture_output=True)
        subprocess.run(["systemctl", "start", "docker"], capture_output=True)
        subprocess.run(["systemctl", "enable", "docker"], capture_output=True)
        console.print("[green]✓[/green] Docker installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[red]✗[/red] Docker installation failed: {e}")
        return False


def detect_ipmi_monitor() -> Optional[Dict]:
    """Detect if ipmi-monitor is installed."""
    ipmi_config_dir = Path("/etc/ipmi-monitor")
    
    if not ipmi_config_dir.exists():
        return None
    
    # Check for running container
    result = subprocess.run(
        ["docker", "inspect", "ipmi-monitor"],
        capture_output=True
    )
    
    if result.returncode != 0:
        return None
    
    return {
        "config_dir": ipmi_config_dir,
        "db_path": ipmi_config_dir / "data" / "ipmi_monitor.db",
        "ssh_keys_dir": ipmi_config_dir / "ssh_keys"
    }


def import_ipmi_config(ipmi_config: Dict) -> Dict:
    """Import SSH keys, servers, and credentials from IPMI Monitor.
    
    Returns:
        Dict with: ssh_keys, servers, default_ssh_user, default_ssh_key_path
    """
    import sqlite3
    
    result = {
        "ssh_keys": [],
        "servers": [],
        "default_ssh_user": "root",
        "default_ssh_key_path": None,
        "default_ssh_key_id": None,
    }
    
    db_path = ipmi_config.get("db_path")
    
    if db_path and db_path.exists():
        try:
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get default SSH settings from system_settings
            cursor.execute("SELECT key, value FROM system_settings WHERE key IN ('ssh_user', 'default_ssh_key_id')")
            for row in cursor.fetchall():
                if row['key'] == 'ssh_user' and row['value']:
                    result["default_ssh_user"] = row['value']
                elif row['key'] == 'default_ssh_key_id' and row['value']:
                    result["default_ssh_key_id"] = int(row['value'])
            
            # Import SSH keys
            cursor.execute("SELECT id, name, key_path FROM ssh_key")
            for row in cursor.fetchall():
                key_info = {
                    "id": row['id'],
                    "name": row['name'],
                    "path": row['key_path']
                }
                result["ssh_keys"].append(key_info)
                
                # If this is the default key, store the path
                if result["default_ssh_key_id"] and row['id'] == result["default_ssh_key_id"]:
                    result["default_ssh_key_path"] = row['key_path']
            
            # Import servers with their SSH config
            cursor.execute("""
                SELECT s.id, s.name, s.bmc_ip, s.server_ip, 
                       COALESCE(sc.ssh_user, ?) as ssh_user,
                       COALESCE(s.ssh_port, 22) as ssh_port,
                       sc.ssh_key_id,
                       sc.ssh_pass
                FROM server s
                LEFT JOIN server_config sc ON s.bmc_ip = sc.bmc_ip
            """, (result["default_ssh_user"],))
            
            for row in cursor.fetchall():
                server = {
                    "name": row['name'],
                    "bmc_ip": row['bmc_ip'],
                    "server_ip": row['server_ip'],
                    "ssh_user": row['ssh_user'] or result["default_ssh_user"],
                    "ssh_port": row['ssh_port'] or 22,
                }
                
                # Get SSH key path if key_id is set
                ssh_key_id = row['ssh_key_id'] or result["default_ssh_key_id"]
                if ssh_key_id:
                    for key in result["ssh_keys"]:
                        if key["id"] == ssh_key_id:
                            server["ssh_key_path"] = key["path"]
                            break
                
                # Store password if available (less preferred than key)
                if row['ssh_pass']:
                    server["ssh_password"] = row['ssh_pass']
                
                result["servers"].append(server)
            
            conn.close()
            console.print(f"[green]✓[/green] Imported {len(result['servers'])} servers from IPMI Monitor")
            console.print(f"[green]✓[/green] Imported {len(result['ssh_keys'])} SSH keys")
            if result["default_ssh_key_path"]:
                console.print(f"[green]✓[/green] Default SSH key: {result['default_ssh_key_path']}")
                
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Could not import from IPMI Monitor: {e}")
    
    # Copy SSH keys to DC Overview directory
    ssh_keys_dir = ipmi_config.get("ssh_keys_dir")
    if ssh_keys_dir and ssh_keys_dir.exists():
        dc_ssh_dir = Path("/etc/dc-overview/ssh_keys")
        dc_ssh_dir.mkdir(parents=True, exist_ok=True)
        
        for key_file in ssh_keys_dir.iterdir():
            if key_file.is_file():
                dest = dc_ssh_dir / key_file.name
                shutil.copy2(key_file, dest)
                os.chmod(dest, 0o600)
                
                # Update key paths to point to copied location
                for key in result["ssh_keys"]:
                    if key["path"] and Path(key["path"]).name == key_file.name:
                        key["copied_path"] = str(dest)
        
        console.print(f"[green]✓[/green] SSH keys copied to /etc/dc-overview/ssh_keys/")
        
        # Update default key path if it was copied
        if result["default_ssh_key_path"]:
            default_key_name = Path(result["default_ssh_key_path"]).name
            copied_path = dc_ssh_dir / default_key_name
            if copied_path.exists():
                result["default_ssh_key_path"] = str(copied_path)
    
    return result


def detect_existing_proxy() -> Optional[Dict]:
    """Detect if cryptolabs-proxy is already running."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "cryptolabs-proxy", "--format", "{{.State.Status}}"],
            capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout.strip() == "running":
            # Get existing proxy config
            config = {"running": True}
            
            # Try to get domain from nginx config
            nginx_conf = Path("/etc/ipmi-monitor/nginx.conf")
            if nginx_conf.exists():
                content = nginx_conf.read_text()
                import re
                match = re.search(r'server_name\s+([^;]+);', content)
                if match:
                    config["domain"] = match.group(1).strip()
            
            # Check if SSL certs exist
            ssl_dir = Path("/etc/ipmi-monitor/ssl")
            if ssl_dir.exists():
                config["ssl_dir"] = ssl_dir
            
            return config
    except Exception:
        pass
    return None


def update_existing_nginx_config(nginx_path: Path, dc_port: int = 5001):
    """Update existing nginx.conf to add /dc/ route for dc-overview."""
    import re
    
    content = nginx_path.read_text()
    
    # Check if /dc/ route already exists
    if '/dc/' in content or 'dc-overview' in content:
        console.print("[dim]  /dc/ route already exists in nginx config[/dim]")
        return
    
    # DC Overview location block to add
    dc_location = f'''
        # DC Overview - GPU Datacenter Monitoring
        location /dc/ {{
            proxy_pass http://dc-overview:{dc_port}/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }}
'''
    
    # Find a good place to insert - after /ipmi/ or /grafana/ location
    # Look for the last location block before the closing brace of the server block
    
    # Try to insert after /ipmi/ location
    ipmi_pattern = r'(location\s+/ipmi/\s*\{[^}]+\})'
    match = re.search(ipmi_pattern, content, re.DOTALL)
    
    if match:
        # Insert after /ipmi/ block
        insert_pos = match.end()
        new_content = content[:insert_pos] + dc_location + content[insert_pos:]
    else:
        # Try to insert before the last closing brace of the server block
        # Find "location / {" and insert before it
        root_pattern = r'(\s+location\s+/\s*\{)'
        match = re.search(root_pattern, content)
        if match:
            insert_pos = match.start()
            new_content = content[:insert_pos] + dc_location + content[insert_pos:]
        else:
            console.print("[yellow]⚠[/yellow] Could not find insertion point in nginx.conf")
            console.print("[dim]  Please add /dc/ location manually[/dim]")
            return
    
    # Write updated config
    nginx_path.write_text(new_content)
    
    # Reload nginx in the proxy container
    try:
        subprocess.run(
            ["docker", "exec", "cryptolabs-proxy", "nginx", "-s", "reload"],
            capture_output=True, check=True
        )
        console.print("[dim]  Nginx configuration reloaded[/dim]")
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Could not reload nginx: {e}")
        console.print("[dim]  Run: docker exec cryptolabs-proxy nginx -s reload[/dim]")


def setup_master_docker():
    """Set up master with Docker using cryptolabs-proxy."""
    from jinja2 import Environment, PackageLoader, select_autoescape
    import secrets
    import shutil
    
    config_dir = Path("/etc/dc-overview")
    config_dir.mkdir(parents=True, exist_ok=True)
    
    # ===========================================================================
    # DETECT EXISTING SETUP
    # ===========================================================================
    ipmi_config = detect_ipmi_monitor()
    existing_proxy = detect_existing_proxy()
    imported_data = None
    imported_servers = []
    imported_ssh_keys = []
    default_ssh_key_path = None
    default_ssh_user = "root"
    ipmi_enabled = False
    
    # If IPMI Monitor exists, auto-import its data
    if ipmi_config:
        console.print("\n[bold green]✓ IPMI Monitor Detected![/bold green]")
        console.print("[dim]Automatically importing servers and SSH credentials.[/dim]\n")
        
        imported_data = import_ipmi_config(ipmi_config)
        imported_servers = imported_data.get("servers", [])
        imported_ssh_keys = imported_data.get("ssh_keys", [])
        default_ssh_key_path = imported_data.get("default_ssh_key_path")
        default_ssh_user = imported_data.get("default_ssh_user", "root")
        ipmi_enabled = True
        
        if imported_servers:
            console.print(f"\n[cyan]Servers imported for GPU monitoring:[/cyan]")
            for srv in imported_servers[:10]:  # Show first 10
                ip = srv.get('server_ip') or srv.get('bmc_ip')
                has_ssh = "✓ SSH" if srv.get('ssh_key_path') or srv.get('ssh_password') else ""
                console.print(f"  • {srv['name']} ({ip}) {has_ssh}")
            if len(imported_servers) > 10:
                console.print(f"  ... and {len(imported_servers) - 10} more")
            console.print()
    
    # If proxy already running, skip proxy setup
    if existing_proxy and existing_proxy.get("running"):
        console.print("\n[bold green]✓ CryptoLabs Proxy Already Running![/bold green]")
        console.print("[dim]Will add DC Overview to existing proxy setup.[/dim]\n")
        setup_proxy = True  # Use existing proxy
        domain = existing_proxy.get("domain")
        use_letsencrypt = False  # Already configured
        external_port = 443
        skip_proxy_questions = True
    else:
        skip_proxy_questions = False
    
    # ===========================================================================
    # CONFIGURATION QUESTIONS
    # ===========================================================================
    
    # Ask for DC Overview port
    console.print("\n[bold]Port Configuration[/bold]")
    console.print("[dim]DC Overview default port is 5001. Change if needed.[/dim]\n")
    
    dc_port = questionary.text(
        "DC Overview port:",
        default="5001",
        validate=lambda x: x.isdigit() and 1 <= int(x) <= 65535,
        style=custom_style
    ).ask() or "5001"
    dc_port = int(dc_port)
    
    # Ask for Grafana password
    grafana_pass = questionary.password(
        "Set Grafana admin password:",
        validate=lambda x: len(x) >= 4 or "Password too short",
        style=custom_style
    ).ask() or "admin"
    
    # Reverse proxy questions (only if not already set up)
    if not skip_proxy_questions:
        console.print("\n[bold]HTTPS Reverse Proxy[/bold]")
        console.print("[dim]Set up cryptolabs-proxy for secure access via HTTPS.[/dim]\n")
        
        setup_proxy = questionary.confirm(
            "Set up HTTPS reverse proxy? (recommended)",
            default=True,
            style=custom_style
        ).ask()
        
        domain = None
        use_letsencrypt = False
        external_port = 443
        
        if setup_proxy:
            has_domain = questionary.confirm(
                "Do you have a domain name pointing to this server?",
                default=False,
                style=custom_style
            ).ask()
            
            if has_domain:
                domain = questionary.text(
                    "Domain name:",
                    validate=lambda x: '.' in x and len(x) > 3,
                    style=custom_style
                ).ask()
                
                use_letsencrypt = questionary.confirm(
                    "Use Let's Encrypt for trusted certificate?",
                    default=False,
                    style=custom_style
                ).ask()
            
            different_port = questionary.confirm(
                "Is the external HTTPS port different from 443?",
                default=False,
                style=custom_style
            ).ask()
            
            if different_port:
                external_port = int(questionary.text(
                    "External HTTPS port:",
                    default="8443",
                    validate=lambda x: x.isdigit(),
                    style=custom_style
                ).ask() or "443")
    
    # Ask about watchtower (skip if already running)
    watchtower_running = False
    try:
        result = subprocess.run(
            ["docker", "inspect", "watchtower", "--format", "{{.State.Status}}"],
            capture_output=True, text=True
        )
        watchtower_running = result.returncode == 0 and result.stdout.strip() == "running"
    except Exception:
        pass
    
    if watchtower_running:
        console.print("[green]✓[/green] Watchtower already running")
        enable_watchtower = False  # Don't create another
    else:
        enable_watchtower = questionary.confirm(
            "Enable automatic updates (Watchtower)?",
            default=True,
            style=custom_style
        ).ask()
    
    # Generate secret key
    secret_key = secrets.token_hex(32)
    
    # Save .env file
    env_content = f"""# DC Overview Environment Configuration
SECRET_KEY={secret_key}
GRAFANA_PASSWORD={grafana_pass}
"""
    (config_dir / ".env").write_text(env_content)
    os.chmod(config_dir / ".env", 0o600)
    
    # Generate docker-compose.yml using template
    try:
        env = Environment(
            loader=PackageLoader("dc_overview", "templates"),
            autoescape=select_autoescape()
        )
        
        # docker-compose.yml
        # Don't start a new proxy if one already exists - just use the network
        start_new_proxy = setup_proxy and not skip_proxy_questions
        
        compose_template = env.get_template("docker-compose.yml.j2")
        compose_content = compose_template.render(
            image_tag="dev",  # Use dev tag for now
            proxy_tag="latest",
            dc_port=dc_port,
            enable_proxy=start_new_proxy,
            enable_watchtower=enable_watchtower,
            use_letsencrypt=use_letsencrypt,
            external_port=external_port,
            ipmi_enabled=ipmi_enabled,
            vast_enabled=False,
            ssh_keys_dir=True if (config_dir / "ssh_keys").exists() else False
        )
        (config_dir / "docker-compose.yml").write_text(compose_content)
        console.print("[green]✓[/green] docker-compose.yml generated")
        
        if skip_proxy_questions:
            console.print("[dim]  (Using existing cryptolabs network, no new proxy)[/dim]")
        
        # prometheus.yml
        prometheus_template = env.get_template("prometheus.yml.j2")
        local_ip = get_local_ip()
        prometheus_content = prometheus_template.render(
            dc_port=dc_port,
            ipmi_enabled=ipmi_enabled,
            vast_enabled=False,
            static_targets=[{"name": "master", "ip": local_ip}]
        )
        (config_dir / "prometheus.yml").write_text(prometheus_content)
        console.print("[green]✓[/green] prometheus.yml generated")
        
        # nginx.conf (if proxy enabled)
        if setup_proxy:
            if skip_proxy_questions and existing_proxy:
                # Update existing ipmi-monitor nginx.conf to add /dc/ route
                ipmi_nginx = Path("/etc/ipmi-monitor/nginx.conf")
                if ipmi_nginx.exists():
                    update_existing_nginx_config(ipmi_nginx, dc_port)
                    console.print("[green]✓[/green] Updated existing nginx.conf with /dc/ route")
                else:
                    # Fallback: create our own nginx.conf
                    nginx_template = env.get_template("nginx.conf.j2")
                    nginx_content = nginx_template.render(
                        domain=domain or local_ip,
                        dc_port=dc_port,
                        ipmi_enabled=ipmi_enabled,
                        use_letsencrypt=use_letsencrypt,
                        ssl_cert="/etc/nginx/ssl/server.crt",
                        ssl_key="/etc/nginx/ssl/server.key"
                    )
                    (config_dir / "nginx.conf").write_text(nginx_content)
                    console.print("[green]✓[/green] nginx.conf generated")
            else:
                nginx_template = env.get_template("nginx.conf.j2")
                nginx_content = nginx_template.render(
                    domain=domain or local_ip,
                    dc_port=dc_port,
                    ipmi_enabled=ipmi_enabled,
                    use_letsencrypt=use_letsencrypt,
                    ssl_cert="/etc/nginx/ssl/server.crt",
                    ssl_key="/etc/nginx/ssl/server.key"
                )
                (config_dir / "nginx.conf").write_text(nginx_content)
                console.print("[green]✓[/green] nginx.conf generated")
                
                # Generate self-signed certificate
                ssl_dir = config_dir / "ssl"
                ssl_dir.mkdir(exist_ok=True)
                generate_self_signed_cert(ssl_dir, domain or local_ip)
        
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Template error: {e}, using fallback")
        # Fallback to basic compose file
        compose_content = generate_basic_compose(dc_port, grafana_pass, setup_proxy)
        (config_dir / "docker-compose.yml").write_text(compose_content)
    
    # Create Grafana provisioning directories
    grafana_dirs = [
        config_dir / "grafana" / "provisioning" / "datasources",
        config_dir / "grafana" / "provisioning" / "dashboards",
        config_dir / "grafana" / "dashboards"
    ]
    for d in grafana_dirs:
        d.mkdir(parents=True, exist_ok=True)
    
    # Copy Grafana provisioning configs
    try:
        # Datasource config
        datasource_config = """apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
"""
        (config_dir / "grafana" / "provisioning" / "datasources" / "prometheus.yml").write_text(datasource_config)
        
        # Dashboard provisioning config
        dashboard_config = """apiVersion: 1
providers:
  - name: 'DC Overview'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    options:
      path: /var/lib/grafana/dashboards
"""
        (config_dir / "grafana" / "provisioning" / "dashboards" / "default.yml").write_text(dashboard_config)
        console.print("[green]✓[/green] Grafana provisioning configured")
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Grafana provisioning warning: {e}")
    
    # Create prometheus targets file with imported servers
    if imported_servers:
        targets = []
        for srv in imported_servers:
            ip = srv.get('server_ip') or srv.get('bmc_ip')
            if ip:
                # Add node_exporter target (will be installed)
                targets.append({
                    "targets": [f"{ip}:9100"],
                    "labels": {"instance": srv['name'], "job": "node-exporter"}
                })
                # Add dc-exporter target (will be installed)
                targets.append({
                    "targets": [f"{ip}:9835"],
                    "labels": {"instance": srv['name'], "job": "dc-exporter"}
                })
        (config_dir / "prometheus_targets.json").write_text(json.dumps(targets, indent=2))
        console.print(f"[green]✓[/green] Prometheus targets configured ({len(imported_servers)} servers)")
    else:
        (config_dir / "prometheus_targets.json").write_text("[]")
    
    # Copy dashboards
    copy_dashboards(config_dir / "grafana" / "dashboards")
    
    # Pull and start services
    console.print("\n[bold]Starting Services[/bold]\n")
    
    with Progress(SpinnerColumn(), TextColumn("Pulling Docker images..."), console=console) as progress:
        progress.add_task("", total=None)
        subprocess.run(["docker", "compose", "pull"], cwd=config_dir, capture_output=True)
    
    with Progress(SpinnerColumn(), TextColumn("Starting containers..."), console=console) as progress:
        progress.add_task("", total=None)
        result = subprocess.run(
            ["docker", "compose", "up", "-d"],
            cwd=config_dir,
            capture_output=True
        )
    
    if result.returncode == 0:
        console.print("[green]✓[/green] DC Overview running on port", dc_port)
        console.print("[green]✓[/green] Prometheus running on port 9090")
        console.print("[green]✓[/green] Grafana running on port 3000")
        if setup_proxy and not skip_proxy_questions:
            console.print("[green]✓[/green] CryptoLabs Proxy running on ports 80/443")
        elif skip_proxy_questions:
            console.print("[green]✓[/green] Using existing CryptoLabs Proxy")
        console.print(f"[dim]  Grafana login: admin / {grafana_pass}[/dim]")
    else:
        console.print(f"[red]Error starting services:[/red] {result.stderr.decode()[:200]}")
        return
    
    # ===========================================================================
    # INSTALL EXPORTERS ON IMPORTED SERVERS
    # ===========================================================================
    if imported_servers:
        console.print("\n[bold]GPU Worker Exporter Installation[/bold]")
        console.print(f"[dim]Found {len(imported_servers)} servers from IPMI Monitor.[/dim]")
        console.print("[dim]DC-exporter provides GPU VRAM temps, hotspot temps, power, utilization.[/dim]\n")
        
        # Check if we have SSH credentials for any server
        has_credentials = any(
            srv.get('ssh_key_path') or srv.get('ssh_password') or default_ssh_key_path
            for srv in imported_servers
        )
        
        if has_credentials:
            console.print("[green]✓[/green] SSH credentials available from IPMI Monitor")
            if default_ssh_key_path:
                console.print(f"[dim]  Default SSH key: {default_ssh_key_path}[/dim]")
        
        install_exporters_flag = questionary.confirm(
            f"Install dc-exporter on {len(imported_servers)} servers?",
            default=True,
            style=custom_style
        ).ask()
        
        if install_exporters_flag:
            # Install on each server
            success_count = 0
            fail_count = 0
            
            for srv in imported_servers:
                ip = srv.get('server_ip') or srv.get('bmc_ip')
                name = srv.get('name', ip)
                ssh_user = srv.get('ssh_user') or default_ssh_user
                ssh_port = srv.get('ssh_port', 22)
                
                if not ip:
                    continue
                
                # Use server-specific SSH credentials, fallback to defaults
                srv_key_path = srv.get('ssh_key_path') or default_ssh_key_path
                srv_password = srv.get('ssh_password')
                
                # Check if key path exists, try copied location
                if srv_key_path and not Path(srv_key_path).exists():
                    # Try in dc-overview ssh_keys dir
                    dc_key = config_dir / "ssh_keys" / Path(srv_key_path).name
                    if dc_key.exists():
                        srv_key_path = str(dc_key)
                
                console.print(f"  Installing on {name} ({ip})...", end=" ")
                
                # Check if already running
                if test_machine_connection(ip, 9835):
                    console.print("[green]✓ already running[/green]")
                    success_count += 1
                    continue
                
                # Skip if no credentials
                if not srv_key_path and not srv_password:
                    console.print("[yellow]⚠ no SSH credentials[/yellow]")
                    fail_count += 1
                    continue
                
                # Try to install
                success = install_exporters_remote(
                    ip=ip,
                    user=ssh_user,
                    password=srv_password,
                    key_path=srv_key_path,
                    port=ssh_port
                )
                
                if success:
                    console.print("[green]✓[/green]")
                    success_count += 1
                else:
                    console.print("[yellow]⚠ manual install needed[/yellow]")
                    fail_count += 1
            
            console.print(f"\n[green]✓[/green] Exporters installed: {success_count}/{len(imported_servers)}")
            if fail_count > 0:
                console.print(f"[yellow]⚠[/yellow] {fail_count} servers need manual installation:")
                console.print("  [cyan]pip install dc-overview && sudo dc-overview install-exporters[/cyan]")
    
    # Save configuration for reference
    config_info = {
        "dc_port": dc_port,
        "grafana_port": 3000,
        "prometheus_port": 9090,
        "proxy_enabled": setup_proxy,
        "domain": domain,
        "external_port": external_port,
        "ipmi_enabled": ipmi_enabled,
        "watchtower_enabled": enable_watchtower,
        "imported_servers": len(imported_servers) if imported_servers else 0
    }
    (config_dir / "config.json").write_text(json.dumps(config_info, indent=2))


def generate_self_signed_cert(ssl_dir: Path, domain: str):
    """Generate self-signed SSL certificate."""
    cert_path = ssl_dir / "server.crt"
    key_path = ssl_dir / "server.key"
    
    cmd = [
        "openssl", "req", "-x509", "-nodes",
        "-days", "365",
        "-newkey", "rsa:2048",
        "-keyout", str(key_path),
        "-out", str(cert_path),
        "-subj", f"/CN={domain}/O=CryptoLabs/C=ZA",
    ]
    
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        os.chmod(key_path, 0o600)
        console.print("[green]✓[/green] Self-signed certificate generated")
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Could not generate certificate: {e}")


def generate_basic_compose(dc_port: int, grafana_pass: str, enable_proxy: bool) -> str:
    """Generate basic docker-compose.yml without templates."""
    return f"""services:
  dc-overview:
    image: ghcr.io/cryptolabsza/dc-overview:latest
    container_name: dc-overview
    restart: unless-stopped
    ports:
      - "{dc_port}:{dc_port}"
    environment:
      - DC_OVERVIEW_PORT={dc_port}
      - SECRET_KEY=${{SECRET_KEY}}
      - GRAFANA_URL=http://grafana:3000
      - PROMETHEUS_URL=http://prometheus:9090
    volumes:
      - dc_data:/data
    networks:
      - cryptolabs

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.retention.time=30d"
    networks:
      - cryptolabs

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD={grafana_pass}
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
      - ./grafana/dashboards:/var/lib/grafana/dashboards:ro
    networks:
      - cryptolabs

volumes:
  dc_data:
  prometheus_data:
  grafana_data:

networks:
  cryptolabs:
    name: cryptolabs
    driver: bridge
"""


def copy_dashboards(dest_dir: Path):
    """Copy bundled dashboards to Grafana directory."""
    try:
        import dc_overview
        pkg_path = Path(dc_overview.__file__).parent / "dashboards"
        if pkg_path.exists():
            import shutil
            for dashboard_file in pkg_path.glob("*.json"):
                shutil.copy(dashboard_file, dest_dir / dashboard_file.name)
            console.print(f"[green]✓[/green] Dashboards copied ({len(list(pkg_path.glob('*.json')))} files)")
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Could not copy dashboards: {e}")


def configure_grafana(password: str):
    """Configure Grafana with Prometheus datasource and dashboards."""
    import time
    import urllib.request
    import json
    import importlib.resources
    
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
    
    # Dashboard definitions - local file first, then GitHub fallback
    # Using packaged dashboards from dc_overview/dashboards/ folder
    dashboards = [
        {
            "name": "DC Overview",
            "local_file": "DC OverView-1768678619438.json",
            "github_url": "https://raw.githubusercontent.com/jjziets/DCMontoring/main/DC_OverView.json",
        },
        {
            "name": "Node Exporter Full",
            "local_file": "Node Exporter Full.json",
            "github_url": "https://raw.githubusercontent.com/jjziets/DCMontoring/main/Node%20Exporter%20Full-1684242153326.json",
        },
        {
            "name": "NVIDIA DCGM Exporter",
            "local_file": "NVIDIA DCGM Exporter.json",
            "github_url": "https://raw.githubusercontent.com/jjziets/DCMontoring/main/NVIDIA%20DCGM%20Exporter-1684242180498.json",
        },
        {
            "name": "Vast Dashboard",
            "local_file": "Vast Dashboard.json",
            "github_url": "https://raw.githubusercontent.com/jjziets/DCMontoring/main/Vast%20Dashboard-1692692563948.json",
        },
        {
            "name": "IPMI Monitor",
            "local_file": "IPMI Monitor-1768678710446.json",
            "github_url": None,  # Only available locally
        },
    ]
    
    # Try to get the dashboards directory from the package
    dashboards_dir = None
    try:
        # Python 3.9+ compatible way to get package resources
        import dc_overview
        pkg_path = Path(dc_overview.__file__).parent / "dashboards"
        if pkg_path.exists():
            dashboards_dir = pkg_path
    except Exception:
        pass
    
    for dashboard in dashboards:
        name = dashboard["name"]
        local_file = dashboard["local_file"]
        github_url = dashboard["github_url"]
        
        dashboard_json = None
        source = None
        
        # Try local packaged file first
        if dashboards_dir and (dashboards_dir / local_file).exists():
            try:
                dashboard_json = (dashboards_dir / local_file).read_text()
                source = "package"
            except Exception:
                pass
        
        # Fall back to GitHub if no local file
        if not dashboard_json and github_url:
            try:
                dashboard_json = urllib.request.urlopen(github_url, timeout=30).read().decode('utf-8')
                source = "github"
            except Exception:
                pass
        
        if not dashboard_json:
            console.print(f"[yellow]⚠[/yellow] {name} dashboard: not found")
            continue
        
        try:
            dashboard_obj = json.loads(dashboard_json)
            
            # Use import API with datasource input mapping
            # Include both common variable names used in dashboards
            import_data = json.dumps({
                "dashboard": dashboard_obj,
                "overwrite": True,
                "inputs": [
                    {
                        "name": "DS_PROMETHEUS",
                        "type": "datasource",
                        "pluginId": "prometheus",
                        "value": "Prometheus"
                    },
                    {
                        "name": "datasource",
                        "type": "datasource", 
                        "pluginId": "prometheus",
                        "value": "Prometheus"
                    }
                ],
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
            console.print(f"[green]✓[/green] {name} dashboard imported ({source})")
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
                    f"{machine['ip']}:9835",
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
                prometheus_enabled=True,  # Now protected by basic auth (htpasswd)
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
        table.add_row("DC Exporter", f"http://{local_ip}:9835/metrics")
    
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
