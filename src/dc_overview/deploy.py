"""
DC Overview Deploy - Remote deployment and management tool

Simplifies deployment for clients by:
- Generating SSH keys and deploying to workers
- Remote installation of exporters from master
- Bulk server import (CSV, interactive, scan)
- One-command setup for entire datacenter
"""

import os
import subprocess
import tempfile
import csv
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import socket

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm
import questionary
from questionary import Style
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


@dataclass
class Worker:
    """Represents a GPU worker node."""
    name: str
    ip: str
    ssh_user: str = "root"
    ssh_port: int = 22
    ssh_password: Optional[str] = None
    gpus: int = 0
    status: str = "unknown"


@dataclass
class VastConfig:
    """Vast.ai exporter configuration."""
    enabled: bool = False
    api_key: Optional[str] = None


class DeployManager:
    """Manages deployment of dc-overview components to workers."""
    
    def __init__(self, config_dir: Optional[Path] = None):
        if config_dir:
            self.config_dir = config_dir
        else:
            xdg = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
            self.config_dir = Path(xdg) / "dc-overview"
        
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.ssh_key_path = self.config_dir / "deploy_key"
        self.workers: List[Worker] = []
        self.vast_config = VastConfig()
        self._load_workers()
        self._load_vast_config()
    
    def _load_workers(self):
        """Load workers from config file."""
        workers_file = self.config_dir / "workers.yaml"
        if workers_file.exists():
            with open(workers_file) as f:
                data = yaml.safe_load(f) or {}
                for w in data.get("workers", []):
                    self.workers.append(Worker(**w))
    
    def _load_vast_config(self):
        """Load Vast.ai configuration."""
        config_file = self.config_dir / "config.yaml"
        if config_file.exists():
            with open(config_file) as f:
                data = yaml.safe_load(f) or {}
                if data.get("vast_api_key"):
                    self.vast_config.enabled = True
                    self.vast_config.api_key = data.get("vast_api_key")
    
    def _save_vast_config(self):
        """Save Vast.ai configuration."""
        config_file = self.config_dir / "config.yaml"
        
        # Load existing config
        data = {}
        if config_file.exists():
            with open(config_file) as f:
                data = yaml.safe_load(f) or {}
        
        # Update vast config
        if self.vast_config.enabled and self.vast_config.api_key:
            data["vast_api_key"] = self.vast_config.api_key
        
        with open(config_file, "w") as f:
            yaml.dump(data, f, default_flow_style=False)
        os.chmod(config_file, 0o600)
    
    def _save_workers(self):
        """Save workers to config file."""
        workers_file = self.config_dir / "workers.yaml"
        data = {"workers": [vars(w) for w in self.workers]}
        with open(workers_file, "w") as f:
            yaml.dump(data, f, default_flow_style=False)
        os.chmod(workers_file, 0o600)
    
    # ============ SSH Key Management ============
    
    def generate_ssh_key(self) -> Tuple[str, str]:
        """Generate a new SSH key pair for deployment."""
        if self.ssh_key_path.exists():
            console.print(f"[yellow]SSH key already exists:[/yellow] {self.ssh_key_path}")
            if not Confirm.ask("Generate new key? (overwrites existing)", default=False):
                pub_key = (self.ssh_key_path.with_suffix(".pub")).read_text().strip()
                return str(self.ssh_key_path), pub_key
        
        console.print("[cyan]Generating SSH key pair...[/cyan]")
        
        # Generate key
        subprocess.run([
            "ssh-keygen", "-t", "ed25519", "-f", str(self.ssh_key_path),
            "-N", "",  # No passphrase
            "-C", "dc-overview-deploy"
        ], check=True, capture_output=True)
        
        # Set permissions
        os.chmod(self.ssh_key_path, 0o600)
        
        pub_key = (self.ssh_key_path.with_suffix(".pub")).read_text().strip()
        console.print(f"[green]✓[/green] SSH key generated: {self.ssh_key_path}")
        
        return str(self.ssh_key_path), pub_key
    
    def deploy_ssh_key_to_worker(self, worker: Worker, password: str) -> bool:
        """Deploy SSH key to a worker using password auth."""
        _, pub_key = self.generate_ssh_key()
        
        console.print(f"[cyan]Deploying SSH key to {worker.name} ({worker.ip})...[/cyan]")
        
        try:
            # Use sshpass to deploy key
            cmd = f'''sshpass -p '{password}' ssh-copy-id -i {self.ssh_key_path}.pub \
                -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                -p {worker.ssh_port} {worker.ssh_user}@{worker.ip}'''
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                console.print(f"[green]✓[/green] SSH key deployed to {worker.name}")
                return True
            else:
                console.print(f"[red]✗[/red] Failed: {result.stderr[:100]}")
                return False
                
        except subprocess.TimeoutExpired:
            console.print(f"[red]✗[/red] Timeout connecting to {worker.name}")
            return False
        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")
            return False
    
    def test_ssh_connection(self, worker: Worker) -> bool:
        """Test SSH connection to worker."""
        try:
            cmd = [
                "ssh", "-i", str(self.ssh_key_path),
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=5",
                "-p", str(worker.ssh_port),
                f"{worker.ssh_user}@{worker.ip}",
                "echo ok"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0 and "ok" in result.stdout
        except Exception:
            return False
    
    # ============ Worker Discovery ============
    
    def add_worker_interactive(self) -> Optional[Worker]:
        """Add a worker interactively."""
        console.print(Panel("[bold]Add Worker Node[/bold]", border_style="cyan"))
        
        ip = questionary.text(
            "Worker IP address:",
            validate=lambda x: len(x) > 0,
            style=custom_style
        ).ask()
        
        if not ip:
            return None
        
        name = questionary.text(
            "Worker name:",
            default=f"worker-{ip.split('.')[-1]}",
            style=custom_style
        ).ask()
        
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
        
        worker = Worker(
            name=name,
            ip=ip,
            ssh_user=ssh_user,
            ssh_port=int(ssh_port)
        )
        
        # Ask for password to deploy SSH key
        console.print("\n[dim]To enable passwordless deployment, enter SSH password:[/dim]")
        password = questionary.password(
            "SSH password (or skip):",
            style=custom_style
        ).ask()
        
        if password:
            if self.deploy_ssh_key_to_worker(worker, password):
                worker.status = "key_deployed"
            else:
                worker.status = "key_failed"
        
        self.workers.append(worker)
        self._save_workers()
        
        return worker
    
    def import_workers_csv(self, csv_path: str) -> List[Worker]:
        """Import workers from CSV file.
        
        CSV format: name,ip,ssh_user,ssh_port,ssh_password
        """
        imported = []
        
        with open(csv_path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                worker = Worker(
                    name=row.get("name", row.get("ip")),
                    ip=row["ip"],
                    ssh_user=row.get("ssh_user", "root"),
                    ssh_port=int(row.get("ssh_port", 22)),
                )
                
                # Deploy SSH key if password provided
                password = row.get("ssh_password")
                if password:
                    if self.deploy_ssh_key_to_worker(worker, password):
                        worker.status = "key_deployed"
                
                self.workers.append(worker)
                imported.append(worker)
        
        self._save_workers()
        console.print(f"[green]✓[/green] Imported {len(imported)} workers from CSV")
        return imported
    
    def scan_network(self, subnet: str = "192.168.1.0/24", ports: List[int] = [22]) -> List[str]:
        """Scan network for potential workers."""
        console.print(f"[cyan]Scanning {subnet} for SSH servers...[/cyan]")
        
        # Use nmap if available, otherwise basic socket scan
        found = []
        
        try:
            # Try nmap first (faster, more reliable)
            result = subprocess.run(
                ["nmap", "-p", ",".join(str(p) for p in ports), "-oG", "-", subnet],
                capture_output=True, text=True, timeout=60
            )
            
            for line in result.stdout.split("\n"):
                if "/open/" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1]
                        found.append(ip)
                        
        except (FileNotFoundError, subprocess.TimeoutExpired):
            console.print("[yellow]nmap not found, using basic scan (slower)...[/yellow]")
            # Basic socket scan
            base_ip = ".".join(subnet.split(".")[:3])
            for i in range(1, 255):
                ip = f"{base_ip}.{i}"
                for port in ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        if sock.connect_ex((ip, port)) == 0:
                            found.append(ip)
                            break
                        sock.close()
                    except Exception:
                        pass
        
        console.print(f"[green]✓[/green] Found {len(found)} potential workers")
        return found
    
    # ============ Remote Deployment ============
    
    def run_remote_command(self, worker: Worker, command: str, sudo: bool = False) -> Tuple[bool, str]:
        """Run a command on a remote worker."""
        if sudo and worker.ssh_user != "root":
            command = f"sudo {command}"
        
        cmd = [
            "ssh", "-i", str(self.ssh_key_path),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-p", str(worker.ssh_port),
            f"{worker.ssh_user}@{worker.ip}",
            command
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return result.returncode == 0, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)
    
    def install_exporters_remote(self, worker: Worker) -> bool:
        """Install exporters on a remote worker."""
        console.print(f"\n[bold cyan]Installing exporters on {worker.name} ({worker.ip})[/bold cyan]")
        
        steps = [
            ("Checking connection", "echo 'Connected'"),
            ("Checking Python", "python3 --version"),
            ("Installing pip", "apt-get update && apt-get install -y python3-pip"),
            ("Installing dc-overview", "pip3 install dc-overview --break-system-packages"),
            ("Installing exporters", "dc-overview install-exporters"),
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            for desc, cmd in steps:
                task = progress.add_task(desc, total=None)
                
                success, output = self.run_remote_command(worker, cmd, sudo=True)
                
                if success:
                    progress.update(task, description=f"[green]✓[/green] {desc}")
                else:
                    progress.update(task, description=f"[red]✗[/red] {desc}")
                    console.print(f"[dim]{output[:200]}[/dim]")
                    return False
        
        worker.status = "exporters_installed"
        self._save_workers()
        console.print(f"[green]✓[/green] Exporters installed on {worker.name}")
        return True
    
    # ============ Vast.ai Exporter ============
    
    def setup_vast_exporter(self, api_key: Optional[str] = None) -> bool:
        """Set up Vast.ai exporter on the master server."""
        if api_key:
            self.vast_config.api_key = api_key
            self.vast_config.enabled = True
            self._save_vast_config()
        
        if not self.vast_config.api_key:
            console.print("[yellow]No Vast.ai API key configured.[/yellow]")
            return False
        
        console.print("\n[bold cyan]Setting up Vast.ai Exporter[/bold cyan]")
        console.print("[dim]This exposes your Vast.ai earnings, reliability, and machine metrics[/dim]\n")
        
        # Check if Docker is available
        try:
            result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
            if result.returncode != 0:
                console.print("[red]Docker not installed.[/red] Install Docker first.")
                return False
        except FileNotFoundError:
            console.print("[red]Docker not installed.[/red] Install Docker first.")
            return False
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Starting Vast.ai exporter...", total=None)
            
            # Stop existing container if any
            subprocess.run(
                ["docker", "rm", "-f", "vastai-exporter"],
                capture_output=True
            )
            
            # Start new container
            result = subprocess.run([
                "docker", "run", "-d",
                "--name", "vastai-exporter",
                "--restart", "unless-stopped",
                "-p", "127.0.0.1:8622:8622",
                "jjziets/vastai-exporter:latest",
                "-api-key", self.vast_config.api_key
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                progress.update(task, description="[green]✓[/green] Vast.ai exporter started")
                console.print(f"[green]✓[/green] Vast.ai exporter running on port 8622")
                console.print("[dim]  Metrics at: http://localhost:8622/metrics[/dim]")
                return True
            else:
                progress.update(task, description="[red]✗[/red] Failed to start")
                console.print(f"[red]Error:[/red] {result.stderr[:200]}")
                return False
    
    def check_vast_exporter_status(self) -> Dict[str, Any]:
        """Check if Vast.ai exporter is running."""
        status = {
            "configured": self.vast_config.enabled,
            "running": False,
            "api_key_set": bool(self.vast_config.api_key),
        }
        
        try:
            result = subprocess.run(
                ["docker", "inspect", "vastai-exporter", "--format", "{{.State.Running}}"],
                capture_output=True, text=True
            )
            status["running"] = result.returncode == 0 and "true" in result.stdout.lower()
        except Exception:
            pass
        
        return status
    
    def check_worker_status(self, worker: Worker) -> Dict[str, Any]:
        """Check status of exporters on a worker."""
        status = {
            "reachable": False,
            "gpus": 0,
            "node_exporter": False,
            "dcgm_exporter": False,
            "dc_exporter": False,
        }
        
        # Test connection
        success, output = self.run_remote_command(worker, "echo ok")
        status["reachable"] = success
        
        if not success:
            return status
        
        # Get GPU count
        success, output = self.run_remote_command(worker, "nvidia-smi -L 2>/dev/null | wc -l")
        if success:
            try:
                status["gpus"] = int(output.strip())
            except ValueError:
                pass
        
        # Check exporters
        for exporter in ["node_exporter", "dcgm-exporter", "dc-exporter"]:
            success, output = self.run_remote_command(
                worker, f"systemctl is-active {exporter} 2>/dev/null"
            )
            key = exporter.replace("-", "_")
            status[key] = success and "active" in output
        
        return status
    
    def deploy_to_all_workers(self, password: Optional[str] = None):
        """Deploy exporters to all workers."""
        if not self.workers:
            console.print("[yellow]No workers configured. Add workers first.[/yellow]")
            return
        
        console.print(Panel(
            f"[bold]Deploying to {len(self.workers)} workers[/bold]",
            border_style="cyan"
        ))
        
        # If password provided, deploy SSH keys first
        if password:
            console.print("[cyan]Deploying SSH keys...[/cyan]")
            for worker in self.workers:
                self.deploy_ssh_key_to_worker(worker, password)
        
        # Install exporters
        results = []
        for worker in self.workers:
            success = self.install_exporters_remote(worker)
            results.append((worker, success))
        
        # Summary
        console.print("\n[bold]Deployment Summary:[/bold]")
        table = Table()
        table.add_column("Worker", style="cyan")
        table.add_column("IP")
        table.add_column("Status")
        
        for worker, success in results:
            status = "[green]✓ Success[/green]" if success else "[red]✗ Failed[/red]"
            table.add_row(worker.name, worker.ip, status)
        
        console.print(table)
    
    # ============ Bulk Operations ============
    
    def bulk_add_workers(self):
        """Interactive bulk add of workers."""
        console.print(Panel(
            "[bold]Bulk Add Workers[/bold]\n\n"
            "Enter workers one per line in format:\n"
            "[cyan]ip,name,user,port[/cyan] (name, user, port optional)\n\n"
            "Examples:\n"
            "  192.168.1.101\n"
            "  192.168.1.102,gpu-worker-02\n"
            "  192.168.1.103,gpu-worker-03,root,22\n\n"
            "Enter empty line when done.",
            border_style="cyan"
        ))
        
        workers_added = []
        
        while True:
            line = Prompt.ask("[cyan]Worker[/cyan]", default="")
            
            if not line:
                break
            
            parts = line.split(",")
            ip = parts[0].strip()
            name = parts[1].strip() if len(parts) > 1 else f"worker-{ip.split('.')[-1]}"
            user = parts[2].strip() if len(parts) > 2 else "root"
            port = int(parts[3].strip()) if len(parts) > 3 else 22
            
            worker = Worker(name=name, ip=ip, ssh_user=user, ssh_port=port)
            self.workers.append(worker)
            workers_added.append(worker)
            console.print(f"  [green]✓[/green] Added: {name} ({ip})")
        
        if workers_added:
            self._save_workers()
            console.print(f"\n[green]✓[/green] Added {len(workers_added)} workers")
            
            # Ask about SSH key deployment
            if Confirm.ask("\nDeploy SSH keys to these workers?", default=True):
                password = questionary.password(
                    "Enter SSH password (same for all):",
                    style=custom_style
                ).ask()
                
                if password:
                    for worker in workers_added:
                        self.deploy_ssh_key_to_worker(worker, password)
    
    def show_workers(self):
        """Display all configured workers with status."""
        if not self.workers:
            console.print("[yellow]No workers configured.[/yellow]")
            console.print("Add workers with: [cyan]dc-overview deploy add[/cyan]")
            return
        
        table = Table(title="Configured Workers")
        table.add_column("Name", style="cyan")
        table.add_column("IP")
        table.add_column("SSH")
        table.add_column("GPUs")
        table.add_column("Exporters")
        table.add_column("Status")
        
        with Progress(SpinnerColumn(), TextColumn("Checking workers..."), console=console) as progress:
            progress.add_task("", total=None)
            
            for worker in self.workers:
                status = self.check_worker_status(worker)
                
                ssh_info = f"{worker.ssh_user}@:{worker.ssh_port}"
                gpus = str(status.get("gpus", "?"))
                
                exporters = []
                if status.get("node_exporter"):
                    exporters.append("node")
                if status.get("dcgm_exporter"):
                    exporters.append("dcgm")
                if status.get("dc_exporter"):
                    exporters.append("dc")
                
                exp_str = ", ".join(exporters) if exporters else "[dim]none[/dim]"
                
                if status.get("reachable"):
                    status_str = "[green]✓ Online[/green]"
                else:
                    status_str = "[red]✗ Offline[/red]"
                
                table.add_row(worker.name, worker.ip, ssh_info, gpus, exp_str, status_str)
        
        console.print(table)


# ============ CLI Commands ============

def deploy_wizard():
    """Interactive deployment wizard."""
    console.print(Panel(
        "[bold cyan]DC Overview Deployment Wizard[/bold cyan]\n\n"
        "This wizard will help you:\n"
        "  1. Add GPU worker nodes\n"
        "  2. Generate and deploy SSH keys\n"
        "  3. Install exporters on all workers\n"
        "  4. Configure Prometheus to scrape workers",
        border_style="cyan"
    ))
    
    manager = DeployManager()
    
    # Step 1: Add workers
    console.print("\n[bold]Step 1: Add Workers[/bold]")
    
    add_method = questionary.select(
        "How would you like to add workers?",
        choices=[
            "Add workers one by one (interactive)",
            "Bulk add (paste multiple IPs)",
            "Import from CSV file",
            "Scan network for workers",
            "Skip (use existing workers)",
        ],
        style=custom_style
    ).ask()
    
    if "one by one" in add_method:
        while True:
            manager.add_worker_interactive()
            if not Confirm.ask("Add another worker?", default=True):
                break
    
    elif "Bulk add" in add_method:
        manager.bulk_add_workers()
    
    elif "CSV" in add_method:
        csv_path = questionary.path(
            "Path to CSV file:",
            style=custom_style
        ).ask()
        if csv_path and Path(csv_path).exists():
            manager.import_workers_csv(csv_path)
    
    elif "Scan" in add_method:
        subnet = questionary.text(
            "Subnet to scan:",
            default="192.168.1.0/24",
            style=custom_style
        ).ask()
        
        found = manager.scan_network(subnet)
        if found:
            console.print("\nFound potential workers:")
            for ip in found:
                console.print(f"  • {ip}")
            
            if Confirm.ask("\nAdd these as workers?", default=True):
                password = questionary.password(
                    "SSH password for all:",
                    style=custom_style
                ).ask()
                
                for ip in found:
                    worker = Worker(name=f"worker-{ip.split('.')[-1]}", ip=ip)
                    if password:
                        manager.deploy_ssh_key_to_worker(worker, password)
                    manager.workers.append(worker)
                manager._save_workers()
    
    # Show current workers
    console.print("\n[bold]Current Workers:[/bold]")
    manager.show_workers()
    
    # Step 2: Deploy exporters
    if manager.workers and Confirm.ask("\nDeploy exporters to all workers?", default=True):
        manager.deploy_to_all_workers()
    
    # Step 3: Vast.ai Exporter (optional)
    console.print("\n[bold]Step 3: Vast.ai Integration (Optional)[/bold]")
    console.print("[dim]If you're a Vast.ai provider, this shows earnings and reliability metrics[/dim]")
    
    vast_status = manager.check_vast_exporter_status()
    
    if vast_status["running"]:
        console.print("[green]✓[/green] Vast.ai exporter already running")
    else:
        setup_vast = questionary.confirm(
            "Set up Vast.ai exporter?",
            default=False,
            style=custom_style
        ).ask()
        
        if setup_vast:
            console.print("\n[dim]Get your API key from: https://cloud.vast.ai/account/[/dim]")
            vast_key = questionary.password(
                "Vast.ai API Key:",
                style=custom_style
            ).ask()
            
            if vast_key:
                manager.setup_vast_exporter(vast_key)
    
    # Step 4: Generate Prometheus config
    console.print("\n[bold]Step 4: Prometheus Configuration[/bold]")
    
    if manager.workers:
        from .config import PrometheusConfig
        
        prom_config = PrometheusConfig.load(manager.config_dir)
        
        for worker in manager.workers:
            status = manager.check_worker_status(worker)
            ports = []
            if status.get("node_exporter"):
                ports.append(9100)
            if status.get("dcgm_exporter"):
                ports.append(9400)
            if status.get("dc_exporter"):
                ports.append(9500)
            
            if ports:
                prom_config.add_target(worker.ip, worker.name, ports)
        
        # Add Vast.ai exporter if configured
        vast_status = manager.check_vast_exporter_status()
        if vast_status["running"]:
            prom_config.add_target("localhost", "vastai-exporter", [8622])
        
        prom_config.save()
        console.print(f"[green]✓[/green] Prometheus config saved to {manager.config_dir}/prometheus.yml")
        console.print("  Copy to your Prometheus server or run: [cyan]dc-overview generate-compose[/cyan]")
    
    console.print("\n[green]✓ Deployment wizard complete![/green]")


if __name__ == "__main__":
    deploy_wizard()
