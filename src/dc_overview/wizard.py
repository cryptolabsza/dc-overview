"""
DC Overview Setup Wizard - Interactive text UI for configuration
"""

import os
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List

import questionary
from questionary import Style
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
import yaml

console = Console()

# Custom style for questionary prompts
custom_style = Style([
    ('qmark', 'fg:cyan bold'),
    ('question', 'bold'),
    ('answer', 'fg:cyan'),
    ('pointer', 'fg:cyan bold'),
    ('highlighted', 'fg:cyan bold'),
    ('selected', 'fg:green'),
    ('separator', 'fg:gray'),
    ('instruction', 'fg:gray'),
    ('text', ''),
    ('disabled', 'fg:gray italic'),
])


class SetupWizard:
    """Interactive setup wizard for DC Overview."""
    
    def __init__(
        self, 
        mode: str = "auto",
        config_dir: Optional[str] = None, 
        non_interactive: bool = False
    ):
        self.mode = mode
        self.non_interactive = non_interactive
        
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            xdg_config = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
            self.config_dir = Path(xdg_config) / "dc-overview"
        
        self.config: Dict[str, Any] = {
            "mode": None,
            "master": {
                "prometheus_port": 9090,
                "grafana_port": 3000,
                "grafana_password": None,
            },
            "exporters": {
                "node_exporter": True,
                "dcgm_exporter": True,
                "dc_exporter": True,
            },
            "targets": [],
            "vast_api_key": None,
        }
    
    def run(self) -> Dict[str, Any]:
        """Run the setup wizard and return configuration."""
        
        # Step 1: Welcome
        self._show_welcome()
        
        # Step 2: Detect mode
        self._detect_mode()
        
        # Step 3: Mode-specific setup
        if self.config["mode"] == "master":
            self._setup_master()
        else:
            self._setup_worker()
        
        # Step 4: Save and summary
        self._save_config()
        self._show_summary()
        
        return self.config
    
    def _show_welcome(self):
        """Display welcome message."""
        console.print()
        console.print(Panel(
            "[bold]Welcome to DC Overview![/bold]\n\n"
            "This wizard will configure your GPU datacenter monitoring.\n\n"
            "[bold cyan]MASTER server[/bold cyan] - Runs Prometheus & Grafana\n"
            "  • Collects metrics from all workers\n"
            "  • Provides dashboards and alerting\n"
            "  • Typically 1 per datacenter\n\n"
            "[bold cyan]WORKER server[/bold cyan] - Runs exporters only\n"
            "  • node_exporter (CPU, RAM, disk)\n"
            "  • dcgm-exporter (GPU metrics)\n"
            "  • dc-exporter (VRAM temps)\n\n"
            "[dim]Press Ctrl+C at any time to cancel.[/dim]",
            title="[cyan]DC Overview Setup[/cyan]",
            border_style="cyan",
        ))
        console.print()
        
        if not self.non_interactive:
            questionary.press_any_key_to_continue(
                message="Press any key to continue...",
                style=custom_style
            ).ask()
    
    def _detect_mode(self):
        """Detect or prompt for installation mode."""
        console.print(Panel(
            "[bold]Step 1: Installation Mode[/bold]",
            border_style="blue"
        ))
        
        if self.mode == "auto":
            # Auto-detect based on GPU presence
            has_gpu = self._check_gpu_present()
            
            if has_gpu:
                console.print("[dim]GPUs detected - suggesting WORKER mode[/dim]")
                suggested_mode = "worker"
            else:
                console.print("[dim]No GPUs detected - suggesting MASTER mode[/dim]")
                suggested_mode = "master"
            
            if not self.non_interactive:
                mode_choice = questionary.select(
                    "Select installation mode:",
                    choices=[
                        questionary.Choice(
                            "Master (Prometheus + Grafana)", 
                            value="master",
                            checked=(suggested_mode == "master")
                        ),
                        questionary.Choice(
                            "Worker (Exporters only)", 
                            value="worker",
                            checked=(suggested_mode == "worker")
                        ),
                    ],
                    style=custom_style
                ).ask()
                self.config["mode"] = mode_choice
            else:
                self.config["mode"] = suggested_mode
        else:
            self.config["mode"] = self.mode
        
        console.print(f"[green]✓[/green] Mode: [cyan]{self.config['mode'].upper()}[/cyan]\n")
    
    def _check_gpu_present(self) -> bool:
        """Check if NVIDIA GPUs are present."""
        try:
            result = subprocess.run(
                ["nvidia-smi", "-L"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0 and b"GPU" in result.stdout
        except Exception:
            return False
    
    def _setup_master(self):
        """Configure master server (Prometheus + Grafana)."""
        console.print(Panel(
            "[bold]Step 2: Master Server Configuration[/bold]\n\n"
            "The master server runs Prometheus and Grafana to collect\n"
            "and visualize metrics from all worker nodes.",
            border_style="blue"
        ))
        
        if self.non_interactive:
            console.print("[dim]Using default master settings[/dim]\n")
            return
        
        # Grafana password
        grafana_pass = questionary.password(
            "Grafana admin password:",
            validate=lambda x: len(x) >= 8 or "Password must be at least 8 characters",
            style=custom_style
        ).ask()
        self.config["master"]["grafana_password"] = grafana_pass
        
        # Prometheus port
        prom_port = questionary.text(
            "Prometheus port:",
            default="9090",
            validate=lambda x: x.isdigit() and 1 <= int(x) <= 65535 or "Invalid port",
            style=custom_style
        ).ask()
        self.config["master"]["prometheus_port"] = int(prom_port)
        
        # Grafana port
        grafana_port = questionary.text(
            "Grafana port:",
            default="3000",
            validate=lambda x: x.isdigit() and 1 <= int(x) <= 65535 or "Invalid port",
            style=custom_style
        ).ask()
        self.config["master"]["grafana_port"] = int(grafana_port)
        
        # Vast.ai API key (optional)
        console.print("\n[dim]Vast.ai integration shows earnings and reliability metrics[/dim]")
        use_vast = questionary.confirm(
            "Configure Vast.ai integration?",
            default=False,
            style=custom_style
        ).ask()
        
        if use_vast:
            vast_key = questionary.password(
                "Vast.ai API Key:",
                style=custom_style
            ).ask()
            self.config["vast_api_key"] = vast_key
        
        # Add worker targets
        console.print("\n[bold]Worker Targets[/bold]")
        console.print("[dim]Add IP addresses of GPU workers to monitor[/dim]")
        
        self._add_targets()
        
        console.print()
    
    def _setup_worker(self):
        """Configure worker server (exporters only)."""
        console.print(Panel(
            "[bold]Step 2: Worker Configuration[/bold]\n\n"
            "Select which exporters to install on this worker.",
            border_style="blue"
        ))
        
        if self.non_interactive:
            console.print("[dim]Installing all exporters[/dim]\n")
            return
        
        # Select exporters
        exporters = questionary.checkbox(
            "Select exporters to install:",
            choices=[
                questionary.Choice("node_exporter (CPU, RAM, disk) - port 9100", value="node_exporter", checked=True),
                questionary.Choice("dcgm-exporter (NVIDIA GPU) - port 9400", value="dcgm_exporter", checked=True),
                questionary.Choice("dc-exporter (VRAM temps) - port 9500", value="dc_exporter", checked=True),
            ],
            style=custom_style
        ).ask()
        
        self.config["exporters"]["node_exporter"] = "node_exporter" in exporters
        self.config["exporters"]["dcgm_exporter"] = "dcgm_exporter" in exporters
        self.config["exporters"]["dc_exporter"] = "dc_exporter" in exporters
        
        # Master server IP
        console.print("\n[dim]Enter the IP of your master server so this worker can be scraped[/dim]")
        master_ip = questionary.text(
            "Master server IP (or skip):",
            default="",
            style=custom_style
        ).ask()
        
        if master_ip:
            self.config["master_ip"] = master_ip
            console.print(f"\n[yellow]Note:[/yellow] Add this worker to master's prometheus.yml:")
            console.print(f"  [cyan]dc-overview add-target {self._get_local_ip()} --name {os.uname().nodename}[/cyan]")
        
        console.print()
    
    def _add_targets(self):
        """Add Prometheus scrape targets."""
        while True:
            add_target = questionary.confirm(
                "Add a worker target?",
                default=len(self.config["targets"]) == 0,
                style=custom_style
            ).ask()
            
            if not add_target:
                break
            
            ip = questionary.text(
                "Worker IP address:",
                validate=lambda x: len(x) > 0 or "IP is required",
                style=custom_style
            ).ask()
            
            name = questionary.text(
                "Friendly name:",
                default=f"gpu-worker-{len(self.config['targets']) + 1:02d}",
                style=custom_style
            ).ask()
            
            ports = questionary.checkbox(
                "Ports to scrape:",
                choices=[
                    questionary.Choice("9100 (node_exporter)", value=9100, checked=True),
                    questionary.Choice("9400 (dcgm-exporter)", value=9400, checked=True),
                    questionary.Choice("9500 (dc-exporter)", value=9500, checked=True),
                ],
                style=custom_style
            ).ask()
            
            self.config["targets"].append({
                "name": name,
                "ip": ip,
                "ports": ports,
            })
            
            console.print(f"[green]✓[/green] Added: {name} ({ip})")
    
    def _get_local_ip(self) -> str:
        """Get local IP address."""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "YOUR_IP"
    
    def _save_config(self):
        """Save configuration to file."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        config_file = self.config_dir / "config.yaml"
        
        with open(config_file, "w") as f:
            yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)
        
        # Secure the file (may contain API keys)
        os.chmod(config_file, 0o600)
        
        console.print(f"[green]✓[/green] Configuration saved to: {config_file}")
    
    def _show_summary(self):
        """Display setup summary."""
        console.print()
        console.print(Panel(
            "[bold green]Setup Complete![/bold green]",
            border_style="green"
        ))
        
        table = Table(title="Configuration Summary", show_header=False)
        table.add_column("Setting", style="dim")
        table.add_column("Value")
        
        table.add_row("Mode", self.config["mode"].upper())
        table.add_row("Config Directory", str(self.config_dir))
        
        if self.config["mode"] == "master":
            table.add_row("Grafana Port", str(self.config["master"]["grafana_port"]))
            table.add_row("Prometheus Port", str(self.config["master"]["prometheus_port"]))
            table.add_row("Worker Targets", str(len(self.config["targets"])))
            table.add_row("Vast.ai", "Configured" if self.config["vast_api_key"] else "Not configured")
        else:
            enabled = [k for k, v in self.config["exporters"].items() if v]
            table.add_row("Exporters", ", ".join(enabled) if enabled else "None")
        
        console.print(table)
        
        console.print("\n[bold]Next Steps:[/bold]")
        
        if self.config["mode"] == "master":
            console.print("  1. Generate docker-compose: [cyan]dc-overview generate-compose[/cyan]")
            console.print("  2. Start services: [cyan]docker compose up -d[/cyan]")
            console.print("  3. Open Grafana: [cyan]http://localhost:3000[/cyan]")
        else:
            console.print("  1. Install exporters: [cyan]sudo dc-overview install-exporters[/cyan]")
            console.print("  2. Verify metrics: [cyan]curl http://localhost:9100/metrics | head[/cyan]")
            if self.config.get("master_ip"):
                console.print(f"  3. Add to master: [cyan]dc-overview add-target {self._get_local_ip()}[/cyan]")
        
        console.print()
