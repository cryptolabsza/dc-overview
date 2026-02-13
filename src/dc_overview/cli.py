"""
DC Overview CLI - Command line interface with setup wizard
"""

import click
import os
import sys
import subprocess
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

from . import __version__, get_version_info, get_image_tag
from .service import ServiceManager
from .exporters import ExporterInstaller
from .deploy import DeployManager, deploy_wizard
from .quickstart import run_quickstart

# New fleet management imports
from .fleet_wizard import run_fleet_wizard
from .fleet_manager import deploy_fleet
from .fleet_config import FleetConfig

console = Console()

# Docker config directory (where setup puts files)
DOCKER_CONFIG_DIR = Path("/etc/dc-overview")


@click.group()
@click.version_option(version=__version__, prog_name="dc-overview", message=get_version_info())
def main():
    """
    DC Overview - GPU Datacenter Monitoring Suite
    
    Monitor your GPU datacenter with Prometheus, Grafana, and AI-powered insights.
    
    \b
    QUICK START:
    
        sudo dc-overview setup      # Interactive fleet setup (recommended)
        dc-overview install-exporters   # Install exporters on current machine
        dc-overview status          # Check service status
    """
    pass


@click.command("install-exporters")
@click.option("--node-exporter/--no-node-exporter", default=True, help="Install node_exporter")
@click.option("--dc-exporter/--no-dc-exporter", default=True, help="Install dc-exporter (includes GPU metrics)")
def install_exporters(node_exporter: bool, dc_exporter: bool):
    """
    Install Prometheus exporters on current machine.
    
    Installs as native systemd services (not Docker) for compatibility
    with Vast.ai and RunPod.
    
    \b
    EXPORTERS:
        node_exporter   - CPU, RAM, disk metrics (port 9100)
        dc-exporter     - GPU metrics: VRAM/hotspot temps, power, util (port 9835)
    
    \b
    EXAMPLE:
        sudo dc-overview install-exporters
    """
    if os.geteuid() != 0:
        console.print("[red]Error:[/red] Installing exporters requires root. Run with sudo.")
        sys.exit(1)
    
    console.print(Panel.fit(
        "[bold cyan]Installing Prometheus Exporters[/bold cyan]",
        border_style="cyan"
    ))
    
    installer = ExporterInstaller()
    
    if node_exporter:
        installer.install_node_exporter()
    
    if dc_exporter:
        installer.install_dc_exporter()
    
    console.print("\n[green]✓[/green] Exporters installed!")
    console.print("  Verify: [cyan]curl http://localhost:9100/metrics | head[/cyan]")


@click.command()
def status():
    """
    Show DC Overview status and configuration.
    
    Checks both Docker container status and native exporter status.
    """
    config_path = DOCKER_CONFIG_DIR if DOCKER_CONFIG_DIR.exists() else get_config_dir()
    
    console.print(Panel.fit(
        "[bold cyan]DC Overview Status[/bold cyan]",
        border_style="cyan"
    ))
    
    table = Table(show_header=False, box=None)
    table.add_column("Key", style="dim")
    table.add_column("Value")
    
    table.add_row("Version", __version__)
    table.add_row("Config Dir", str(config_path))
    
    # Check Docker deployment
    docker_status = get_docker_container_status("dc-overview")
    if docker_status:
        table.add_row("DC Overview Container", docker_status)
    
    grafana_status = get_docker_container_status("grafana")
    if grafana_status:
        table.add_row("Grafana Container", grafana_status)
    
    prometheus_status = get_docker_container_status("prometheus")
    if prometheus_status:
        table.add_row("Prometheus Container", prometheus_status)
    
    table.add_row("Compose File", "✓" if (config_path / "docker-compose.yml").exists() else "✗")
    
    console.print(table)
    console.print()
    
    # Check native exporters (for worker machines)
    console.print("[bold]Native Exporter Status (Workers):[/bold]")
    exporters = [
        ("node_exporter", 9100),
        ("dc-exporter", 9835),
    ]
    
    exp_table = Table()
    exp_table.add_column("Service", style="cyan")
    exp_table.add_column("Port")
    exp_table.add_column("Status")
    
    for name, port in exporters:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", name],
                capture_output=True, text=True
            )
            status_val = result.stdout.strip()
            if status_val == "active":
                status_str = "[green]✓ Running[/green]"
            elif status_val == "inactive":
                status_str = "[yellow]○ Stopped[/yellow]"
            else:
                status_str = f"[dim]{status_val}[/dim]"
        except Exception:
            status_str = "[dim]Not installed[/dim]"
        
        exp_table.add_row(name, str(port), status_str)
    
    console.print(exp_table)
    
    # Show helpful commands
    if docker_status:
        console.print("\n[bold]Commands:[/bold]")
        console.print("  [cyan]dc-overview logs[/cyan]     - View container logs")
        console.print("  [cyan]dc-overview stop[/cyan]     - Stop containers")
        console.print("  [cyan]dc-overview start[/cyan]    - Start containers")
        console.print("  [cyan]dc-overview upgrade[/cyan]  - Pull latest image & restart")


def get_docker_container_status(container_name: str) -> str:
    """Get status of a Docker container."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Status}}", container_name],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            status = result.stdout.strip()
            if status == "running":
                return "[green]running ✓[/green]"
            elif status == "exited":
                return "[red]stopped[/red]"
            else:
                return f"[yellow]{status}[/yellow]"
        return None
    except Exception:
        return None


def run_docker_compose_cmd(command: str):
    """Run a docker compose command in the config directory."""
    compose_file = DOCKER_CONFIG_DIR / "docker-compose.yml"
    
    if not compose_file.exists():
        return False, "docker-compose.yml not found"
    
    # Try docker compose (v2) first
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(compose_file)] + command.split(),
            capture_output=True, text=True, cwd=str(DOCKER_CONFIG_DIR)
        )
        if result.returncode == 0:
            return True, result.stdout
    except Exception:
        pass
    
    # Try docker-compose (v1)
    try:
        result = subprocess.run(
            ["docker-compose", "-f", str(compose_file)] + command.split(),
            capture_output=True, text=True, cwd=str(DOCKER_CONFIG_DIR)
        )
        return result.returncode == 0, result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return False, str(e)


@click.command()
@click.option("--follow", "-f", is_flag=True, help="Follow log output")
@click.option("--lines", "-n", default=100, help="Number of lines to show")
@click.argument("service", default="dc-overview")
def logs(follow: bool, lines: int, service: str):
    """
    View DC Overview container logs.
    
    SERVICE can be: dc-overview, grafana, prometheus, or a native service name.
    
    \b
    EXAMPLES:
        dc-overview logs -f              # Follow dc-overview logs
        dc-overview logs grafana -n 50   # Last 50 lines of Grafana logs
    """
    # Docker containers
    docker_services = ["dc-overview", "grafana", "prometheus", "cryptolabs-proxy"]
    
    if service in docker_services:
        cmd = ["docker", "logs"]
        if follow:
            cmd.append("-f")
        cmd.extend(["--tail", str(lines), service])
        
        try:
            subprocess.run(cmd)
        except FileNotFoundError:
            console.print("[red]Error:[/red] Docker is not installed")
            sys.exit(1)
        except KeyboardInterrupt:
            pass
    else:
        # Native systemd services
        console.print(f"\n[bold cyan]Logs for {service}:[/bold cyan]")
        cmd = ["journalctl", "-u", service, "-n", str(lines)]
        if follow:
            cmd.append("-f")
        subprocess.run(cmd)


@click.command()
def stop():
    """
    Stop DC Overview containers.
    
    Stops the Docker containers defined in docker-compose.yml.
    """
    if not DOCKER_CONFIG_DIR.exists():
        console.print("[red]Error:[/red] Config directory not found. Run [cyan]sudo dc-overview setup[/cyan] first.")
        sys.exit(1)
    
    compose_file = DOCKER_CONFIG_DIR / "docker-compose.yml"
    if not compose_file.exists():
        console.print("[red]Error:[/red] docker-compose.yml not found. Run [cyan]sudo dc-overview setup[/cyan] first.")
        sys.exit(1)
    
    success, output = run_docker_compose_cmd("down")
    if success:
        console.print("[green]✓[/green] DC Overview stopped")
    else:
        console.print(f"[red]Error:[/red] {output}")


@click.command()
def start():
    """
    Start DC Overview containers.
    
    Starts the Docker containers defined in docker-compose.yml.
    """
    if not DOCKER_CONFIG_DIR.exists():
        console.print("[red]Error:[/red] Config directory not found. Run [cyan]sudo dc-overview setup[/cyan] first.")
        sys.exit(1)
    
    compose_file = DOCKER_CONFIG_DIR / "docker-compose.yml"
    if not compose_file.exists():
        console.print("[red]Error:[/red] docker-compose.yml not found. Run [cyan]sudo dc-overview setup[/cyan] first.")
        sys.exit(1)
    
    success, output = run_docker_compose_cmd("up -d")
    if success:
        console.print("[green]✓[/green] DC Overview started")
    else:
        console.print(f"[red]Error:[/red] {output}")


@click.command()
@click.option("--dev", is_flag=True, help="Switch to dev images (UNSTABLE - may break your system)")
@click.option("--stable", is_flag=True, help="Switch to stable/latest images (default)")
def upgrade(dev: bool, stable: bool):
    """
    Upgrade all fleet containers to the latest images.
    
    Pulls new images and recreates containers for: dc-overview,
    cryptolabs-proxy, ipmi-monitor, and compose services.
    
    \b
    EXAMPLES:
        sudo dc-overview upgrade              # Upgrade to latest stable
        sudo dc-overview upgrade --dev        # Switch to dev (UNSTABLE)
        sudo dc-overview upgrade --stable     # Switch back to stable
    """
    if dev and stable:
        console.print("[red]Error:[/red] Cannot use --dev and --stable together")
        sys.exit(1)
    
    tag = 'dev' if dev else 'latest'
    
    # Dev warning
    if dev:
        console.print()
        console.print("[bold red]⚠️  WARNING: Dev images are UNSTABLE[/bold red]")
        console.print("[yellow]Dev builds may contain untested changes that could:[/yellow]")
        console.print("[yellow]  • Break your monitoring dashboard[/yellow]")
        console.print("[yellow]  • Cause data loss or service outages[/yellow]")
        console.print("[yellow]  • Require manual intervention to fix[/yellow]")
        console.print()
        
        import questionary
        if not questionary.confirm("Are you sure you want to switch to dev images?", default=False).ask():
            console.print("[green]Cancelled.[/green] Staying on stable images.")
            return
        console.print()
    
    # Detect running containers and their current tags
    FLEET_IMAGES = {
        'dc-overview': 'ghcr.io/cryptolabsza/dc-overview',
        'cryptolabs-proxy': 'ghcr.io/cryptolabsza/cryptolabs-proxy',
        'ipmi-monitor': 'ghcr.io/cryptolabsza/ipmi-monitor',
    }
    
    console.print(f"[bold]Upgrading fleet to :{tag}[/bold]\n")
    
    updated = 0
    skipped = 0
    
    for container_name, image_base in FLEET_IMAGES.items():
        # Check if container exists
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.Config.Image}}", container_name],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            console.print(f"[dim]  {container_name}: not running (skip)[/dim]")
            skipped += 1
            continue
        
        current_image = result.stdout.strip()
        target_image = f"{image_base}:{tag}"
        
        # Pull new image
        console.print(f"[dim]  Pulling {container_name}:{tag}...[/dim]")
        pull_result = subprocess.run(
            ["docker", "pull", target_image],
            capture_output=True, text=True, timeout=120
        )
        if pull_result.returncode != 0:
            console.print(f"[red]  ✗ Failed to pull {target_image}[/red]")
            continue
        
        # Check if image actually changed
        if current_image == target_image:
            # Check if digest changed (new build of same tag)
            console.print(f"[dim]  {container_name}: already on :{tag}, checking for updates...[/dim]")
        
        # Get current container config for recreation
        inspect_result = subprocess.run(
            ["docker", "inspect", container_name],
            capture_output=True, text=True
        )
        if inspect_result.returncode != 0:
            console.print(f"[yellow]  ⚠ Could not inspect {container_name}[/yellow]")
            continue
        
        import json as json_module
        try:
            container_info = json_module.loads(inspect_result.stdout)[0]
            env_vars = container_info['Config'].get('Env', [])
            
            # Stop and remove old container
            subprocess.run(["docker", "stop", container_name], capture_output=True, timeout=30)
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
            
            # Rebuild the run command from inspection
            config = container_info['Config']
            host_config = container_info['HostConfig']
            
            cmd = ["docker", "run", "-d", "--name", container_name, "--restart", "unless-stopped"]
            
            # Environment variables
            skip_env = {'PATH', 'HOSTNAME', 'HOME'}
            for env in env_vars:
                key = env.split('=')[0]
                if key not in skip_env:
                    cmd.extend(["-e", env])
            
            # Volumes/mounts
            for mount in container_info.get('Mounts', []):
                if mount['Type'] == 'volume':
                    cmd.extend(["-v", f"{mount['Name']}:{mount['Destination']}"])
                elif mount['Type'] == 'bind':
                    ro = ':ro' if not mount.get('RW', True) else ''
                    cmd.extend(["-v", f"{mount['Source']}:{mount['Destination']}{ro}"])
            
            # Port bindings
            port_bindings = host_config.get('PortBindings') or {}
            for container_port, bindings in port_bindings.items():
                if bindings:
                    for binding in bindings:
                        host_port = binding.get('HostPort', '')
                        host_ip = binding.get('HostIp', '')
                        if host_ip:
                            cmd.extend(["-p", f"{host_ip}:{host_port}:{container_port}"])
                        else:
                            cmd.extend(["-p", f"{host_port}:{container_port}"])
            
            # Network
            networks = container_info['NetworkSettings'].get('Networks', {})
            for net_name, net_config in networks.items():
                if net_name != 'bridge':
                    cmd.extend(["--network", net_name])
                    if net_config.get('IPAddress'):
                        cmd.extend(["--ip", net_config['IPAddress']])
            
            # Labels (watchtower etc.)
            labels = config.get('Labels', {})
            for label_key, label_val in labels.items():
                if label_key.startswith('com.centurylinklabs') or label_key.startswith('org.opencontainers'):
                    cmd.extend(["--label", f"{label_key}={label_val}"])
            
            # Health check
            healthcheck = config.get('Healthcheck')
            if healthcheck and healthcheck.get('Test'):
                test = healthcheck['Test']
                if isinstance(test, list) and len(test) > 1 and test[0] == 'CMD':
                    cmd.extend(["--health-cmd", ' '.join(test[1:])])
            
            # The image
            cmd.append(target_image)
            
            # Start new container
            run_result = subprocess.run(cmd, capture_output=True, text=True)
            if run_result.returncode == 0:
                console.print(f"[green]  ✓ {container_name}: upgraded to :{tag}[/green]")
                updated += 1
            else:
                console.print(f"[red]  ✗ {container_name}: failed to start - {run_result.stderr[:100]}[/red]")
                
        except Exception as e:
            console.print(f"[red]  ✗ {container_name}: error - {str(e)[:100]}[/red]")
    
    # Also update compose-managed services (prometheus, grafana)
    if DOCKER_CONFIG_DIR.exists() and (DOCKER_CONFIG_DIR / "docker-compose.yml").exists():
        console.print("[dim]  Updating compose services (prometheus, grafana)...[/dim]")
        success, output = run_docker_compose_cmd("pull")
        if success:
            success, output = run_docker_compose_cmd("up -d")
            if success:
                console.print("[green]  ✓ Compose services updated[/green]")
    
    console.print(f"\n[bold]Done:[/bold] {updated} upgraded, {skipped} skipped")
    if dev:
        console.print("[yellow]⚠ Running dev images. Switch back with: sudo dc-overview upgrade --stable[/yellow]")


@click.command()
def restart():
    """
    Restart DC Overview containers.
    """
    if not DOCKER_CONFIG_DIR.exists():
        console.print("[red]Error:[/red] Config directory not found. Run [cyan]sudo dc-overview setup[/cyan] first.")
        sys.exit(1)
    
    success, output = run_docker_compose_cmd("restart")
    if success:
        console.print("[green]✓[/green] DC Overview restarted")
    else:
        console.print(f"[red]Error:[/red] {output}")


@click.command("add-target")
@click.argument("ip")
@click.option("--name", default=None, help="Friendly name for the target")
@click.option("--ports", default="9100,9835", help="Ports to scrape (comma-separated)")
def add_target(ip: str, name: str, ports: str):
    """
    Add a new scrape target to Prometheus.
    
    \b
    EXAMPLE:
        dc-overview add-target 192.168.1.101 --name gpu-worker-01
    """
    from .config import PrometheusConfig
    
    config = PrometheusConfig.load(get_config_dir())
    port_list = [int(p.strip()) for p in ports.split(",")]
    
    config.add_target(
        ip=ip,
        name=name or ip,
        ports=port_list
    )
    config.save()
    
    console.print(f"[green]✓[/green] Added target: {name or ip} ({ip})")
    console.print("  Reload Prometheus: [cyan]sudo systemctl reload prometheus[/cyan]")


@click.command("list-targets")
def list_targets():
    """
    List all Prometheus scrape targets.
    """
    from .config import PrometheusConfig
    
    config = PrometheusConfig.load(get_config_dir())
    
    if not config.targets:
        console.print("[yellow]No targets configured.[/yellow]")
        console.print("Add with: [cyan]dc-overview add-target <IP>[/cyan]")
        return
    
    table = Table(title="Prometheus Scrape Targets")
    table.add_column("Name", style="cyan")
    table.add_column("IP")
    table.add_column("Ports")
    
    for target in config.targets:
        table.add_row(
            target.get("name", "—"),
            target.get("ip", "—"),
            ", ".join(str(p) for p in target.get("ports", [])),
        )
    
    console.print(table)


@click.command("generate-compose")
@click.option("--output", "-o", default="docker-compose.yml", help="Output file")
def generate_compose(output: str):
    """
    Generate docker-compose.yml for master server.
    
    Creates a compose file with Prometheus, Grafana, and optional exporters.
    """
    from .templates import generate_docker_compose
    
    config_path = get_config_dir()
    compose_content = generate_docker_compose(config_path)
    
    with open(output, "w") as f:
        f.write(compose_content)
    
    console.print(f"[green]✓[/green] Generated: {output}")
    console.print("  Start with: [cyan]docker compose up -d[/cyan]")


def get_config_dir() -> Path:
    """Get the configuration directory."""
    if "DC_OVERVIEW_CONFIG" in os.environ:
        return Path(os.environ["DC_OVERVIEW_CONFIG"])
    
    xdg_config = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    return Path(xdg_config) / "dc-overview"


# ============ Deploy Commands ============

@click.group()
def deploy():
    """
    Deploy and manage workers remotely.
    
    \b
    COMMANDS:
        dc-overview deploy wizard     # Interactive deployment wizard
        dc-overview deploy add        # Add workers interactively
        dc-overview deploy bulk       # Bulk add workers
        dc-overview deploy list       # List all workers
        dc-overview deploy install    # Install exporters on workers
        dc-overview deploy ssh-key    # Generate/deploy SSH keys
    """
    pass


@deploy.command("wizard")
def deploy_wizard_cmd():
    """Run the interactive deployment wizard."""
    deploy_wizard()


@deploy.command("add")
def deploy_add():
    """Add a worker interactively."""
    manager = DeployManager()
    manager.add_worker_interactive()


@deploy.command("bulk")
@click.option("--csv", "csv_path", help="Import from CSV file")
def deploy_bulk(csv_path: str):
    """Bulk add workers (interactive or CSV import)."""
    manager = DeployManager()
    
    if csv_path:
        manager.import_workers_csv(csv_path)
    else:
        manager.bulk_add_workers()


@deploy.command("list")
def deploy_list():
    """List all configured workers with status."""
    manager = DeployManager()
    manager.show_workers()


@deploy.command("install")
@click.option("--worker", "-w", help="Install on specific worker (name or IP)")
@click.option("--password", "-p", help="SSH password for key deployment")
def deploy_install(worker: str, password: str):
    """Install exporters on workers remotely."""
    manager = DeployManager()
    
    if not manager.workers:
        console.print("[yellow]No workers configured.[/yellow]")
        console.print("Add workers first: [cyan]dc-overview deploy add[/cyan]")
        return
    
    if worker:
        # Find specific worker
        target = None
        for w in manager.workers:
            if w.name == worker or w.ip == worker:
                target = w
                break
        
        if not target:
            console.print(f"[red]Worker not found:[/red] {worker}")
            return
        
        if password:
            manager.deploy_ssh_key_to_worker(target, password)
        manager.install_exporters_remote(target)
    else:
        # Install on all
        manager.deploy_to_all_workers(password)


@deploy.command("ssh-key")
@click.option("--generate", is_flag=True, help="Generate new SSH key")
@click.option("--deploy", "deploy_to", help="Deploy to worker (name or IP)")
@click.option("--password", "-p", help="SSH password for deployment")
def deploy_ssh_key(generate: bool, deploy_to: str, password: str):
    """Generate or deploy SSH keys."""
    manager = DeployManager()
    
    if generate:
        key_path, pub_key = manager.generate_ssh_key()
        console.print(f"\n[bold]Public key:[/bold]")
        console.print(f"[dim]{pub_key}[/dim]")
    
    if deploy_to:
        if not password:
            import questionary
            password = questionary.password("SSH password:").ask()
        
        target = None
        for w in manager.workers:
            if w.name == deploy_to or w.ip == deploy_to:
                target = w
                break
        
        if target:
            manager.deploy_ssh_key_to_worker(target, password)
        else:
            # Try as IP directly
            from .deploy import Worker
            target = Worker(name=deploy_to, ip=deploy_to)
            manager.deploy_ssh_key_to_worker(target, password)


@deploy.command("scan")
@click.option("--subnet", default="192.168.1.0/24", help="Subnet to scan")
def deploy_scan(subnet: str):
    """Scan network for potential workers."""
    manager = DeployManager()
    found = manager.scan_network(subnet)
    
    if found:
        console.print("\n[bold]Found potential workers:[/bold]")
        for ip in found:
            console.print(f"  • {ip}")
        console.print(f"\nAdd with: [cyan]dc-overview deploy bulk[/cyan]")


@deploy.command("vast")
@click.option("--api-key", "-k", help="Vast.ai API key")
@click.option("--status", is_flag=True, help="Check Vast.ai exporter status")
def deploy_vast(api_key: str, status: bool):
    """Set up Vast.ai exporter for earnings/reliability metrics.
    
    Get your API key from: https://cloud.vast.ai/account/
    
    \b
    EXAMPLES:
        dc-overview deploy vast                    # Interactive setup
        dc-overview deploy vast --api-key KEY     # Direct setup
        dc-overview deploy vast --status          # Check status
    """
    manager = DeployManager()
    
    if status:
        vast_status = manager.check_vast_exporter_status()
        
        table = Table(title="Vast.ai Exporter Status")
        table.add_column("Setting")
        table.add_column("Value")
        
        table.add_row("Configured", "✓ Yes" if vast_status["configured"] else "✗ No")
        table.add_row("API Key Set", "✓ Yes" if vast_status["api_key_set"] else "✗ No")
        table.add_row("Container Running", "[green]✓ Running[/green]" if vast_status["running"] else "[red]✗ Stopped[/red]")
        
        if vast_status["running"]:
            table.add_row("Metrics URL", "http://localhost:8622/metrics")
        
        console.print(table)
        return
    
    if not api_key:
        console.print("[dim]Get your API key from: https://cloud.vast.ai/account/[/dim]\n")
        import questionary
        api_key = questionary.password("Vast.ai API Key:").ask()
    
    if api_key:
        manager.setup_vast_exporter(api_key)


@click.command()
@click.option("--legacy", is_flag=True, help="Use legacy single-machine setup (not recommended)")
@click.option("--config", "-c", "config_file", type=click.Path(exists=True), help="YAML config file for automated setup")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts (use with --config)")
@click.option("--dev", is_flag=True, help="Use dev Docker images instead of stable (latest)")
def setup(legacy: bool, config_file: str, yes: bool, dev: bool):
    """
    ⚡ One-command setup - does everything!
    
    Collects ALL information upfront, then deploys automatically.
    
    \b
    WHAT IT DOES:
        - Asks for all configuration ONCE at the start
        - Installs Docker, exporters, Prometheus, Grafana
        - Optionally installs IPMI Monitor
        - Optionally adds Vast.ai / RunPod integration
        - Deploys to all workers via SSH
        - Sets up HTTPS reverse proxy with Fleet Management
    
    \b
    INFORMATION COLLECTED:
        - Components to install (DC Overview, IPMI Monitor, Vast.ai, RunPod)
        - Grafana/IPMI passwords
        - SSH credentials for worker deployment
        - BMC/IPMI credentials (if IPMI enabled)
        - Server list (IPs, names, BMC addresses)
        - Domain + SSL configuration
    
    \b
    EXAMPLES:
        sudo dc-overview setup                    # Interactive setup
        sudo dc-overview setup -c config.yaml     # Automated from config file
        sudo dc-overview setup -c config.yaml -y  # Skip confirmations
    """
    if legacy:
        run_quickstart()
    else:
        run_fleet_quickstart(config_file, yes, dev=dev)


def run_fleet_quickstart(config_file: str = None, auto_confirm: bool = False, dev: bool = False):
    """Run the fleet setup (collects config then deploys everything)."""
    if os.geteuid() != 0:
        console.print("[red]Error:[/red] This command requires root privileges.")
        console.print("Run with: [cyan]sudo dc-overview setup[/cyan]")
        sys.exit(1)
    
    try:
        if config_file:
            # Load configuration from file
            config = load_config_from_file(config_file)
            config.auto_confirm = auto_confirm  # Pass -y flag to deployment
            config.image_tag = 'dev' if dev else 'latest'
            
            if not auto_confirm:
                # Show config summary and confirm
                console.print(Panel.fit(
                    f"[bold cyan]Configuration from {config_file}[/bold cyan]",
                    border_style="cyan"
                ))
                console.print(f"  Site: {config.site_name}")
                console.print(f"  Domain: {config.ssl.domain}")
                console.print(f"  Servers: {len(config.servers)}")
                console.print(f"  Components: DC Overview" + 
                             (", IPMI Monitor" if config.components.ipmi_monitor else "") +
                             (", Vast.ai" if config.components.vast_exporter else "") +
                             (f", RunPod ({len(config.runpod.api_keys)} account(s))" if config.runpod.enabled else ""))
                console.print()
                
                import questionary
                if not questionary.confirm("Proceed with deployment?", default=True).ask():
                    console.print("[yellow]Setup cancelled.[/yellow]")
                    return
        else:
            # Step 1: Collect all configuration upfront via wizard
            config = run_fleet_wizard()
            config.image_tag = 'dev' if dev else 'latest'
        
        if dev:
            console.print("[yellow]⚠ Using dev Docker images (--dev flag)[/yellow]")
        
        # Step 2: Deploy everything using collected config
        success = deploy_fleet(config)
        
        if not success:
            sys.exit(1)
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Setup cancelled.[/yellow]")
        sys.exit(1)


def load_config_from_file(config_file: str) -> FleetConfig:
    """Load FleetConfig from a YAML file.
    
    Also loads secrets from .secrets.yaml if found:
    1. Same directory as config_file (e.g., /root/.secrets.yaml next to /root/test-config.yaml)
    2. /etc/dc-overview/.secrets.yaml (default secrets location)
    
    This allows API keys (Vast, RunPod, etc.) to be kept separate from the config.
    """
    import yaml
    from .fleet_config import FleetConfig, SSLConfig, SSHCredentials, BMCCredentials, Server
    from .fleet_config import ComponentConfig, GrafanaConfig, VastConfig, IPMIMonitorConfig
    from .fleet_config import SecurityConfig, SSLMode, AuthMethod
    
    try:
        with open(config_file, 'r') as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        console.print(f"[red]Config file not found:[/red] {config_file}")
        sys.exit(1)
    except yaml.YAMLError as e:
        console.print(f"[red]Invalid YAML in config file:[/red] {config_file}")
        if hasattr(e, 'problem_mark'):
            mark = e.problem_mark
            console.print(f"  Line {mark.line + 1}, column {mark.column + 1}: {e.problem}")
        else:
            console.print(f"  {e}")
        console.print("\n[dim]Common causes: inconsistent indentation (use 2 spaces), list items aligned (e.g. '  - name:' not '   - name:').[/dim]")
        sys.exit(1)
    
    if data is None:
        console.print(f"[red]Config file is empty:[/red] {config_file}")
        sys.exit(1)
    
    config = FleetConfig()
    
    # Site info
    config.site_name = data.get('site_name', 'DC Overview')
    
    # Fleet admin credentials -- prefer config file, then detect from running proxy
    config.fleet_admin_user = data.get('fleet_admin_user', 'admin')
    config.fleet_admin_pass = data.get('fleet_admin_pass')
    
    # If credentials missing from config, try to read from running proxy
    if not config.fleet_admin_pass:
        try:
            import subprocess as _sp2
            _r = _sp2.run(
                ["docker", "inspect", "cryptolabs-proxy", "--format",
                 "{{range .Config.Env}}{{println .}}{{end}}"],
                capture_output=True, text=True, timeout=10
            )
            if _r.returncode == 0:
                _proxy_env = {}
                for _line in _r.stdout.strip().split('\n'):
                    if '=' in _line:
                        _k, _v = _line.split('=', 1)
                        _proxy_env[_k] = _v
                if _proxy_env.get("FLEET_ADMIN_USER") and _proxy_env.get("FLEET_ADMIN_PASS"):
                    config.fleet_admin_user = _proxy_env["FLEET_ADMIN_USER"]
                    config.fleet_admin_pass = _proxy_env["FLEET_ADMIN_PASS"]
                    console.print(f"[green]✓[/green] Fleet credentials: reused from existing proxy")
                if not config.site_name or config.site_name == 'DC Overview':
                    _pname = _proxy_env.get("SITE_NAME")
                    if _pname and _pname not in ("CryptoLabs Fleet", ""):
                        config.site_name = _pname
        except Exception:
            pass
    
    # SSH configuration
    # Note: use `or {}` instead of default={} because YAML sections with only
    # comments parse as None, and data.get('key', {}) returns None (not {})
    # when the key exists but its value is None.
    ssh = data.get('ssh') or {}
    config.ssh.username = ssh.get('username', 'root')
    config.ssh.key_path = ssh.get('key_path')
    config.ssh.password = ssh.get('password')
    config.ssh.port = ssh.get('port', 22)
    if ssh.get('key_path'):
        config.ssh.auth_method = AuthMethod.KEY
    
    # BMC configuration
    bmc = data.get('bmc') or {}
    config.bmc.username = bmc.get('username', 'ADMIN')
    config.bmc.password = bmc.get('password')
    
    # SSL configuration
    ssl = data.get('ssl') or {}
    config.ssl.domain = ssl.get('domain')
    config.ssl.email = ssl.get('email')
    ssl_mode = ssl.get('mode', 'self_signed')
    config.ssl.mode = SSLMode.LETSENCRYPT if ssl_mode == 'letsencrypt' else SSLMode.SELF_SIGNED
    
    # Auto-detect existing cryptolabs-proxy (e.g., set up by ipmi-monitor setup)
    # This prevents dc-overview from deploying a conflicting proxy
    config.ssl.use_existing_proxy = ssl.get('use_existing_proxy', False)
    if not config.ssl.use_existing_proxy:
        try:
            import subprocess as _sp
            _result = _sp.run(
                ["docker", "inspect", "cryptolabs-proxy", "--format", "{{.State.Status}}"],
                capture_output=True, text=True, timeout=5
            )
            if _result.returncode == 0 and _result.stdout.strip() == "running":
                config.ssl.use_existing_proxy = True
                console.print("[green]✓[/green] Detected existing CryptoLabs Proxy (e.g., from ipmi-monitor)")
                # Inherit domain from existing proxy if not set in config
                if not config.ssl.domain:
                    import re as _re
                    for _nginx_path in ["/etc/ipmi-monitor/nginx.conf", "/etc/cryptolabs-proxy/nginx.conf"]:
                        try:
                            with open(_nginx_path) as _f:
                                _content = _f.read()
                            _match = _re.search(r'server_name\s+([^;]+);', _content)
                            if _match:
                                _domain = _match.group(1).strip()
                                if _domain and _domain not in ('_', 'localhost', ''):
                                    config.ssl.domain = _domain
                                    console.print(f"[dim]  Using domain from existing proxy: {_domain}[/dim]")
                                    break
                        except Exception:
                            continue
                # Inherit SSL mode from existing proxy
                for _nginx_path in ["/etc/ipmi-monitor/nginx.conf", "/etc/cryptolabs-proxy/nginx.conf"]:
                    try:
                        with open(_nginx_path) as _f:
                            _content = _f.read()
                        if '/etc/letsencrypt/' in _content:
                            config.ssl.mode = SSLMode.LETSENCRYPT
                        break
                    except Exception:
                        continue
        except Exception:
            pass
    
    # Components
    components = data.get('components') or {}
    config.components.dc_overview = components.get('dc_overview', True)
    config.components.ipmi_monitor = components.get('ipmi_monitor', False)
    config.components.vast_exporter = components.get('vast_exporter', False)
    config.components.runpod_exporter = components.get('runpod_exporter', False)
    config.components.dc_watchdog = components.get('dc_watchdog', False)
    
    # Vast.ai
    vast = data.get('vast') or {}
    config.vast.enabled = config.components.vast_exporter
    config.vast.api_key = vast.get('api_key')
    # Support api_keys list with name/key pairs (multi-account)
    for api_key_data in (vast.get('api_keys') or []):
        if isinstance(api_key_data, dict):
            config.vast.add_key(
                name=api_key_data.get('name', 'default'),
                key=api_key_data.get('key', '')
            )
    # If Vast is enabled via api_keys, also set the component flag
    if config.vast.api_keys or config.vast.api_key:
        config.vast.enabled = True
    
    # RunPod (supports multiple API keys)
    runpod = data.get('runpod') or {}
    config.runpod.enabled = runpod.get('enabled', False) or config.components.runpod_exporter
    config.runpod.port = runpod.get('port', 8623)
    # Support api_keys list with name/key pairs
    for api_key_data in (runpod.get('api_keys') or []):
        if isinstance(api_key_data, dict):
            config.runpod.add_key(
                name=api_key_data.get('name', 'default'),
                key=api_key_data.get('key', '')
            )
    # If RunPod is enabled via api_keys, also set the component flag
    if config.runpod.api_keys:
        config.runpod.enabled = True
        config.components.runpod_exporter = True
    
    # Grafana
    grafana = data.get('grafana') or {}
    config.grafana.admin_password = grafana.get('admin_password', 'admin')
    # home_dashboard: "dc-overview-main", "vast-dashboard", or None to disable
    config.grafana.home_dashboard = grafana.get('home_dashboard', 'dc-overview-main')
    
    # IPMI Monitor
    ipmi = data.get('ipmi_monitor') or {}
    config.ipmi_monitor.enabled = config.components.ipmi_monitor
    config.ipmi_monitor.admin_password = ipmi.get('admin_password')
    config.ipmi_monitor.ai_license_key = ipmi.get('ai_license_key')
    config.ipmi_monitor.enable_ssh_inventory = ipmi.get('enable_ssh_inventory', True)
    config.ipmi_monitor.enable_ssh_logs = ipmi.get('enable_ssh_logs', False)
    
    # DC Watchdog (external uptime monitoring)
    watchdog = data.get('watchdog') or {}
    config.watchdog.server_url = watchdog.get('server_url', 'https://watchdog.cryptolabs.co.za')
    config.watchdog.ping_interval = watchdog.get('ping_interval', 30)
    config.watchdog.fail_timeout = watchdog.get('fail_timeout', 120)
    config.watchdog.install_agent = watchdog.get('install_agent', True)
    config.watchdog.agent_use_mtr = watchdog.get('agent_use_mtr', True)
    # API key: use watchdog.api_key, or fallback to ipmi_monitor.ai_license_key
    config.watchdog.api_key = watchdog.get('api_key') or ipmi.get('ai_license_key')
    
    # Auto-updates: by default only cryptolabs-proxy; when True, all components get watchtower label
    config.enable_watchtower_all = data.get('enable_watchtower_all', False)
    
    # Security / Firewall — skip if proxy is already running
    security = data.get('security') or {}
    config.security.ufw_enabled = security.get('ufw_enabled', True)
    if config.ssl.use_existing_proxy:
        config.security.ufw_enabled = False
    config.security.ufw_ports = security.get('ufw_ports', [22, 80, 443])
    config.security.ufw_additional_ports = security.get('ufw_additional_ports', [])
    config.security.ufw_udp_ports = security.get('ufw_udp_ports', [])
    
    # Servers from config file
    for srv in data.get('servers', []):
        config.add_server(
            name=srv.get('name', f"server-{len(config.servers)+1}"),
            server_ip=srv.get('server_ip'),
            bmc_ip=srv.get('bmc_ip'),
            bmc_user=srv.get('bmc_user'),
            bmc_password=srv.get('bmc_password'),
        )
    
    # If no servers in config file, try to import from existing IPMI Monitor
    if not config.servers:
        ipmi_config_dir = Path("/etc/ipmi-monitor")
        if ipmi_config_dir.exists():
            try:
                import subprocess as _sp3
                _r = _sp3.run(
                    ["docker", "inspect", "ipmi-monitor"],
                    capture_output=True, timeout=5
                )
                if _r.returncode == 0:
                    from .quickstart import import_ipmi_config
                    _ipmi_data = import_ipmi_config({
                        "config_dir": ipmi_config_dir,
                        "db_path": ipmi_config_dir / "data" / "ipmi_monitor.db",
                        "ssh_keys_dir": ipmi_config_dir / "ssh_keys"
                    })
                    for srv in _ipmi_data.get("servers", []):
                        config.add_server(
                            name=srv.get("name", ""),
                            server_ip=srv.get("server_ip"),
                            bmc_ip=srv.get("bmc_ip"),
                        )
                    if config.servers:
                        console.print(f"[green]✓[/green] Imported {len(config.servers)} servers from IPMI Monitor")
            except Exception:
                pass
    
    console.print(f"[green]✓[/green] Loaded configuration from {config_file}")
    
    # =========================================================================
    # Load secrets from .secrets.yaml (API keys, passwords kept separate)
    # Search order:
    #   1. Same directory as the config file
    #   2. /etc/dc-overview/.secrets.yaml
    # =========================================================================
    secrets = {}
    config_dir = Path(config_file).resolve().parent
    secrets_candidates = [
        config_dir / ".secrets.yaml",
        Path("/etc/dc-overview/.secrets.yaml"),
    ]
    
    for secrets_path in secrets_candidates:
        if secrets_path.exists():
            try:
                with open(secrets_path, 'r') as f:
                    secrets = yaml.safe_load(f) or {}
                console.print(f"[green]✓[/green] Loaded secrets from {secrets_path}")
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] Could not load secrets from {secrets_path}: {e}")
            break  # Use first found
    
    if secrets:
        # Fleet admin credentials (secrets override config)
        if secrets.get("fleet_admin_user"):
            config.fleet_admin_user = secrets["fleet_admin_user"]
        if secrets.get("fleet_admin_pass"):
            config.fleet_admin_pass = secrets["fleet_admin_pass"]
        
        # SSH password (if not already set from config)
        if secrets.get("ssh_password") and not config.ssh.password:
            config.ssh.password = secrets["ssh_password"]
        
        # BMC password (if not already set from config)
        if secrets.get("bmc_password") and not config.bmc.password:
            config.bmc.password = secrets["bmc_password"]
        
        # Use fleet_admin_pass as default for service passwords (optional overrides)
        default_pass = config.fleet_admin_pass or config.grafana.admin_password
        if secrets.get("grafana_password"):
            config.grafana.admin_password = secrets["grafana_password"]
        elif config.fleet_admin_pass and config.grafana.admin_password == 'admin':
            config.grafana.admin_password = config.fleet_admin_pass
        
        if secrets.get("ipmi_monitor_password"):
            config.ipmi_monitor.admin_password = secrets["ipmi_monitor_password"]
        elif config.fleet_admin_pass and not config.ipmi_monitor.admin_password:
            config.ipmi_monitor.admin_password = config.fleet_admin_pass
        
        # Load Vast API keys from secrets (supports multiple or legacy single key)
        for api_key_data in secrets.get("vast_api_keys", []):
            if isinstance(api_key_data, dict):
                config.vast.add_key(
                    name=api_key_data.get("name", "default"),
                    key=api_key_data.get("key", "")
                )
        # Legacy single key support
        if secrets.get("vast_api_key") and not config.vast.api_keys:
            config.vast.api_key = secrets["vast_api_key"]
        
        # If Vast API keys found in secrets and component is enabled, ensure vast is enabled
        if (config.vast.api_keys or config.vast.api_key) and config.components.vast_exporter:
            config.vast.enabled = True
        # If Vast API keys found in secrets but component was false, auto-enable
        if (config.vast.api_keys or config.vast.api_key) and not config.components.vast_exporter:
            config.components.vast_exporter = True
            config.vast.enabled = True
            console.print("[dim]  Vast.ai auto-enabled (API keys found in secrets)[/dim]")
        
        # IPMI AI license key
        if secrets.get("ipmi_ai_license"):
            config.ipmi_monitor.ai_license_key = secrets["ipmi_ai_license"]
        
        # Load RunPod API keys from secrets
        for api_key_data in secrets.get("runpod_api_keys", []):
            if isinstance(api_key_data, dict):
                config.runpod.add_key(
                    name=api_key_data.get("name", "default"),
                    key=api_key_data.get("key", "")
                )
        # If RunPod API keys found in secrets, auto-enable
        if config.runpod.api_keys and not config.components.runpod_exporter:
            config.components.runpod_exporter = True
            config.runpod.enabled = True
            console.print("[dim]  RunPod auto-enabled (API keys found in secrets)[/dim]")
        
        # Load DC Watchdog API key from secrets
        # Falls back to ipmi_ai_license since they use the same sk-ipmi-xxx key
        watchdog_key = (
            secrets.get("watchdog_api_key") or 
            secrets.get("ipmi_ai_license") or
            secrets.get("cryptolabs_api_key")
        )
        if watchdog_key and not config.watchdog.api_key:
            config.watchdog.api_key = watchdog_key
    
    return config


@click.command("add-machine")
@click.argument("ip")
@click.option("--name", "-n", help="Friendly name for this machine")
@click.option("--ssh-user", default="root", help="SSH username")
@click.option("--ssh-port", default=22, help="SSH port")
@click.option("--ssh-pass", help="SSH password (for remote install)")
def add_machine(ip: str, name: str, ssh_user: str, ssh_port: int, ssh_pass: str):
    """
    Add a machine to monitor.
    
    \b
    EXAMPLES:
        dc-overview add-machine 192.168.1.101
        dc-overview add-machine 192.168.1.101 --name gpu-worker-01
        dc-overview add-machine 192.168.1.101 --ssh-pass mypass  # Also installs exporters
    """
    from .quickstart import test_machine_connection, setup_remote_machine, update_prometheus_targets
    
    name = name or f"machine-{ip.split('.')[-1]}"
    
    # Test connection
    if test_machine_connection(ip):
        console.print(f"[green]✓[/green] {name} ({ip}) - exporters reachable")
    else:
        console.print(f"[yellow]⚠[/yellow] {name} ({ip}) - exporters not reachable")
        
        if ssh_pass:
            setup_remote_machine(ip, name)
        else:
            console.print("[dim]To install exporters remotely, provide --ssh-pass[/dim]")
    
    # Add to Prometheus
    update_prometheus_targets([{"name": name, "ip": ip}])
    console.print(f"[green]✓[/green] Added {name} to Prometheus")


# ============ Reverse Proxy Commands ============

@click.command("setup-ssl")
@click.option("--domain", "-d", help="Domain name (e.g., monitor.example.com)")
@click.option("--email", "-e", help="Email for Let's Encrypt certificate")
@click.option("--letsencrypt", is_flag=True, help="Use Let's Encrypt instead of self-signed")
@click.option("--site-name", default="DC Overview", help="Name shown on landing page")
@click.option("--ipmi/--no-ipmi", default=False, help="Include IPMI Monitor in reverse proxy")
@click.option("--prometheus/--no-prometheus", default=False, help="Expose Prometheus UI (disabled by default - no auth)")
def setup_ssl(domain: str, email: str, letsencrypt: bool, site_name: str, ipmi: bool, prometheus: bool):
    """
    Set up reverse proxy with SSL (nginx).
    
    Creates a branded landing page with links to all services.
    Only exposes port 443 externally - backend services bind to localhost.
    
    \b
    SECURITY:
        - Grafana (3000), Prometheus (9090), IPMI (5000) bind to 127.0.0.1
        - Only port 443 (HTTPS) is exposed to the network
        - Prometheus is disabled by default (no authentication)
    
    \b
    CERTIFICATE OPTIONS:
    
      Self-signed (default):
        - Works immediately with any IP or domain
        - Browser shows "Not Secure" warning (normal for internal networks)
        - No external dependencies
    
      Let's Encrypt (--letsencrypt):
        - Free trusted certificate (no browser warnings)
        - REQUIRES: Port 80 AND 443 open to the internet
        - REQUIRES: Valid domain with DNS pointing to this server
        - Auto-renews every 90 days (ports must stay open!)
    
    \b
    EXAMPLES:
        sudo dc-overview setup-ssl                           # Self-signed (IP access)
        sudo dc-overview setup-ssl -d monitor.example.com   # Self-signed (domain)
        sudo dc-overview setup-ssl -d example.com --letsencrypt -e admin@example.com
    
    \b
    DNS SETUP (for Let's Encrypt):
        1. Add A record: monitor.example.com → <server-ip>
        2. Open firewall ports 80 AND 443
        3. Wait for DNS propagation (5-30 minutes)
        4. Run setup-ssl with --letsencrypt
    """
    if os.geteuid() != 0:
        console.print("[red]Error:[/red] Setting up SSL requires root. Run with sudo.")
        sys.exit(1)
    
    if letsencrypt and not email:
        console.print("[red]Error:[/red] Let's Encrypt requires --email")
        sys.exit(1)
    
    if letsencrypt and not domain:
        console.print("[red]Error:[/red] Let's Encrypt requires --domain")
        sys.exit(1)
    
    from .reverse_proxy import setup_reverse_proxy
    
    setup_reverse_proxy(
        domain=domain,
        email=email,
        site_name=site_name,
        ipmi_enabled=ipmi,
        prometheus_enabled=prometheus,
        use_letsencrypt=letsencrypt,
    )


@click.command("reset")
@click.option("--exporters", is_flag=True, help="Remove dc-exporter from workers")
@click.option("--monitoring", is_flag=True, help="Remove Prometheus/Grafana containers")
@click.option("--ipmi", is_flag=True, help="Remove IPMI Monitor")
@click.option("--proxy", is_flag=True, help="Remove cryptolabs-proxy")
@click.option("--all", "remove_all", is_flag=True, help="Remove everything")
@click.option("--workers", "-w", multiple=True, help="Specific worker IPs (can be repeated)")
@click.option("--ssh-key", default="~/.ssh/ubuntu_key", help="SSH key path")
@click.option("--ssh-port", default=22, type=int, help="SSH port")
@click.option("--force", "-f", is_flag=True, help="Skip confirmation prompts")
def reset(exporters: bool, monitoring: bool, ipmi: bool, proxy: bool, 
          remove_all: bool, workers: tuple, ssh_key: str, ssh_port: int, force: bool):
    """
    Reset/remove DC Overview components for re-testing.
    
    Useful for cleaning up a dev fleet before re-running setup.
    
    \b
    COMPONENTS:
        --exporters    Remove dc-exporter service from workers
        --monitoring   Remove Prometheus + Grafana containers (local)
        --ipmi         Remove IPMI Monitor container
        --proxy        Remove cryptolabs-proxy container
        --all          Remove ALL components
    
    \b
    EXAMPLES:
        # Remove exporters from specific workers
        dc-overview reset --exporters -w 192.168.1.10 -w 192.168.1.11
        
        # Remove monitoring stack only (keep proxy/ipmi)
        dc-overview reset --monitoring --exporters
        
        # Full reset (remove everything except proxy/ipmi)
        dc-overview reset --exporters --monitoring
        
        # Nuclear option - remove everything
        dc-overview reset --all --force
    
    \b
    DEV FLEET EXAMPLE:
        dc-overview reset --exporters --monitoring \\
            -w root@41.193.204.66:101 -w root@41.193.204.66:103
    """
    from pathlib import Path
    
    if remove_all:
        exporters = monitoring = True
        # Note: ipmi and proxy are NOT included in --all by default
        # They require explicit flags
    
    if not any([exporters, monitoring, ipmi, proxy]):
        console.print("[yellow]No components selected.[/yellow]")
        console.print("Use --exporters, --monitoring, --ipmi, --proxy, or --all")
        console.print("\nRun [cyan]dc-overview reset --help[/cyan] for usage")
        return
    
    # Summary of what will be removed
    console.print(Panel.fit(
        "[bold red]DC Overview Reset[/bold red]\n"
        "[dim]This will remove selected components[/dim]",
        border_style="red"
    ))
    
    components = []
    if exporters:
        components.append("dc-exporter (on workers)")
    if monitoring:
        components.append("Prometheus + Grafana containers")
    if ipmi:
        components.append("IPMI Monitor container")
    if proxy:
        components.append("cryptolabs-proxy container")
    
    console.print("\n[bold]Components to remove:[/bold]")
    for c in components:
        console.print(f"  • {c}")
    
    if workers:
        console.print(f"\n[bold]Target workers:[/bold]")
        for w in workers:
            console.print(f"  • {w}")
    
    if not force:
        try:
            import questionary
            confirm = questionary.confirm(
                "\nAre you sure you want to proceed?",
                default=False
            ).ask()
            if not confirm:
                console.print("[yellow]Cancelled.[/yellow]")
                return
        except ImportError:
            # If questionary not available, require --force
            console.print("[red]Error:[/red] Use --force to skip confirmation (questionary not installed)")
            return
    
    console.print()
    
    # Expand SSH key path
    ssh_key = os.path.expanduser(ssh_key)
    
    # Remove exporters from workers
    if exporters and workers:
        console.print("[bold]Removing dc-exporter from workers...[/bold]")
        for worker in workers:
            _remove_exporter_from_worker(worker, ssh_key, ssh_port)
    elif exporters and not workers:
        console.print("[yellow]⚠[/yellow] --exporters specified but no workers given (-w)")
        console.print("  Use: [cyan]dc-overview reset --exporters -w <ip>[/cyan]")
    
    # Remove local containers
    if monitoring:
        console.print("\n[bold]Removing monitoring containers...[/bold]")
        _remove_containers(["prometheus", "grafana", "dc-overview"])
        # Also remove config
        if DOCKER_CONFIG_DIR.exists():
            import shutil
            should_remove = force
            if not force:
                try:
                    import questionary
                    should_remove = questionary.confirm(f"Remove config directory {DOCKER_CONFIG_DIR}?").ask()
                except ImportError:
                    should_remove = True  # Default to yes if questionary not available
            if should_remove:
                shutil.rmtree(DOCKER_CONFIG_DIR, ignore_errors=True)
                console.print(f"[green]✓[/green] Removed {DOCKER_CONFIG_DIR}")
    
    if ipmi:
        console.print("\n[bold]Removing IPMI Monitor...[/bold]")
        _remove_containers(["ipmi-monitor"])
    
    if proxy:
        console.print("\n[bold]Removing cryptolabs-proxy...[/bold]")
        _remove_containers(["cryptolabs-proxy"])
    
    console.print("\n[green]✓[/green] Reset complete!")
    console.print("  Re-run: [cyan]sudo dc-overview setup[/cyan]")


def _remove_exporter_from_worker(worker: str, ssh_key: str, default_port: int):
    """Remove dc-exporter from a remote worker."""
    import subprocess
    
    # Parse worker string: [user@]host[:port]
    user = "root"
    host = worker
    port = default_port
    
    if "@" in worker:
        user, host = worker.split("@", 1)
    if ":" in host:
        host, port_str = host.rsplit(":", 1)
        port = int(port_str)
    
    console.print(f"  → {user}@{host}:{port}", end=" ")
    
    ssh_opts = [
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=yes",
    ]
    if os.path.exists(ssh_key):
        ssh_opts.extend(["-i", ssh_key])
    
    # Commands to remove dc-exporter
    remove_cmd = """
        systemctl stop dc-exporter 2>/dev/null || true
        systemctl disable dc-exporter 2>/dev/null || true
        rm -f /etc/systemd/system/dc-exporter.service
        rm -f /usr/local/bin/dc-exporter-rs
        rm -f /usr/local/bin/dc-exporter
        rm -rf /etc/dc-exporter
        systemctl daemon-reload
        echo "REMOVED"
    """
    
    try:
        result = subprocess.run(
            ["ssh"] + ssh_opts + ["-p", str(port), f"{user}@{host}", remove_cmd],
            capture_output=True, text=True, timeout=30
        )
        if "REMOVED" in result.stdout:
            console.print("[green]✓[/green]")
        else:
            console.print(f"[yellow]⚠[/yellow] {result.stderr.strip()[:50]}")
    except subprocess.TimeoutExpired:
        console.print("[red]timeout[/red]")
    except Exception as e:
        console.print(f"[red]error: {e}[/red]")


def _remove_containers(container_names: list):
    """Remove Docker containers by name."""
    import subprocess
    
    for name in container_names:
        try:
            # Check if container exists
            result = subprocess.run(
                ["docker", "inspect", name],
                capture_output=True
            )
            if result.returncode != 0:
                console.print(f"  {name}: [dim]not found[/dim]")
                continue
            
            # Stop and remove
            subprocess.run(["docker", "stop", name], capture_output=True)
            subprocess.run(["docker", "rm", name], capture_output=True)
            console.print(f"  {name}: [green]removed[/green]")
        except Exception as e:
            console.print(f"  {name}: [red]error - {e}[/red]")


@click.command("serve")
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", "-p", default=5001, help="Port to run on")
@click.option("--debug", is_flag=True, help="Enable debug mode")
def serve(host: str, port: int, debug: bool):
    """
    Start the DC Overview web interface.
    
    This runs the Flask application that provides:
    - Server management (add/remove servers)
    - Prometheus target management  
    - Exporter deployment to workers
    - Monitoring status dashboard
    
    \b
    EXAMPLE:
        dc-overview serve                    # Run on port 5001
        dc-overview serve -p 8080            # Run on port 8080
        sudo dc-overview serve               # Run as root for SSH access
    
    \b
    ACCESS:
        Web UI: http://localhost:5001/
        API: http://localhost:5001/api/
    """
    from .app import app, init_db
    
    console.print(Panel(
        f"[bold green]DC Overview Web Interface[/bold green]\n\n"
        f"Running on: [cyan]http://{host}:{port}/[/cyan]\n"
        f"Press Ctrl+C to stop",
        title="DC Overview",
        border_style="green"
    ))
    
    # Initialize database
    with app.app_context():
        init_db()
    
    app.run(host=host, port=port, debug=debug)


@click.command("refresh-dashboards")
@click.option("--branch", "-b", default=None, help="GitHub branch to fetch from (default: uses DASHBOARD_BRANCH env or 'main')")
def refresh_dashboards(branch: str):
    """
    Refresh Grafana dashboards from GitHub.
    
    Re-imports all dashboards with latest versions from GitHub.
    Useful for testing dashboard changes without full reinstall.
    
    \b
    Examples:
        dc-overview refresh-dashboards                  # Uses DASHBOARD_BRANCH env or 'main'
        dc-overview refresh-dashboards --branch dev    # Fetch from dev branch
        DASHBOARD_BRANCH=dev dc-overview refresh-dashboards
    """
    import base64
    import json
    import urllib.request
    
    if branch:
        os.environ['DASHBOARD_BRANCH'] = branch
    
    branch_name = os.environ.get('DASHBOARD_BRANCH', 'main')
    console.print(f"\n[bold]Refreshing Dashboards from GitHub ({branch_name} branch)[/bold]\n")
    
    # Load config to get Grafana password
    config_path = DOCKER_CONFIG_DIR / "fleet-config.yaml"
    if not config_path.exists():
        console.print("[red]✗[/red] Fleet config not found. Run [cyan]sudo dc-overview setup[/cyan] first.")
        return
    
    try:
        config = FleetConfig.load(config_path)
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to load config: {e}")
        return
    
    from .fleet_manager import FleetManager
    manager = FleetManager(config)
    
    # Wait for Grafana and get datasource UID
    grafana_url = "http://localhost:3000"
    auth = f"admin:{config.grafana.admin_password}"
    auth_header = base64.b64encode(auth.encode()).decode()
    
    console.print("[dim]Connecting to Grafana...[/dim]")
    prometheus_uid = manager._wait_for_grafana_and_get_datasource_uid(grafana_url, auth_header)
    
    if not prometheus_uid:
        console.print("[red]✗[/red] Could not connect to Grafana or get Prometheus datasource")
        return
    
    console.print(f"[dim]Prometheus datasource UID: {prometheus_uid}[/dim]")
    
    dashboards = manager._get_dashboard_list()
    grafana_dash_dir = config.config_dir / "grafana" / "dashboards"
    
    imported = 0
    for dashboard in dashboards:
        name = dashboard["name"]
        console.print(f"  {name}...", end=" ")
        
        dashboard_json = manager._get_dashboard_json(dashboard)
        if not dashboard_json:
            console.print("[yellow]not found[/yellow]")
            continue
        
        try:
            # Parse and fix datasources
            dash_obj = json.loads(dashboard_json)
            dash_obj = manager._fix_dashboard_datasources(dash_obj, prometheus_uid)
            
            # Remove id to avoid conflicts
            if "id" in dash_obj:
                dash_obj["id"] = None
            
            # Write to file
            output_path = grafana_dash_dir / dashboard["local_file"]
            output_path.write_text(json.dumps(dash_obj, indent=2))
            console.print("[green]✓[/green]")
            imported += 1
        except Exception as e:
            console.print(f"[red]error: {str(e)[:50]}[/red]")
    
    console.print(f"\n[green]✓[/green] Refreshed {imported} dashboards")
    console.print("[dim]Grafana will auto-reload dashboards within 30 seconds[/dim]")


# Register commands
main.add_command(setup)
main.add_command(add_machine)
main.add_command(install_exporters)
main.add_command(status)
main.add_command(logs)
main.add_command(stop)
main.add_command(start)
main.add_command(upgrade)
main.add_command(restart)
main.add_command(add_target)
main.add_command(list_targets)
main.add_command(generate_compose)
main.add_command(deploy)
main.add_command(setup_ssl)
main.add_command(serve)
main.add_command(reset)
main.add_command(refresh_dashboards)


if __name__ == "__main__":
    main()
