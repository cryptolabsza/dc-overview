"""
DC Overview CLI - Command line interface with setup wizard
"""

import click
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

from . import __version__
from .wizard import SetupWizard
from .service import ServiceManager
from .exporters import ExporterInstaller
from .deploy import DeployManager, deploy_wizard
from .quickstart import run_quickstart

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="dc-overview")
def main():
    """
    DC Overview - GPU Datacenter Monitoring Suite
    
    Monitor your GPU datacenter with Prometheus, Grafana, and AI-powered insights.
    
    \b
    INSTALLATION MODES:
    
    For MASTER/MONITORING server (runs Prometheus + Grafana):
        dc-overview setup master
    
    For GPU WORKER nodes (runs exporters only):
        dc-overview setup worker
    
    \b
    QUICK START:
    
        dc-overview setup           # Interactive setup wizard
        dc-overview install-exporters   # Install exporters on current machine
        dc-overview status          # Check service status
    """
    pass


@click.command()
@click.argument("mode", type=click.Choice(["master", "worker", "auto"]), default="auto")
@click.option("--install-services", is_flag=True, help="Install as systemd services")
@click.option("--config-dir", default=None, help="Configuration directory")
@click.option("--non-interactive", is_flag=True, help="Use defaults, no prompts")
def setup(mode: str, install_services: bool, config_dir: str, non_interactive: bool):
    """
    Run the interactive setup wizard.
    
    \b
    MODES:
        master  - Install Prometheus, Grafana, and configure scraping
        worker  - Install exporters (node_exporter, dcgm-exporter, dc-exporter)
        auto    - Auto-detect based on GPU presence
    
    \b
    EXAMPLES:
        sudo dc-overview setup master --install-services
        sudo dc-overview setup worker --install-services
    """
    console.print()
    console.print(Panel.fit(
        "[bold cyan]DC Overview Setup Wizard[/bold cyan]\n"
        f"[dim]Version {__version__}[/dim]",
        border_style="cyan"
    ))
    console.print()
    
    wizard = SetupWizard(
        mode=mode,
        config_dir=config_dir,
        non_interactive=non_interactive
    )
    
    try:
        config = wizard.run()
        
        if install_services:
            if os.geteuid() != 0:
                console.print("[red]Error:[/red] Installing services requires root. Run with sudo.")
                sys.exit(1)
            
            service_mgr = ServiceManager(mode=config.get("mode", "worker"))
            service_mgr.install_all(config)
            console.print("\n[green]✓[/green] Services installed!")
            console.print("  Start with: [cyan]sudo systemctl start dc-overview[/cyan]")
        else:
            console.print("\n[green]✓[/green] Setup complete!")
            console.print("  Install services: [cyan]sudo dc-overview setup --install-services[/cyan]")
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Setup cancelled.[/yellow]")
        sys.exit(1)


@click.command("install-exporters")
@click.option("--node-exporter/--no-node-exporter", default=True, help="Install node_exporter")
@click.option("--dcgm-exporter/--no-dcgm-exporter", default=True, help="Install dcgm-exporter")
@click.option("--dc-exporter/--no-dc-exporter", default=True, help="Install dc-exporter")
def install_exporters(node_exporter: bool, dcgm_exporter: bool, dc_exporter: bool):
    """
    Install Prometheus exporters on current machine.
    
    Installs as native systemd services (not Docker) for compatibility
    with Vast.ai and RunPod.
    
    \b
    EXPORTERS:
        node_exporter   - CPU, RAM, disk metrics (port 9100)
        dcgm-exporter   - NVIDIA GPU metrics (port 9400)
        dc-exporter     - VRAM temps, hotspot temps (port 9500)
    
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
    
    if dcgm_exporter:
        installer.install_dcgm_exporter()
    
    if dc_exporter:
        installer.install_dc_exporter()
    
    console.print("\n[green]✓[/green] Exporters installed!")
    console.print("  Verify: [cyan]curl http://localhost:9100/metrics | head[/cyan]")


@click.command()
def status():
    """
    Show DC Overview status and services.
    """
    config_path = get_config_dir()
    
    console.print(Panel.fit(
        "[bold cyan]DC Overview Status[/bold cyan]",
        border_style="cyan"
    ))
    
    table = Table(show_header=False, box=None)
    table.add_column("Key", style="dim")
    table.add_column("Value")
    
    table.add_row("Version", __version__)
    table.add_row("Config Dir", str(config_path))
    
    console.print(table)
    console.print()
    
    # Check exporters
    console.print("[bold]Exporter Status:[/bold]")
    exporters = [
        ("node_exporter", 9100),
        ("dcgm-exporter", 9400),
        ("dc-exporter", 9500),
    ]
    
    exp_table = Table()
    exp_table.add_column("Service", style="cyan")
    exp_table.add_column("Port")
    exp_table.add_column("Status")
    
    import subprocess
    for name, port in exporters:
        # Check systemd status
        try:
            result = subprocess.run(
                ["systemctl", "is-active", name],
                capture_output=True, text=True
            )
            status = result.stdout.strip()
            if status == "active":
                status_str = "[green]✓ Running[/green]"
            elif status == "inactive":
                status_str = "[yellow]○ Stopped[/yellow]"
            else:
                status_str = f"[red]{status}[/red]"
        except Exception:
            status_str = "[dim]Not installed[/dim]"
        
        exp_table.add_row(name, str(port), status_str)
    
    console.print(exp_table)


@click.command()
@click.option("--follow", "-f", is_flag=True, help="Follow log output")
@click.option("--lines", "-n", default=50, help="Number of lines to show")
@click.argument("service", default="all")
def logs(follow: bool, lines: int, service: str):
    """
    View service logs.
    
    SERVICE can be: all, node_exporter, dcgm-exporter, dc-exporter, prometheus, grafana
    """
    import subprocess
    
    services = {
        "all": ["node_exporter", "dcgm-exporter", "dc-exporter"],
        "node_exporter": ["node_exporter"],
        "dcgm-exporter": ["dcgm-exporter"],
        "dc-exporter": ["dc-exporter"],
        "prometheus": ["prometheus"],
        "grafana": ["grafana"],
    }
    
    targets = services.get(service, [service])
    
    for svc in targets:
        console.print(f"\n[bold cyan]Logs for {svc}:[/bold cyan]")
        cmd = ["journalctl", "-u", svc, "-n", str(lines)]
        if follow:
            cmd.append("-f")
        subprocess.run(cmd)


@click.command("add-target")
@click.argument("ip")
@click.option("--name", default=None, help="Friendly name for the target")
@click.option("--ports", default="9100,9400,9500", help="Ports to scrape (comma-separated)")
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
def quickstart():
    """
    ⚡ One-command setup - does everything!
    
    Just answer a few questions and your monitoring will be set up.
    
    \b
    WHAT IT DOES:
        - Detects your GPUs
        - Installs exporters (node, dcgm, dc-exporter)
        - Sets up Prometheus & Grafana (if master)
        - Configures everything automatically
        - Optionally adds Vast.ai integration
    
    \b
    EXAMPLE:
        sudo dc-overview quickstart
    """
    run_quickstart()


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


# Register commands
main.add_command(quickstart)
main.add_command(add_machine)
main.add_command(setup)
main.add_command(install_exporters)
main.add_command(status)
main.add_command(logs)
main.add_command(add_target)
main.add_command(list_targets)
main.add_command(generate_compose)
main.add_command(deploy)
main.add_command(setup_ssl)


if __name__ == "__main__":
    main()
