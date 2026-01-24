"""
DC Overview Fleet Wizard
Collects ALL configuration upfront in one pass.
Ask once, deploy everywhere.
"""

import os
import subprocess
import shutil
import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

import questionary
from questionary import Style
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

from .fleet_config import (
    FleetConfig, Server, SSLConfig, SSLMode, SSHCredentials,
    BMCCredentials, AuthMethod, ComponentConfig, VastConfig,
    GrafanaConfig, IPMIMonitorConfig, get_local_ip
)

console = Console()

# Custom questionary style
custom_style = Style([
    ('qmark', 'fg:cyan bold'),
    ('question', 'bold'),
    ('answer', 'fg:cyan'),
    ('pointer', 'fg:cyan bold'),
    ('highlighted', 'fg:cyan bold'),
    ('selected', 'fg:green'),
    ('separator', 'fg:gray'),
])


class FleetWizard:
    """
    Interactive wizard that collects ALL configuration upfront.
    
    The goal is to ask the user for everything we need ONCE at the start,
    then use that configuration throughout the deployment without
    asking any more questions.
    """
    
    def __init__(self, config_dir: Path = None):
        self.config_dir = config_dir or Path("/etc/dc-overview")
        self.config = FleetConfig(config_dir=self.config_dir)
        self.config.master_ip = get_local_ip()
        # Cache for IPMI data import (to avoid reading database multiple times)
        self._ipmi_data_cache: Optional[Tuple[List[Dict], List[Dict]]] = None
        # Cache for existing proxy detection
        self._existing_proxy: Optional[Dict] = None
    
    def run(self) -> FleetConfig:
        """Run the complete wizard and return configuration."""
        
        self._show_welcome()
        
        # Step 1: Components
        self._collect_components()
        
        # Step 2: Passwords/Credentials (all at once)
        self._collect_credentials()
        
        # Step 3: Servers to monitor
        self._collect_servers()
        
        # Step 4: SSL Configuration
        self._collect_ssl_config()
        
        # Step 5: Review
        self._show_review()
        
        # Save config
        self.config.save()
        
        return self.config
    
    def _show_welcome(self):
        """Display welcome message with overview of what we'll collect."""
        console.print()
        console.print(Panel(
            "[bold cyan]DC Overview - Fleet Setup Wizard[/bold cyan]\n\n"
            "This wizard will collect all the information needed to set up\n"
            "your datacenter monitoring. [bold]We'll ask everything upfront[/bold],\n"
            "then handle the installation automatically.\n\n"
            "[bold]What we'll ask for:[/bold]\n"
            "  1. Which components to install (GPU monitoring, IPMI, Vast.ai)\n"
            "  2. Login credentials (Grafana password, SSH, BMC/IPMI)\n"
            "  3. Servers to monitor (IPs, machine names)\n"
            "  4. HTTPS/SSL configuration\n\n"
            "[dim]Press Ctrl+C at any time to cancel.[/dim]",
            border_style="cyan"
        ))
        console.print()
        
        questionary.press_any_key_to_continue(
            message="Press any key to continue...",
            style=custom_style
        ).ask()
    
    # ============ Step 1: Components ============

    def _detect_existing_ipmi(self) -> bool:
        """Detect if IPMI Monitor is already installed."""
        ipmi_config_dir = Path("/etc/ipmi-monitor")

        if not ipmi_config_dir.exists():
            return False

        # Check for running container
        try:
            result = subprocess.run(
                ["docker", "inspect", "ipmi-monitor"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _detect_existing_proxy(self) -> Optional[Dict]:
        """Detect if cryptolabs-proxy is already running and get its config."""
        try:
            result = subprocess.run(
                ["docker", "inspect", "cryptolabs-proxy", "--format", "{{.State.Status}}"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip() == "running":
                config = {"running": True}
                
                # Try to get domain from nginx config
                nginx_conf = Path("/etc/ipmi-monitor/nginx.conf")
                if nginx_conf.exists():
                    import re
                    content = nginx_conf.read_text()
                    match = re.search(r'server_name\s+([^;]+);', content)
                    if match:
                        domain = match.group(1).strip()
                        # Filter out placeholder values
                        if domain and domain not in ('_', 'localhost', ''):
                            config["domain"] = domain
                    
                    # Check SSL mode
                    if '/etc/letsencrypt/' in content:
                        config["ssl_mode"] = "letsencrypt"
                    elif '/etc/nginx/ssl/' in content or 'ssl_certificate' in content:
                        config["ssl_mode"] = "self_signed"
                
                # Check if SSL certs exist
                ssl_dir = Path("/etc/ipmi-monitor/ssl")
                if ssl_dir.exists():
                    config["ssl_dir"] = str(ssl_dir)
                
                return config
        except Exception:
            pass
        return None

    def _collect_components(self):
        """Ask which components to install."""
        console.print(Panel(
            "[bold]Step 1: Components to Install[/bold]",
            border_style="blue"
        ))

        # Detect GPUs on this machine
        has_local_gpu = self._detect_local_gpus() > 0

        if has_local_gpu:
            console.print(f"[dim]Detected GPUs on this machine[/dim]\n")

        # Detect existing IPMI Monitor installation
        ipmi_already_installed = self._detect_existing_ipmi()

        if ipmi_already_installed:
            console.print(f"[bold green]✓ IPMI Monitor already installed[/bold green]")
            console.print(f"[dim]We'll automatically integrate with your existing IPMI Monitor setup.[/dim]\n")

        components = questionary.checkbox(
            "Select components to install:",
            choices=[
                questionary.Choice(
                    "DC Overview (Prometheus + Grafana + GPU dashboards)",
                    value="dc_overview",
                    checked=True
                ),
                questionary.Choice(
                    "IPMI Monitor (BMC/IPMI server monitoring)" +
                    (" - [Already Installed]" if ipmi_already_installed else ""),
                    value="ipmi_monitor",
                    checked=ipmi_already_installed  # Auto-check if already installed
                ),
                questionary.Choice(
                    "Vast.ai Integration (Earnings & reliability metrics)",
                    value="vast_exporter",
                    checked=False
                ),
            ],
            style=custom_style
        ).ask()
        
        if not components:
            components = ["dc_overview"]
        
        self.config.components.dc_overview = "dc_overview" in components
        self.config.components.ipmi_monitor = "ipmi_monitor" in components
        self.config.components.vast_exporter = "vast_exporter" in components
        
        # Update dependent configs
        self.config.ipmi_monitor.enabled = self.config.components.ipmi_monitor
        self.config.vast.enabled = self.config.components.vast_exporter
        
        console.print()
    
    def _detect_local_gpus(self) -> int:
        """Detect number of GPUs on local machine."""
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
    
    # ============ Step 2: Credentials ============
    
    def _collect_credentials(self):
        """Collect ALL credentials upfront."""
        console.print(Panel(
            "[bold]Step 2: Credentials[/bold]\n\n"
            "We'll collect all passwords and credentials now.\n"
            "These are stored securely and used for automated deployment.",
            border_style="blue"
        ))
        
        # Site name
        self.config.site_name = questionary.text(
            "Site/Company name (for dashboard branding):",
            default="My GPU Farm",
            style=custom_style
        ).ask() or "My GPU Farm"
        
        # Grafana password
        console.print("\n[bold]Grafana Dashboard[/bold]")
        self.config.grafana.admin_password = questionary.password(
            "Grafana admin password:",
            validate=lambda x: len(x) >= 4 or "Password must be at least 4 characters",
            style=custom_style
        ).ask() or "admin"
        
        # IPMI Monitor password (only if enabled AND not already installed)
        if self.config.components.ipmi_monitor and not self._detect_existing_ipmi():
            console.print("\n[bold]IPMI Monitor[/bold]")
            console.print("[dim]Setting up a new IPMI Monitor installation[/dim]\n")

            self.config.ipmi_monitor.admin_password = questionary.password(
                "IPMI Monitor admin password:",
                validate=lambda x: len(x) >= 4 or "Password must be at least 4 characters",
                style=custom_style
            ).ask()

            # AI License (optional)
            console.print("\n[dim]AI Insights provides intelligent diagnostics (optional)[/dim]")
            has_ai = questionary.confirm(
                "Do you have a CryptoLabs AI license?",
                default=False,
                style=custom_style
            ).ask()

            if has_ai:
                self.config.ipmi_monitor.ai_license_key = questionary.password(
                    "CryptoLabs License Key:",
                    style=custom_style
                ).ask()
        elif self.config.components.ipmi_monitor and self._detect_existing_ipmi():
            # IPMI Monitor already installed - we'll just integrate with it
            console.print("\n[bold]IPMI Monitor[/bold]")
            console.print("[green]✓[/green] Using existing IPMI Monitor installation")
            console.print("[dim]No additional configuration needed - we'll import your servers automatically[/dim]")
        
        # SSH Credentials (for worker deployment)
        # If IPMI Monitor is installed, try to get SSH credentials from it
        ssh_username_default = "root"
        ssh_key_path_default = None
        has_complete_ipmi_ssh = False

        if self.config.components.ipmi_monitor and self._detect_existing_ipmi():
            servers, ssh_keys = self._import_ipmi_data()

            if servers and ssh_keys:
                # We have BOTH username AND keys from IPMI - auto-configure!
                ssh_username_default = servers[0].get("ssh_user", "root")
                ssh_key_path_default = ssh_keys[0].get("path")

                if ssh_key_path_default:
                    # Convert to DC Overview path if copied
                    key_name = Path(ssh_key_path_default).name
                    dc_key_path = Path("/etc/dc-overview/ssh_keys") / key_name
                    if dc_key_path.exists():
                        ssh_key_path_default = str(dc_key_path)
                        has_complete_ipmi_ssh = True

        if has_complete_ipmi_ssh:
            # We have everything from IPMI - validate the key first!
            console.print("\n[bold]SSH Access[/bold]")
            console.print(f"[dim]Validating SSH key from IPMI Monitor...[/dim]")
            
            # Validate the SSH key
            from .ssh_manager import SSHManager
            ssh_mgr = SSHManager(self.config_dir)
            key_valid, key_msg = ssh_mgr.validate_key(ssh_key_path_default)
            
            if key_valid:
                console.print(f"[green]✓[/green] SSH key validated")
                console.print(f"[dim]Username: {ssh_username_default}[/dim]")
                console.print(f"[dim]SSH Key: {ssh_key_path_default}[/dim]")
                
                # Test connection to first server if we have any
                if servers:
                    first_server = servers[0]
                    test_ip = first_server.get('server_ip') or first_server.get('bmc_ip')
                    if test_ip:
                        console.print(f"[dim]Testing connection to {first_server.get('name', test_ip)}...[/dim]")
                        if ssh_mgr.test_connection(test_ip, ssh_username_default, 22, ssh_key_path_default):
                            console.print(f"[green]✓[/green] SSH connection test successful")
                        else:
                            console.print(f"[yellow]⚠[/yellow] Could not connect to {test_ip}")
                            console.print(f"[dim]  The key may not be authorized on this server.[/dim]")
                            console.print(f"[dim]  Deployment will attempt to use password fallback if needed.[/dim]")
                
                console.print()
                self.config.ssh.username = ssh_username_default
                self.config.ssh.auth_method = AuthMethod.KEY
                self.config.ssh.key_path = ssh_key_path_default
                self.config.ssh_key_generated = True
            else:
                # Key is invalid/corrupted
                console.print(f"[red]✗[/red] SSH key validation failed")
                console.print(f"[yellow]  {key_msg}[/yellow]")
                console.print()
                
                # Ask user what to do
                fix_action = questionary.select(
                    "How would you like to proceed?",
                    choices=[
                        questionary.Choice("Use a different SSH key", value="different_key"),
                        questionary.Choice("Use SSH password instead", value="password"),
                        questionary.Choice("Generate a new SSH key", value="generate"),
                    ],
                    style=custom_style
                ).ask()
                
                if fix_action == "different_key":
                    new_key_path = questionary.text(
                        "Path to SSH private key:",
                        default=os.path.expanduser("~/.ssh/id_rsa"),
                        style=custom_style
                    ).ask()
                    
                    # Validate the new key
                    key_valid, key_msg = ssh_mgr.validate_key(new_key_path)
                    if key_valid:
                        console.print(f"[green]✓[/green] SSH key validated")
                        self.config.ssh.auth_method = AuthMethod.KEY
                        self.config.ssh.key_path = new_key_path
                        self.config.ssh_key_generated = True
                    else:
                        console.print(f"[red]✗[/red] {key_msg}")
                        console.print("[yellow]Falling back to password authentication[/yellow]")
                        self.config.ssh.auth_method = AuthMethod.PASSWORD
                        self.config.ssh.password = questionary.password(
                            "SSH password:",
                            style=custom_style
                        ).ask()
                
                elif fix_action == "password":
                    self.config.ssh.auth_method = AuthMethod.PASSWORD
                    self.config.ssh.password = questionary.password(
                        "SSH password (for all workers):",
                        style=custom_style
                    ).ask()
                
                else:  # generate
                    self.config.ssh.auth_method = AuthMethod.KEY
                    console.print("[dim]A new SSH key will be generated and deployed to workers[/dim]")
                    self.config.ssh.password = questionary.password(
                        "SSH password (needed once to deploy the new key):",
                        style=custom_style
                    ).ask()
                
                self.config.ssh.username = ssh_username_default
                has_complete_ipmi_ssh = False  # Fall through to normal handling if needed
        else:
            # Need to ask for SSH credentials
            console.print("\n[bold]SSH Access (for deploying to workers)[/bold]")
            console.print("[dim]Used to install exporters on GPU worker machines[/dim]\n")

            self.config.ssh.username = questionary.text(
                "SSH username:",
                default=ssh_username_default,
                style=custom_style
            ).ask() or ssh_username_default

            # Auto-select existing key if we found one from IPMI
            if ssh_key_path_default:
                auth_method = questionary.select(
                    "SSH authentication method:",
                    choices=[
                        questionary.Choice("Existing SSH Key (already has access to workers)", value="existing_key", checked=True),
                        questionary.Choice("SSH Key (will generate and deploy)", value="key"),
                        questionary.Choice("Password", value="password"),
                    ],
                    style=custom_style
                ).ask()
            else:
                auth_method = questionary.select(
                    "SSH authentication method:",
                    choices=[
                        questionary.Choice("Existing SSH Key (already has access to workers)", value="existing_key"),
                        questionary.Choice("SSH Key (will generate and deploy)", value="key"),
                        questionary.Choice("Password", value="password"),
                    ],
                    style=custom_style
                ).ask()

            if auth_method == "existing_key":
                self.config.ssh.auth_method = AuthMethod.KEY
                # Use imported key path from IPMI or default to ~/.ssh/id_rsa
                default_key = ssh_key_path_default or os.path.expanduser("~/.ssh/id_rsa")
                
                from .ssh_manager import SSHManager
                ssh_mgr = SSHManager(self.config_dir)

                # If we have a key from IPMI, allow just pressing Enter
                if ssh_key_path_default:
                    key_input = questionary.text(
                        "Path to SSH private key (press Enter to use IPMI Monitor key):",
                        default=default_key,
                        style=custom_style
                    ).ask()
                    # Accept empty input if we have a default
                    self.config.ssh.key_path = key_input or default_key
                else:
                    self.config.ssh.key_path = questionary.text(
                        "Path to SSH private key (already authorized on workers):",
                        default=default_key,
                        validate=lambda x: Path(x).exists() or f"Key not found: {x}",
                        style=custom_style
                    ).ask()
                
                # Validate the SSH key
                console.print(f"[dim]Validating SSH key...[/dim]")
                key_valid, key_msg = ssh_mgr.validate_key(self.config.ssh.key_path)
                
                if key_valid:
                    console.print(f"[green]✓[/green] SSH key validated")
                    self.config.ssh_key_generated = True  # Mark as already set up
                else:
                    console.print(f"[red]✗[/red] SSH key validation failed: {key_msg}")
                    
                    # Offer alternatives
                    retry = questionary.confirm(
                        "Try a different key?",
                        default=True,
                        style=custom_style
                    ).ask()
                    
                    if retry:
                        new_key_path = questionary.text(
                            "Path to SSH private key:",
                            default=os.path.expanduser("~/.ssh/id_rsa"),
                            style=custom_style
                        ).ask()
                        
                        key_valid, key_msg = ssh_mgr.validate_key(new_key_path)
                        if key_valid:
                            console.print(f"[green]✓[/green] SSH key validated")
                            self.config.ssh.key_path = new_key_path
                            self.config.ssh_key_generated = True
                        else:
                            console.print(f"[red]✗[/red] {key_msg}")
                            console.print("[yellow]⚠[/yellow] Proceeding anyway - deployment may fail")
                            self.config.ssh_key_generated = True
                    else:
                        console.print("[yellow]⚠[/yellow] Proceeding with potentially invalid key")
            elif auth_method == "key":
                self.config.ssh.auth_method = AuthMethod.KEY
                console.print("[dim]A new SSH key will be generated and deployed to workers[/dim]")
                self.config.ssh.password = questionary.password(
                    "SSH password (needed once to deploy the new key):",
                    style=custom_style
                ).ask()
            else:
                self.config.ssh.auth_method = AuthMethod.PASSWORD
                self.config.ssh.password = questionary.password(
                    "SSH password (for all workers):",
                    style=custom_style
                ).ask()
        
        self.config.ssh.port = int(questionary.text(
            "SSH port (for internal network):",
            default="22",
            validate=lambda x: x.isdigit() and 1 <= int(x) <= 65535,
            style=custom_style
        ).ask() or "22")
        
        # BMC/IPMI Credentials (only if IPMI Monitor enabled AND not already installed)
        if self.config.components.ipmi_monitor:
            if self._detect_existing_ipmi():
                # IPMI Monitor already has BMC credentials configured
                console.print("\n[bold]BMC/IPMI Access[/bold]")
                console.print("[green]✓[/green] Using BMC credentials from existing IPMI Monitor")
                console.print("[dim]BMC access already configured in IPMI Monitor[/dim]")
            else:
                # Setting up new IPMI Monitor - need BMC credentials
                console.print("\n[bold]BMC/IPMI Access (for server management)[/bold]")
                console.print("[dim]Used to monitor server health via IPMI[/dim]")
                console.print("[dim]You can set per-server credentials later when adding servers[/dim]\n")

                self.config.bmc.username = questionary.text(
                    "Default BMC username (for all servers):",
                    default="admin",
                    style=custom_style
                ).ask() or "admin"

                self.config.bmc.password = questionary.password(
                    "Default BMC password (for all servers):",
                    style=custom_style
                ).ask()
        
        # Vast.ai API Key
        if self.config.components.vast_exporter:
            console.print("\n[bold]Vast.ai Integration[/bold]")
            console.print("[dim]Get your API key from: https://cloud.vast.ai/account/[/dim]\n")
            
            self.config.vast.api_key = questionary.password(
                "Vast.ai API Key:",
                style=custom_style
            ).ask()
        
        console.print()
    
    # ============ Step 3: Servers ============

    def _import_ipmi_data(self) -> Tuple[List[Dict], List[Dict]]:
        """Import servers and SSH keys from existing IPMI Monitor installation.

        Returns:
            Tuple of (servers, ssh_keys)
        """
        # Return cached data if already imported
        if self._ipmi_data_cache is not None:
            return self._ipmi_data_cache

        ipmi_config_dir = Path("/etc/ipmi-monitor")
        servers = []
        ssh_keys = []

        if not ipmi_config_dir.exists():
            self._ipmi_data_cache = (servers, ssh_keys)
            return servers, ssh_keys

        # Try to import from servers.yaml first (Docker deployment)
        yaml_path = ipmi_config_dir / "servers.yaml"
        if yaml_path.exists():
            try:
                import yaml
                with open(yaml_path, 'r') as f:
                    config = yaml.safe_load(f)
                    if config and 'servers' in config:
                        for server in config['servers']:
                            servers.append({
                                "name": server.get('name'),
                                "bmc_ip": server.get('bmc_ip'),
                                "server_ip": server.get('server_ip'),
                                "ssh_user": server.get('ssh_user', 'root'),
                                "ssh_port": server.get('ssh_port', 22)
                            })
                console.print(f"[dim]Imported from servers.yaml[/dim]")
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] Could not read servers.yaml: {e}")

        # Try database for SSH keys (always check, even if YAML loaded servers)
        # Check multiple possible database locations
        db_paths = [
            ipmi_config_dir / "data" / "ipmi_monitor.db",
            ipmi_config_dir / "ipmi_monitor.db",
            Path("/var/lib/ipmi-monitor/ipmi_monitor.db"),
        ]
        
        db_path = None
        for p in db_paths:
            if p.exists():
                db_path = p
                console.print(f"[dim]Found IPMI Monitor database: {db_path}[/dim]")
                break
        
        if db_path:
            try:
                conn = sqlite3.connect(str(db_path))
                cursor = conn.cursor()

                # Import servers - try to get as much data as possible
                try:
                    # First check what columns exist in the server table
                    cursor.execute("PRAGMA table_info(server)")
                    columns = {row[1]: row[0] for row in cursor.fetchall()}

                    # Build query based on available columns
                    select_cols = []
                    col_mapping = {}

                    if 'name' in columns:
                        select_cols.append('name')
                        col_mapping['name'] = len(select_cols) - 1
                    if 'hostname' in columns:
                        select_cols.append('hostname')
                        col_mapping['hostname'] = len(select_cols) - 1
                    if 'bmc_ip' in columns:
                        select_cols.append('bmc_ip')
                        col_mapping['bmc_ip'] = len(select_cols) - 1
                    if 'server_ip' in columns:
                        select_cols.append('server_ip')
                        col_mapping['server_ip'] = len(select_cols) - 1
                    if 'ssh_ip' in columns:
                        select_cols.append('ssh_ip')
                        col_mapping['ssh_ip'] = len(select_cols) - 1
                    if 'ssh_user' in columns:
                        select_cols.append('ssh_user')
                        col_mapping['ssh_user'] = len(select_cols) - 1
                    if 'ssh_username' in columns:
                        select_cols.append('ssh_username')
                        col_mapping['ssh_username'] = len(select_cols) - 1
                    if 'ssh_port' in columns:
                        select_cols.append('ssh_port')
                        col_mapping['ssh_port'] = len(select_cols) - 1

                    if select_cols:
                        query = f"SELECT {', '.join(select_cols)} FROM server"
                        cursor.execute(query)

                        for row in cursor.fetchall():
                            # Get name (prefer 'name', fallback to 'hostname')
                            name = None
                            if 'name' in col_mapping:
                                name = row[col_mapping['name']]
                            elif 'hostname' in col_mapping:
                                name = row[col_mapping['hostname']]

                            # Get server IP (prefer 'server_ip', fallback to 'ssh_ip')
                            server_ip = None
                            if 'server_ip' in col_mapping:
                                server_ip = row[col_mapping['server_ip']]
                            elif 'ssh_ip' in col_mapping:
                                server_ip = row[col_mapping['ssh_ip']]

                            # Get SSH user (prefer 'ssh_user', fallback to 'ssh_username')
                            ssh_user = "root"
                            if 'ssh_user' in col_mapping:
                                ssh_user = row[col_mapping['ssh_user']] or "root"
                            elif 'ssh_username' in col_mapping:
                                ssh_user = row[col_mapping['ssh_username']] or "root"

                            # Get BMC IP
                            bmc_ip = None
                            if 'bmc_ip' in col_mapping:
                                bmc_ip = row[col_mapping['bmc_ip']]

                            # Get SSH port
                            ssh_port = 22
                            if 'ssh_port' in col_mapping:
                                ssh_port = row[col_mapping['ssh_port']] or 22

                            if name and server_ip:
                                servers.append({
                                    "name": name,
                                    "bmc_ip": bmc_ip,
                                    "server_ip": server_ip,
                                    "ssh_user": ssh_user,
                                    "ssh_port": ssh_port
                                })
                except Exception as e:
                    console.print(f"[yellow]⚠[/yellow] Could not query server table: {e}")

                # Import SSH keys from database
                # ipmi-monitor stores key_content in DB, we need to write to file
                try:
                    cursor.execute("SELECT id, name, key_content FROM ssh_key")
                    rows = cursor.fetchall()
                    console.print(f"[dim]Found {len(rows)} SSH keys in database[/dim]")
                    
                    if rows:
                        dc_ssh_dir = Path("/etc/dc-overview/ssh_keys")
                        dc_ssh_dir.mkdir(parents=True, exist_ok=True)
                        
                        for row in rows:
                            key_id, key_name, key_content = row
                            if key_content:
                                # Write key content to file - preserve exact format
                                safe_name = key_name.replace(" ", "-").lower()
                                key_file = dc_ssh_dir / f"{safe_name}.pem"
                                
                                # Normalize line endings and ensure proper format
                                key_content_clean = key_content.replace('\r\n', '\n').strip()
                                if not key_content_clean.endswith('\n'):
                                    key_content_clean += '\n'
                                
                                key_file.write_text(key_content_clean)
                                os.chmod(key_file, 0o600)
                                
                                ssh_keys.append({
                                    "id": key_id,
                                    "name": key_name,
                                    "path": str(key_file)
                                })
                                console.print(f"[green]✓[/green] Imported SSH key: {key_name} -> {key_file}")
                            else:
                                console.print(f"[yellow]⚠[/yellow] SSH key '{key_name}' has no content")
                except Exception as e:
                    console.print(f"[yellow]⚠[/yellow] Could not import SSH keys from database: {e}")

                conn.close()
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] Could not connect to IPMI Monitor database: {e}")
                self._ipmi_data_cache = (servers, ssh_keys)
                return servers, ssh_keys

        # Import SSH keys from ssh_keys directory
        ssh_keys_dir = ipmi_config_dir / "ssh_keys"
        if ssh_keys_dir.exists():
            dc_ssh_dir = Path("/etc/dc-overview/ssh_keys")
            dc_ssh_dir.mkdir(parents=True, exist_ok=True)

            for key_file in ssh_keys_dir.iterdir():
                if key_file.is_file() and not key_file.name.startswith('.'):
                    ssh_keys.append({
                        "id": None,
                        "name": key_file.stem,  # filename without extension
                        "path": str(key_file)
                    })
                    try:
                        # Copy to DC Overview directory
                        shutil.copy2(key_file, dc_ssh_dir / key_file.name)
                        os.chmod(dc_ssh_dir / key_file.name, 0o600)
                    except Exception as e:
                        console.print(f"[yellow]⚠[/yellow] Could not copy SSH key {key_file.name}: {e}")

        # Cache the result so we don't read database multiple times
        self._ipmi_data_cache = (servers, ssh_keys)
        return servers, ssh_keys

    def _collect_servers(self):
        """Collect list of servers to monitor."""
        console.print(Panel(
            "[bold]Step 3: Servers to Monitor[/bold]\n\n"
            "Add the GPU workers you want to monitor.\n"
            "We'll automatically install exporters on each one.",
            border_style="blue"
        ))

        # If IPMI Monitor is selected and already installed, offer to import
        imported_servers = []
        if self.config.components.ipmi_monitor and self._detect_existing_ipmi():
            console.print("[bold green]✓ Detecting existing IPMI Monitor data...[/bold green]\n")

            servers, ssh_keys = self._import_ipmi_data()

            if servers:
                console.print(f"[green]✓[/green] Found {len(servers)} servers in IPMI Monitor")
                if ssh_keys:
                    console.print(f"[green]✓[/green] Found {len(ssh_keys)} SSH keys")
                console.print()

                import_ipmi = questionary.confirm(
                    f"Import {len(servers)} servers from IPMI Monitor?",
                    default=True,
                    style=custom_style
                ).ask()

                if import_ipmi:
                    # Add imported servers to config
                    for server_data in servers:
                        server = Server(
                            name=server_data["name"],
                            server_ip=server_data["server_ip"],
                            bmc_ip=server_data.get("bmc_ip"),
                            ssh_user=server_data.get("ssh_user", self.config.ssh.username),
                            ssh_port=server_data.get("ssh_port", self.config.ssh.port)
                        )
                        self.config.servers.append(server)

                    imported_servers = servers
                    console.print(f"[green]✓[/green] Imported {len(servers)} servers\n")

        # If we have imported servers, ask if user wants to add more
        if imported_servers:
            add_more = questionary.confirm(
                "Add more servers?",
                default=False,
                style=custom_style
            ).ask()

            if not add_more:
                console.print()
                return

        add_method = questionary.select(
            "How would you like to add servers?",
            choices=[
                questionary.Choice("Import from text (recommended for many servers)", value="import"),
                questionary.Choice("Enter servers manually", value="manual"),
                questionary.Choice("Skip for now (add later)", value="skip"),
            ],
            style=custom_style
        ).ask()

        if add_method == "import":
            self._import_servers()
        elif add_method == "manual":
            self._add_servers_manual()

        console.print()
    
    def _import_servers(self):
        """Import servers from text input."""
        has_ipmi = self.config.components.ipmi_monitor
        
        if has_ipmi:
            format_help = """
[bold]Import Format[/bold]

[cyan]Option 1: Just server IPs (SSH only)[/cyan]
  192.168.1.101
  192.168.1.102
  192.168.1.103

[cyan]Option 2: Server IP + BMC IP[/cyan]
  192.168.1.101,192.168.1.83
  192.168.1.102,192.168.1.85
  192.168.1.103,192.168.1.88

[cyan]Option 3: Name, Server IP, BMC IP[/cyan]
  gpu-01,192.168.1.101,192.168.1.83
  gpu-02,192.168.1.102,192.168.1.85
  gpu-03,192.168.1.103,192.168.1.88

[cyan]Option 4: Name, Server IP, BMC IP, BMC User, BMC Pass[/cyan]
  master,192.168.1.100,192.168.1.83,root,password
  gpu-01,192.168.1.101,192.168.1.85,admin,password

[dim]Paste your list below, then press Enter on an empty line.[/dim]
"""
        else:
            format_help = """
[bold]Import Format[/bold]

[cyan]Option 1: Just IPs[/cyan]
  192.168.1.101
  192.168.1.102
  192.168.1.103

[cyan]Option 2: Name, IP[/cyan]
  gpu-01,192.168.1.101
  gpu-02,192.168.1.102
  gpu-03,192.168.1.103

[dim]Paste your list below, then press Enter on an empty line.[/dim]
"""
        
        console.print(Panel(format_help, border_style="cyan"))
        console.print("\n[bold]Paste your server list:[/bold]")
        
        lines = []
        while True:
            line = questionary.text("", style=custom_style).ask()
            if not line or line.strip() == "":
                break
            lines.append(line.strip())
        
        if not lines:
            console.print("[yellow]No servers added.[/yellow]")
            return
        
        # Parse lines
        for i, line in enumerate(lines):
            if not line or line.startswith("#"):
                continue
            
            parts = [p.strip() for p in line.split(",")]
            
            # Initialize variables
            name = None
            server_ip = None
            bmc_ip = None
            bmc_user = None
            bmc_password = None
            
            if len(parts) == 1:
                # Just IP
                server_ip = parts[0]
                name = f"server-{i+1:02d}"
            elif len(parts) == 2:
                # Could be name,ip or ip,bmc_ip
                if self._looks_like_ip(parts[0]) and self._looks_like_ip(parts[1]):
                    # ip,bmc_ip
                    server_ip = parts[0]
                    bmc_ip = parts[1]
                    name = f"server-{i+1:02d}"
                else:
                    # name,ip
                    name = parts[0]
                    server_ip = parts[1]
            elif len(parts) == 3:
                # name,ip,bmc_ip
                name = parts[0]
                server_ip = parts[1]
                bmc_ip = parts[2] if parts[2] else None
            elif len(parts) == 4:
                # name,ip,bmc_ip,bmc_user
                name = parts[0]
                server_ip = parts[1]
                bmc_ip = parts[2] if parts[2] else None
                bmc_user = parts[3] if parts[3] else None
            elif len(parts) >= 5:
                # name,ip,bmc_ip,bmc_user,bmc_password
                name = parts[0]
                server_ip = parts[1]
                bmc_ip = parts[2] if parts[2] else None
                bmc_user = parts[3] if parts[3] else None
                bmc_password = parts[4] if parts[4] else None
            else:
                continue
            
            if not self._looks_like_ip(server_ip):
                continue
            
            self.config.add_server(
                name=name,
                server_ip=server_ip,
                bmc_ip=bmc_ip,
                bmc_user=bmc_user,
                bmc_password=bmc_password,
            )
            
            # Show credential info if per-server credentials were provided
            if bmc_user:
                console.print(f"  [green]✓[/green] Added: {name} ({server_ip}) [dim]BMC user: {bmc_user}[/dim]")
            else:
                console.print(f"  [green]✓[/green] Added: {name} ({server_ip})")
        
        console.print(f"\n[green]✓[/green] Added {len(self.config.servers)} servers")
    
    def _add_servers_manual(self):
        """Add servers one by one."""
        has_ipmi = self.config.components.ipmi_monitor
        
        while True:
            console.print()
            name = questionary.text(
                f"Server name (e.g., gpu-{len(self.config.servers)+1:02d}):",
                default=f"server-{len(self.config.servers)+1:02d}",
                style=custom_style
            ).ask()
            
            if not name:
                break
            
            server_ip = questionary.text(
                "Server IP (for SSH/exporters):",
                validate=lambda x: self._looks_like_ip(x) or "Invalid IP format",
                style=custom_style
            ).ask()
            
            if not server_ip:
                break
            
            bmc_ip = None
            bmc_user = None
            bmc_password = None
            
            if has_ipmi:
                bmc_ip = questionary.text(
                    "BMC/IPMI IP (or leave empty to skip):",
                    default="",
                    style=custom_style
                ).ask()
                
                if bmc_ip and not self._looks_like_ip(bmc_ip):
                    bmc_ip = None
                
                # Ask for per-server BMC credentials if different from default
                if bmc_ip:
                    use_custom_bmc = questionary.confirm(
                        f"Use different BMC credentials for {name}? (default: {self.config.bmc.username})",
                        default=False,
                        style=custom_style
                    ).ask()
                    
                    if use_custom_bmc:
                        bmc_user = questionary.text(
                            f"BMC username for {name}:",
                            default=self.config.bmc.username,
                            style=custom_style
                        ).ask()
                        
                        bmc_password = questionary.password(
                            f"BMC password for {name}:",
                            style=custom_style
                        ).ask()
            
            self.config.add_server(
                name=name,
                server_ip=server_ip,
                bmc_ip=bmc_ip or None,
                bmc_user=bmc_user,
                bmc_password=bmc_password,
            )
            console.print(f"[green]✓[/green] Added: {name}")
            
            if not questionary.confirm("Add another server?", default=True, style=custom_style).ask():
                break
    
    def _looks_like_ip(self, s: str) -> bool:
        """Check if string looks like an IP address."""
        if not s:
            return False
        parts = s.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    
    # ============ Step 4: SSL ============
    
    def _collect_ssl_config(self):
        """Collect SSL/HTTPS configuration."""
        console.print(Panel(
            "[bold]Step 4: HTTPS Configuration[/bold]\n\n"
            "Set up secure access to your dashboards.",
            border_style="blue"
        ))
        
        # Check for existing cryptolabs-proxy
        self._existing_proxy = self._detect_existing_proxy()
        
        if self._existing_proxy and self._existing_proxy.get("running"):
            console.print("[bold green]✓ CryptoLabs Proxy Already Running![/bold green]")
            console.print("[dim]DC Overview will be added to your existing proxy configuration.[/dim]\n")
            
            # Show detected config
            if self._existing_proxy.get("domain"):
                console.print(f"  Domain: [cyan]{self._existing_proxy['domain']}[/cyan]")
                self.config.ssl.domain = self._existing_proxy["domain"]
            
            ssl_mode = self._existing_proxy.get("ssl_mode", "self_signed")
            if ssl_mode == "letsencrypt":
                console.print("  SSL: [cyan]Let's Encrypt[/cyan]")
                self.config.ssl.mode = SSLMode.LETSENCRYPT
            else:
                console.print("  SSL: [cyan]Self-signed certificate[/cyan]")
                self.config.ssl.mode = SSLMode.SELF_SIGNED
            
            self.config.ssl.external_port = 443
            self.config.ssl.use_existing_proxy = True
            console.print("\n[dim]No additional SSL configuration needed.[/dim]")
            console.print()
            return
        
        has_domain = questionary.confirm(
            "Do you have a domain name pointing to this server?",
            default=False,
            style=custom_style
        ).ask()
        
        if has_domain:
            self.config.ssl.domain = questionary.text(
                "Enter your domain name:",
                validate=lambda x: len(x) > 3 and "." in x,
                style=custom_style
            ).ask()
            
            if self.config.ssl.domain:
                console.print("\n[bold yellow]Let's Encrypt Requirements:[/bold yellow]")
                console.print("  • Port [cyan]80[/cyan] must be open (for certificate verification)")
                console.print("  • Port [cyan]443[/cyan] must be open (for HTTPS)")
                console.print("  • DNS must already point to this server's IP")
                console.print("  • Both ports must stay open for auto-renewal\n")
                
                use_letsencrypt = questionary.confirm(
                    "Use Let's Encrypt for trusted certificate?",
                    default=False,
                    style=custom_style
                ).ask()
                
                if use_letsencrypt:
                    self.config.ssl.mode = SSLMode.LETSENCRYPT
                    self.config.ssl.email = questionary.text(
                        "Email for certificate notifications:",
                        validate=lambda x: "@" in x,
                        style=custom_style
                    ).ask()
                else:
                    self.config.ssl.mode = SSLMode.SELF_SIGNED
                    console.print("[dim]Using self-signed certificate (browser will show warning)[/dim]")
        else:
            self.config.ssl.mode = SSLMode.SELF_SIGNED
            console.print("[dim]Using self-signed certificate for IP access[/dim]")
        
        # Ask about external port mapping
        console.print("\n[bold]External Port Configuration[/bold]")
        console.print("[dim]If your router forwards a different port to this server's port 443[/dim]")
        console.print("[dim]Example: Router port 8443 → Server port 443[/dim]\n")
        
        different_port = questionary.confirm(
            "Is the external HTTPS port different from 443?",
            default=False,
            style=custom_style
        ).ask()
        
        if different_port:
            external_port = questionary.text(
                "External HTTPS port (the port users connect to):",
                default="8443",
                validate=lambda x: x.isdigit() and 1 <= int(x) <= 65535,
                style=custom_style
            ).ask()
            self.config.ssl.external_port = int(external_port)
            console.print(f"[dim]Grafana will be configured for external port {external_port}[/dim]")
        else:
            self.config.ssl.external_port = 443
        
        console.print()
    
    # ============ Step 5: Review ============
    
    def _show_review(self):
        """Show configuration review before deployment."""
        console.print(Panel(
            "[bold green]Configuration Complete![/bold green]\n\n"
            "Here's a summary of what will be deployed:",
            border_style="green"
        ))
        
        # Components table
        comp_table = Table(title="Components", show_header=False)
        comp_table.add_column("Component", style="cyan")
        comp_table.add_column("Status")
        
        comp_table.add_row(
            "DC Overview (Prometheus + Grafana)",
            "[green]✓ Enabled[/green]" if self.config.components.dc_overview else "[dim]Disabled[/dim]"
        )
        comp_table.add_row(
            "IPMI Monitor",
            "[green]✓ Enabled[/green]" if self.config.components.ipmi_monitor else "[dim]Disabled[/dim]"
        )
        comp_table.add_row(
            "Vast.ai Integration",
            "[green]✓ Enabled[/green]" if self.config.components.vast_exporter else "[dim]Disabled[/dim]"
        )
        
        console.print(comp_table)
        console.print()
        
        # Configuration table
        config_table = Table(title="Configuration", show_header=False)
        config_table.add_column("Setting", style="dim")
        config_table.add_column("Value")
        
        config_table.add_row("Site Name", self.config.site_name)
        config_table.add_row("Master IP", self.config.master_ip or "auto-detect")
        config_table.add_row("SSH User", self.config.ssh.username)
        config_table.add_row("SSH Auth", self.config.ssh.auth_method.value)
        
        if self.config.components.ipmi_monitor:
            config_table.add_row("BMC User", self.config.bmc.username)
        
        ssl_mode = "Let's Encrypt" if self.config.ssl.mode == SSLMode.LETSENCRYPT else "Self-signed"
        if self.config.ssl.domain:
            config_table.add_row("Domain", self.config.ssl.domain)
        config_table.add_row("SSL Mode", ssl_mode)
        if self.config.ssl.external_port != 443:
            config_table.add_row("External Port", str(self.config.ssl.external_port))
        
        console.print(config_table)
        console.print()
        
        # Servers table
        if self.config.servers:
            srv_table = Table(title=f"Servers ({len(self.config.servers)})")
            srv_table.add_column("Name", style="cyan")
            srv_table.add_column("Server IP")
            if self.config.components.ipmi_monitor:
                srv_table.add_column("BMC IP")
                srv_table.add_column("BMC User")
            
            for server in self.config.servers[:10]:  # Show first 10
                if self.config.components.ipmi_monitor:
                    # Show per-server BMC user or default
                    bmc_user = server.bmc_user or self.config.bmc.username
                    bmc_user_display = bmc_user if server.bmc_user else f"[dim]{bmc_user}[/dim]"
                    srv_table.add_row(
                        server.name, 
                        server.server_ip, 
                        server.bmc_ip or "—",
                        bmc_user_display
                    )
                else:
                    srv_table.add_row(server.name, server.server_ip)
            
            if len(self.config.servers) > 10:
                remaining = len(self.config.servers) - 10
                if self.config.components.ipmi_monitor:
                    srv_table.add_row(f"... and {remaining} more", "", "", "")
                else:
                    srv_table.add_row(f"... and {remaining} more", "")
            
            console.print(srv_table)
        else:
            console.print("[yellow]No servers added.[/yellow] You can add them later.")
        
        console.print()
        
        # Dashboards that will be installed
        dash_table = Table(title="Dashboards to Install", show_header=False)
        dash_table.add_column("Dashboard", style="cyan")
        
        if self.config.components.dc_overview:
            dash_table.add_row("DC Overview (main dashboard)")
            dash_table.add_row("Node Exporter Full (CPU/RAM/disk)")
            dash_table.add_row("NVIDIA DCGM Exporter (GPU metrics)")
        
        if self.config.components.ipmi_monitor:
            dash_table.add_row("IPMI Monitor (server health)")
        
        if self.config.components.vast_exporter:
            dash_table.add_row("Vast Dashboard (earnings/reliability)")
        
        console.print(dash_table)
        console.print()
        
        # Confirm
        proceed = questionary.confirm(
            "Ready to deploy?",
            default=True,
            style=custom_style
        ).ask()
        
        if not proceed:
            console.print("[yellow]Deployment cancelled.[/yellow]")
            raise KeyboardInterrupt()


def run_fleet_wizard(config_dir: Path = None) -> FleetConfig:
    """Run the fleet wizard and return configuration."""
    wizard = FleetWizard(config_dir)
    return wizard.run()
