"""
DC Overview Fleet Manager
Orchestrates deployment using collected configuration.
No more questions - just deploy.
"""

import os
import subprocess
import shutil
import time
import json
import urllib.request
import urllib.error
import base64
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
import yaml

from .fleet_config import FleetConfig, Server, SSLMode, AuthMethod, get_local_ip
from .prerequisites import PrerequisitesInstaller
from .ssh_manager import SSHManager

console = Console()


class FleetManager:
    """
    Orchestrates the complete fleet deployment.
    Uses configuration collected by FleetWizard.
    """
    
    def __init__(self, config: FleetConfig):
        self.config = config
        self.ssh = SSHManager(config.config_dir)
        self.prerequisites = PrerequisitesInstaller()
    
    def deploy(self) -> bool:
        """
        Run the complete deployment.
        This is the main entry point after configuration is collected.
        """
        console.print(Panel(
            "[bold cyan]Deploying DC Overview Fleet[/bold cyan]\n\n"
            "This will:\n"
            "  1. Install prerequisites (Docker, nginx, etc.)\n"
            "  2. Generate SSH keys and deploy to workers\n"
            "  3. Start Prometheus, Grafana, and other services\n"
            "  4. Install exporters on all workers\n"
            "  5. Configure dashboards and reverse proxy",
            border_style="cyan"
        ))
        console.print()
        
        try:
            # Step 1: Prerequisites
            self._install_prerequisites()
            
            # Step 2: SSH Keys
            self._setup_ssh_keys()
            
            # Step 3: Start core services (Prometheus, Grafana)
            if self.config.components.dc_overview:
                self._deploy_prometheus_grafana()
            
            # Step 4: Deploy to workers
            if self.config.servers:
                self._deploy_to_workers()
            
            # Step 5: Configure Prometheus scrape targets
            self._configure_prometheus_targets()
            
            # Step 6: Import dashboards
            self._import_dashboards()
            
            # Step 7: IPMI Monitor (if enabled)
            if self.config.components.ipmi_monitor:
                self._deploy_ipmi_monitor()
            
            # Step 8: Vast.ai exporter (if enabled)
            if self.config.components.vast_exporter:
                self._deploy_vast_exporter()
            
            # Step 9: SSL/Reverse Proxy
            self._setup_reverse_proxy()
            
            # Done!
            self._show_completion()
            return True
            
        except Exception as e:
            console.print(f"\n[red]Deployment failed:[/red] {e}")
            return False
    
    # ============ Step 1: Prerequisites ============
    
    def _install_prerequisites(self):
        """Install required system packages."""
        console.print("\n[bold]Step 1: Installing Prerequisites[/bold]\n")
        
        self.prerequisites.install_all(
            docker=self.config.components.dc_overview,
            nginx=True,
            ipmitool=self.config.components.ipmi_monitor,
            certbot=self.config.ssl.mode == SSLMode.LETSENCRYPT,
        )
    
    # ============ Step 2: SSH Keys ============
    
    def _setup_ssh_keys(self):
        """Generate and deploy SSH keys to workers."""
        if not self.config.servers:
            return
        
        console.print("\n[bold]Step 2: Setting up SSH Keys[/bold]\n")
        
        # Check if using existing key that already has access
        if self.config.ssh_key_generated and self.config.ssh.key_path:
            console.print(f"[dim]Using existing SSH key: {self.config.ssh.key_path}[/dim]")
            console.print("[green]✓[/green] SSH key already configured")
            return
        
        # Generate key if not using existing
        if not self.config.ssh.key_path:
            key_path, pub_key = self.ssh.generate_key()
            self.config.ssh.key_path = key_path
        
        # Deploy to workers (only if we have password to do so)
        if self.config.ssh.password:
            console.print("[dim]Deploying SSH keys to workers...[/dim]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                task = progress.add_task("Deploying keys...", total=len(self.config.servers))
                
                for server in self.config.servers:
                    progress.update(task, description=f"Deploying to {server.name}...")
                    
                    creds = self.config.get_server_ssh_creds(server)
                    
                    success = self.ssh.deploy_key_with_password(
                        host=server.server_ip,
                        username=creds.username,
                        password=creds.password,
                        port=creds.port,
                    )
                    
                    progress.advance(task)
            
            self.config.ssh_key_generated = True
            console.print("[green]✓[/green] SSH keys deployed")
        else:
            console.print("[dim]No password provided - assuming SSH key already deployed[/dim]")
            self.config.ssh_key_generated = True
    
    # ============ Step 3: Prometheus + Grafana ============
    
    def _deploy_prometheus_grafana(self):
        """Deploy Prometheus and Grafana via Docker Compose."""
        console.print("\n[bold]Step 3: Starting Prometheus & Grafana[/bold]\n")
        
        compose_dir = self.config.config_dir
        compose_dir.mkdir(parents=True, exist_ok=True)
        
        # Create docker-compose.yml
        compose_content = self._generate_docker_compose()
        (compose_dir / "docker-compose.yml").write_text(compose_content)
        
        # Create prometheus.yml (initial, will be updated later)
        prometheus_content = self._generate_prometheus_config()
        (compose_dir / "prometheus.yml").write_text(prometheus_content)
        
        # Create recording_rules.yml for unified GPU metrics
        recording_rules = self._generate_recording_rules()
        (compose_dir / "recording_rules.yml").write_text(recording_rules)
        
        # Create grafana provisioning directories
        grafana_dir = compose_dir / "grafana"
        (grafana_dir / "provisioning" / "datasources").mkdir(parents=True, exist_ok=True)
        (grafana_dir / "provisioning" / "dashboards").mkdir(parents=True, exist_ok=True)
        (grafana_dir / "dashboards").mkdir(parents=True, exist_ok=True)
        
        # Datasource config
        datasource_config = """apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
"""
        (grafana_dir / "provisioning" / "datasources" / "prometheus.yml").write_text(datasource_config)
        
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
        (grafana_dir / "provisioning" / "dashboards" / "default.yml").write_text(dashboard_config)
        
        # Start services
        with Progress(SpinnerColumn(), TextColumn("Starting services..."), console=console) as progress:
            progress.add_task("", total=None)
            
            result = subprocess.run(
                ["docker", "compose", "up", "-d"],
                cwd=compose_dir,
                capture_output=True,
                text=True
            )
        
        if result.returncode == 0:
            console.print("[green]✓[/green] Prometheus running on port 9090")
            console.print("[green]✓[/green] Grafana running on port 3000")
        else:
            console.print(f"[red]Error:[/red] {result.stderr[:200]}")
    
    def _generate_docker_compose(self) -> str:
        """Generate docker-compose.yml content."""
        # Determine the ROOT_URL based on domain and external port
        external_port = self.config.ssl.external_port
        domain = self.config.ssl.domain or "%(domain)s"
        
        # If using non-standard port, include it in URL
        if external_port and external_port != 443:
            root_url = f"https://{domain}:{external_port}/grafana/"
        else:
            root_url = f"%(protocol)s://{domain}/grafana/"
        
        return f"""version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./recording_rules.yml:/etc/prometheus/recording_rules.yml:ro
      - prometheus-data:/prometheus
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.retention.time={self.config.prometheus.retention_days}d"
      - "--web.enable-lifecycle"
    extra_hosts:
      - "host.docker.internal:host-gateway"
    networks:
      - monitoring

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
      - ./grafana/dashboards:/var/lib/grafana/dashboards:ro
    environment:
      - GF_SECURITY_ADMIN_PASSWORD={self.config.grafana.admin_password}
      - GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-piechart-panel
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_SERVER_ROOT_URL={root_url}
      - GF_SERVER_SERVE_FROM_SUB_PATH=true
    depends_on:
      - prometheus
    networks:
      - monitoring

volumes:
  prometheus-data:
  grafana-data:

networks:
  monitoring:
    driver: bridge
"""
    
    def _generate_prometheus_config(self) -> str:
        """Generate initial prometheus.yml."""
        master_ip = self.config.master_ip or get_local_ip()
        
        config = f"""global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "/etc/prometheus/recording_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    metrics_path: /metrics
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'master'
    static_configs:
      - targets: ['{master_ip}:9100', '{master_ip}:9835']
        labels:
          instance: 'master'
"""
        return config
    
    def _generate_recording_rules(self) -> str:
        """Generate recording_rules.yml for unified GPU metrics."""
        return '''groups:
  - name: gpu_unified_metrics
    rules:
      # Core GPU temperature
      - record: gpu:core_temp:celsius
        expr: DCGM_FI_DEV_GPU_TEMP{UUID!="VM-PASSTHROUGH"}

      # Hotspot temperature
      - record: gpu:hotspot_temp:celsius
        expr: DCXP_FI_DEV_HOT_SPOT_TEMP

      # VRAM temperature
      - record: gpu:memory_temp:celsius
        expr: DCXP_FI_DEV_VRAM_TEMP

      # GPU Power usage
      - record: gpu:power_usage:watts
        expr: DCGM_FI_DEV_POWER_USAGE{UUID!="VM-PASSTHROUGH"}

      # GPU Utilization
      - record: gpu:utilization:percent
        expr: DCGM_FI_DEV_GPU_UTIL{UUID!="VM-PASSTHROUGH"}

      # Fan speed
      - record: gpu:fan_speed:percent
        expr: DCGM_FI_DEV_FAN_SPEED{UUID!="VM-PASSTHROUGH"}

      # SM Clock
      - record: gpu:sm_clock:mhz
        expr: DCGM_FI_DEV_SM_CLOCK{UUID!="VM-PASSTHROUGH"}

      # Memory Clock
      - record: gpu:mem_clock:mhz
        expr: DCGM_FI_DEV_MEM_CLOCK{UUID!="VM-PASSTHROUGH"}

      # FB Used (GPU memory used in MB)
      - record: gpu:fb_used:mb
        expr: DCGM_FI_DEV_FB_USED{UUID!="VM-PASSTHROUGH"}

      # FB Free (GPU memory free in MB)
      - record: gpu:fb_free:mb
        expr: DCGM_FI_DEV_FB_FREE{UUID!="VM-PASSTHROUGH"}

      # Memory used in bytes
      - record: gpu:memory_used:bytes
        expr: DCGM_FI_DEV_FB_USED{UUID!="VM-PASSTHROUGH"} * 1024 * 1024

      # Memory free in bytes
      - record: gpu:memory_free:bytes
        expr: DCGM_FI_DEV_FB_FREE{UUID!="VM-PASSTHROUGH"} * 1024 * 1024

      # Throttle reasons
      - record: gpu:throttle_reason:bool
        expr: DCXP_FI_DEV_CLOCKS_THROTTLE_REASON

      # AER errors
      - record: gpu:aer_errors:total
        expr: DCXP_AER_TOTAL_ERRORS

      # GPU error state
      - record: gpu:error_state:status
        expr: DCXP_ERROR_STATE

      # GPU state (0=OK, 3=VM)
      - record: gpu:state:value
        expr: DCXP_GPU_STATE

      # VM GPU count per host
      - record: gpu:vm_count:total
        expr: DCXP_VM_GPU_COUNT

  - name: gpu_fleet_aggregates
    rules:
      # Total GPUs with real metrics
      - record: fleet:gpu_count:total
        expr: count(DCGM_FI_DEV_GPU_TEMP{UUID!="VM-PASSTHROUGH"})

      # Total GPUs on PCIe bus
      - record: fleet:gpu_count_pcie:total
        expr: sum(DCXP_GPU_COUNT{type="pcie"})

      # GPUs in VMs with real metrics
      - record: fleet:gpu_count_vm:total
        expr: count(DCGM_FI_DEV_GPU_TEMP{source="vm"})

      - record: fleet:memory_temp:avg_celsius
        expr: avg(DCXP_FI_DEV_VRAM_TEMP > 0) or vector(0)

      - record: fleet:hotspot_temp:max_celsius
        expr: max(DCXP_FI_DEV_HOT_SPOT_TEMP > 0) or vector(0)

      - record: fleet:power_usage:total_watts
        expr: sum(gpu:power_usage:watts)

      - record: fleet:utilization:avg_percent
        expr: avg(gpu:utilization:percent)
'''
    
    # ============ Step 4: Deploy to Workers ============
    
    def _deploy_to_workers(self):
        """Install exporters on all workers."""
        console.print("\n[bold]Step 4: Installing Exporters on Workers[/bold]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Installing...", total=len(self.config.servers))
            
            for server in self.config.servers:
                progress.update(task, description=f"Installing on {server.name}...")
                
                success = self._install_exporters_on_server(server)
                server.exporters_installed = success
                
                if success:
                    console.print(f"  [green]✓[/green] {server.name} ({server.server_ip})")
                else:
                    console.print(f"  [yellow]⚠[/yellow] {server.name} - manual install needed")
                
                progress.advance(task)
        
        installed = sum(1 for s in self.config.servers if s.exporters_installed)
        console.print(f"\n[green]✓[/green] Exporters installed on {installed}/{len(self.config.servers)} workers")
    
    def _install_exporters_on_server(self, server: Server) -> bool:
        """Install exporters on a single server via SSH."""
        creds = self.config.get_server_ssh_creds(server)
        
        # Determine which SSH key to use
        ssh_key = creds.key_path or self.config.ssh.key_path
        
        # First, test connection
        if not self.ssh.test_connection(server.server_ip, creds.username, creds.port, key_path=ssh_key):
            return False
        
        # Install dc-overview and exporters
        # Note: Install from GitHub dev branch during testing
        # TODO: Change to PyPI once dev branch is validated and pushed to main
        install_cmd = (
            "pip3 install git+https://github.com/cryptolabsza/dc-overview.git@dev "
            "--break-system-packages -q 2>/dev/null || "
            "pip3 install git+https://github.com/cryptolabsza/dc-overview.git@dev -q"
        )
        commands = [
            "which pip3 || (apt-get update -qq && apt-get install -y -qq python3-pip)",
            install_cmd,
            "dc-overview install-exporters",
        ]
        
        for cmd in commands:
            result = self.ssh.run_command(
                host=server.server_ip,
                command=cmd,
                username=creds.username,
                port=creds.port,
                timeout=120,
                sudo=True,
                key_path=ssh_key,
            )
            
            if not result.success and "install-exporters" in cmd:
                return False
        
        # Detect GPUs
        result = self.ssh.run_command(
            host=server.server_ip,
            command="nvidia-smi -L 2>/dev/null | wc -l",
            username=creds.username,
            port=creds.port,
            key_path=ssh_key,
        )
        
        if result.success:
            try:
                server.has_gpu = int(result.output.strip()) > 0
            except ValueError:
                pass
        
        return True
    
    # ============ Step 5: Prometheus Targets ============
    
    def _configure_prometheus_targets(self):
        """Update Prometheus with all scrape targets."""
        console.print("\n[bold]Step 5: Configuring Prometheus Targets[/bold]\n")
        
        prometheus_file = self.config.config_dir / "prometheus.yml"
        
        # Load existing or start fresh
        master_ip = self.config.master_ip or get_local_ip()
        
        scrape_configs = [
            {
                "job_name": "prometheus",
                "static_configs": [{"targets": ["prometheus:9090"]}]
            },
            {
                "job_name": "master",
                "static_configs": [{
                    "targets": [f"{master_ip}:9100", f"{master_ip}:9835"],
                    "labels": {"instance": "master"}
                }]
            }
        ]
        
        # Add workers (skip master since it's already added above)
        for server in self.config.servers:
            if server.exporters_installed and server.server_ip != master_ip:
                targets = [
                    f"{server.server_ip}:9100",  # node_exporter
                    f"{server.server_ip}:9835",  # dc-exporter (includes DCGM metrics)
                ]
                scrape_configs.append({
                    "job_name": server.name,
                    "static_configs": [{
                        "targets": targets,
                        "labels": {"instance": server.name}
                    }]
                })
        
        # Add Vast.ai exporter if enabled
        if self.config.components.vast_exporter and self.config.vast.api_key:
            scrape_configs.append({
                "job_name": "vastai",
                "scrape_interval": "60s",
                "static_configs": [{
                    "targets": ["host.docker.internal:8622"],
                    "labels": {"instance": "vastai"}
                }]
            })
        
        # Add IPMI Monitor if enabled
        if self.config.components.ipmi_monitor:
            scrape_configs.append({
                "job_name": "ipmi-monitor",
                "static_configs": [{
                    "targets": ["host.docker.internal:5000"],
                    "labels": {"instance": "ipmi-monitor"}
                }],
                "metrics_path": "/metrics"
            })
        
        # Write config
        config = {
            "global": {
                "scrape_interval": "15s",
                "evaluation_interval": "15s"
            },
            "scrape_configs": scrape_configs
        }
        
        with open(prometheus_file, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
        
        # Reload Prometheus
        subprocess.run(
            ["docker", "exec", "prometheus", "kill", "-HUP", "1"],
            capture_output=True
        )
        
        console.print(f"[green]✓[/green] Prometheus configured with {len(scrape_configs)} targets")
    
    # ============ Step 6: Import Dashboards ============
    
    def _import_dashboards(self):
        """Import Grafana dashboards with correct datasource UID."""
        console.print("\n[bold]Step 6: Importing Dashboards[/bold]\n")
        
        # Wait for Grafana to be ready
        grafana_url = "http://localhost:3000"
        auth = f"admin:{self.config.grafana.admin_password}"
        auth_header = base64.b64encode(auth.encode()).decode()
        
        # Wait for Grafana to start and be ready
        console.print("[dim]Waiting for Grafana to start...[/dim]")
        prometheus_uid = self._wait_for_grafana_and_get_datasource_uid(
            grafana_url, auth_header, max_wait=60
        )
        
        if not prometheus_uid:
            console.print("[yellow]⚠[/yellow] Could not get Prometheus datasource UID, using fallback")
            prometheus_uid = "prometheus"  # Fallback name-based reference
        else:
            console.print(f"[dim]Prometheus datasource UID: {prometheus_uid}[/dim]")
        
        dashboards = self._get_dashboard_list()
        grafana_dash_dir = self.config.config_dir / "grafana" / "dashboards"
        
        for dashboard in dashboards:
            name = dashboard["name"]
            
            dashboard_json = self._get_dashboard_json(dashboard)
            if not dashboard_json:
                console.print(f"  [yellow]⚠[/yellow] {name}: not found")
                continue
            
            try:
                # Parse dashboard
                dash_obj = json.loads(dashboard_json)
                
                # Fix datasource references throughout the dashboard
                dash_obj = self._fix_dashboard_datasources(dash_obj, prometheus_uid)
                
                # Remove id to avoid conflicts
                if "id" in dash_obj:
                    dash_obj["id"] = None
                
                # Write to provisioning directory
                filename = name.lower().replace(" ", "_") + ".json"
                with open(grafana_dash_dir / filename, "w") as f:
                    json.dump(dash_obj, f, indent=2)
                
                console.print(f"  [green]✓[/green] {name}")
                
            except Exception as e:
                console.print(f"  [yellow]⚠[/yellow] {name}: {str(e)[:50]}")
        
        console.print("[green]✓[/green] Dashboards imported")
    
    def _wait_for_grafana_and_get_datasource_uid(
        self,
        grafana_url: str,
        auth_header: str,
        max_wait: int = 60
    ) -> Optional[str]:
        """
        Wait for Grafana to start and return the Prometheus datasource UID.
        Creates the datasource if it doesn't exist.
        """
        import time
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth_header}"
        }
        
        # Wait for Grafana to be ready
        for i in range(max_wait // 2):
            try:
                req = urllib.request.Request(
                    f"{grafana_url}/api/health",
                    headers=headers
                )
                resp = urllib.request.urlopen(req, timeout=5)
                if resp.status == 200:
                    break
            except Exception:
                pass
            time.sleep(2)
        
        # Try to get existing Prometheus datasource
        try:
            req = urllib.request.Request(
                f"{grafana_url}/api/datasources/name/Prometheus",
                headers=headers
            )
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read().decode())
            return data.get("uid")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Datasource doesn't exist, create it
                pass
            else:
                return None
        except Exception:
            pass
        
        # Create Prometheus datasource
        try:
            datasource_data = json.dumps({
                "name": "Prometheus",
                "type": "prometheus",
                "url": "http://prometheus:9090",
                "access": "proxy",
                "isDefault": True,
            }).encode('utf-8')
            
            req = urllib.request.Request(
                f"{grafana_url}/api/datasources",
                data=datasource_data,
                headers=headers,
                method="POST"
            )
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read().decode())
            console.print("[green]✓[/green] Prometheus datasource created")
            return data.get("datasource", {}).get("uid") or data.get("uid")
        except urllib.error.HTTPError as e:
            # May already exist (409 conflict)
            if e.code == 409:
                # Try to get it again
                try:
                    req = urllib.request.Request(
                        f"{grafana_url}/api/datasources/name/Prometheus",
                        headers=headers
                    )
                    resp = urllib.request.urlopen(req, timeout=10)
                    data = json.loads(resp.read().decode())
                    return data.get("uid")
                except Exception:
                    pass
            return None
        except Exception:
            return None
    
    def _fix_dashboard_datasources(self, dashboard: dict, prometheus_uid: str) -> dict:
        """
        Recursively fix all datasource references in a dashboard.
        
        Replaces:
        - "${DS_PROMETHEUS}" -> prometheus_uid
        - "${datasource}" -> prometheus_uid  
        - {"uid": "${DS_PROMETHEUS}"} -> {"uid": prometheus_uid, "type": "prometheus"}
        - {"uid": "${datasource}"} -> {"uid": prometheus_uid, "type": "prometheus"}
        """
        
        def fix_value(value):
            """Fix a single value if it's a datasource variable."""
            if isinstance(value, str):
                if value in ["${DS_PROMETHEUS}", "${datasource}", "$datasource", "$DS_PROMETHEUS"]:
                    return prometheus_uid
            return value
        
        def fix_datasource_object(obj):
            """Fix a datasource object like {"uid": "${DS_PROMETHEUS}"}."""
            if isinstance(obj, dict):
                uid = obj.get("uid", "")
                if uid in ["${DS_PROMETHEUS}", "${datasource}", "$datasource", "$DS_PROMETHEUS"]:
                    return {
                        "type": "prometheus",
                        "uid": prometheus_uid
                    }
            return obj
        
        def recursive_fix(obj):
            """Recursively process the dashboard structure."""
            if isinstance(obj, dict):
                result = {}
                for key, value in obj.items():
                    if key == "datasource":
                        # Handle datasource field specially
                        if isinstance(value, dict):
                            result[key] = fix_datasource_object(value)
                        elif isinstance(value, str):
                            fixed = fix_value(value)
                            if fixed != value:
                                # Convert string datasource to object format
                                result[key] = {
                                    "type": "prometheus",
                                    "uid": prometheus_uid
                                }
                            else:
                                result[key] = value
                        else:
                            result[key] = value
                    elif key == "uid" and isinstance(value, str):
                        # Fix uid values that are datasource variables
                        result[key] = fix_value(value)
                    else:
                        result[key] = recursive_fix(value)
                return result
            elif isinstance(obj, list):
                return [recursive_fix(item) for item in obj]
            else:
                return fix_value(obj)
        
        # Also fix templating/variables section
        fixed = recursive_fix(dashboard)
        
        # Fix templating variables that define DS_PROMETHEUS or datasource
        if "templating" in fixed and "list" in fixed["templating"]:
            for var in fixed["templating"]["list"]:
                if var.get("type") == "datasource" and var.get("name") in ["DS_PROMETHEUS", "datasource"]:
                    # Set current value to our Prometheus datasource
                    var["current"] = {
                        "selected": True,
                        "text": "Prometheus",
                        "value": prometheus_uid
                    }
                    var["options"] = [{
                        "selected": True,
                        "text": "Prometheus", 
                        "value": prometheus_uid
                    }]
        
        # Remove __inputs section (used for import mapping, not needed after fix)
        if "__inputs" in fixed:
            del fixed["__inputs"]
        
        # Remove __requires section
        if "__requires" in fixed:
            del fixed["__requires"]
        
        return fixed
    
    def _get_dashboard_list(self) -> List[Dict[str, Any]]:
        """Get list of dashboards to install based on enabled components."""
        dashboards = []
        
        if self.config.components.dc_overview:
            dashboards.extend([
                {
                    "name": "DC Overview",
                    "local_file": "DC_Overview.json",
                    "github_url": "https://raw.githubusercontent.com/cryptolabsza/dc-overview/main/dashboards/DC_Overview.json",
                },
                {
                    "name": "Node Exporter Full",
                    "local_file": "Node_Exporter_Full.json",
                    "github_url": "https://raw.githubusercontent.com/cryptolabsza/dc-overview/main/dashboards/Node_Exporter_Full.json",
                },
                {
                    "name": "NVIDIA DCGM Exporter",
                    "local_file": "NVIDIA_DCGM_Exporter.json",
                    "github_url": "https://raw.githubusercontent.com/cryptolabsza/dc-overview/main/dashboards/NVIDIA_DCGM_Exporter.json",
                },
            ])
        
        if self.config.components.vast_exporter:
            dashboards.append({
                "name": "Vast Dashboard",
                "local_file": "Vast_Dashboard.json",
                "github_url": "https://raw.githubusercontent.com/cryptolabsza/dc-overview/main/dashboards/Vast_Dashboard.json",
            })
        
        if self.config.components.ipmi_monitor:
            dashboards.append({
                "name": "IPMI Monitor",
                "local_file": "IPMI_Monitor.json",
                "github_url": "https://raw.githubusercontent.com/cryptolabsza/dc-overview/main/dashboards/IPMI_Monitor.json",
            })
        
        return dashboards
    
    def _get_dashboard_json(self, dashboard: Dict[str, Any]) -> Optional[str]:
        """Get dashboard JSON from local file or GitHub."""
        # Try local file first
        try:
            import dc_overview
            pkg_path = Path(dc_overview.__file__).parent / "dashboards"
            local_file = pkg_path / dashboard["local_file"]
            if local_file.exists():
                return local_file.read_text()
        except Exception:
            pass
        
        # Fall back to GitHub
        github_url = dashboard.get("github_url")
        if github_url:
            try:
                return urllib.request.urlopen(github_url, timeout=30).read().decode('utf-8')
            except Exception:
                pass
        
        return None
    
    # ============ Step 7: IPMI Monitor ============
    
    def _deploy_ipmi_monitor(self):
        """Deploy IPMI Monitor service."""
        console.print("\n[bold]Step 7: Installing IPMI Monitor[/bold]\n")
        
        # Install ipmi-monitor from pip
        if not self._install_ipmi_monitor_package():
            console.print("[yellow]⚠[/yellow] IPMI Monitor package installation failed")
            console.print("[dim]You can install manually: pip3 install ipmi-monitor[/dim]")
            return
        
        # Create IPMI Monitor config directory
        ipmi_config_dir = Path("/etc/ipmi-monitor")
        ipmi_config_dir.mkdir(parents=True, exist_ok=True)
        
        # Write config
        ipmi_config = {
            "web": {
                "port": self.config.ipmi_monitor.port,
                "host": "127.0.0.1"  # Bind to localhost only
            },
            "database": "/var/lib/ipmi-monitor/ipmi_monitor.db"
        }
        
        if self.config.ipmi_monitor.ai_license_key:
            ipmi_config["ai"] = {
                "enabled": True,
                "license_key": self.config.ipmi_monitor.ai_license_key
            }
        
        with open(ipmi_config_dir / "config.yaml", "w") as f:
            yaml.dump(ipmi_config, f)
        
        # Write servers config
        servers = []
        for server in self.config.servers:
            if server.bmc_ip:
                bmc_creds = self.config.get_server_bmc_creds(server)
                servers.append({
                    "name": server.name,
                    "bmc_ip": server.bmc_ip,
                    "bmc_user": bmc_creds.username,
                    "bmc_password": bmc_creds.password,
                    "server_ip": server.server_ip,
                })
        
        if servers:
            with open(ipmi_config_dir / "servers.yaml", "w") as f:
                yaml.dump({"servers": servers}, f)
            os.chmod(ipmi_config_dir / "servers.yaml", 0o600)
        
        # Create data directory
        Path("/var/lib/ipmi-monitor").mkdir(parents=True, exist_ok=True)
        
        # Install systemd service
        service_content = """[Unit]
Description=IPMI Monitor - Server Health Monitoring
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ipmi-monitor daemon
WorkingDirectory=/etc/ipmi-monitor
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
        Path("/etc/systemd/system/ipmi-monitor.service").write_text(service_content)
        
        # Start service
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "enable", "ipmi-monitor"], capture_output=True)
        subprocess.run(["systemctl", "start", "ipmi-monitor"], capture_output=True)
        
        console.print(f"[green]✓[/green] IPMI Monitor running on port {self.config.ipmi_monitor.port}")
        
        if servers:
            console.print(f"[dim]  Configured {len(servers)} servers for IPMI monitoring[/dim]")
    
    def _install_ipmi_monitor_package(self) -> bool:
        """Install ipmi-monitor package via pip with proper error handling."""
        try:
            # Check if already installed
            result = subprocess.run(
                ["pip3", "show", "ipmi-monitor"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                console.print("[dim]ipmi-monitor already installed[/dim]")
                return True
            
            console.print("[dim]Installing ipmi-monitor package...[/dim]")
            
            # Try standard install first
            result = subprocess.run(
                ["pip3", "install", "ipmi-monitor", "--break-system-packages", "-q"],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                console.print("[green]✓[/green] ipmi-monitor installed via pip")
                return True
            
            # If failed due to dependency conflicts, try with --ignore-installed
            if "Cannot uninstall" in result.stderr or "blinker" in result.stderr.lower():
                console.print("[dim]Retrying with --ignore-installed...[/dim]")
                result = subprocess.run(
                    ["pip3", "install", "ipmi-monitor", "--break-system-packages", 
                     "--ignore-installed", "blinker", "-q"],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                if result.returncode == 0:
                    console.print("[green]✓[/green] ipmi-monitor installed via pip")
                    return True
            
            console.print(f"[yellow]⚠[/yellow] pip install failed: {result.stderr[:100]}")
            return False
            
        except subprocess.TimeoutExpired:
            console.print("[yellow]⚠[/yellow] pip install timed out")
            return False
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Error installing ipmi-monitor: {e}")
            return False
    
    # ============ Step 8: Vast.ai Exporter ============
    
    def _deploy_vast_exporter(self):
        """Deploy Vast.ai exporter."""
        if not self.config.vast.api_key:
            return
        
        console.print("\n[bold]Step 8: Starting Vast.ai Exporter[/bold]\n")
        
        # Stop existing container
        subprocess.run(["docker", "rm", "-f", "vastai-exporter"], capture_output=True)
        
        # Start new container
        result = subprocess.run([
            "docker", "run", "-d",
            "--name", "vastai-exporter",
            "--restart", "unless-stopped",
            "-p", "8622:8622",
            "jjziets/vastai-exporter:latest",
            "-api-key", self.config.vast.api_key
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            console.print("[green]✓[/green] Vast.ai exporter running on port 8622")
        else:
            console.print(f"[yellow]⚠[/yellow] Vast.ai exporter failed: {result.stderr[:100]}")
    
    # ============ Step 9: Reverse Proxy ============
    
    def _setup_reverse_proxy(self):
        """Set up nginx reverse proxy with SSL."""
        console.print("\n[bold]Step 9: Setting up HTTPS Reverse Proxy[/bold]\n")
        
        from .reverse_proxy import setup_reverse_proxy
        
        setup_reverse_proxy(
            domain=self.config.ssl.domain,
            email=self.config.ssl.email,
            site_name=self.config.site_name,
            ipmi_enabled=self.config.components.ipmi_monitor,
            prometheus_enabled=False,  # Disabled by default (no auth)
            use_letsencrypt=self.config.ssl.mode == SSLMode.LETSENCRYPT,
        )
    
    # ============ Completion ============
    
    def _show_completion(self):
        """Show deployment completion summary."""
        console.print()
        console.print(Panel(
            "[bold green]✓ Deployment Complete![/bold green]",
            border_style="green"
        ))
        
        master_ip = self.config.master_ip or get_local_ip()
        domain = self.config.ssl.domain or master_ip
        external_port = self.config.ssl.external_port
        
        # Build base URL with port if non-standard
        if external_port and external_port != 443:
            base_url = f"https://{domain}:{external_port}"
        else:
            base_url = f"https://{domain}"
        
        # Access info table
        table = Table(title="Access Information", show_header=False)
        table.add_column("Service", style="cyan")
        table.add_column("URL")
        
        table.add_row("Dashboard", f"{base_url}/")
        table.add_row("Grafana", f"{base_url}/grafana/")
        table.add_row("  └─ Login", f"admin / {self.config.grafana.admin_password}")
        
        if self.config.components.ipmi_monitor:
            table.add_row("IPMI Monitor", f"{base_url}/ipmi/")
        
        console.print(table)
        console.print()
        
        # Workers table
        if self.config.servers:
            worker_table = Table(title="Monitored Servers")
            worker_table.add_column("Name", style="cyan")
            worker_table.add_column("IP")
            worker_table.add_column("Exporters")
            if self.config.components.ipmi_monitor:
                worker_table.add_column("IPMI")
            
            for server in self.config.servers[:10]:
                exp_status = "[green]✓[/green]" if server.exporters_installed else "[yellow]⚠[/yellow]"
                
                if self.config.components.ipmi_monitor:
                    ipmi_status = "[green]✓[/green]" if server.bmc_ip else "[dim]—[/dim]"
                    worker_table.add_row(server.name, server.server_ip, exp_status, ipmi_status)
                else:
                    worker_table.add_row(server.name, server.server_ip, exp_status)
            
            if len(self.config.servers) > 10:
                worker_table.add_row(f"... and {len(self.config.servers) - 10} more", "", "")
            
            console.print(worker_table)
            console.print()
        
        # Dashboards
        console.print("[bold]Installed Dashboards:[/bold]")
        console.print("  • DC Overview (main dashboard)")
        console.print("  • Node Exporter Full (CPU/RAM/disk)")
        console.print("  • NVIDIA DCGM Exporter (GPU metrics)")
        if self.config.components.vast_exporter:
            console.print("  • Vast Dashboard (earnings/reliability)")
        if self.config.components.ipmi_monitor:
            console.print("  • IPMI Monitor (server health)")
        
        console.print()
        
        # Next steps
        console.print("[bold]Next Steps:[/bold]")
        console.print(f"  1. Open your browser: [cyan]{base_url}/[/cyan]")
        if self.config.ssl.mode == SSLMode.SELF_SIGNED:
            console.print("     (Accept the certificate warning - normal for self-signed)")
        console.print("  2. Log into Grafana and explore dashboards")
        console.print("  3. Add more servers: [cyan]dc-overview add-machine <IP>[/cyan]")
        
        console.print()
        
        # Save final config
        self.config.save()


def deploy_fleet(config: FleetConfig) -> bool:
    """Deploy the complete fleet using provided configuration."""
    manager = FleetManager(config)
    return manager.deploy()
