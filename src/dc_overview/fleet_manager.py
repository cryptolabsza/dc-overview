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
            
            # Step 9: Proxy Integration (skip if using existing cryptolabs-proxy)
            if not getattr(self.config.ssl, 'use_existing_proxy', False):
                self._setup_reverse_proxy()
            else:
                self._integrate_with_proxy()
            
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
        
        # Skip nginx installation if using existing proxy
        use_existing_proxy = getattr(self.config.ssl, 'use_existing_proxy', False)
        
        self.prerequisites.install_all(
            docker=self.config.components.dc_overview,
            nginx=not use_existing_proxy,  # Skip if using existing proxy
            ipmitool=self.config.components.ipmi_monitor,
            certbot=self.config.ssl.mode == SSLMode.LETSENCRYPT and not use_existing_proxy,
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
        
        # Datasource config (with /prometheus/ path for proxy setup)
        datasource_config = """apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    uid: prometheus
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
        
        # Ensure cryptolabs network exists before starting services
        subprocess.run(["docker", "network", "create", "cryptolabs"], capture_output=True)
        
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
        # Check if using existing proxy (cryptolabs network)
        use_existing_proxy = getattr(self.config.ssl, 'use_existing_proxy', False)
        
        # Determine the ROOT_URL based on domain and external port
        external_port = self.config.ssl.external_port
        domain = self.config.ssl.domain or "%(domain)s"
        
        # If using non-standard port, include it in URL
        if external_port and external_port != 443:
            root_url = f"https://{domain}:{external_port}/grafana/"
        else:
            root_url = f"%(protocol)s://{domain}/grafana/"
        
        # When using existing proxy, don't expose ports (proxy handles routing)
        # and use cryptolabs network
        if use_existing_proxy:
            return f"""services:
  dc-overview:
    image: ghcr.io/cryptolabsza/dc-overview:latest
    container_name: dc-overview
    restart: unless-stopped
    environment:
      - DC_OVERVIEW_PORT=5001
      - APPLICATION_ROOT=/dc
      - GRAFANA_URL=http://grafana:3000
      - PROMETHEUS_URL=http://prometheus:9090
    volumes:
      - dc-data:/data
      - ./ssh_keys:/etc/dc-overview/ssh_keys:ro
    networks:
      - cryptolabs
    labels:
      - "com.centurylinklabs.watchtower.enable=true"

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./recording_rules.yml:/etc/prometheus/recording_rules.yml:ro
      - prometheus-data:/prometheus
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.retention.time={self.config.prometheus.retention_days}d"
      - "--web.enable-lifecycle"
      - "--web.external-url=/prometheus/"
      - "--web.route-prefix=/prometheus/"
    extra_hosts:
      - "host.docker.internal:host-gateway"
    networks:
      - cryptolabs
    labels:
      - "com.centurylinklabs.watchtower.enable=true"

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
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
      - cryptolabs
    labels:
      - "com.centurylinklabs.watchtower.enable=true"

volumes:
  dc-data:
  prometheus-data:
  grafana-data:

networks:
  cryptolabs:
    external: true
"""
        else:
            # Fresh install - use cryptolabs network (proxy will be deployed later)
            # Create the network first since docker-compose will use external: true
            return f"""services:
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
      - cryptolabs

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
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_SERVER_ROOT_URL={root_url}
      - GF_SERVER_SERVE_FROM_SUB_PATH=true
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer
      - GF_AUTH_PROXY_ENABLED=true
      - GF_AUTH_PROXY_HEADER_NAME=X-WEBAUTH-USER
      - GF_AUTH_PROXY_AUTO_SIGN_UP=true
    depends_on:
      - prometheus
    networks:
      - cryptolabs

volumes:
  prometheus-data:
  grafana-data:

networks:
  cryptolabs:
    name: cryptolabs
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
        
        # Install node_exporter and dc-exporter directly (no pip required)
        # dc-exporter is downloaded from public releases repo
        install_script = '''#!/bin/bash
set -e

# Install node_exporter if not running
if ! systemctl is-active --quiet node_exporter 2>/dev/null; then
    cd /tmp
    curl -sLO https://github.com/prometheus/node_exporter/releases/download/v1.7.0/node_exporter-1.7.0.linux-amd64.tar.gz
    tar xzf node_exporter-1.7.0.linux-amd64.tar.gz
    cp node_exporter-1.7.0.linux-amd64/node_exporter /usr/local/bin/
    
    cat > /etc/systemd/system/node_exporter.service << 'EOF'
[Unit]
Description=Node Exporter
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/node_exporter
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable node_exporter
    systemctl start node_exporter
    rm -rf /tmp/node_exporter-*
fi

# Install dc-exporter if not running
if ! systemctl is-active --quiet dc-exporter 2>/dev/null; then
    curl -L https://github.com/cryptolabsza/dc-exporter-releases/releases/latest/download/dc-exporter-rs -o /usr/local/bin/dc-exporter-rs
    chmod +x /usr/local/bin/dc-exporter-rs
    
    cat > /etc/systemd/system/dc-exporter.service << 'EOF'
[Unit]
Description=DC Exporter - GPU Metrics
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dc-exporter-rs --port 9835
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable dc-exporter
    systemctl start dc-exporter
fi

echo "Exporters installed successfully"
'''
        
        result = self.ssh.run_command(
            host=server.server_ip,
            command=install_script,
            username=creds.username,
            port=creds.port,
            timeout=180,  # Allow more time for downloads
            sudo=True,
            key_path=ssh_key,
        )
        
        if not result.success:
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
        console.print("[dim]Waiting for Grafana to start...[/dim]")
        grafana_ready = False
        for i in range(max_wait // 2):
            try:
                req = urllib.request.Request(
                    f"{grafana_url}/api/health",
                    headers=headers
                )
                resp = urllib.request.urlopen(req, timeout=5)
                if resp.status == 200:
                    grafana_ready = True
                    # Give it a few more seconds for datasource API
                    time.sleep(3)
                    break
            except Exception:
                pass
            time.sleep(2)
        
        if not grafana_ready:
            console.print("[yellow]⚠[/yellow] Grafana not ready after waiting")
            return None
        
        # Try to get existing Prometheus datasource (with retries)
        for attempt in range(3):
            try:
                req = urllib.request.Request(
                    f"{grafana_url}/api/datasources/name/Prometheus",
                    headers=headers
                )
                resp = urllib.request.urlopen(req, timeout=10)
                data = json.loads(resp.read().decode())
                uid = data.get("uid")
                if uid:
                    return uid
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    # Datasource doesn't exist, create it
                    break
                elif e.code == 401:
                    # Auth issue, wait and retry
                    time.sleep(2)
                    continue
            except Exception:
                time.sleep(2)
                continue
        
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
            """Fix a datasource object - replace ANY uid with the correct Prometheus UID."""
            if isinstance(obj, dict):
                ds_type = obj.get("type", "")
                # If it's a prometheus datasource (or unspecified), replace the uid
                if ds_type in ["prometheus", ""] or "uid" in obj:
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
        
        # Check if already installed
        ipmi_config_dir = Path("/etc/ipmi-monitor")
        if (ipmi_config_dir / "servers.yaml").exists():
            console.print("[green]✓[/green] IPMI Monitor already installed")
            console.print("[dim]Skipping installation - using existing configuration[/dim]")
            return
        
        # Also check if the container is running
        try:
            result = subprocess.run(
                ["docker", "inspect", "ipmi-monitor"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                console.print("[green]✓[/green] IPMI Monitor container already running")
                return
        except Exception:
            pass
        
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
            console.print("[dim]Installing ipmi-monitor package...[/dim]")
            
            # Install from GitHub dev branch to get development version with tag
            # TODO: Change to PyPI once dev branch is validated and pushed to main
            install_cmd = [
                "pip3", "install", 
                "git+https://github.com/cryptolabsza/ipmi-monitor.git@dev",
                "--break-system-packages", "-q", "--force-reinstall"
            ]
            
            result = subprocess.run(
                install_cmd,
                capture_output=True,
                text=True,
                timeout=180
            )
            
            if result.returncode == 0:
                console.print("[green]✓[/green] ipmi-monitor installed via pip (dev)")
                return True
            
            # If failed due to dependency conflicts, try with --ignore-installed
            if "Cannot uninstall" in result.stderr or "blinker" in result.stderr.lower():
                console.print("[dim]Retrying with --ignore-installed...[/dim]")
                install_cmd.extend(["--ignore-installed", "blinker"])
                result = subprocess.run(
                    install_cmd,
                    capture_output=True,
                    text=True,
                    timeout=180
                )
                
                if result.returncode == 0:
                    console.print("[green]✓[/green] ipmi-monitor installed via pip (dev)")
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
        """Set up Docker-based cryptolabs-proxy with SSL."""
        console.print("\n[bold]Step 9: Setting up HTTPS Reverse Proxy[/bold]\n")
        
        # Check if using existing cryptolabs-proxy
        if getattr(self.config.ssl, 'use_existing_proxy', False):
            self._integrate_with_proxy()
            return
        
        # Deploy cryptolabs-proxy Docker container
        self._deploy_cryptolabs_proxy()
    
    def _deploy_cryptolabs_proxy(self):
        """Deploy the cryptolabs-proxy Docker container.
        
        The proxy handles its own nginx configuration internally.
        We just need to provide SSL certs and auth credentials.
        """
        import secrets as secrets_module
        
        domain = self.config.ssl.domain or "localhost"
        
        # Create directory for SSL certs
        ssl_dir = Path("/etc/cryptolabs-proxy/ssl")
        ssl_dir.mkdir(parents=True, exist_ok=True)
        
        # Ensure cryptolabs network exists
        subprocess.run(["docker", "network", "create", "cryptolabs"], capture_output=True)
        
        # Handle SSL certificate
        use_letsencrypt = False
        if self.config.ssl.mode == SSLMode.LETSENCRYPT:
            console.print("[dim]Obtaining Let's Encrypt certificate...[/dim]")
            cert_result = self._obtain_letsencrypt_cert(domain, self.config.ssl.email)
            if cert_result:
                use_letsencrypt = True
            else:
                console.print("[yellow]⚠[/yellow] Could not obtain Let's Encrypt cert, using self-signed")
                self._generate_self_signed_cert(domain, ssl_dir)
        else:
            self._generate_self_signed_cert(domain, ssl_dir)
        
        # Deploy dc-overview container first
        self._deploy_dc_overview_container()
        
        # Connect existing containers to cryptolabs network
        for container in ["prometheus", "grafana"]:
            subprocess.run(["docker", "network", "connect", "cryptolabs", container], capture_output=True)
        
        # Pull proxy image
        console.print("[dim]Pulling cryptolabs-proxy image...[/dim]")
        subprocess.run(["docker", "pull", "ghcr.io/cryptolabsza/cryptolabs-proxy:dev"], 
                      capture_output=True, timeout=120)
        
        # Remove existing proxy container if any
        subprocess.run(["docker", "rm", "-f", "cryptolabs-proxy"], capture_output=True)
        
        # Generate auth secret
        auth_secret = secrets_module.token_hex(32)
        
        # Start proxy - no nginx.conf override, use built-in config
        cmd = [
            "docker", "run", "-d",
            "--name", "cryptolabs-proxy",
            "--restart", "unless-stopped",
            "-p", "80:80", "-p", "443:443",
            "-e", f"FLEET_ADMIN_USER={self.config.fleet_admin_user}",
            "-e", f"FLEET_ADMIN_PASS={self.config.fleet_admin_pass}",
            "-e", f"AUTH_SECRET_KEY={auth_secret}",
            "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
            "-v", "fleet-auth-data:/data/auth",
            "--network", "cryptolabs",
        ]
        
        # Add SSL volume based on what was actually obtained
        if use_letsencrypt:
            # Mount Let's Encrypt certs to the path the proxy expects
            cmd.extend(["-v", "/etc/letsencrypt/live/{}/fullchain.pem:/etc/nginx/ssl/server.crt:ro".format(domain)])
            cmd.extend(["-v", "/etc/letsencrypt/live/{}/privkey.pem:/etc/nginx/ssl/server.key:ro".format(domain)])
        else:
            cmd.extend(["-v", f"{ssl_dir}:/etc/nginx/ssl:ro"])
        
        cmd.append("ghcr.io/cryptolabsza/cryptolabs-proxy:dev")
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            console.print("[green]✓[/green] CryptoLabs Proxy started")
            console.print(f"\n  Fleet Management: [cyan]https://{domain}/[/cyan]")
            console.print(f"  Server Manager: [cyan]https://{domain}/dc/[/cyan]")
            console.print(f"  Grafana: [cyan]https://{domain}/grafana/[/cyan]")
            console.print(f"  Prometheus: [cyan]https://{domain}/prometheus/[/cyan]")
            console.print(f"\n  Login: [cyan]{self.config.fleet_admin_user}[/cyan] / [dim](password you set)[/dim]")
        else:
            console.print(f"[red]✗[/red] Failed to start proxy: {result.stderr[:200]}")
    
    def _deploy_dc_overview_container(self):
        """Deploy dc-overview container on cryptolabs network."""
        import secrets as secrets_module
        
        # Remove existing container if any
        subprocess.run(["docker", "rm", "-f", "dc-overview"], capture_output=True)
        
        # Pull latest image
        subprocess.run(["docker", "pull", "ghcr.io/cryptolabsza/dc-overview:dev"], 
                      capture_output=True, timeout=120)
        
        # Start dc-overview container
        flask_secret = secrets_module.token_hex(16)
        cmd = [
            "docker", "run", "-d",
            "--name", "dc-overview",
            "--restart", "unless-stopped",
            "-e", f"FLASK_SECRET_KEY={flask_secret}",
            "-e", "DC_OVERVIEW_PORT=5001",
            "-v", "dc-overview-data:/data",
            "-v", f"{self.config.config_dir}:/etc/dc-overview:ro",
            "--network", "cryptolabs",
            "ghcr.io/cryptolabsza/dc-overview:dev"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            console.print("[green]✓[/green] DC Overview (Server Manager) container started")
    
    def _generate_self_signed_cert(self, domain: str, ssl_dir: Path):
        """Generate self-signed SSL certificate."""
        ssl_dir.mkdir(parents=True, exist_ok=True)
        
        cmd = [
            "openssl", "req", "-x509", "-nodes",
            "-days", "365",
            "-newkey", "rsa:2048",
            "-keyout", str(ssl_dir / "server.key"),
            "-out", str(ssl_dir / "server.crt"),
            "-subj", f"/CN={domain}/O=DC Overview",
        ]
        
        result = subprocess.run(cmd, capture_output=True)
        if result.returncode == 0:
            console.print("[green]✓[/green] Generated self-signed SSL certificate")
        else:
            console.print("[yellow]⚠[/yellow] Could not generate SSL certificate")
    
    def _obtain_letsencrypt_cert(self, domain: str, email: str) -> bool:
        """Obtain Let's Encrypt certificate using certbot."""
        # Check if certbot is installed
        if not shutil.which("certbot"):
            subprocess.run(["apt-get", "update", "-qq"], capture_output=True)
            subprocess.run(["apt-get", "install", "-y", "-qq", "certbot"], capture_output=True)
        
        if not shutil.which("certbot"):
            return False
        
        # Stop nginx temporarily if running on port 80
        subprocess.run(["systemctl", "stop", "nginx"], capture_output=True)
        subprocess.run(["docker", "stop", "cryptolabs-proxy"], capture_output=True)
        
        cmd = [
            "certbot", "certonly", "--standalone",
            "-d", domain,
            "--email", email,
            "--agree-tos",
            "--non-interactive",
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            console.print("[green]✓[/green] Let's Encrypt certificate obtained")
            return True
        else:
            console.print(f"[yellow]⚠[/yellow] certbot failed: {result.stderr[:100]}")
            return False
    
    def _integrate_with_proxy(self):
        """Integrate with existing cryptolabs-proxy - add routes for dc-overview services."""
        import re
        
        console.print("\n[bold]Step 9: Integrating with CryptoLabs Proxy[/bold]\n")
        console.print("[green]✓[/green] Using existing CryptoLabs Proxy")
        console.print("[dim]Adding routes for DC Overview, Grafana, and Prometheus.[/dim]\n")
        
        # Find the existing nginx.conf
        nginx_paths = [
            Path("/etc/ipmi-monitor/nginx.conf"),
            Path("/etc/cryptolabs-proxy/nginx.conf"),
        ]
        
        nginx_path = None
        for path in nginx_paths:
            if path.exists():
                nginx_path = path
                break
        
        if not nginx_path:
            console.print("[yellow]⚠[/yellow] Could not find proxy nginx config")
            return
        
        content = nginx_path.read_text()
        modified = False
        
        # Services to add (only if not already present)
        services_to_add = []
        
        # DC Overview route (server management web UI)
        if '/dc/' not in content:
            services_to_add.append(('DC Overview', '/dc/', 'dc-overview', 5001))
        
        # Add /servers shortcut redirect (if not already present)
        if 'location /servers' not in content:
            # Insert redirect before /dc/ location
            redirect_block = '''
        # Servers shortcut - redirect to DC Overview
        location /servers {
            return 301 /dc/servers;
        }
'''
            dc_pattern = r'(location /dc/)'
            if re.search(dc_pattern, content):
                content = re.sub(dc_pattern, redirect_block + r'\n        \1', content)
                nginx_path.write_text(content)
                console.print(f"[green]✓[/green] Added /servers redirect")
        
        # Grafana route
        if '/grafana/' not in content:
            services_to_add.append(('Grafana', '/grafana/', 'grafana', 3000))
        
        # Prometheus route
        if '/prometheus/' not in content:
            services_to_add.append(('Prometheus', '/prometheus/', 'prometheus', 9090))
        
        if not services_to_add:
            console.print("[green]✓[/green] All service routes already configured")
        
        # Update /api/services endpoint to include all running services
        self._update_api_services_endpoint(nginx_path, content if not services_to_add else None)
        
        if services_to_add:
            # Build location blocks for missing services with unified auth
            location_blocks = ""
            for display_name, path, container, port in services_to_add:
                # Grafana needs special handling - no trailing slash to preserve subpath
                if container == 'grafana':
                    proxy_pass = f"http://{container}:{port}"
                elif container == 'prometheus':
                    # Prometheus needs the subpath passed to it
                    proxy_pass = f"http://{container}:{port}/prometheus/"
                else:
                    proxy_pass = f"http://{container}:{port}/"
                
                location_blocks += f'''
        # {display_name} (requires auth)
        location {path} {{
            auth_request /_auth_check;
            auth_request_set $auth_user $upstream_http_x_fleet_auth_user;
            auth_request_set $auth_role $upstream_http_x_fleet_auth_role;
            auth_request_set $auth_token $upstream_http_x_fleet_auth_token;
            error_page 401 = @login_redirect;

            proxy_pass {proxy_pass};
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Script-Name {path.rstrip('/')};
            
            # Forward Fleet auth headers to backend
            proxy_set_header X-Fleet-Auth-User $auth_user;
            proxy_set_header X-Fleet-Auth-Role $auth_role;
            proxy_set_header X-Fleet-Auth-Token $auth_token;
            proxy_set_header X-Fleet-Authenticated "true";

            proxy_read_timeout 300s;
            proxy_connect_timeout 10s;
        }}
'''
            
            # Find insertion point - before the root location / block
            # Look for "location / {" that serves the landing page
            root_location_pattern = r'(\s+# Fleet Management Landing Page.*?\n\s+location / \{)'
            match = re.search(root_location_pattern, content, re.DOTALL)
            
            if match:
                insert_pos = match.start()
                new_content = content[:insert_pos] + location_blocks + content[insert_pos:]
            else:
                # Try simpler pattern - find last location block before closing braces
                alt_pattern = r'(\s+location / \{[^}]+\})\s*\n\s*\}\s*\n\}'
                match = re.search(alt_pattern, content, re.DOTALL)
                if match:
                    insert_pos = match.start()
                    new_content = content[:insert_pos] + location_blocks + content[insert_pos:]
                else:
                    console.print("[yellow]⚠[/yellow] Could not find insertion point")
                    console.print("[dim]Please add routes manually to nginx.conf[/dim]")
                    return
            
            # Write updated config
            nginx_path.write_text(new_content)
            modified = True
            
            for display_name, path, _, _ in services_to_add:
                console.print(f"[green]✓[/green] Added {path} route for {display_name}")
        
        # Ensure containers are on the cryptolabs network
        network = "cryptolabs"
        containers = ["prometheus", "grafana"]
        
        for container in containers:
            try:
                result = subprocess.run(
                    ["docker", "inspect", container],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    subprocess.run(
                        ["docker", "network", "connect", network, container],
                        capture_output=True
                    )
            except Exception:
                pass
        
        console.print("[green]✓[/green] Containers connected to cryptolabs network")
        
        # Reload nginx in the proxy container
        if modified or services_to_add:
            try:
                result = subprocess.run(
                    ["docker", "exec", "cryptolabs-proxy", "nginx", "-t"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    subprocess.run(
                        ["docker", "exec", "cryptolabs-proxy", "nginx", "-s", "reload"],
                        capture_output=True, text=True, timeout=10
                    )
                    console.print("[green]✓[/green] Proxy configuration reloaded")
                else:
                    console.print(f"[yellow]⚠[/yellow] Nginx config test failed: {result.stderr[:100]}")
                    console.print("[dim]Run: docker exec cryptolabs-proxy nginx -t[/dim]")
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] Could not reload proxy: {e}")
        
        domain = self.config.ssl.domain or "your-server"
        console.print(f"\n  DC Overview: [cyan]https://{domain}/dc/[/cyan]")
        console.print(f"  Grafana: [cyan]https://{domain}/grafana/[/cyan]")
        console.print(f"  Prometheus: [cyan]https://{domain}/prometheus/[/cyan]")
    
    def _update_api_services_endpoint(self, nginx_path: Path, content: str = None):
        """Update /api/services endpoint to include all running services."""
        import re
        
        if content is None:
            content = nginx_path.read_text()
        
        # Build the services JSON with all services
        # Check which containers are running
        services = {}
        containers_to_check = [
            ('ipmi-monitor', 'ipmi-monitor'),
            ('dc-overview', 'dc-overview'),
            ('grafana', 'grafana'),
            ('prometheus', 'prometheus'),
        ]
        
        for service_name, container_name in containers_to_check:
            try:
                result = subprocess.run(
                    ["docker", "inspect", container_name, "--format", "{{.State.Running}}"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0 and result.stdout.strip() == "true":
                    services[service_name] = {"running": True}
            except Exception:
                pass
        
        # Build JSON string (escape for nginx)
        import json
        services_json = json.dumps(services).replace('"', '\\"')
        
        # Find and replace the /api/services location block
        api_services_pattern = r'(location /api/services \{[^}]+\})'
        
        new_api_services = f'''location /api/services {{
            default_type application/json;
            return 200 '{services_json}';
        }}'''
        
        if re.search(api_services_pattern, content):
            new_content = re.sub(api_services_pattern, new_api_services, content)
            nginx_path.write_text(new_content)
            console.print(f"[green]✓[/green] Updated /api/services with {len(services)} services")
    
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
