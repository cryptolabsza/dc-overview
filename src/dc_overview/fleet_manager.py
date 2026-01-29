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

# Docker network configuration - use fixed subnet and IPs for security
DOCKER_NETWORK_NAME = "cryptolabs"
DOCKER_NETWORK_SUBNET = "172.30.0.0/16"
DOCKER_NETWORK_GATEWAY = "172.30.0.1"

# Static IPs for all services - proxy IP is trusted by downstream services
STATIC_IPS = {
    "cryptolabs-proxy": "172.30.0.2",
    "dc-overview": "172.30.0.3",
    "prometheus": "172.30.0.4",
    "grafana": "172.30.0.5",
    "ipmi-monitor": "172.30.0.6",
    "vast-exporter": "172.30.0.7",
    "server-manager": "172.30.0.8",
}
PROXY_STATIC_IP = STATIC_IPS["cryptolabs-proxy"]

# Default UFW ports to allow
DEFAULT_UFW_PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    100: "SSH (port 100)",
    101: "SSH (port 101)", 
    103: "SSH (port 103)",
    9100: "Node Exporter",
    9400: "DC Exporter",
}


def _ensure_docker_network():
    """Ensure the cryptolabs Docker network exists with the correct subnet.
    
    Uses a fixed subnet so containers can be assigned static IPs for security.
    This allows services to trust only specific proxy IPs rather than entire ranges.
    """
    # Check if network exists
    result = subprocess.run(
        ["docker", "network", "inspect", DOCKER_NETWORK_NAME],
        capture_output=True, text=True
    )
    
    if result.returncode == 0:
        # Network exists - check if it has the right subnet
        try:
            network_info = json.loads(result.stdout)
            if network_info:
                existing_subnet = network_info[0].get("IPAM", {}).get("Config", [{}])[0].get("Subnet", "")
                if existing_subnet == DOCKER_NETWORK_SUBNET:
                    console.print(f"[dim]Network {DOCKER_NETWORK_NAME} exists with subnet {existing_subnet}[/dim]")
                    return True  # Network already configured correctly
                
                # Network exists but with wrong subnet - need to recreate it for static IPs to work
                console.print(f"[yellow]⚠[/yellow] Network {DOCKER_NETWORK_NAME} has wrong subnet ({existing_subnet}), recreating...")
                
                # Disconnect all containers from the network first
                containers = network_info[0].get("Containers", {})
                for container_id, container_info in containers.items():
                    container_name = container_info.get("Name", container_id)
                    subprocess.run(
                        ["docker", "network", "disconnect", "-f", DOCKER_NETWORK_NAME, container_name],
                        capture_output=True
                    )
                
                # Remove the old network
                subprocess.run(["docker", "network", "rm", DOCKER_NETWORK_NAME], capture_output=True)
                
        except (json.JSONDecodeError, IndexError, KeyError) as e:
            # Network exists but can't parse info - try to remove and recreate
            console.print(f"[yellow]⚠[/yellow] Cannot inspect network, recreating...")
            subprocess.run(["docker", "network", "rm", DOCKER_NETWORK_NAME], capture_output=True)
    
    # Create network with specific subnet
    result = subprocess.run(
        ["docker", "network", "create",
         "--subnet", DOCKER_NETWORK_SUBNET,
         "--gateway", DOCKER_NETWORK_GATEWAY,
         DOCKER_NETWORK_NAME],
        capture_output=True, text=True
    )
    
    if result.returncode == 0:
        console.print(f"[green]✓[/green] Created Docker network {DOCKER_NETWORK_NAME} with subnet {DOCKER_NETWORK_SUBNET}")
        return True
    else:
        console.print(f"[red]✗[/red] Failed to create network: {result.stderr[:100]}")
        # Fallback - create without specific subnet (won't support static IPs)
        fallback = subprocess.run(["docker", "network", "create", DOCKER_NETWORK_NAME], capture_output=True)
        if fallback.returncode == 0:
            console.print(f"[yellow]⚠[/yellow] Created network without subnet (static IPs disabled)")
        return fallback.returncode == 0


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
                try:
                    self._deploy_ipmi_monitor()
                except Exception as e:
                    console.print(f"[red]IPMI Monitor deployment failed:[/red] {e}")
                    import traceback
                    traceback.print_exc()
            
            # Step 8: Vast.ai exporter (if enabled)
            if self.config.components.vast_exporter:
                self._deploy_vast_exporter()
            
            # Step 9: Proxy Integration (skip if using existing cryptolabs-proxy)
            if not getattr(self.config.ssl, 'use_existing_proxy', False):
                self._setup_reverse_proxy()
            else:
                self._integrate_with_proxy()
            
            # Step 10: Security Hardening (firewall setup)
            self._setup_security_hardening()
            
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
            # Still copy to shared location for sub-services
            self._copy_ssh_key_to_config_dir()
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
        
        # Copy SSH key to shared config directory for sub-services (IPMI Monitor, dc-overview)
        self._copy_ssh_key_to_config_dir()
    
    def _copy_ssh_key_to_config_dir(self):
        """Copy SSH key to config directory for use by sub-services."""
        import shutil
        
        if not self.config.ssh.key_path:
            return
        
        source_key = Path(self.config.ssh.key_path)
        if not source_key.exists():
            return
        
        ssh_keys_dir = self.config.config_dir / "ssh_keys"
        ssh_keys_dir.mkdir(parents=True, exist_ok=True)
        dest_key = ssh_keys_dir / "fleet_key"
        
        try:
            shutil.copy2(source_key, dest_key)
            os.chmod(dest_key, 0o600)
            console.print(f"[dim]  Copied SSH key to {dest_key}[/dim]")
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Failed to copy SSH key: {e}")
    
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
    url: http://prometheus:9090/prometheus/
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
        
        # Ensure cryptolabs network exists with correct subnet before starting services
        _ensure_docker_network()
        
        # Pull images first (docker compose writes progress to stderr which can look like errors)
        with Progress(SpinnerColumn(), TextColumn("Pulling images..."), console=console) as progress:
            progress.add_task("", total=None)
            
            subprocess.run(
                ["docker", "compose", "pull"],
                cwd=compose_dir,
                capture_output=True,
                text=True
            )
            # Ignore pull exit code - images may be cached, docker compose up will handle it
        
        # Start services (docker compose writes all progress to stderr, even on success)
        with Progress(SpinnerColumn(), TextColumn("Starting services..."), console=console) as progress:
            progress.add_task("", total=None)
            
            subprocess.run(
                ["docker", "compose", "up", "-d"],
                cwd=compose_dir,
                capture_output=True,
                text=True
            )
            # Don't check return code - docker compose returns non-zero during normal operation
            # We'll verify by checking if containers are actually running
        
        # Wait a moment for containers to initialize, then check status
        time.sleep(2)
        
        # Check if containers are actually running (the only reliable way)
        check_result = subprocess.run(
            ["docker", "ps", "--filter", "name=prometheus", "--filter", "name=grafana", "--format", "{{.Names}}"],
            capture_output=True,
            text=True
        )
        running_containers = [c.strip() for c in check_result.stdout.strip().split('\n') if c.strip()]
        
        prometheus_running = any('prometheus' in c.lower() for c in running_containers)
        grafana_running = any('grafana' in c.lower() for c in running_containers)
        
        if prometheus_running and grafana_running:
            console.print("[green]✓[/green] Prometheus running on port 9090")
            console.print("[green]✓[/green] Grafana running on port 3000")
        elif prometheus_running or grafana_running:
            console.print("[green]✓[/green] Services starting...")
            if not prometheus_running:
                console.print("[yellow]⚠[/yellow] Prometheus may still be starting")
            if not grafana_running:
                console.print("[yellow]⚠[/yellow] Grafana may still be starting")
        else:
            # Check for actual errors in container status
            status_result = subprocess.run(
                ["docker", "compose", "ps", "-a"],
                cwd=compose_dir,
                capture_output=True,
                text=True
            )
            console.print(f"[yellow]⚠[/yellow] Services may still be starting. Status:")
            console.print(f"[dim]{status_result.stdout[:300]}[/dim]")
    
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
        # and use cryptolabs network with static IPs
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
      - TRUSTED_PROXY_IPS=127.0.0.1,{PROXY_STATIC_IP}
    volumes:
      - dc-data:/data
      - ./ssh_keys:/etc/dc-overview/ssh_keys:ro
    networks:
      cryptolabs:
        ipv4_address: {STATIC_IPS['dc-overview']}
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
      cryptolabs:
        ipv4_address: {STATIC_IPS['prometheus']}
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
      - GF_AUTH_PROXY_ENABLED=true
      - GF_AUTH_PROXY_HEADER_NAME=X-WEBAUTH-USER
      - GF_AUTH_PROXY_AUTO_SIGN_UP=true
    depends_on:
      - prometheus
    networks:
      cryptolabs:
        ipv4_address: {STATIC_IPS['grafana']}
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
            # Fresh install - use cryptolabs network with static IPs
            # Proxy will be deployed later and will get its static IP
            return f"""services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    ports:
      - "127.0.0.1:9090:9090"
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
      cryptolabs:
        ipv4_address: {STATIC_IPS['prometheus']}

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    ports:
      - "127.0.0.1:3000:3000"
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
      cryptolabs:
        ipv4_address: {STATIC_IPS['grafana']}

volumes:
  prometheus-data:
  grafana-data:

networks:
  cryptolabs:
    external: true
"""
    
    def _generate_prometheus_config(self) -> str:
        """Generate initial prometheus.yml."""
        # Use host.docker.internal for master since Prometheus runs in Docker
        # and can't reach the host's LAN IP from within the container
        master_target = "host.docker.internal"
        
        config = f"""global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "/etc/prometheus/recording_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    metrics_path: /prometheus/metrics
    static_configs:
      - targets: ['prometheus:9090']

  - job_name: 'master'
    static_configs:
      - targets: ['{master_target}:9100', '{master_target}:9835']
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
                "metrics_path": "/prometheus/metrics",
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
        
        # Add IPMI Monitor if enabled (runs as container on cryptolabs network)
        if self.config.components.ipmi_monitor:
            scrape_configs.append({
                "job_name": "ipmi-monitor",
                "static_configs": [{
                    "targets": ["ipmi-monitor:5000"],
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
        
        # Set DC Overview as the home dashboard
        self._set_grafana_home_dashboard(grafana_url, auth_header)
    
    # Dashboard UID to display name mapping
    DASHBOARD_NAMES = {
        "dc-overview-main": "DC Overview",
        "vast-dashboard": "Vast.ai Dashboard",
        "node-exporter-full": "Node Exporter Full",
    }
    
    def _set_grafana_home_dashboard(self, grafana_url: str, auth_header: str):
        """
        Set the configured dashboard as Grafana home dashboard.
        
        This API call is safe because:
        1. Grafana is bound to 127.0.0.1:3000 (not externally accessible)
        2. Only called during local quickstart setup
        3. Uses already-configured admin credentials
        """
        # Check if home dashboard is configured
        dashboard_uid = self.config.grafana.home_dashboard
        if not dashboard_uid:
            console.print("[dim]Home dashboard: Using Grafana default[/dim]")
            return
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth_header}"
        }
        
        try:
            # Set org preferences to use configured dashboard as home
            data = json.dumps({
                "homeDashboardUID": dashboard_uid
            }).encode('utf-8')
            
            req = urllib.request.Request(
                f"{grafana_url}/api/org/preferences",
                data=data,
                headers=headers,
                method="PUT"
            )
            
            resp = urllib.request.urlopen(req, timeout=10)
            dashboard_name = self.DASHBOARD_NAMES.get(dashboard_uid, dashboard_uid)
            if resp.status == 200:
                console.print(f"[green]✓[/green] {dashboard_name} set as Grafana home dashboard")
            else:
                console.print("[yellow]⚠[/yellow] Could not set home dashboard")
                
        except Exception as e:
            # Non-critical - just log and continue
            console.print(f"[dim]Note: Could not set home dashboard: {str(e)[:40]}[/dim]")
    
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
                "url": "http://prometheus:9090/prometheus/",
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
    
    def _get_dashboard_branch(self) -> str:
        """Get the GitHub branch to fetch dashboards from.
        
        Environment variable DASHBOARD_BRANCH controls this:
        - 'dev' or 'development': fetch from dev branch (for testing)
        - 'main' or unset: fetch from main branch (default)
        - Any other value: use as branch name
        """
        branch = os.environ.get('DASHBOARD_BRANCH', 'main').lower()
        if branch in ('dev', 'development'):
            return 'dev'
        elif branch in ('main', 'master', ''):
            return 'main'
        return branch
    
    def _get_dashboard_list(self) -> List[Dict[str, Any]]:
        """Get list of dashboards to install based on enabled components."""
        dashboards = []
        branch = self._get_dashboard_branch()
        base_url = f"https://raw.githubusercontent.com/cryptolabsza/dc-overview/{branch}/dashboards"
        
        if self.config.components.dc_overview:
            dashboards.extend([
                {
                    "name": "DC Overview",
                    "local_file": "DC_Overview.json",
                    "github_url": f"{base_url}/DC_Overview.json",
                },
                {
                    "name": "Node Exporter Full",
                    "local_file": "Node_Exporter_Full.json",
                    "github_url": f"{base_url}/Node_Exporter_Full.json",
                },
                {
                    "name": "DC Exporter Details",
                    "local_file": "DC_Exporter_Details.json",
                    "github_url": f"{base_url}/DC_Exporter_Details.json",
                },
            ])
        
        if self.config.components.vast_exporter:
            dashboards.append({
                "name": "Vast Dashboard",
                "local_file": "Vast_Dashboard.json",
                "github_url": f"{base_url}/Vast_Dashboard.json",
            })
        
        if self.config.components.ipmi_monitor:
            dashboards.append({
                "name": "IPMI Monitor",
                "local_file": "IPMI_Monitor.json",
                "github_url": f"{base_url}/IPMI_Monitor.json",
            })
        
        return dashboards
    
    def _get_dashboard_json(self, dashboard: Dict[str, Any]) -> Optional[str]:
        """Get dashboard JSON from GitHub or local file.
        
        When DASHBOARD_BRANCH is set (dev mode), fetch from GitHub first
        to ensure you get the latest changes. Otherwise, prefer local files.
        """
        branch = self._get_dashboard_branch()
        fetch_from_github_first = branch != 'main'
        
        if fetch_from_github_first:
            # Dev mode: try GitHub first to get latest changes
            github_url = dashboard.get("github_url")
            if github_url:
                try:
                    console.print(f"[dim]  Fetching from GitHub ({branch} branch)...[/dim]")
                    return urllib.request.urlopen(github_url, timeout=30).read().decode('utf-8')
                except Exception as e:
                    console.print(f"[dim]  GitHub fetch failed: {e}, trying local...[/dim]")
        
        # Try local file
        try:
            import dc_overview
            pkg_path = Path(dc_overview.__file__).parent / "dashboards"
            local_file = pkg_path / dashboard["local_file"]
            if local_file.exists():
                return local_file.read_text()
        except Exception:
            pass
        
        # Fall back to GitHub (for production when local doesn't exist)
        if not fetch_from_github_first:
            github_url = dashboard.get("github_url")
            if github_url:
                try:
                    return urllib.request.urlopen(github_url, timeout=30).read().decode('utf-8')
                except Exception:
                    pass
        
        return None
    
    # ============ Step 7: IPMI Monitor ============
    
    def _deploy_ipmi_monitor(self):
        """Deploy IPMI Monitor as a Docker container on the cryptolabs network."""
        console.print("\n[bold]Step 7: Installing IPMI Monitor[/bold]\n")
        
        # Check if container is already running
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
        
        # Create config directory
        ipmi_config_dir = Path("/etc/ipmi-monitor")
        ipmi_config_dir.mkdir(parents=True, exist_ok=True)
        
        # Build servers config for IPMI Monitor
        # Note: ipmi-monitor expects 'ipmi_user' and 'ipmi_pass' (not bmc_user/bmc_password)
        # Also: ipmi-monitor's parser expects each server to START with '- name:' 
        servers = []
        for server in self.config.servers:
            if server.bmc_ip:
                bmc_creds = self.config.get_server_bmc_creds(server)
                servers.append({
                    "name": server.name,
                    "bmc_ip": server.bmc_ip,
                    "ipmi_user": bmc_creds.username,
                    "ipmi_pass": bmc_creds.password,
                    "server_ip": server.server_ip,
                })
        
        # Write servers.yaml config with specific format (name must be first key)
        if servers:
            yaml_lines = ["servers:"]
            for srv in servers:
                # Ensure 'name' is first as ipmi-monitor parser requires '- name:' to start
                yaml_lines.append(f"  - name: {srv['name']}")
                yaml_lines.append(f"    bmc_ip: {srv['bmc_ip']}")
                yaml_lines.append(f"    ipmi_user: {srv['ipmi_user']}")
                yaml_lines.append(f"    ipmi_pass: {srv['ipmi_pass']}")
                yaml_lines.append(f"    server_ip: {srv['server_ip']}")
            with open(ipmi_config_dir / "servers.yaml", "w") as f:
                f.write("\n".join(yaml_lines) + "\n")
            os.chmod(ipmi_config_dir / "servers.yaml", 0o600)
        else:
            # Create empty servers file so container starts
            with open(ipmi_config_dir / "servers.yaml", "w") as f:
                yaml.dump({"servers": []}, f)
        
        # Ensure cryptolabs network exists with correct subnet
        _ensure_docker_network()
        
        # Pull latest image
        console.print("[dim]Pulling ipmi-monitor image...[/dim]")
        subprocess.run(
            ["docker", "pull", "ghcr.io/cryptolabsza/ipmi-monitor:dev"],
            capture_output=True
        )
        
        # Remove old container if exists
        subprocess.run(["docker", "rm", "-f", "ipmi-monitor"], capture_output=True)
        
        # Get admin password (use fleet admin or IPMI monitor specific)
        admin_pass = self.config.ipmi_monitor.admin_password or self.config.fleet_admin_pass or "changeme"
        
        # Build environment variables
        env_vars = [
            "-e", "APP_NAME=IPMI Monitor",
            "-e", f"ADMIN_USER={self.config.fleet_admin_user or 'admin'}",
            "-e", f"ADMIN_PASS={admin_pass}",
            "-e", f"SECRET_KEY={os.urandom(32).hex()}",
            "-e", "POLL_INTERVAL=300",
        ]
        
        # Add default BMC credentials if configured
        if self.config.bmc and self.config.bmc.password:
            env_vars.extend([
                "-e", f"IPMI_USER={self.config.bmc.username}",
                "-e", f"IPMI_PASS={self.config.bmc.password}",
            ])
        
        # Add AI license key if configured
        if self.config.ipmi_monitor.ai_license_key:
            env_vars.extend([
                "-e", "AI_SERVICE_URL=https://ipmi-ai.cryptolabs.co.za",
                "-e", f"AI_LICENSE_KEY={self.config.ipmi_monitor.ai_license_key}",
            ])
        
        # Security: Trust proxy's static IP and localhost (for internal curl commands)
        env_vars.extend([
            "-e", f"TRUSTED_PROXY_IPS=127.0.0.1,{PROXY_STATIC_IP}",
        ])
        
        # Prepare SSH keys mount if available
        ssh_keys_dir = self.config.config_dir / "ssh_keys"
        ssh_keys_mount = []
        if ssh_keys_dir.exists() and any(ssh_keys_dir.iterdir()):
            ssh_keys_mount = ["-v", f"{ssh_keys_dir}:/app/ssh_keys:ro"]
            console.print("[dim]  Mounting shared SSH keys for ipmi-monitor[/dim]")
        
        # Run container on cryptolabs network with static IP for security
        docker_cmd = [
            "docker", "run", "-d",
            "--name", "ipmi-monitor",
            "--restart", "unless-stopped",
            "--network", DOCKER_NETWORK_NAME,
            "--ip", STATIC_IPS["ipmi-monitor"],
            "-v", "ipmi-monitor-data:/app/data",
            "-v", f"{ipmi_config_dir}/servers.yaml:/app/config/servers.yaml:ro",
        ] + ssh_keys_mount + [
            "--label", "com.centurylinklabs.watchtower.enable=true",
        ] + env_vars + [
            "ghcr.io/cryptolabsza/ipmi-monitor:dev"
        ]
        
        result = subprocess.run(docker_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            console.print("[green]✓[/green] IPMI Monitor container started")
            if servers:
                console.print(f"[dim]  Configured {len(servers)} servers for IPMI monitoring[/dim]")
            
            # Wait for container to be healthy and database migrations to complete
            console.print("[dim]  Waiting for IPMI Monitor to initialize...[/dim]")
            self._wait_for_ipmi_monitor_ready()
            self._import_ssh_key_to_ipmi_monitor()
            self._activate_ai_license_in_ipmi_monitor()
        else:
            console.print(f"[yellow]⚠[/yellow] Failed to start IPMI Monitor: {result.stderr[:100]}")
    
    def _wait_for_ipmi_monitor_ready(self, timeout: int = 60):
        """Wait for IPMI Monitor container to be healthy and database ready."""
        import time
        start = time.time()
        
        while time.time() - start < timeout:
            try:
                # Check if the container is healthy and API is responding
                result = subprocess.run(
                    ['docker', 'exec', 'ipmi-monitor', 'curl', '-s', '-f', 
                     'http://127.0.0.1:5000/health'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and 'healthy' in result.stdout:
                    # Also verify database tables exist
                    check_script = '''
import sys
from app import db, app
from sqlalchemy import inspect
with app.app_context():
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    if "ssh_key" in tables and "ssh_logs" in tables:
        print("READY")
        sys.exit(0)
    sys.exit(1)
'''
                    check_result = subprocess.run(
                        ['docker', 'exec', 'ipmi-monitor', 'python3', '-c', check_script],
                        capture_output=True, text=True, timeout=15
                    )
                    if "READY" in check_result.stdout:
                        return True
            except Exception:
                pass
            time.sleep(2)
        
        console.print("[yellow]⚠[/yellow] IPMI Monitor taking longer than expected to initialize")
        return False
    
    def _import_ssh_key_to_ipmi_monitor(self):
        """Import the fleet SSH key into IPMI Monitor's database."""
        ssh_keys_dir = self.config.config_dir / "ssh_keys"
        fleet_key_path = ssh_keys_dir / "fleet_key"
        
        if not fleet_key_path.exists():
            console.print("[dim]  No SSH key to import into IPMI Monitor[/dim]")
            return
        
        try:
            # Read the key content
            with open(fleet_key_path, 'r') as f:
                key_content = f.read().strip()
            
            # Get fingerprint
            try:
                result = subprocess.run(
                    ['ssh-keygen', '-lf', str(fleet_key_path)],
                    capture_output=True, text=True, timeout=5
                )
                fingerprint = result.stdout.split()[1] if result.returncode == 0 else "unknown"
            except Exception:
                fingerprint = "unknown"
            
            # Import into IPMI Monitor database via Flask app context
            enable_ssh_inventory = "true" if self.config.ipmi_monitor.enable_ssh_inventory else "false"
            enable_ssh_logs = "true" if self.config.ipmi_monitor.enable_ssh_logs else "false"
            
            # Escape key content for safe embedding in script
            escaped_key = key_content.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
            
            import_script = f'''
from app import db, app, SSHKey, SystemSettings
import sys

key_content = """{key_content}"""
fingerprint = "{fingerprint}"

with app.app_context():
    try:
        key_id = None
        
        # Check for existing keys
        existing_fleet_ssh_key = SSHKey.query.filter_by(name="Fleet SSH Key").first()
        existing_fleet_key = SSHKey.query.filter_by(name="fleet_key").first()  # Auto-imported key
        existing_by_fp = SSHKey.query.filter_by(fingerprint=fingerprint).first() if fingerprint and fingerprint != "unknown" else None
        
        if existing_fleet_ssh_key:
            # Fleet SSH Key already exists - use it
            print(f"Fleet SSH Key already exists with ID {{existing_fleet_ssh_key.id}}", file=sys.stderr)
            key_id = existing_fleet_ssh_key.id
            # Update fingerprint if needed
            if existing_fleet_ssh_key.fingerprint != fingerprint:
                existing_fleet_ssh_key.fingerprint = fingerprint
                db.session.commit()
            # Delete duplicate "fleet_key" if it exists (from auto-import)
            if existing_fleet_key:
                print(f"Deleting duplicate auto-imported key: fleet_key", file=sys.stderr)
                db.session.delete(existing_fleet_key)
                db.session.commit()
        elif existing_fleet_key:
            # Auto-imported "fleet_key" exists - rename it to "Fleet SSH Key"
            print(f"Renaming auto-imported fleet_key to Fleet SSH Key", file=sys.stderr)
            existing_fleet_key.name = "Fleet SSH Key"
            existing_fleet_key.fingerprint = fingerprint  # Set correct fingerprint
            db.session.commit()
            key_id = existing_fleet_key.id
        elif existing_by_fp:
            # Key with same fingerprint exists but different name
            print(f"Renaming {{existing_by_fp.name}} to Fleet SSH Key", file=sys.stderr)
            existing_by_fp.name = "Fleet SSH Key"
            db.session.commit()
            key_id = existing_by_fp.id
        else:
            # Create new key
            key = SSHKey(name="Fleet SSH Key", key_content=key_content, fingerprint=fingerprint)
            db.session.add(key)
            db.session.commit()
            key_id = key.id
            print(f"Imported Fleet SSH Key with ID: {{key_id}}", file=sys.stderr)
        
        # Set as default SSH key
        SystemSettings.set("default_ssh_key_id", str(key_id))
        SystemSettings.set("ssh_user", "root")
        
        # Enable SSH features based on config
        SystemSettings.set("enable_ssh_inventory", "{enable_ssh_inventory}")
        # SSH log collection settings (correct setting names for IPMI Monitor)
        SystemSettings.set("enable_ssh_log_collection", "{enable_ssh_logs}")
        if "{enable_ssh_logs}" == "true":
            SystemSettings.set("ssh_log_interval", "15")  # 15 minute interval
        db.session.commit()
        
        print("Set as default SSH key and enabled SSH features", file=sys.stderr)
    except Exception as e:
        print(f"Error: {{e}}", file=sys.stderr)
        db.session.rollback()
'''
            
            result = subprocess.run(
                ['docker', 'exec', 'ipmi-monitor', 'python3', '-c', import_script],
                capture_output=True, text=True, timeout=30
            )
            
            if "Imported" in result.stderr or "already exists" in result.stderr:
                console.print("[green]✓[/green] SSH key imported into IPMI Monitor")
                if self.config.ipmi_monitor.enable_ssh_inventory:
                    console.print("[green]✓[/green] SSH inventory enabled")
                if self.config.ipmi_monitor.enable_ssh_logs:
                    console.print("[green]✓[/green] SSH log collection enabled")
            else:
                console.print(f"[yellow]⚠[/yellow] SSH key import: {result.stderr[:100]}")
                
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Failed to import SSH key to IPMI Monitor: {e}")
    
    def _activate_ai_license_in_ipmi_monitor(self):
        """Activate AI license in IPMI Monitor if configured."""
        if not self.config.ipmi_monitor.ai_license_key:
            return
        
        license_key = self.config.ipmi_monitor.ai_license_key
        console.print("[dim]  Activating AI license in IPMI Monitor...[/dim]")
        
        try:
            # Activate AI license via docker exec
            # This validates the key with CryptoLabs AI service and stores it in the database
            activate_script = f'''
import sqlite3
import requests
import sys

license_key = "{license_key}"
ai_service_url = "https://ipmi-ai.cryptolabs.co.za"
db_path = "/app/data/ipmi_events.db"

try:
    # Validate with AI service
    response = requests.post(
        f"{{ai_service_url}}/api/v1/validate",
        json={{"license_key": license_key}},
        timeout=10
    )
    validation = response.json()
    
    if validation.get("valid"):
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Check if cloud_sync record exists
        c.execute("SELECT id FROM cloud_sync LIMIT 1")
        existing = c.fetchone()
        
        if existing:
            c.execute("""
                UPDATE cloud_sync SET 
                    license_key = ?,
                    subscription_valid = 1,
                    subscription_tier = ?,
                    max_servers = ?,
                    sync_enabled = 1
                WHERE id = ?
            """, (license_key, validation.get("tier", "standard"), validation.get("max_servers", 50), existing[0]))
        else:
            c.execute("""
                INSERT INTO cloud_sync (license_key, subscription_valid, subscription_tier, max_servers, sync_enabled)
                VALUES (?, 1, ?, ?, 1)
            """, (license_key, validation.get("tier", "standard"), validation.get("max_servers", 50)))
        
        conn.commit()
        conn.close()
        print(f"ACTIVATED:tier={{validation.get('tier')}},max_servers={{validation.get('max_servers')}}", file=sys.stderr)
    else:
        print(f"INVALID:{{validation.get('error', 'Unknown error')}}", file=sys.stderr)
except Exception as e:
    print(f"ERROR:{{e}}", file=sys.stderr)
'''
            
            result = subprocess.run(
                ['docker', 'exec', 'ipmi-monitor', 'python3', '-c', activate_script],
                capture_output=True, text=True, timeout=30
            )
            
            if "ACTIVATED" in result.stderr:
                # Parse tier info from output
                parts = result.stderr.strip().split(":")
                if len(parts) >= 2:
                    info = parts[1]
                    console.print(f"[green]✓[/green] AI license activated ({info})")
                else:
                    console.print("[green]✓[/green] AI license activated")
            elif "INVALID" in result.stderr:
                console.print(f"[yellow]⚠[/yellow] AI license invalid: {result.stderr.split(':')[1] if ':' in result.stderr else 'unknown'}")
            else:
                console.print(f"[yellow]⚠[/yellow] AI license activation: {result.stderr[:100]}")
                
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Failed to activate AI license: {e}")
    
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
        
        # Ensure cryptolabs network exists with correct subnet
        _ensure_docker_network()
        
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
        # Use static IP so downstream services can trust only this specific IP
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
            "--network", DOCKER_NETWORK_NAME,
            "--ip", PROXY_STATIC_IP,
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
        
        # Start dc-overview container with static IP
        flask_secret = secrets_module.token_hex(16)
        cmd = [
            "docker", "run", "-d",
            "--name", "dc-overview",
            "--restart", "unless-stopped",
            "-e", f"FLASK_SECRET_KEY={flask_secret}",
            "-e", "DC_OVERVIEW_PORT=5001",
            "-e", f"TRUSTED_PROXY_IPS=127.0.0.1,{PROXY_STATIC_IP}",
            "-v", "dc-overview-data:/data",
            "-v", f"{self.config.config_dir}:/etc/dc-overview:ro",
            "--health-cmd", "curl -f http://127.0.0.1:5001/api/health || exit 1",
            "--health-interval", "10s",
            "--health-timeout", "5s",
            "--health-retries", "3",
            "--health-start-period", "10s",
            "--network", DOCKER_NETWORK_NAME,
            "--ip", STATIC_IPS["dc-overview"],
            "--label", "com.centurylinklabs.watchtower.enable=true",
            "ghcr.io/cryptolabsza/dc-overview:dev"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            console.print("[green]✓[/green] DC Overview (Server Manager) container started")
            # Populate servers after container starts
            self._populate_dc_overview_servers()
    
    def _populate_dc_overview_servers(self):
        """Populate dc-overview database with configured servers via API."""
        import time
        import json
        import shutil
        
        if not self.config.servers:
            return
            
        console.print("[dim]Populating Server Manager with configured servers...[/dim]")
        
        # Wait for dc-overview container to be healthy
        max_retries = 30
        for i in range(max_retries):
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}", "dc-overview"],
                capture_output=True, text=True
            )
            if result.returncode == 0 and result.stdout.strip() == "healthy":
                break
            time.sleep(1)
        else:
            console.print("[yellow]⚠[/yellow] dc-overview container not healthy, skipping server population")
            return
        
        # Step 1: Set up SSH key if configured
        ssh_key_id = None
        if self.config.ssh.key_path:
            ssh_key_id = self._setup_dc_overview_ssh_key()
        
        # Step 2: Add each server via docker exec curl
        added = 0
        for server in self.config.servers:
            data = json.dumps({
                "name": server.name,
                "server_ip": server.server_ip,
                "ssh_user": self.config.ssh.username,
                "ssh_port": self.config.ssh.port,
            })
            
            result = subprocess.run([
                "docker", "exec", "dc-overview",
                "curl", "-s", "-X", "POST",
                "http://127.0.0.1:5001/api/servers",
                "-H", "Content-Type: application/json",
                "-H", "X-Fleet-Authenticated: true",
                "-H", "X-Fleet-Auth-User: admin",
                "-H", "X-Fleet-Auth-Role: admin",
                "-d", data
            ], capture_output=True, text=True)
            
            server_id = None
            if result.returncode == 0:
                try:
                    response = json.loads(result.stdout)
                    if "id" in response:
                        server_id = response["id"]
                        added += 1
                    elif "error" in response and "already exists" in response["error"]:
                        # Get existing server ID for SSH key assignment
                        server_id = response.get("id")
                    else:
                        console.print(f"[yellow]⚠[/yellow] Failed to add {server.name}: {response.get('error', 'Unknown error')}")
                except:
                    console.print(f"[yellow]⚠[/yellow] Failed to add {server.name}: {result.stdout[:100]}")
            else:
                console.print(f"[yellow]⚠[/yellow] Failed to add {server.name}: {result.stderr[:100]}")
            
            # Step 3: Associate SSH key with server if we have both
            if server_id and ssh_key_id:
                self._set_server_ssh_key(server_id, ssh_key_id)
        
        if added > 0:
            console.print(f"[green]✓[/green] Added {added} servers to Server Manager")
    
    def _setup_dc_overview_ssh_key(self) -> int:
        """Copy SSH key to dc-overview volume and register it in the database."""
        import json
        import shutil
        
        if not self.config.ssh.key_path:
            return None
        
        # Create ssh_keys directory in config path
        ssh_keys_dir = self.config.config_dir / "ssh_keys"
        ssh_keys_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy the private key
        key_name = "fleet_key"
        dest_key_path = ssh_keys_dir / key_name
        
        try:
            shutil.copy2(self.config.ssh.key_path, dest_key_path)
            os.chmod(dest_key_path, 0o600)
            # Set ownership to uid 1000 (dcuser in the container)
            # This allows the dc-overview container to read the key
            try:
                os.chown(dest_key_path, 1000, 1000)
            except (OSError, PermissionError):
                # If we can't chown (e.g., not running as root), that's OK
                # The container might still work if running as root or with proper mounts
                pass
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Failed to copy SSH key: {e}")
            return None
        
        # The path inside the container (as per docker-compose volume mount)
        container_key_path = f"/etc/dc-overview/ssh_keys/{key_name}"
        
        # Register the SSH key in dc-overview database
        data = json.dumps({
            "name": "Fleet SSH Key",
            "key_path": container_key_path,
        })
        
        result = subprocess.run([
            "docker", "exec", "dc-overview",
            "curl", "-s", "-X", "POST",
            "http://127.0.0.1:5001/api/ssh-keys",
            "-H", "Content-Type: application/json",
            "-H", "X-Fleet-Authenticated: true",
            "-H", "X-Fleet-Auth-User: admin",
            "-H", "X-Fleet-Auth-Role: admin",
            "-d", data
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            try:
                response = json.loads(result.stdout)
                if "id" in response:
                    console.print(f"[green]✓[/green] SSH key registered in Server Manager")
                    return response["id"]
                elif "error" in response:
                    # Key might already exist
                    if "already exists" in response.get("error", ""):
                        return response.get("id")
                    console.print(f"[yellow]⚠[/yellow] Failed to register SSH key: {response.get('error')}")
            except:
                console.print(f"[yellow]⚠[/yellow] Failed to register SSH key: {result.stdout[:100]}")
        
        return None
    
    def _set_server_ssh_key(self, server_id: int, ssh_key_id: int):
        """Associate an SSH key with a server in dc-overview."""
        import json
        
        data = json.dumps({"ssh_key_id": ssh_key_id})
        
        subprocess.run([
            "docker", "exec", "dc-overview",
            "curl", "-s", "-X", "POST",
            f"http://127.0.0.1:5001/api/servers/{server_id}/ssh-key",
            "-H", "Content-Type: application/json",
            "-H", "X-Fleet-Authenticated: true",
            "-H", "X-Fleet-Auth-User: admin",
            "-H", "X-Fleet-Auth-Role: admin",
            "-d", data
        ], capture_output=True, text=True)
    
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
        """Integrate with existing cryptolabs-proxy - update it with correct config."""
        import secrets as secrets_module
        
        console.print("\n[bold]Step 9: Integrating with CryptoLabs Proxy[/bold]\n")
        console.print("[dim]Updating proxy with Fleet credentials and Docker socket access...[/dim]\n")
        
        domain = self.config.ssl.domain or "localhost"
        
        # Check if proxy needs to be updated (missing credentials or Docker socket)
        needs_update = False
        try:
            result = subprocess.run(
                ["docker", "inspect", "cryptolabs-proxy", "--format", 
                 "{{range .Config.Env}}{{println .}}{{end}}"],
                capture_output=True, text=True, timeout=10
            )
            env_vars = result.stdout if result.returncode == 0 else ""
            
            # Check if credentials are set
            if "FLEET_ADMIN_USER=" not in env_vars or "FLEET_ADMIN_PASS=" not in env_vars:
                console.print("[dim]Proxy missing Fleet credentials - will update[/dim]")
                needs_update = True
            
            # Check if Docker socket is mounted
            result = subprocess.run(
                ["docker", "exec", "cryptolabs-proxy", "ls", "/var/run/docker.sock"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                console.print("[dim]Proxy missing Docker socket - will update[/dim]")
                needs_update = True
                
        except Exception as e:
            console.print(f"[dim]Could not inspect proxy: {e} - will recreate[/dim]")
            needs_update = True
        
        if needs_update:
            # Determine SSL certificate paths
            letsencrypt_path = Path(f"/etc/letsencrypt/live/{domain}")
            ssl_mounts = []
            
            if letsencrypt_path.exists():
                # Use Let's Encrypt certificates
                ssl_mounts = [
                    "-v", f"{letsencrypt_path}/fullchain.pem:/etc/nginx/ssl/server.crt:ro",
                    "-v", f"{letsencrypt_path}/privkey.pem:/etc/nginx/ssl/server.key:ro",
                    "-v", "/etc/letsencrypt:/etc/letsencrypt:ro",
                ]
                console.print(f"[dim]Using Let's Encrypt certificate for {domain}[/dim]")
            else:
                # Check for self-signed certs
                ssl_dir = Path("/etc/dc-overview/ssl")
                if not ssl_dir.exists() or not (ssl_dir / "server.crt").exists():
                    ssl_dir.mkdir(parents=True, exist_ok=True)
                    self._generate_self_signed_cert(domain, ssl_dir)
                ssl_mounts = ["-v", f"{ssl_dir}:/etc/nginx/ssl:ro"]
                console.print("[dim]Using self-signed certificate[/dim]")
            
            # Generate auth secret
            auth_secret = secrets_module.token_hex(32)
            
            # Remove existing proxy
            subprocess.run(["docker", "rm", "-f", "cryptolabs-proxy"], capture_output=True)
            
            # Ensure network exists with correct subnet before recreating proxy
            _ensure_docker_network()
            
            # Recreate proxy with correct configuration and static IP for security
            cmd = [
                "docker", "run", "-d",
                "--name", "cryptolabs-proxy",
                "--restart", "unless-stopped",
                "-p", "80:80", "-p", "443:443",
                "-e", f"FLEET_ADMIN_USER={self.config.fleet_admin_user}",
                "-e", f"FLEET_ADMIN_PASS={self.config.fleet_admin_pass}",
                "-e", f"AUTH_SECRET_KEY={auth_secret}",
                "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
                "-v", "fleet-auth-data:/data",
                "--network", DOCKER_NETWORK_NAME,
                "--ip", PROXY_STATIC_IP,
                "--label", "com.centurylinklabs.watchtower.enable=true",
            ] + ssl_mounts + [
                "ghcr.io/cryptolabsza/cryptolabs-proxy:dev"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                console.print("[green]✓[/green] CryptoLabs Proxy updated with Fleet credentials")
                # Wait for proxy to be healthy
                time.sleep(3)
            else:
                console.print(f"[red]✗[/red] Failed to update proxy: {result.stderr[:200]}")
                return
        else:
            console.print("[green]✓[/green] Proxy already configured correctly")
        
        # Ensure containers are on the cryptolabs network
        network = "cryptolabs"
        containers = ["prometheus", "grafana", "dc-overview", "ipmi-monitor"]
        
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
        
        # Verify service detection is working
        try:
            result = subprocess.run(
                ["curl", "-s", "http://localhost/api/services"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and '"running": true' in result.stdout:
                console.print("[green]✓[/green] Service detection working")
            else:
                console.print("[yellow]⚠[/yellow] Service detection may need a moment to initialize")
        except Exception:
            pass
        
        console.print(f"\n  Fleet Management: [cyan]https://{domain}/[/cyan]")
        console.print(f"  DC Overview: [cyan]https://{domain}/dc/[/cyan]")
        console.print(f"  Grafana: [cyan]https://{domain}/grafana/[/cyan]")
        console.print(f"  Prometheus: [cyan]https://{domain}/prometheus/[/cyan]")
        console.print(f"\n  Login: [cyan]{self.config.fleet_admin_user}[/cyan] / [dim](password you set)[/dim]")
    
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
    
    # ============ Step 10: Security Hardening ============
    
    def _setup_security_hardening(self):
        """Configure UFW firewall and security settings."""
        console.print("\n[bold]Step 10: Security Hardening[/bold]\n")
        
        # Check if UFW is enabled in config
        if hasattr(self.config, 'security') and not self.config.security.ufw_enabled:
            console.print("[dim]UFW firewall disabled in configuration[/dim]")
            return
        
        # Check if UFW is available
        result = subprocess.run(["which", "ufw"], capture_output=True)
        if result.returncode != 0:
            console.print("[yellow]⚠[/yellow] UFW not installed - skipping firewall configuration")
            console.print("[dim]Install with: apt install ufw[/dim]")
            return
        
        # Check current UFW status
        result = subprocess.run(["ufw", "status"], capture_output=True, text=True)
        if "Status: active" in result.stdout:
            console.print("[green]✓[/green] UFW firewall already active")
            return
        
        # Build list of ports to allow
        ssh_port = getattr(self.config.ssh, 'port', 22) or 22
        
        ports_to_allow = {
            ssh_port: "SSH (primary)",
            80: "HTTP (redirect to HTTPS)",
            443: "HTTPS (proxy)",
        }
        
        # Add ports from security config
        if hasattr(self.config, 'security'):
            for port in self.config.security.ufw_ports:
                if port not in ports_to_allow:
                    ports_to_allow[port] = f"Port {port}"
            for port in self.config.security.ufw_additional_ports:
                if port not in ports_to_allow:
                    ports_to_allow[port] = f"Port {port} (custom)"
        
        # Check if common alternative SSH ports might be in use (100, 101, 103)
        for alt_port in [100, 101, 103]:
            if alt_port != ssh_port:
                # Check if something is listening on this port
                check_result = subprocess.run(
                    ["ss", "-tlnp", f"sport = :{alt_port}"],
                    capture_output=True, text=True
                )
                if f":{alt_port}" in check_result.stdout:
                    ports_to_allow[alt_port] = f"SSH (port {alt_port})"
        
        # Show ports to be allowed and ask for confirmation
        console.print("[bold]UFW Firewall Configuration[/bold]")
        console.print()
        console.print("The following ports will be [green]ALLOWED[/green] through the firewall:")
        console.print()
        
        port_table = Table(show_header=True, header_style="bold")
        port_table.add_column("Port", style="cyan", justify="right")
        port_table.add_column("Service")
        port_table.add_column("Status", justify="center")
        
        for port, service in sorted(ports_to_allow.items()):
            port_table.add_row(str(port), service, "[green]ALLOW[/green]")
        
        port_table.add_row("*", "All other incoming", "[red]DENY[/red]")
        console.print(port_table)
        console.print()
        
        console.print("[dim]Internal services (Prometheus :9090, Grafana :3000, exporters) will")
        console.print("only be accessible through the HTTPS proxy, not directly.[/dim]")
        console.print()
        
        # Check if non-interactive mode (auto-confirm)
        auto_confirm = getattr(self.config, 'auto_confirm', False)
        
        if not auto_confirm:
            from rich.prompt import Confirm
            if not Confirm.ask("Enable UFW firewall with these rules?", default=True):
                console.print("[yellow]⚠[/yellow] Skipping firewall configuration")
                console.print("[dim]You can enable UFW manually later: ufw enable[/dim]")
                return
        
        console.print()
        console.print("[dim]Configuring UFW firewall rules...[/dim]")
        
        # Set default policies
        subprocess.run(["ufw", "default", "deny", "incoming"], capture_output=True)
        subprocess.run(["ufw", "default", "allow", "outgoing"], capture_output=True)
        
        # Allow configured ports
        for port in sorted(ports_to_allow.keys()):
            subprocess.run(["ufw", "allow", str(port)], capture_output=True)
        
        # Allow Docker network to access host ports (required for Prometheus to scrape host exporters)
        subprocess.run(
            ["ufw", "allow", "from", DOCKER_NETWORK_SUBNET, "comment", "Docker cryptolabs network"],
            capture_output=True
        )
        
        # Enable UFW (non-interactive)
        result = subprocess.run(
            ["ufw", "--force", "enable"],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            console.print("[green]✓[/green] UFW firewall enabled")
            console.print()
            console.print("[bold]Active Firewall Rules:[/bold]")
            for port, service in sorted(ports_to_allow.items()):
                console.print(f"  • {service} (port {port}): [green]ALLOWED[/green]")
            console.print("  • All other incoming: [red]DENIED[/red]")
        else:
            console.print(f"[yellow]⚠[/yellow] Failed to enable UFW: {result.stderr[:100]}")
    
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
        console.print("  • DC Exporter Details (GPU metrics)")
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
