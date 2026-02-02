"""
DC Overview Fleet Configuration
Data classes that hold ALL configuration collected upfront.
Ask once, use everywhere.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from pathlib import Path
from enum import Enum
import yaml
import os


class SSLMode(Enum):
    """SSL certificate mode."""
    SELF_SIGNED = "self_signed"
    LETSENCRYPT = "letsencrypt"


class AuthMethod(Enum):
    """SSH authentication method."""
    PASSWORD = "password"
    KEY = "key"


@dataclass
class SSLConfig:
    """SSL/TLS configuration."""
    mode: SSLMode = SSLMode.SELF_SIGNED
    domain: Optional[str] = None
    email: Optional[str] = None  # Required for Let's Encrypt
    cert_path: Optional[str] = None
    key_path: Optional[str] = None
    external_port: int = 443  # External HTTPS port (e.g., 8443 if router maps 8443->443)
    use_existing_proxy: bool = False  # True if cryptolabs-proxy already running


@dataclass
class SSHCredentials:
    """SSH credentials for worker deployment."""
    username: str = "root"
    auth_method: AuthMethod = AuthMethod.PASSWORD
    password: Optional[str] = None
    key_path: Optional[str] = None
    port: int = 22


@dataclass
class BMCCredentials:
    """IPMI/BMC credentials for server management."""
    username: str = "ADMIN"
    password: Optional[str] = None


@dataclass
class Server:
    """A server to monitor (worker or IPMI target)."""
    name: str
    server_ip: str  # SSH/exporter IP
    bmc_ip: Optional[str] = None  # IPMI BMC IP (may be different)
    
    # Per-server overrides (if different from global)
    ssh_user: Optional[str] = None
    ssh_password: Optional[str] = None
    ssh_key_path: Optional[str] = None
    ssh_port: Optional[int] = None
    
    bmc_user: Optional[str] = None
    bmc_password: Optional[str] = None
    
    # Status tracking
    has_gpu: bool = False
    exporters_installed: bool = False
    ipmi_configured: bool = False


@dataclass
class ComponentConfig:
    """Which components to install."""
    dc_overview: bool = True  # Prometheus + Grafana + dashboards
    ipmi_monitor: bool = False  # IPMI/BMC monitoring
    vast_exporter: bool = False  # Vast.ai earnings/reliability
    runpod_exporter: bool = False  # RunPod earnings/reliability
    dc_watchdog: bool = False  # External uptime monitoring (requires CryptoLabs subscription)


@dataclass
class VastApiKey:
    """A single Vast.ai API key with account name."""
    name: str  # Account name (e.g., "VastMain", "VastSecondary")
    key: str   # API key


@dataclass
class VastConfig:
    """Vast.ai configuration - supports multiple accounts."""
    enabled: bool = False
    api_keys: List['VastApiKey'] = field(default_factory=list)
    port: int = 8622  # Exporter port
    
    # Legacy single key support (for backwards compatibility)
    api_key: Optional[str] = None
    
    def add_key(self, name: str, key: str) -> None:
        """Add an API key."""
        self.api_keys.append(VastApiKey(name=name, key=key))
    
    def get_all_keys(self) -> List['VastApiKey']:
        """Get all API keys (including legacy single key if set)."""
        keys = list(self.api_keys)
        # Include legacy api_key if set and not already in list
        if self.api_key and not any(k.key == self.api_key for k in keys):
            keys.insert(0, VastApiKey(name="default", key=self.api_key))
        return keys


@dataclass
class RunPodApiKey:
    """A single RunPod API key with account name."""
    name: str  # Account name (e.g., "RunpodCCC", "Brickbox")
    key: str   # API key (rpa_XXXX)


@dataclass
class RunPodConfig:
    """RunPod configuration - supports multiple accounts."""
    enabled: bool = False
    api_keys: List[RunPodApiKey] = field(default_factory=list)
    port: int = 8623  # Exporter port
    
    def add_key(self, name: str, key: str) -> None:
        """Add an API key."""
        self.api_keys.append(RunPodApiKey(name=name, key=key))
    
    def get_docker_args(self) -> List[str]:
        """Get Docker command arguments for multiple API keys."""
        args = []
        for api_key in self.api_keys:
            args.extend(["-api-key", f"{api_key.name}:{api_key.key}"])
        return args


@dataclass
class GrafanaConfig:
    """Grafana configuration."""
    admin_password: str = "admin"
    port: int = 3000
    # Home dashboard setting: None (disabled), or dashboard UID
    # Available options: "dc-overview-main", "vast-dashboard", etc.
    home_dashboard: Optional[str] = "dc-overview-main"


@dataclass
class PrometheusConfig:
    """Prometheus configuration."""
    port: int = 9090
    retention_days: int = 30


@dataclass
class IPMIMonitorConfig:
    """IPMI Monitor configuration."""
    enabled: bool = False
    port: int = 5000
    admin_password: Optional[str] = None
    ai_license_key: Optional[str] = None
    # SSH settings for IPMI Monitor
    enable_ssh_inventory: bool = True  # Enable SSH for detailed inventory
    enable_ssh_logs: bool = False  # Enable SSH log collection (disabled by default)


@dataclass
class WatchdogConfig:
    """DC Watchdog configuration for external uptime monitoring.
    
    DC Watchdog runs externally (watchdog.cryptolabs.co.za) and monitors
    servers from outside the datacenter. Useful for detecting DC-wide outages
    when internal monitoring (Prometheus/Grafana) would also be down.
    
    Requires active CryptoLabs subscription.
    """
    enabled: bool = False
    server_url: str = "https://watchdog.cryptolabs.co.za"
    api_key: Optional[str] = None  # From WordPress SSO (sk-ipmi-XXX)
    ping_interval: int = 30  # Seconds between heartbeats
    fail_timeout: int = 120  # Seconds before server marked DOWN
    
    # Agent settings
    install_agent: bool = True  # Deploy dc-watchdog-agent to workers
    agent_use_mtr: bool = True  # Include MTR hop data for root cause analysis


@dataclass
class SecurityConfig:
    """Security and firewall configuration."""
    ufw_enabled: bool = True  # Enable UFW firewall
    ufw_ports: List[int] = field(default_factory=lambda: [22, 80, 443])  # Ports to allow (TCP)
    ufw_additional_ports: List[int] = field(default_factory=list)  # Extra ports to allow (TCP)
    ufw_udp_ports: List[int] = field(default_factory=list)  # UDP ports to allow (e.g., 69 for TFTP/PXE)


@dataclass
class FleetConfig:
    """
    Master configuration object that holds EVERYTHING.
    Collected once at the start, used throughout deployment.
    """
    # Site info
    site_name: str = "DC Overview"
    
    # Fleet Management credentials (unified login)
    fleet_admin_user: str = "admin"
    fleet_admin_pass: Optional[str] = None
    
    # Components
    components: ComponentConfig = field(default_factory=ComponentConfig)
    
    # SSL/HTTPS
    ssl: SSLConfig = field(default_factory=SSLConfig)
    
    # Global SSH credentials (for all workers)
    ssh: SSHCredentials = field(default_factory=SSHCredentials)
    
    # Global BMC credentials (for all IPMI targets)
    bmc: BMCCredentials = field(default_factory=BMCCredentials)
    
    # Services
    grafana: GrafanaConfig = field(default_factory=GrafanaConfig)
    prometheus: PrometheusConfig = field(default_factory=PrometheusConfig)
    ipmi_monitor: IPMIMonitorConfig = field(default_factory=IPMIMonitorConfig)
    vast: VastConfig = field(default_factory=VastConfig)
    runpod: RunPodConfig = field(default_factory=RunPodConfig)
    watchdog: WatchdogConfig = field(default_factory=WatchdogConfig)
    
    # Security
    security: SecurityConfig = field(default_factory=SecurityConfig)
    
    # Servers to monitor
    servers: List[Server] = field(default_factory=list)
    
    # Paths
    config_dir: Path = field(default_factory=lambda: Path("/etc/dc-overview"))
    data_dir: Path = field(default_factory=lambda: Path("/var/lib/dc-overview"))
    
    # Internal state
    master_ip: Optional[str] = None
    ssh_key_generated: bool = False
    auto_confirm: bool = False  # Skip interactive prompts (set by -y flag)
    
    def add_server(
        self,
        name: str,
        server_ip: str,
        bmc_ip: Optional[str] = None,
        **overrides
    ) -> Server:
        """Add a server to the fleet."""
        server = Server(
            name=name,
            server_ip=server_ip,
            bmc_ip=bmc_ip,
            **overrides
        )
        self.servers.append(server)
        return server
    
    def get_server_ssh_creds(self, server: Server) -> SSHCredentials:
        """Get effective SSH credentials for a server (with overrides)."""
        return SSHCredentials(
            username=server.ssh_user or self.ssh.username,
            auth_method=self.ssh.auth_method,
            password=server.ssh_password or self.ssh.password,
            key_path=server.ssh_key_path or self.ssh.key_path,
            port=server.ssh_port or self.ssh.port,
        )
    
    def get_server_bmc_creds(self, server: Server) -> BMCCredentials:
        """Get effective BMC credentials for a server (with overrides)."""
        return BMCCredentials(
            username=server.bmc_user or self.bmc.username,
            password=server.bmc_password or self.bmc.password,
        )
    
    def save(self, path: Optional[Path] = None) -> Path:
        """Save configuration to YAML file."""
        path = path or self.config_dir / "fleet-config.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert to dict, excluding sensitive data from main file
        data = self._to_dict(include_secrets=False)
        
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        
        os.chmod(path, 0o600)
        
        # Save secrets separately
        secrets_path = path.parent / ".secrets.yaml"
        secrets = self._get_secrets()
        with open(secrets_path, "w") as f:
            yaml.dump(secrets, f, default_flow_style=False)
        os.chmod(secrets_path, 0o600)
        
        return path
    
    def _to_dict(self, include_secrets: bool = False) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = {
            "site_name": self.site_name,
            "master_ip": self.master_ip,
            "components": {
                "dc_overview": self.components.dc_overview,
                "ipmi_monitor": self.components.ipmi_monitor,
                "vast_exporter": self.components.vast_exporter,
                "runpod_exporter": self.components.runpod_exporter,
                "dc_watchdog": self.components.dc_watchdog,
            },
            "ssl": {
                "mode": self.ssl.mode.value,
                "domain": self.ssl.domain,
                "email": self.ssl.email,
                "cert_path": self.ssl.cert_path,
                "key_path": self.ssl.key_path,
                "external_port": self.ssl.external_port,
            },
            "ssh": {
                "username": self.ssh.username,
                "auth_method": self.ssh.auth_method.value,
                "port": self.ssh.port,
                "key_path": self.ssh.key_path,
            },
            "bmc": {
                "username": self.bmc.username,
            },
            "grafana": {
                "port": self.grafana.port,
            },
            "prometheus": {
                "port": self.prometheus.port,
                "retention_days": self.prometheus.retention_days,
            },
            "ipmi_monitor": {
                "enabled": self.ipmi_monitor.enabled,
                "port": self.ipmi_monitor.port,
                "enable_ssh_inventory": self.ipmi_monitor.enable_ssh_inventory,
                "enable_ssh_logs": self.ipmi_monitor.enable_ssh_logs,
            },
            "vast": {
                "enabled": self.vast.enabled,
                "port": self.vast.port,
            },
            "runpod": {
                "enabled": self.runpod.enabled,
                "port": self.runpod.port,
            },
            "watchdog": {
                "enabled": self.watchdog.enabled,
                "server_url": self.watchdog.server_url,
                "ping_interval": self.watchdog.ping_interval,
                "fail_timeout": self.watchdog.fail_timeout,
                "install_agent": self.watchdog.install_agent,
                "agent_use_mtr": self.watchdog.agent_use_mtr,
            },
            "servers": [
                {
                    "name": s.name,
                    "server_ip": s.server_ip,
                    "bmc_ip": s.bmc_ip,
                    "bmc_user": s.bmc_user,  # Per-server BMC credentials
                    "has_gpu": s.has_gpu,
                    "exporters_installed": s.exporters_installed,
                    "ipmi_configured": s.ipmi_configured,
                }
                for s in self.servers
            ],
        }
        
        if include_secrets:
            data["ssh"]["password"] = self.ssh.password
            data["bmc"]["password"] = self.bmc.password
            data["grafana"]["admin_password"] = self.grafana.admin_password
            data["ipmi_monitor"]["admin_password"] = self.ipmi_monitor.admin_password
            data["vast"]["api_keys"] = [
                {"name": k.name, "key": k.key} for k in self.vast.api_keys
            ]
            # Legacy single key for backwards compatibility
            if self.vast.api_key and not self.vast.api_keys:
                data["vast"]["api_key"] = self.vast.api_key
            data["runpod"]["api_keys"] = [
                {"name": k.name, "key": k.key} for k in self.runpod.api_keys
            ]
        
        return data
    
    def _get_secrets(self) -> Dict[str, Any]:
        """Get secrets for separate storage."""
        secrets = {
            "fleet_admin_user": self.fleet_admin_user,
            "fleet_admin_pass": self.fleet_admin_pass,
            "ssh_password": self.ssh.password,
            "bmc_password": self.bmc.password,
            "grafana_password": self.grafana.admin_password,
            "ipmi_monitor_password": self.ipmi_monitor.admin_password,
            "vast_api_keys": [{"name": k.name, "key": k.key} for k in self.vast.get_all_keys()],
            "ipmi_ai_license": self.ipmi_monitor.ai_license_key,
            "runpod_api_keys": [{"name": k.name, "key": k.key} for k in self.runpod.api_keys],
            "watchdog_api_key": self.watchdog.api_key,
        }
        
        # Add per-server BMC passwords
        server_bmc_passwords = {}
        for s in self.servers:
            if s.bmc_password:
                server_bmc_passwords[s.name] = s.bmc_password
        if server_bmc_passwords:
            secrets["server_bmc_passwords"] = server_bmc_passwords
        
        return secrets
    
    @classmethod
    def load(cls, config_dir: Path = None) -> "FleetConfig":
        """Load configuration from files."""
        config_dir = config_dir or Path("/etc/dc-overview")
        config_path = config_dir / "fleet-config.yaml"
        secrets_path = config_dir / ".secrets.yaml"
        
        config = cls(config_dir=config_dir)
        
        if config_path.exists():
            with open(config_path) as f:
                data = yaml.safe_load(f) or {}
            
            config.site_name = data.get("site_name", "DC Overview")
            config.master_ip = data.get("master_ip")
            
            # Components
            comp = data.get("components", {})
            config.components.dc_overview = comp.get("dc_overview", True)
            config.components.ipmi_monitor = comp.get("ipmi_monitor", False)
            config.components.vast_exporter = comp.get("vast_exporter", False)
            config.components.runpod_exporter = comp.get("runpod_exporter", False)
            
            # SSL
            ssl = data.get("ssl", {})
            config.ssl.mode = SSLMode(ssl.get("mode", "self_signed"))
            config.ssl.domain = ssl.get("domain")
            config.ssl.email = ssl.get("email")
            config.ssl.cert_path = ssl.get("cert_path")
            config.ssl.key_path = ssl.get("key_path")
            config.ssl.external_port = ssl.get("external_port", 443)
            
            # SSH
            ssh = data.get("ssh", {})
            config.ssh.username = ssh.get("username", "root")
            config.ssh.auth_method = AuthMethod(ssh.get("auth_method", "password"))
            config.ssh.port = ssh.get("port", 22)
            config.ssh.key_path = ssh.get("key_path")
            
            # BMC
            bmc = data.get("bmc", {})
            config.bmc.username = bmc.get("username", "ADMIN")
            
            # Services
            grafana = data.get("grafana", {})
            config.grafana.port = grafana.get("port", 3000)
            
            prometheus = data.get("prometheus", {})
            config.prometheus.port = prometheus.get("port", 9090)
            config.prometheus.retention_days = prometheus.get("retention_days", 30)
            
            ipmi = data.get("ipmi_monitor", {})
            config.ipmi_monitor.enabled = ipmi.get("enabled", False)
            config.ipmi_monitor.port = ipmi.get("port", 5000)
            config.ipmi_monitor.enable_ssh_inventory = ipmi.get("enable_ssh_inventory", True)
            config.ipmi_monitor.enable_ssh_logs = ipmi.get("enable_ssh_logs", False)
            
            vast = data.get("vast", {})
            config.vast.enabled = vast.get("enabled", False)
            config.vast.port = vast.get("port", 8622)
            
            # RunPod (supports multiple API keys)
            runpod = data.get("runpod", {})
            config.runpod.enabled = runpod.get("enabled", False)
            config.runpod.port = runpod.get("port", 8623)
            for api_key_data in runpod.get("api_keys", []):
                if isinstance(api_key_data, dict):
                    config.runpod.add_key(
                        name=api_key_data.get("name", "default"),
                        key=api_key_data.get("key", "")
                    )
            
            # DC Watchdog (external uptime monitoring)
            watchdog = data.get("watchdog", {})
            config.watchdog.enabled = watchdog.get("enabled", False)
            config.watchdog.server_url = watchdog.get("server_url", "https://watchdog.cryptolabs.co.za")
            config.watchdog.ping_interval = watchdog.get("ping_interval", 30)
            config.watchdog.fail_timeout = watchdog.get("fail_timeout", 120)
            config.watchdog.install_agent = watchdog.get("install_agent", True)
            config.watchdog.agent_use_mtr = watchdog.get("agent_use_mtr", True)
            
            # Servers
            for s in data.get("servers", []):
                config.servers.append(Server(
                    name=s.get("name"),
                    server_ip=s.get("server_ip"),
                    bmc_ip=s.get("bmc_ip"),
                    bmc_user=s.get("bmc_user"),  # Per-server BMC credentials
                    has_gpu=s.get("has_gpu", False),
                    exporters_installed=s.get("exporters_installed", False),
                    ipmi_configured=s.get("ipmi_configured", False),
                ))
        
        # Load secrets
        if secrets_path.exists():
            with open(secrets_path) as f:
                secrets = yaml.safe_load(f) or {}
            
            config.fleet_admin_user = secrets.get("fleet_admin_user", "admin")
            config.fleet_admin_pass = secrets.get("fleet_admin_pass")
            config.ssh.password = secrets.get("ssh_password")
            config.bmc.password = secrets.get("bmc_password")
            config.grafana.admin_password = secrets.get("grafana_password", "admin")
            config.ipmi_monitor.admin_password = secrets.get("ipmi_monitor_password")
            # Load Vast API keys from secrets (supports multiple or legacy single key)
            for api_key_data in secrets.get("vast_api_keys", []):
                if isinstance(api_key_data, dict):
                    config.vast.add_key(
                        name=api_key_data.get("name", "default"),
                        key=api_key_data.get("key", "")
                    )
            # Legacy single key support
            if secrets.get("vast_api_key") and not config.vast.api_keys:
                config.vast.api_key = secrets.get("vast_api_key")
            
            config.ipmi_monitor.ai_license_key = secrets.get("ipmi_ai_license")
            
            # Load RunPod API keys from secrets
            for api_key_data in secrets.get("runpod_api_keys", []):
                if isinstance(api_key_data, dict):
                    config.runpod.add_key(
                        name=api_key_data.get("name", "default"),
                        key=api_key_data.get("key", "")
                    )
            
            # Load DC Watchdog API key from secrets
            config.watchdog.api_key = secrets.get("watchdog_api_key")
            
            # Load per-server BMC passwords
            server_bmc_passwords = secrets.get("server_bmc_passwords", {})
            for server in config.servers:
                if server.name in server_bmc_passwords:
                    server.bmc_password = server_bmc_passwords[server.name]
        
        return config


# Convenience function to get local IP
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
