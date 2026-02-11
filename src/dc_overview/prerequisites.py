"""
DC Overview Prerequisites Installer
Automatically installs all required dependencies.
"""

import subprocess
import shutil
import os
import sys
from pathlib import Path
from typing import Tuple, List, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

console = Console()


class PrerequisitesInstaller:
    """Install all required system dependencies."""
    
    def __init__(self):
        self.is_root = os.geteuid() == 0
        self.distro = self._detect_distro()
    
    def _detect_distro(self) -> str:
        """Detect Linux distribution."""
        try:
            with open("/etc/os-release") as f:
                content = f.read().lower()
                if "ubuntu" in content or "debian" in content:
                    return "debian"
                elif "centos" in content or "rhel" in content or "rocky" in content:
                    return "rhel"
                elif "arch" in content:
                    return "arch"
        except Exception:
            pass
        return "unknown"
    
    def _run_cmd(
        self,
        cmd: List[str],
        timeout: int = 300,
        check: bool = True
    ) -> Tuple[bool, str]:
        """Run a command and return success status + output."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            output = result.stdout + result.stderr
            if check and result.returncode != 0:
                return False, output
            return True, output
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)
    
    def check_root(self) -> bool:
        """Check if running as root."""
        if not self.is_root:
            console.print("[red]Error:[/red] This command requires root privileges.")
            console.print("Run with: [cyan]sudo dc-overview setup[/cyan]")
            return False
        return True
    
    # ============ Docker ============
    
    def is_docker_installed(self) -> bool:
        """Check if Docker is installed and running."""
        return shutil.which("docker") is not None
    
    def is_docker_running(self) -> bool:
        """Check if Docker daemon is running."""
        success, _ = self._run_cmd(["docker", "info"], check=False)
        return success
    
    def install_docker(self) -> bool:
        """Install Docker using the official script."""
        console.print("[cyan]Installing Docker...[/cyan]")
        
        if self.is_docker_installed():
            if not self.is_docker_running():
                console.print("[dim]Docker installed but not running, starting...[/dim]")
                self._run_cmd(["systemctl", "start", "docker"])
                self._run_cmd(["systemctl", "enable", "docker"])
            console.print("[green]✓[/green] Docker already installed")
            return True
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("Downloading Docker installer...", total=None)
            
            # Download and run official Docker install script
            success, output = self._run_cmd([
                "bash", "-c",
                "curl -fsSL https://get.docker.com | sh"
            ], timeout=300)
            
            if not success:
                progress.update(task, description="[red]✗[/red] Docker installation failed")
                console.print(f"[dim]{output[:200]}[/dim]")
                return False
            
            progress.update(task, description="[green]✓[/green] Docker installed")
        
        # Start and enable Docker
        self._run_cmd(["systemctl", "start", "docker"])
        self._run_cmd(["systemctl", "enable", "docker"])
        
        # Install docker-compose plugin if not present
        if not self._has_compose():
            self._install_compose()
        
        console.print("[green]✓[/green] Docker installed and running")
        return True
    
    def _has_compose(self) -> bool:
        """Check if docker compose is available."""
        success, _ = self._run_cmd(["docker", "compose", "version"], check=False)
        return success
    
    def _install_compose(self) -> bool:
        """Install docker-compose plugin."""
        console.print("[dim]Installing docker-compose plugin...[/dim]")
        
        # Try apt first (Debian/Ubuntu)
        if self.distro == "debian":
            success, _ = self._run_cmd([
                "apt-get", "install", "-y", "-qq", "docker-compose-plugin"
            ])
            if success:
                return True
        
        # Fall back to pip
        success, _ = self._run_cmd([
            "pip3", "install", "docker-compose"
        ])
        return success
    
    # ============ IPMI Tools ============
    
    def is_ipmitool_installed(self) -> bool:
        """Check if ipmitool is installed."""
        return shutil.which("ipmitool") is not None
    
    def install_ipmitool(self) -> bool:
        """Install ipmitool for IPMI access."""
        if self.is_ipmitool_installed():
            console.print("[green]✓[/green] ipmitool already installed")
            return True
        
        console.print("[cyan]Installing ipmitool...[/cyan]")
        
        if self.distro == "debian":
            success, _ = self._run_cmd([
                "apt-get", "install", "-y", "-qq", "ipmitool"
            ])
        elif self.distro == "rhel":
            success, _ = self._run_cmd([
                "yum", "install", "-y", "ipmitool"
            ])
        else:
            console.print("[yellow]⚠[/yellow] Please install ipmitool manually")
            return False
        
        if success:
            console.print("[green]✓[/green] ipmitool installed")
        return success
    
    # ============ Nginx ============
    
    def is_nginx_installed(self) -> bool:
        """Check if nginx is installed."""
        return shutil.which("nginx") is not None
    
    def install_nginx(self) -> bool:
        """Install nginx for reverse proxy."""
        if self.is_nginx_installed():
            console.print("[green]✓[/green] nginx already installed")
            return True
        
        console.print("[cyan]Installing nginx...[/cyan]")
        
        if self.distro == "debian":
            self._run_cmd(["apt-get", "update", "-qq"])
            success, _ = self._run_cmd([
                "apt-get", "install", "-y", "-qq", "nginx"
            ])
        elif self.distro == "rhel":
            success, _ = self._run_cmd([
                "yum", "install", "-y", "nginx"
            ])
        else:
            console.print("[yellow]⚠[/yellow] Please install nginx manually")
            return False
        
        if success:
            self._run_cmd(["systemctl", "enable", "nginx"])
            console.print("[green]✓[/green] nginx installed")
        return success
    
    # ============ Certbot ============
    
    def is_certbot_installed(self) -> bool:
        """Check if certbot is installed."""
        return shutil.which("certbot") is not None
    
    def install_certbot(self) -> bool:
        """Install certbot for Let's Encrypt."""
        if self.is_certbot_installed():
            console.print("[green]✓[/green] certbot already installed")
            return True
        
        console.print("[cyan]Installing certbot...[/cyan]")
        
        if self.distro == "debian":
            success, _ = self._run_cmd([
                "apt-get", "install", "-y", "-qq", "certbot"
            ])
        elif self.distro == "rhel":
            success, _ = self._run_cmd([
                "yum", "install", "-y", "certbot"
            ])
        else:
            console.print("[yellow]⚠[/yellow] Please install certbot manually")
            return False
        
        if success:
            console.print("[green]✓[/green] certbot installed")
        return success
    
    # ============ SSH Tools ============
    
    def is_sshpass_installed(self) -> bool:
        """Check if sshpass is installed (for password-based SSH key deployment)."""
        return shutil.which("sshpass") is not None
    
    def install_sshpass(self) -> bool:
        """Install sshpass for SSH key deployment."""
        if self.is_sshpass_installed():
            return True
        
        console.print("[dim]Installing sshpass for SSH key deployment...[/dim]")
        
        if self.distro == "debian":
            success, _ = self._run_cmd([
                "apt-get", "install", "-y", "-qq", "sshpass"
            ])
        elif self.distro == "rhel":
            success, _ = self._run_cmd([
                "yum", "install", "-y", "sshpass"
            ])
        else:
            return False
        
        return success
    
    # ============ Python Dependencies ============
    
    def install_python_deps(self) -> bool:
        """Install required Python packages."""
        packages = ["paramiko"]
        
        for pkg in packages:
            try:
                __import__(pkg)
            except ImportError:
                console.print(f"[dim]Installing {pkg}...[/dim]")
                success, _ = self._run_cmd([
                    sys.executable, "-m", "pip", "install", pkg,
                    "--break-system-packages", "-q"
                ], check=False)
                if not success:
                    # Try without --break-system-packages
                    self._run_cmd([
                        sys.executable, "-m", "pip", "install", pkg, "-q"
                    ])
        
        return True
    
    # ============ OpenSSL ============
    
    def is_openssl_installed(self) -> bool:
        """Check if OpenSSL is installed."""
        return shutil.which("openssl") is not None
    
    def install_openssl(self) -> bool:
        """Install OpenSSL for certificate generation."""
        if self.is_openssl_installed():
            return True
        
        console.print("[cyan]Installing OpenSSL...[/cyan]")
        
        if self.distro == "debian":
            success, _ = self._run_cmd([
                "apt-get", "install", "-y", "-qq", "openssl"
            ])
        elif self.distro == "rhel":
            success, _ = self._run_cmd([
                "yum", "install", "-y", "openssl"
            ])
        else:
            return False
        
        return success
    
    # ============ Master Install ============
    
    def install_all(
        self,
        docker: bool = True,
        nginx: bool = True,
        ipmitool: bool = False,
        certbot: bool = False,
    ) -> bool:
        """Install all required prerequisites."""
        
        console.print(Panel(
            "[bold]Installing Prerequisites[/bold]",
            border_style="cyan"
        ))
        
        if not self.check_root():
            return False
        
        # Update package manager
        if self.distro == "debian":
            with Progress(SpinnerColumn(), TextColumn("Updating package lists..."), console=console) as progress:
                progress.add_task("", total=None)
                self._run_cmd(["apt-get", "update", "-qq"])
        
        # Install base requirements
        self.install_openssl()
        self.install_sshpass()
        self.install_python_deps()
        
        # Docker
        if docker:
            if not self.install_docker():
                console.print("[yellow]⚠[/yellow] Docker installation failed, some features may not work")
        
        # Nginx
        if nginx:
            if not self.install_nginx():
                console.print("[yellow]⚠[/yellow] Nginx installation failed, reverse proxy unavailable")
        
        # IPMI tools
        if ipmitool:
            if not self.install_ipmitool():
                console.print("[yellow]⚠[/yellow] ipmitool installation failed, IPMI features unavailable")
        
        # Certbot
        if certbot:
            if not self.install_certbot():
                console.print("[yellow]⚠[/yellow] Certbot installation failed, Let's Encrypt unavailable")
        
        console.print("\n[green]✓[/green] Prerequisites installed")
        return True


def ensure_prerequisites(
    docker: bool = True,
    nginx: bool = True, 
    ipmitool: bool = False,
    certbot: bool = False,
) -> bool:
    """Ensure all prerequisites are installed."""
    installer = PrerequisitesInstaller()
    return installer.install_all(
        docker=docker,
        nginx=nginx,
        ipmitool=ipmitool,
        certbot=certbot,
    )
