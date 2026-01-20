"""
DC Overview SSH Manager
Unified SSH key management for fleet deployment.
Generate once, deploy everywhere.
"""

import os
import subprocess
import shutil
from pathlib import Path
from typing import Tuple, Optional, List
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@dataclass
class SSHResult:
    """Result of an SSH operation."""
    success: bool
    output: str
    exit_code: int = 0


class SSHManager:
    """
    Manages SSH keys and connections for fleet deployment.
    Uses a single key pair for all workers.
    """
    
    def __init__(self, config_dir: Path = None):
        self.config_dir = config_dir or Path("/etc/dc-overview")
        self.key_path = self.config_dir / "fleet_key"
        self.pub_key_path = self.config_dir / "fleet_key.pub"
        self.known_hosts_path = self.config_dir / "known_hosts"
    
    # ============ Key Management ============
    
    def key_exists(self) -> bool:
        """Check if SSH key pair already exists."""
        return self.key_path.exists() and self.pub_key_path.exists()
    
    def generate_key(self, force: bool = False) -> Tuple[str, str]:
        """
        Generate SSH key pair for fleet management.
        
        Returns:
            Tuple of (private_key_path, public_key)
        """
        if self.key_exists() and not force:
            console.print("[dim]Using existing fleet SSH key[/dim]")
            return str(self.key_path), self.pub_key_path.read_text().strip()
        
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Remove existing key if forcing
        if force:
            if self.key_path.exists():
                self.key_path.unlink()
            if self.pub_key_path.exists():
                self.pub_key_path.unlink()
        
        console.print("[cyan]Generating fleet SSH key...[/cyan]")
        
        # Generate ed25519 key (more secure, faster than RSA)
        result = subprocess.run([
            "ssh-keygen",
            "-t", "ed25519",
            "-f", str(self.key_path),
            "-N", "",  # No passphrase
            "-C", "dc-overview-fleet"
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            raise RuntimeError(f"Failed to generate SSH key: {result.stderr}")
        
        # Set correct permissions
        os.chmod(self.key_path, 0o600)
        os.chmod(self.pub_key_path, 0o644)
        
        pub_key = self.pub_key_path.read_text().strip()
        console.print(f"[green]✓[/green] SSH key generated: {self.key_path}")
        
        return str(self.key_path), pub_key
    
    def get_public_key(self) -> Optional[str]:
        """Get the public key content."""
        if not self.pub_key_path.exists():
            return None
        return self.pub_key_path.read_text().strip()
    
    # ============ Key Deployment ============
    
    def deploy_key_with_password(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 22,
    ) -> bool:
        """
        Deploy SSH key to a remote host using password authentication.
        Uses sshpass for automated password entry.
        """
        if not shutil.which("sshpass"):
            console.print("[red]Error:[/red] sshpass not installed")
            return False
        
        if not self.key_exists():
            self.generate_key()
        
        pub_key = self.get_public_key()
        
        # Build the command to add key to authorized_keys
        remote_cmd = f'''
            mkdir -p ~/.ssh && 
            chmod 700 ~/.ssh && 
            echo "{pub_key}" >> ~/.ssh/authorized_keys && 
            chmod 600 ~/.ssh/authorized_keys &&
            sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys
        '''
        
        cmd = [
            "sshpass", "-p", password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-p", str(port),
            f"{username}@{host}",
            remote_cmd
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                console.print(f"[green]✓[/green] SSH key deployed to {host}")
                return True
            else:
                console.print(f"[red]✗[/red] Failed to deploy key to {host}: {result.stderr[:100]}")
                return False
                
        except subprocess.TimeoutExpired:
            console.print(f"[red]✗[/red] Timeout connecting to {host}")
            return False
        except Exception as e:
            console.print(f"[red]✗[/red] Error deploying key to {host}: {e}")
            return False
    
    def deploy_key_with_existing_key(
        self,
        host: str,
        username: str,
        existing_key_path: str,
        port: int = 22,
    ) -> bool:
        """
        Deploy our fleet key to a remote host using an existing SSH key.
        """
        if not self.key_exists():
            self.generate_key()
        
        pub_key = self.get_public_key()
        
        remote_cmd = f'''
            mkdir -p ~/.ssh && 
            chmod 700 ~/.ssh && 
            echo "{pub_key}" >> ~/.ssh/authorized_keys && 
            chmod 600 ~/.ssh/authorized_keys &&
            sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys
        '''
        
        cmd = [
            "ssh",
            "-i", existing_key_path,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-p", str(port),
            f"{username}@{host}",
            remote_cmd
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                console.print(f"[green]✓[/green] SSH key deployed to {host}")
                return True
            else:
                console.print(f"[red]✗[/red] Failed to deploy key to {host}")
                return False
                
        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")
            return False
    
    # ============ Remote Execution ============
    
    def test_connection(self, host: str, username: str = "root", port: int = 22) -> bool:
        """Test SSH connection to a host using our fleet key."""
        if not self.key_exists():
            return False
        
        cmd = [
            "ssh",
            "-i", str(self.key_path),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            "-o", "BatchMode=yes",
            "-p", str(port),
            f"{username}@{host}",
            "echo ok"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0 and "ok" in result.stdout
        except Exception:
            return False
    
    def run_command(
        self,
        host: str,
        command: str,
        username: str = "root",
        port: int = 22,
        timeout: int = 300,
        sudo: bool = False,
    ) -> SSHResult:
        """
        Run a command on a remote host via SSH.
        
        Args:
            host: Remote host IP or hostname
            command: Command to execute
            username: SSH username
            port: SSH port
            timeout: Command timeout in seconds
            sudo: Whether to prefix with sudo
        
        Returns:
            SSHResult with success status and output
        """
        if not self.key_exists():
            return SSHResult(success=False, output="No SSH key configured", exit_code=-1)
        
        if sudo and username != "root":
            command = f"sudo {command}"
        
        cmd = [
            "ssh",
            "-i", str(self.key_path),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-p", str(port),
            f"{username}@{host}",
            command
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return SSHResult(
                success=result.returncode == 0,
                output=result.stdout + result.stderr,
                exit_code=result.returncode
            )
            
        except subprocess.TimeoutExpired:
            return SSHResult(success=False, output="Command timed out", exit_code=-1)
        except Exception as e:
            return SSHResult(success=False, output=str(e), exit_code=-1)
    
    def copy_file(
        self,
        host: str,
        local_path: str,
        remote_path: str,
        username: str = "root",
        port: int = 22,
    ) -> bool:
        """Copy a file to a remote host via SCP."""
        if not self.key_exists():
            return False
        
        cmd = [
            "scp",
            "-i", str(self.key_path),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-P", str(port),
            local_path,
            f"{username}@{host}:{remote_path}"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.returncode == 0
        except Exception:
            return False
    
    # ============ Bulk Operations ============
    
    def deploy_keys_to_hosts(
        self,
        hosts: List[dict],
        global_password: Optional[str] = None,
    ) -> dict:
        """
        Deploy SSH keys to multiple hosts.
        
        Args:
            hosts: List of dicts with keys: ip, username, password (optional), port
            global_password: Password to use for all hosts (if not per-host)
        
        Returns:
            Dict mapping host IPs to success status
        """
        results = {}
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Deploying SSH keys...", total=len(hosts))
            
            for host in hosts:
                ip = host["ip"]
                username = host.get("username", "root")
                password = host.get("password") or global_password
                port = host.get("port", 22)
                
                progress.update(task, description=f"Deploying to {ip}...")
                
                if password:
                    success = self.deploy_key_with_password(ip, username, password, port)
                else:
                    # Try with existing fleet key (may fail if first time)
                    success = self.test_connection(ip, username, port)
                
                results[ip] = success
                progress.advance(task)
        
        # Summary
        succeeded = sum(1 for v in results.values() if v)
        console.print(f"\n[green]✓[/green] SSH keys deployed: {succeeded}/{len(hosts)} hosts")
        
        return results
    
    def run_command_on_hosts(
        self,
        hosts: List[dict],
        command: str,
        sudo: bool = False,
    ) -> dict:
        """
        Run a command on multiple hosts.
        
        Args:
            hosts: List of dicts with keys: ip, username, port
            command: Command to execute
            sudo: Whether to run with sudo
        
        Returns:
            Dict mapping host IPs to SSHResult
        """
        results = {}
        
        for host in hosts:
            ip = host["ip"]
            username = host.get("username", "root")
            port = host.get("port", 22)
            
            result = self.run_command(
                host=ip,
                command=command,
                username=username,
                port=port,
                sudo=sudo,
            )
            results[ip] = result
        
        return results


# Convenience instance
_ssh_manager = None

def get_ssh_manager(config_dir: Path = None) -> SSHManager:
    """Get or create the SSH manager singleton."""
    global _ssh_manager
    if _ssh_manager is None:
        _ssh_manager = SSHManager(config_dir)
    return _ssh_manager
