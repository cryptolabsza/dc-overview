"""
DC Overview Exporter Installer - Install Prometheus exporters as systemd services

Includes:
- Version detection from metrics endpoints and SSH
- GitHub release checking for updates
- Remote installation and update via SSH
"""

import os
import re
import json
import base64
import shlex
import subprocess
import urllib.request
import urllib.error
import tarfile
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Latest versions (defaults, used as fallback when GitHub API is rate limited)
NODE_EXPORTER_VERSION = "1.10.2"
DC_EXPORTER_RS_VERSION = "0.2.8"
DCGM_EXPORTER_VERSION = "3.3.8-3.6.0"

# The remote timeout sends TERM to Bash so its rollback trap can run, then
# allows a bounded grace period before KILL.  The caller timeout includes SSH
# connection setup and is deliberately greater than both values combined.
DC_EXPORTER_SCRIPT_TIMEOUT_SECONDS = 240
# Rollback may need seven bounded systemctl calls. At five seconds per call
# plus each command's two-second kill grace, sixty seconds leaves time for the
# small local file restores as well.
DC_EXPORTER_ROLLBACK_GRACE_SECONDS = 60
DC_EXPORTER_CALLER_TIMEOUT_SECONDS = 330

# Fallback versions when GitHub API fails
FALLBACK_VERSIONS = {
    'node_exporter': NODE_EXPORTER_VERSION,
    'dc_exporter': DC_EXPORTER_RS_VERSION,
    'dcgm_exporter': DCGM_EXPORTER_VERSION,
}

# Version cache - check GitHub once per hour, not per server
import time
_VERSION_CACHE = {
    'versions': {},      # exporter -> version
    'last_update': 0,    # timestamp of last GitHub check
    'ttl': 3600,         # cache TTL in seconds (1 hour)
}

def _get_cached_versions() -> Dict[str, Optional[str]]:
    """Get latest versions from cache, refreshing from GitHub if stale."""
    now = time.time()
    
    # If cache is fresh, return cached versions
    if _VERSION_CACHE['versions'] and (now - _VERSION_CACHE['last_update']) < _VERSION_CACHE['ttl']:
        return _VERSION_CACHE['versions']
    
    # Cache is stale - try to refresh from GitHub
    new_versions = {}
    for exporter, repo in EXPORTER_REPOS.items():
        release = get_latest_github_release(repo, 'main')
        if release:
            new_versions[exporter] = release.get('version')
        else:
            # GitHub failed - use fallback or previous cached value
            new_versions[exporter] = _VERSION_CACHE['versions'].get(exporter) or FALLBACK_VERSIONS.get(exporter)
    
    # Update cache
    _VERSION_CACHE['versions'] = new_versions
    _VERSION_CACHE['last_update'] = now
    
    return new_versions

# GitHub repositories for each exporter
EXPORTER_REPOS = {
    'node_exporter': 'prometheus/node_exporter',
    'dc_exporter': 'cryptolabsza/dc-exporter-releases',
    'dcgm_exporter': 'NVIDIA/dcgm-exporter'
}

# Exporter ports
EXPORTER_PORTS = {
    'node_exporter': 9100,
    'dc_exporter': 9835,
    'dcgm_exporter': 9400
}

# Download URLs
NODE_EXPORTER_URL = f"https://github.com/prometheus/node_exporter/releases/download/v{NODE_EXPORTER_VERSION}/node_exporter-{NODE_EXPORTER_VERSION}.linux-amd64.tar.gz"

# DC Exporter RS (Rust version) - preferred. Production downloads are pinned
# to an immutable release tag; development builds use the explicit dev-latest
# prerelease through their own workflow rather than this installer.
DC_EXPORTER_RELEASES_BASE_URL = (
    "https://github.com/cryptolabsza/dc-exporter-releases/releases/download"
)


def _normalise_dc_exporter_version(version: Optional[str] = None) -> str:
    return (version or DC_EXPORTER_RS_VERSION).removeprefix("v")


def get_dc_exporter_download_url(version: Optional[str] = None) -> str:
    release_version = _normalise_dc_exporter_version(version)
    return f"{DC_EXPORTER_RELEASES_BASE_URL}/v{release_version}/dc-exporter-rs"


def get_dc_exporter_checksum_url(version: Optional[str] = None) -> str:
    release_version = _normalise_dc_exporter_version(version)
    return f"{DC_EXPORTER_RELEASES_BASE_URL}/v{release_version}/SHA256SUMS"


def dc_exporter_bash_command() -> list[str]:
    """Return the bounded explicit-Bash command used for delivery scripts."""
    return [
        "timeout",
        "--signal=TERM",
        f"--kill-after={DC_EXPORTER_ROLLBACK_GRACE_SECONDS}s",
        f"{DC_EXPORTER_SCRIPT_TIMEOUT_SECONDS}s",
        "bash",
        "-s",
    ]


def dc_exporter_remote_bash_command() -> str:
    """Return the shell-safe command appended to an SSH invocation."""
    return shlex.join(dc_exporter_bash_command())


def build_dc_exporter_remote_command(script: str, *, sudo: bool = False) -> str:
    """Encode a script for SSH clients that cannot provide remote stdin.

    The login shell only parses a static POSIX pipeline.  The safety script is
    base64-encoded and always executed by an explicit, bounded Bash process.
    """
    payload = base64.b64encode(script.encode("utf-8")).decode("ascii")
    runner = dc_exporter_remote_bash_command()
    if sudo:
        runner = f"sudo -- {runner}"
    return f"printf '%s' {shlex.quote(payload)} | base64 --decode | {runner}"


DC_EXPORTER_RS_URL = get_dc_exporter_download_url()
DC_EXPORTER_RS_DEB_URL = (
    f"{DC_EXPORTER_RELEASES_BASE_URL}/v{DC_EXPORTER_RS_VERSION}/"
    f"dc-exporter-rs_{DC_EXPORTER_RS_VERSION}_amd64.deb"
)


# Systemd service templates
NODE_EXPORTER_SERVICE = """[Unit]
Description=Node Exporter
Documentation=https://github.com/prometheus/node_exporter
After=network.target

[Service]
Type=simple
User=node_exporter
Group=node_exporter
ExecStart=/usr/local/bin/node_exporter
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

DCGM_EXPORTER_SERVICE = """[Unit]
Description=NVIDIA DCGM Exporter
Documentation=https://github.com/NVIDIA/dcgm-exporter
After=network.target nvidia-dcgm.service
Requires=nvidia-dcgm.service

[Service]
Type=simple
ExecStart=/usr/local/bin/dcgm-exporter -a :9400
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

DC_EXPORTER_SERVICE = """[Unit]
Description=DC Exporter - GPU Metrics for Prometheus (Rust)
Documentation=https://github.com/cryptolabsza/dc-exporter-rs
After=network.target nvidia-persistenced.service

[Service]
Type=simple
ExecStart=/usr/local/bin/dc-exporter-rs --port 9835
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def build_dc_exporter_install_script(
    version: Optional[str] = None,
    *,
    mode: str = "install",
    binary_path: str = "/usr/local/bin/dc-exporter-rs",
    service_path: str = "/etc/systemd/system/dc-exporter.service",
    backup_dir: str = "/var/backups/dc-exporter",
    temp_parent: str = "/tmp",
    lock_path: str = "/run/lock/dc-exporter-install.lock",
    proc_root: str = "/proc",
    metrics_url: str = "http://127.0.0.1:9835/metrics",
    verification_attempts: int = 3,
) -> str:
    """Build the single safe installer used by local and remote deployments.

    Production delivery is deliberately pinned to the version shipped with DC
    Overview.  The script downloads both release assets to a temporary
    directory, verifies the exact ``dc-exporter-rs`` manifest entry and the
    binary's own version, and only then mutates the live installation.  Any
    failure after mutation restores both the previous binary and service state.
    """
    release_version = _normalise_dc_exporter_version(version)
    if release_version != DC_EXPORTER_RS_VERSION:
        raise ValueError(
            "dc-exporter production delivery is pinned to "
            f"{DC_EXPORTER_RS_VERSION}, not {release_version}"
        )
    if mode not in {"install", "update"}:
        raise ValueError("dc-exporter delivery mode must be 'install' or 'update'")
    if not 1 <= verification_attempts <= 60:
        raise ValueError("verification_attempts must be between 1 and 60")

    replacements = {
        "__MODE__": shlex.quote(mode),
        "__VERSION__": shlex.quote(release_version),
        "__BINARY_URL__": shlex.quote(get_dc_exporter_download_url(release_version)),
        "__CHECKSUM_URL__": shlex.quote(get_dc_exporter_checksum_url(release_version)),
        "__TARGET__": shlex.quote(binary_path),
        "__UNIT_PATH__": shlex.quote(service_path),
        "__BACKUP_DIR__": shlex.quote(backup_dir),
        "__TEMP_PARENT__": shlex.quote(temp_parent),
        "__LOCK_PATH__": shlex.quote(lock_path),
        "__PROC_ROOT__": shlex.quote(proc_root),
        "__METRICS_URL__": shlex.quote(metrics_url),
        "__VERIFY_ATTEMPTS__": str(verification_attempts),
        "__SERVICE_UNIT__": DC_EXPORTER_SERVICE.rstrip(),
    }

    script = r'''set -Eeuo pipefail
MODE=__MODE__
VERSION=__VERSION__
BINARY_URL=__BINARY_URL__
CHECKSUM_URL=__CHECKSUM_URL__
TARGET=__TARGET__
UNIT_PATH=__UNIT_PATH__
BACKUP_DIR=__BACKUP_DIR__
TEMP_PARENT=__TEMP_PARENT__
LOCK_PATH=__LOCK_PATH__
PROC_ROOT=__PROC_ROOT__
METRICS_URL=__METRICS_URL__
VERIFY_ATTEMPTS=__VERIFY_ATTEMPTS__
SERVICE=dc-exporter
SYSTEMCTL_TIMEOUT=5
VERIFY_COMMAND_TIMEOUT=5

work_dir="$(mktemp -d "${TEMP_PARENT}/dc-exporter-install.XXXXXX")"
candidate="${work_dir}/dc-exporter-rs"
manifest="${work_dir}/SHA256SUMS"
target_tmp="${TARGET}.new.$$"
unit_tmp="${UNIT_PATH}.new.$$"
mutated=0
completed=0
had_binary=0
had_unit=0
was_active=0
was_enabled=0
was_present=0
desired_active=1
desired_enabled=1
binary_backup=''
unit_backup=''
probed_active=''
probed_enabled=''
probed_present=''

systemctl_bounded() {
    timeout --signal=TERM --kill-after=2s "${SYSTEMCTL_TIMEOUT}s" systemctl "$@"
}

probe_service_state() {
    local active_state active_rc enabled_state enabled_rc load_state load_rc

    if active_state="$(systemctl_bounded is-active "$SERVICE" 2>/dev/null)"; then
        active_rc=0
    else
        active_rc=$?
    fi
    if enabled_state="$(systemctl_bounded is-enabled "$SERVICE" 2>/dev/null)"; then
        enabled_rc=0
    else
        enabled_rc=$?
    fi

    case "$active_state:$active_rc" in
        active:0) probed_active=1 ;;
        inactive:3) probed_active=0 ;;
        *) return 1 ;;
    esac
    case "$enabled_state:$enabled_rc" in
        enabled:0)
            probed_enabled=1
            probed_present=1
            ;;
        disabled:1)
            probed_enabled=0
            probed_present=1
            ;;
        not-found:1|:1)
            # A non-zero is-enabled result is not by itself proof that a unit
            # is absent: timeouts and D-Bus failures also return non-zero.
            # Require an inactive service, no live unit at the intended path,
            # and systemd's own load-path lookup to agree that it is absent.
            [ "$probed_active" -eq 0 ] || return 1
            if [ -e "$UNIT_PATH" ] || [ -L "$UNIT_PATH" ]; then
                return 1
            fi
            if load_state="$(systemctl_bounded show --property LoadState --value "$SERVICE" 2>/dev/null)"; then
                load_rc=0
            else
                load_rc=$?
            fi
            [ "$load_state:$load_rc" = not-found:0 ] || return 1
            probed_enabled=0
            probed_present=0
            ;;
        *) return 1 ;;
    esac
}

cleanup() {
    rm -rf "$work_dir"
    rm -f "$target_tmp" "$unit_tmp"
}

rollback() {
    set +e
    rollback_failed=0

    # Stop/disable the candidate while its unit still exists when those were
    # the prior states. Final state checks below determine whether this worked.
    if [ "$was_active" -eq 0 ]; then
        systemctl_bounded stop "$SERVICE" >/dev/null 2>&1 || true
    fi
    if [ "$was_enabled" -eq 0 ]; then
        systemctl_bounded disable "$SERVICE" >/dev/null 2>&1 || true
    fi

    if [ "$had_binary" -eq 1 ]; then
        if ! cp -a "$binary_backup" "$target_tmp" || ! mv -f "$target_tmp" "$TARGET"; then
            rollback_failed=1
        fi
    else
        rm -f "$TARGET" || rollback_failed=1
    fi
    if [ "$had_unit" -eq 1 ]; then
        if ! cp -a "$unit_backup" "$unit_tmp" || ! mv -f "$unit_tmp" "$UNIT_PATH"; then
            rollback_failed=1
        fi
    else
        rm -f "$UNIT_PATH" || rollback_failed=1
    fi
    systemctl_bounded daemon-reload >/dev/null 2>&1 || rollback_failed=1
    if [ "$was_enabled" -eq 1 ]; then
        systemctl_bounded enable "$SERVICE" >/dev/null 2>&1 || rollback_failed=1
    fi
    if [ "$was_active" -eq 1 ]; then
        systemctl_bounded restart "$SERVICE" >/dev/null 2>&1 || rollback_failed=1
    fi

    if probe_service_state; then
        if [ "$probed_present" -ne "$was_present" ] || [ "$probed_enabled" -ne "$was_enabled" ] || [ "$probed_active" -ne "$was_active" ]; then
            rollback_failed=1
        fi
    else
        rollback_failed=1
    fi

    if [ "$rollback_failed" -eq 0 ]; then
        echo "dc-exporter installation failed; previous binary and service state restored" >&2
    else
        echo "dc-exporter installation failed; rollback incomplete, manual recovery required" >&2
    fi
    set -e
    return "$rollback_failed"
}

on_error() {
    rc=$?
    trap - ERR
    if [ "$mutated" -eq 1 ] && [ "$completed" -eq 0 ]; then
        rollback || true
    fi
    exit "$rc"
}

on_signal() {
    trap - ERR HUP INT TERM
    if [ "$mutated" -eq 1 ] && [ "$completed" -eq 0 ]; then
        rollback || true
    fi
    exit 130
}

trap cleanup EXIT
trap on_error ERR
trap on_signal HUP INT TERM

exec 9>"$LOCK_PATH"
flock --exclusive --wait 5 9

# Complete every candidate validation before touching the live installation.
curl --fail --show-error --silent --location --connect-timeout 10 --max-time 60 --output "$candidate" "$BINARY_URL"
curl --fail --show-error --silent --location --connect-timeout 10 --max-time 15 --output "$manifest" "$CHECKSUM_URL"

# shellcheck disable=SC2016 # $2 belongs to awk, not Bash.
manifest_matches="$(timeout "${VERIFY_COMMAND_TIMEOUT}s" awk '$2 == "dc-exporter-rs" || $2 == "*dc-exporter-rs" { count++ } END { print count + 0 }' "$manifest")"
[ "$manifest_matches" -eq 1 ]
# shellcheck disable=SC2016 # $2 and $1 belong to awk, not Bash.
expected_checksum="$(timeout "${VERIFY_COMMAND_TIMEOUT}s" awk '$2 == "dc-exporter-rs" || $2 == "*dc-exporter-rs" { print $1 }' "$manifest")"
printf '%s\n' "$expected_checksum" | timeout "${VERIFY_COMMAND_TIMEOUT}s" grep -Eq '^[[:xdigit:]]{64}$'
actual_checksum="$(timeout "${VERIFY_COMMAND_TIMEOUT}s" sha256sum "$candidate" | awk '{ print $1 }')"
[ "$actual_checksum" = "$expected_checksum" ]

chmod 0755 "$candidate"
candidate_output="$(timeout "${VERIFY_COMMAND_TIMEOUT}s" "$candidate" --version 2>&1)"
candidate_version="$(printf '%s\n' "$candidate_output" | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+$/) { print $i; exit } }')"
[ "$candidate_version" = "$VERSION" ]

if [ -e "$TARGET" ]; then
    had_binary=1
fi
if [ -e "$UNIT_PATH" ] || [ -L "$UNIT_PATH" ]; then
    had_unit=1
fi
if ! probe_service_state; then
    echo "could not determine original dc-exporter service state; refusing to mutate" >&2
    false
fi
was_active="$probed_active"
was_enabled="$probed_enabled"
was_present="$probed_present"
if [ "$MODE" = update ]; then
    desired_active="$was_active"
    desired_enabled="$was_enabled"
fi

mkdir -p "$BACKUP_DIR"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
if [ "$had_binary" -eq 1 ]; then
    binary_backup="${BACKUP_DIR}/dc-exporter-rs.${run_id}"
    cp -a "$TARGET" "$binary_backup"
fi
if [ "$had_unit" -eq 1 ]; then
    unit_backup="${BACKUP_DIR}/dc-exporter.service.${run_id}"
    cp -a "$UNIT_PATH" "$unit_backup"
fi

mutated=1
install -m 0755 "$candidate" "$target_tmp"
mv -f "$target_tmp" "$TARGET"

if [ "$MODE" = install ] || [ "$had_unit" -eq 0 ]; then
    cat > "$unit_tmp" <<'DC_EXPORTER_SERVICE_EOF'
__SERVICE_UNIT__
DC_EXPORTER_SERVICE_EOF
    chmod 0644 "$unit_tmp"
    mv -f "$unit_tmp" "$UNIT_PATH"
fi

systemctl_bounded daemon-reload
if [ "$MODE" = install ]; then
    systemctl_bounded enable "$SERVICE"
    systemctl_bounded restart "$SERVICE"
elif [ "$was_active" -eq 1 ]; then
    systemctl_bounded restart "$SERVICE"
else
    # Temporarily start an inactive installation so the candidate can be
    # proven through its live metrics endpoint, then restore inactivity.
    systemctl_bounded start "$SERVICE"
fi

verified=0
attempt=1
while [ "$attempt" -le "$VERIFY_ATTEMPTS" ]; do
    if systemctl_bounded is-active --quiet "$SERVICE"; then
        metrics_output="$(curl --fail --show-error --silent --connect-timeout 2 --max-time 4 "$METRICS_URL")" || metrics_output=''
        if timeout "${VERIFY_COMMAND_TIMEOUT}s" grep -Fq "dc_exporter_build_info{version=\"${VERSION}\"" <<< "$metrics_output"; then
            main_pid="$(systemctl_bounded show --property MainPID --value "$SERVICE")" || main_pid=''
            process_checksum=''
            if [[ "$main_pid" =~ ^[1-9][0-9]*$ ]] && [ -r "${PROC_ROOT}/${main_pid}/exe" ]; then
                process_checksum="$(timeout "${VERIFY_COMMAND_TIMEOUT}s" sha256sum "${PROC_ROOT}/${main_pid}/exe" | awk '{ print $1 }')" || process_checksum=''
            fi
            if [ "$process_checksum" = "$expected_checksum" ]; then
                verified=1
                break
            fi
        fi
    fi
    attempt=$((attempt + 1))
    sleep 1
done
[ "$verified" -eq 1 ]

if [ "$desired_active" -eq 0 ]; then
    systemctl_bounded stop "$SERVICE"
fi
if [ "$desired_enabled" -eq 1 ]; then
    systemctl_bounded enable "$SERVICE"
else
    systemctl_bounded disable "$SERVICE"
fi

if ! probe_service_state; then
    echo "could not determine final dc-exporter service state" >&2
    false
fi
if [ "$probed_present" -ne 1 ] || [ "$probed_active" -ne "$desired_active" ] || [ "$probed_enabled" -ne "$desired_enabled" ]; then
    echo "dc-exporter final service state did not match requested ${MODE} mode" >&2
    false
fi

completed=1
echo "DC_EXPORTER_INSTALL_SUCCESS version=${VERSION}"
'''
    for marker, value in replacements.items():
        script = script.replace(marker, value)
    return script

# Legacy run script (deprecated, kept for backwards compatibility)
DC_EXPORTER_RUN_SCRIPT = '''#!/bin/bash
# This script is deprecated. Use dc-exporter-rs instead.
exec /usr/local/bin/dc-exporter-rs --port 9835
'''

DC_EXPORTER_CONFIG = """[agent]
machine_id=auto
interval=5

[gpu]
enabled=1
DCGM_FI_DEV_VRAM_TEMP
DCGM_FI_DEV_HOT_SPOT_TEMP
DCGM_FI_DEV_FAN_SPEED
DCGM_FI_DEV_CLOCKS_THROTTLE_REASON
GPU_AER_TOTAL_ERRORS
GPU_AER_ERROR_STATE

[system]
enabled=1
SYS_LOAD_AVG
SYS_CPU_USAGE
SYS_MEM_USED

[ipmi]
enabled=0
"""


class ExporterInstaller:
    """Install Prometheus exporters as native systemd services."""
    
    def __init__(self):
        if os.geteuid() != 0:
            raise PermissionError("ExporterInstaller requires root privileges")
    
    def install_node_exporter(self) -> bool:
        """Install node_exporter."""
        console.print("\n[bold]Installing node_exporter...[/bold]")
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                # Download
                task = progress.add_task("Downloading node_exporter...", total=None)
                
                with tempfile.TemporaryDirectory() as tmpdir:
                    tarball = Path(tmpdir) / "node_exporter.tar.gz"
                    
                    urllib.request.urlretrieve(NODE_EXPORTER_URL, tarball)
                    progress.update(task, description="Extracting...")
                    
                    with tarfile.open(tarball, "r:gz") as tar:
                        tar.extractall(tmpdir)
                    
                    # Find and move binary
                    for item in Path(tmpdir).iterdir():
                        if item.is_dir() and "node_exporter" in item.name:
                            binary = item / "node_exporter"
                            if binary.exists():
                                progress.update(task, description="Installing...")
                                subprocess.run(["cp", str(binary), "/usr/local/bin/"], check=True)
                                subprocess.run(["chmod", "+x", "/usr/local/bin/node_exporter"], check=True)
                                break
                
                # Create user
                progress.update(task, description="Creating service user...")
                subprocess.run(
                    ["useradd", "-r", "-s", "/bin/false", "node_exporter"],
                    capture_output=True
                )
                
                # Install service
                progress.update(task, description="Installing systemd service...")
                with open("/etc/systemd/system/node_exporter.service", "w") as f:
                    f.write(NODE_EXPORTER_SERVICE)
                
                subprocess.run(["systemctl", "daemon-reload"], check=True)
                subprocess.run(["systemctl", "enable", "node_exporter"], check=True)
                subprocess.run(["systemctl", "start", "node_exporter"], check=True)
            
            console.print("[green]✓[/green] node_exporter installed (port 9100)")
            return True
            
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to install node_exporter: {e}")
            return False
    
    def install_dcgm_exporter(self, vastai_mode: bool = None) -> bool:
        """Install dcgm-exporter via Docker.
        
        Args:
            vastai_mode: If True, use --runtime=nvidia instead of --gpus all.
                        If None, auto-detect Vast.ai hosts.
        """
        console.print("\n[bold]Installing dcgm-exporter...[/bold]")
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Checking NVIDIA drivers...", total=None)
                
                # Check for nvidia-smi
                result = subprocess.run(["nvidia-smi", "-L"], capture_output=True)
                if result.returncode != 0:
                    console.print("[yellow]⚠[/yellow] NVIDIA drivers not found. Skipping dcgm-exporter.")
                    return False
                
                # Check for Docker
                progress.update(task, description="Checking Docker...")
                result = subprocess.run(["which", "docker"], capture_output=True)
                if result.returncode != 0:
                    console.print("[yellow]⚠[/yellow] Docker not found. Install Docker first.")
                    return False
                
                # Auto-detect Vast.ai host if not specified
                if vastai_mode is None:
                    vastai_mode = os.path.exists("/var/lib/vastai_kaalia") or \
                                  os.path.exists("/etc/systemd/system/vastai.service")
                
                # Check if already running
                progress.update(task, description="Checking existing containers...")
                result = subprocess.run(
                    ["docker", "ps", "-q", "-f", "name=dcgm-exporter"],
                    capture_output=True, text=True
                )
                if result.stdout.strip():
                    console.print("[green]✓[/green] dcgm-exporter already running")
                    return True
                
                # Remove old container if exists
                subprocess.run(
                    ["docker", "rm", "-f", "dcgm-exporter"],
                    capture_output=True
                )
                
                # Start dcgm-exporter container
                progress.update(task, description="Starting dcgm-exporter container...")
                
                # Use --runtime=nvidia for Vast.ai hosts (required)
                # Use --gpus all for standard Docker hosts
                if vastai_mode:
                    docker_cmd = [
                        "docker", "run", "-d",
                        "--name", "dcgm-exporter",
                        "--runtime=nvidia",  # Required for Vast.ai hosts
                        "-p", "9400:9400",
                        "--restart", "unless-stopped",
                        "nvidia/dcgm-exporter:3.3.5-3.4.1-ubuntu22.04"
                    ]
                    console.print("[dim]Using --runtime=nvidia (Vast.ai mode)[/dim]")
                else:
                    docker_cmd = [
                        "docker", "run", "-d",
                        "--name", "dcgm-exporter",
                        "--gpus", "all",
                        "-p", "9400:9400",
                        "--restart", "unless-stopped",
                        "nvidia/dcgm-exporter:3.3.5-3.4.1-ubuntu22.04"
                    ]
                    console.print("[dim]Using --gpus all (standard mode)[/dim]")
                
                result = subprocess.run(docker_cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    console.print(f"[red]✗[/red] Failed to start dcgm-exporter: {result.stderr}")
                    return False
            
            console.print("[green]✓[/green] dcgm-exporter installed (port 9400)")
            return True
            
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to install dcgm-exporter: {e}")
            return False
    
    def install_dc_exporter(self) -> bool:
        """Install the pinned dc-exporter-rs release with rollback safety."""
        console.print("\n[bold]Installing dc-exporter-rs...[/bold]")

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(
                    f"Installing verified dc-exporter-rs {DC_EXPORTER_RS_VERSION}...",
                    total=None,
                )
                result = subprocess.run(
                    dc_exporter_bash_command(),
                    input=build_dc_exporter_install_script(mode="install"),
                    capture_output=True,
                    text=True,
                    timeout=DC_EXPORTER_CALLER_TIMEOUT_SECONDS,
                )
                if result.returncode != 0:
                    detail = (result.stderr or result.stdout or "unknown error").strip()
                    console.print(f"[red]✗[/red] Failed to install dc-exporter-rs: {detail}")
                    return False
                if "DC_EXPORTER_INSTALL_SUCCESS" not in result.stdout:
                    console.print("[red]✗[/red] Installer did not report successful verification")
                    return False
                progress.update(task, description="Verified and running")

            console.print("[green]✓[/green] dc-exporter-rs installed (port 9835)")
            return True

        except Exception as e:
            console.print(f"[red]✗[/red] Failed to install dc-exporter-rs: {e}")
            return False
    
    def _compile_dc_exporter_from_source(self) -> bool:
        """Try to compile dc-exporter from bundled source."""
        try:
            # Check for required dependencies
            result = subprocess.run(["which", "gcc"], capture_output=True)
            if result.returncode != 0:
                console.print("[dim]gcc not found, installing...[/dim]")
                subprocess.run(["apt-get", "update", "-qq"], capture_output=True)
                subprocess.run(["apt-get", "install", "-y", "-qq", "gcc", "libpci-dev"], capture_output=True)
            
            # Copy bundled source from package
            try:
                import dc_overview
                pkg_path = Path(dc_overview.__file__).parent / "dc_exporter" / "dc-exporter.c"
                if pkg_path.exists():
                    import shutil
                    shutil.copy(pkg_path, "/opt/dc-exporter/dc-exporter.c")
                    console.print("[dim]Using bundled source[/dim]")
                else:
                    console.print("[dim]Bundled source not found[/dim]")
                    return False
            except Exception as e:
                console.print(f"[dim]Could not locate bundled source: {e}[/dim]")
                return False
            
            # Compile
            result = subprocess.run(
                ["gcc", "-O2", "-Wall", "-o", "/opt/dc-exporter/dc-exporter-c", 
                 "/opt/dc-exporter/dc-exporter.c", "-lpci", "-lnvidia-ml",
                 "-I/usr/local/cuda/include"],
                capture_output=True,
                text=True,
                cwd="/opt/dc-exporter"
            )
            
            if result.returncode == 0 and Path("/opt/dc-exporter/dc-exporter-c").exists():
                subprocess.run(["chmod", "+x", "/opt/dc-exporter/dc-exporter-c"], check=True)
                console.print("[dim]Compiled from source[/dim]")
                return True
            else:
                console.print(f"[dim]Compilation failed: {result.stderr[:100]}[/dim]")
                
        except Exception as e:
            console.print(f"[dim]Source compilation failed: {e}[/dim]")
        
        return False
    
    def uninstall_all(self):
        """Uninstall all exporters."""
        services = ["node_exporter", "dcgm-exporter", "dc-exporter"]
        
        for service in services:
            try:
                subprocess.run(["systemctl", "stop", service], capture_output=True)
                subprocess.run(["systemctl", "disable", service], capture_output=True)
                
                service_file = f"/etc/systemd/system/{service}.service"
                if os.path.exists(service_file):
                    os.remove(service_file)
                
                console.print(f"[green]✓[/green] Uninstalled {service}")
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] Could not uninstall {service}: {e}")
        
        subprocess.run(["systemctl", "daemon-reload"], check=True)
    
    @staticmethod
    def check_status() -> dict:
        """Check status of all exporters."""
        status = {}
        services = [
            ("node_exporter", 9100),
            ("dc-exporter", 9835),
        ]
        
        for name, port in services:
            try:
                # First check systemd service
                result = subprocess.run(
                    ["systemctl", "is-active", name],
                    capture_output=True,
                    text=True
                )
                if result.stdout.strip() == "active":
                    status[name] = {
                        "status": "active",
                        "port": port,
                        "running": True
                    }
                    continue
                
                # For dcgm-exporter, also check Docker container
                if name == "dcgm-exporter":
                    docker_result = subprocess.run(
                        ["docker", "ps", "-q", "-f", "name=dcgm-exporter"],
                        capture_output=True, text=True
                    )
                    if docker_result.returncode == 0 and docker_result.stdout.strip():
                        status[name] = {
                            "status": "active (docker)",
                            "port": port,
                            "running": True
                        }
                        continue
                
                status[name] = {
                    "status": result.stdout.strip() or "not installed",
                    "port": port,
                    "running": False
                }
            except Exception:
                status[name] = {
                    "status": "not installed",
                    "port": port,
                    "running": False
                }
        
        return status


# =============================================================================
# VERSION DETECTION FUNCTIONS
# =============================================================================

def get_version_from_metrics(server_ip: str, exporter: str, timeout: int = 5) -> Optional[str]:
    """
    Get exporter version from its metrics endpoint.
    
    Args:
        server_ip: IP address of the server
        exporter: One of 'node_exporter', 'dc_exporter', 'dcgm_exporter'
        timeout: Request timeout in seconds
        
    Returns:
        Version string or None if not available
    """
    port = EXPORTER_PORTS.get(exporter)
    if not port:
        return None
    
    try:
        url = f"http://{server_ip}:{port}/metrics"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            metrics = response.read().decode('utf-8')
            
            if exporter == 'node_exporter':
                # Parse: node_exporter_build_info{...version="1.7.0"...}
                match = re.search(r'node_exporter_build_info\{[^}]*version="([^"]+)"', metrics)
                if match:
                    return match.group(1)
                    
            elif exporter == 'dc_exporter':
                # Parse: DCXP_BUILD_INFO or look for version in any metric
                match = re.search(r'dc_exporter_build_info\{[^}]*version="([^"]+)"', metrics)
                if match:
                    return match.group(1)
                # Try to find version in any DCXP metric
                match = re.search(r'DCXP_VERSION\{[^}]*\}\s+([0-9.]+)', metrics)
                if match:
                    return match.group(1)
                # Check if metrics are present (exporter is working)
                if 'DCXP_GPU_SUPPORTED' in metrics or 'DCXP_FI_DEV' in metrics:
                    return "running"  # Version unknown but exporter is active
                    
            elif exporter == 'dcgm_exporter':
                # Parse: dcgm_exporter_build_info{...version="3.3.5-3.4.1"...}
                match = re.search(r'dcgm_exporter_build_info\{[^}]*version="([^"]+)"', metrics)
                if match:
                    return match.group(1)
                # Check if DCGM metrics present
                if 'DCGM_FI_' in metrics:
                    return "running"
                    
    except Exception:
        pass
    
    return None


def _build_exporter_ssh_cmd(server_ip: str, ssh_user: str = 'root',
                            ssh_port: int = 22, ssh_key_path: Optional[str] = None,
                            ssh_password: Optional[str] = None,
                            timeout: int = 5) -> tuple:
    """Build SSH command for exporter operations, supporting both key and password auth.
    
    Returns (cmd_prefix, env_dict) where env_dict contains SSHPASS if password auth.
    """
    env = {}
    
    if ssh_key_path:
        ssh_cmd = [
            'ssh',
            '-o', f'ConnectTimeout={timeout}',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'BatchMode=yes',
            '-p', str(ssh_port)
        ]
        ssh_cmd.extend(['-i', ssh_key_path])
    elif ssh_password:
        ssh_cmd = [
            'sshpass', '-e',
            'ssh',
            '-o', f'ConnectTimeout={timeout}',
            '-o', 'StrictHostKeyChecking=no',
            '-p', str(ssh_port)
        ]
        env['SSHPASS'] = ssh_password
    else:
        ssh_cmd = [
            'ssh',
            '-o', f'ConnectTimeout={timeout}',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'BatchMode=yes',
            '-p', str(ssh_port)
        ]
    
    ssh_cmd.append(f'{ssh_user}@{server_ip}')
    return ssh_cmd, env


def get_version_from_ssh(server_ip: str, exporter: str, ssh_user: str = 'root',
                         ssh_port: int = 22, ssh_key_path: Optional[str] = None,
                         ssh_password: Optional[str] = None,
                         timeout: int = 10) -> Optional[str]:
    """
    Get exporter version by running --version on the remote server via SSH.
    
    Args:
        server_ip: IP address of the server
        exporter: One of 'node_exporter', 'dc_exporter', 'dcgm_exporter'
        ssh_user: SSH username
        ssh_port: SSH port
        ssh_key_path: Path to SSH key (optional)
        ssh_password: SSH password for password-based auth (optional)
        timeout: Command timeout
        
    Returns:
        Version string or None if not available
    """
    binary_paths = {
        'node_exporter': '/usr/local/bin/node_exporter',
        'dc_exporter': '/usr/local/bin/dc-exporter-rs',
        'dcgm_exporter': None  # Docker-based, use docker inspect
    }
    
    binary = binary_paths.get(exporter)
    
    try:
        ssh_cmd, env = _build_exporter_ssh_cmd(server_ip, ssh_user, ssh_port, ssh_key_path, ssh_password, timeout=5)
        
        if exporter == 'dcgm_exporter':
            # For Docker-based dcgm-exporter, get image tag
            ssh_cmd.append("docker inspect dcgm-exporter --format '{{.Config.Image}}' 2>/dev/null || echo ''")
        else:
            ssh_cmd.append(f"{binary} --version 2>/dev/null || echo ''")
        
        run_env = {**os.environ, **env} if env else None
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout, env=run_env)
        
        if result.returncode == 0 and result.stdout.strip():
            output = result.stdout.strip()
            
            if exporter == 'node_exporter':
                # Parse: node_exporter, version 1.7.0 (branch: ...)
                match = re.search(r'version\s+([0-9.]+)', output)
                if match:
                    return match.group(1)
                    
            elif exporter == 'dc_exporter':
                # Parse: dc-exporter-rs 0.1.0 or similar
                match = re.search(r'([0-9]+\.[0-9]+\.[0-9]+)', output)
                if match:
                    return match.group(1)
                    
            elif exporter == 'dcgm_exporter':
                # Parse Docker image tag: nvidia/dcgm-exporter:3.3.5-3.4.1-ubuntu22.04
                match = re.search(r':([0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+\.[0-9]+)', output)
                if match:
                    return match.group(1)
                    
    except Exception:
        pass
    
    return None


def get_exporter_version(server_ip: str, exporter: str, ssh_user: str = 'root',
                        ssh_port: int = 22, ssh_key_path: Optional[str] = None,
                        ssh_password: Optional[str] = None) -> Optional[str]:
    """
    Get exporter version, trying metrics endpoint first then SSH fallback.
    
    Args:
        server_ip: IP address of the server
        exporter: One of 'node_exporter', 'dc_exporter', 'dcgm_exporter'
        ssh_user: SSH username
        ssh_port: SSH port
        ssh_key_path: Path to SSH key (optional)
        ssh_password: SSH password for password-based auth (optional)
        
    Returns:
        Version string or None if not available
    """
    # Try metrics endpoint first (faster, doesn't require SSH)
    version = get_version_from_metrics(server_ip, exporter)
    if version and version != "running":
        return version
    
    # Fall back to SSH
    version = get_version_from_ssh(server_ip, exporter, ssh_user, ssh_port, ssh_key_path, ssh_password)
    if version:
        return version
    
    # If metrics showed "running" but we couldn't get version
    if version == "running":
        return "unknown"
    
    return None


def get_all_exporter_versions(server_ip: str, ssh_user: str = 'root',
                              ssh_port: int = 22, ssh_key_path: Optional[str] = None,
                              ssh_password: Optional[str] = None) -> Dict[str, Optional[str]]:
    """
    Get versions of all exporters on a server.
    
    Returns:
        Dictionary mapping exporter name to version (or None if not installed)
    """
    return {
        'node_exporter': get_exporter_version(server_ip, 'node_exporter', ssh_user, ssh_port, ssh_key_path, ssh_password),
        'dc_exporter': get_exporter_version(server_ip, 'dc_exporter', ssh_user, ssh_port, ssh_key_path, ssh_password),
        'dcgm_exporter': get_exporter_version(server_ip, 'dcgm_exporter', ssh_user, ssh_port, ssh_key_path, ssh_password),
    }


# =============================================================================
# GITHUB RELEASE FUNCTIONS
# =============================================================================

def get_latest_github_release(repo: str, branch: str = 'main') -> Optional[Dict[str, Any]]:
    """
    Get the latest release from a GitHub repository.
    
    Args:
        repo: GitHub repository in 'owner/repo' format
        branch: Branch to check ('main' or 'dev') - affects pre-release filtering
        
    Returns:
        Dictionary with 'version', 'tag', 'url', 'published_at' or None
    """
    try:
        # GitHub API for releases
        url = f"https://api.github.com/repos/{repo}/releases"
        req = urllib.request.Request(url)
        req.add_header('Accept', 'application/vnd.github.v3+json')
        req.add_header('User-Agent', 'dc-overview')
        
        # Add GitHub token if available (increases rate limit from 60 to 5000 req/hour)
        github_token = os.environ.get('GITHUB_TOKEN')
        if github_token:
            req.add_header('Authorization', f'token {github_token}')
        
        with urllib.request.urlopen(req, timeout=10) as response:
            releases = json.loads(response.read().decode('utf-8'))
            
            if not releases:
                return None
            
            for release in releases:
                # Skip pre-releases unless using dev branch
                if release.get('prerelease') and branch == 'main':
                    continue
                
                tag = release.get('tag_name', '')
                version = tag.lstrip('v')
                
                return {
                    'version': version,
                    'tag': tag,
                    'url': release.get('html_url'),
                    'published_at': release.get('published_at'),
                    'prerelease': release.get('prerelease', False),
                    'assets': release.get('assets', [])
                }
                
    except Exception:
        pass
    
    return None


def get_latest_exporter_version(exporter: str, branch: str = 'main') -> Optional[str]:
    """
    Get the latest available version for an exporter.
    Uses a 1-hour cache to avoid GitHub API rate limiting.
    
    Args:
        exporter: One of 'node_exporter', 'dc_exporter', 'dcgm_exporter'
        branch: Branch to check ('main' or 'dev')
        
    Returns:
        Version string or None
    """
    # Use cached versions (refreshes from GitHub once per hour)
    cached = _get_cached_versions()
    version = cached.get(exporter)
    
    if version:
        return version
    
    # Ultimate fallback
    return FALLBACK_VERSIONS.get(exporter)


def get_all_latest_versions(branch: str = 'main') -> Dict[str, Optional[str]]:
    """
    Get the latest available versions for all exporters.
    Uses a 1-hour cache to minimize GitHub API calls.
    
    Args:
        branch: Branch to check ('main' or 'dev')
        
    Returns:
        Dictionary mapping exporter name to latest version
    """
    # Use the cache directly - it handles GitHub API and fallbacks
    return _get_cached_versions()


def check_for_updates(server_ip: str, ssh_user: str = 'root', ssh_port: int = 22,
                     ssh_key_path: Optional[str] = None, ssh_password: Optional[str] = None,
                     branch: str = 'main') -> Dict[str, Dict[str, Any]]:
    """
    Check if any exporters on a server have updates available.
    
    Returns:
        Dictionary with update info per exporter:
        {
            'node_exporter': {
                'installed': '1.6.0',
                'latest': '1.7.0',
                'update_available': True
            },
            ...
        }
    """
    installed = get_all_exporter_versions(server_ip, ssh_user, ssh_port, ssh_key_path, ssh_password)
    latest = get_all_latest_versions(branch)
    
    result = {}
    for exporter in EXPORTER_REPOS.keys():
        inst_ver = installed.get(exporter)
        lat_ver = latest.get(exporter)
        
        update_available = False
        if inst_ver and lat_ver and inst_ver not in ('running', 'unknown'):
            # Simple version comparison (works for semver)
            try:
                inst_parts = [int(x) for x in inst_ver.split('.')[:3]]
                lat_parts = [int(x) for x in lat_ver.split('.')[:3]]
                update_available = lat_parts > inst_parts
            except ValueError:
                # Non-numeric version parts, do string comparison
                update_available = lat_ver != inst_ver
        
        result[exporter] = {
            'installed': inst_ver,
            'latest': lat_ver,
            'update_available': update_available
        }
    
    return result


def get_exporter_download_url(exporter: str, version: str = None, branch: str = 'main') -> Optional[str]:
    """
    Get the download URL for an exporter binary.
    
    Args:
        exporter: One of 'node_exporter', 'dc_exporter', 'dcgm_exporter'
        version: Specific version (or None for latest)
        branch: Branch ('main' or 'dev')
        
    Returns:
        Download URL or None
    """
    if not version:
        version = get_latest_exporter_version(exporter, branch)
    
    if not version:
        return None
    
    if exporter == 'node_exporter':
        return f"https://github.com/prometheus/node_exporter/releases/download/v{version}/node_exporter-{version}.linux-amd64.tar.gz"
    elif exporter == 'dc_exporter':
        return get_dc_exporter_download_url(version)
    elif exporter == 'dcgm_exporter':
        # Docker image, return image tag
        return f"nvidia/dcgm-exporter:{version}-ubuntu22.04"
    
    return None
