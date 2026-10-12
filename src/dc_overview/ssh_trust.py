"""Read-only trust configuration shared by ordinary outbound SSH transports."""
import base64
import os
import stat
import struct
from pathlib import Path


class SSHTrustError(ValueError):
    """The operator must enroll trusted host keys before connecting."""


def resolve_known_hosts_path(server=None, *, known_hosts_path=None):
    """Resolve existing operator-enrolled trust without scans or fallback writes."""
    configured = os.environ.get('DC_OVERVIEW_SSH_KNOWN_HOSTS')
    if configured is None:
        configured = getattr(server, 'ssh_known_hosts_path', None)
    if configured is None:
        configured = known_hosts_path if known_hosts_path is not None else '/etc/dc-overview/known_hosts'
    try:
        value = os.fspath(configured)
        if not isinstance(value, str) or not value or '$' in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError
        path = Path(value)
        if not path.is_absolute():
            raise ValueError
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise ValueError
        entries = 0
        for line in path.read_text(encoding='utf-8').splitlines():
            fields = line.split()
            if not fields or fields[0].startswith('#'):
                continue
            if fields[0].startswith('@'):
                if fields[0] not in ('@cert-authority', '@revoked'):
                    raise ValueError
                fields = fields[1:]
            if len(fields) < 3:
                raise ValueError
            blob = base64.b64decode(fields[2], validate=True)
            size = struct.unpack('>I', blob[:4])[0]
            if not size or len(blob) <= 4 + size or blob[4:4+size].decode('ascii') != fields[1]:
                raise ValueError
            entries += 1
        if not entries:
            raise ValueError
        return path
    except (OSError, TypeError, ValueError, UnicodeError, struct.error):
        raise SSHTrustError('SSH host trust unavailable: enroll fingerprint-verified host keys in the configured known_hosts file before retrying.') from None


def openssh_trust_options(server=None, *, known_hosts_path=None):
    """Pin trust before other options while retaining ordinary SSH routing."""
    path = resolve_known_hosts_path(server, known_hosts_path=known_hosts_path)
    # OpenSSH parses option values itself even when argv bypasses the shell.
    quoted = str(path).replace('%', '%%').replace('\\', '\\\\').replace('"', '\\"')
    options = [
        'StrictHostKeyChecking=yes', f'UserKnownHostsFile="{quoted}"',
        'GlobalKnownHostsFile=/dev/null', 'KnownHostsCommand=none',
        'VerifyHostKeyDNS=no', 'UpdateHostKeys=no', 'ForwardAgent=no',
        'ControlMaster=no', 'ControlPath=none',
    ]
    return [part for option in options for part in ('-o', option)]


def validated_extra_ssh_options(options):
    """Allow bounded liveness options; reject destination/trust overrides."""
    options = list(options or [])
    allowed = {'serveraliveinterval', 'serveralivecountmax', 'connecttimeout'}
    if len(options) % 2:
        raise SSHTrustError('Unsupported extra SSH options; host trust cannot be overridden.')
    for flag, option in zip(options[::2], options[1::2]):
        name, separator, value = str(option).partition('=')
        if flag != '-o' or name.lower() not in allowed or not separator or not value.isdecimal():
            raise SSHTrustError('Unsupported extra SSH options; host trust cannot be overridden.')
    return options


def configure_paramiko_host_trust(client, server=None, *, known_hosts_path=None):
    """Load exactly the enrolled file; never use agent or implicit system trust."""
    import paramiko
    path = resolve_known_hosts_path(server, known_hosts_path=known_hosts_path)
    # Paramiko has no OpenSSH CA/revocation implementation. Refuse rather than
    # silently ignoring these operator policies or treating CA keys as host keys.
    if any(line.lstrip().startswith('@') for line in path.read_text().splitlines()):
        raise SSHTrustError('This trust file requires OpenSSH CA/revocation support; use OpenSSH transport or an ordinary pinned host-key file.')
    try:
        client.load_host_keys(str(path))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    except Exception:
        raise SSHTrustError('SSH host trust could not be loaded; verify the configured known_hosts file.') from None
    return path
