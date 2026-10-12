"""Apply approved worker artifacts through existing SSH and verified installers."""
from types import SimpleNamespace
import re
import shlex
import os
import base64
from pathlib import Path
import yaml

from .exporters import (build_dc_exporter_install_script, build_node_exporter_install_script,
                        build_dc_exporter_remote_command, DC_EXPORTER_CALLER_TIMEOUT_SECONDS)
from .release_catalog import artifact_identity
from .ssh_manager import SSHManager
from .fleet_config import AuthMethod

PATHS = {'dc-exporter':('/usr/local/bin/dc-exporter-rs','dc-exporter'),
         'node-exporter':('/usr/local/bin/node_exporter','node_exporter'),
         'dc-watchdog-agent':('/usr/local/bin/dc-watchdog-agent','dc-watchdog-agent')}


def selected_worker_mutation_refusal(config_dir=None):
    """Keep the suite CLI as the single worker update authority in selected mode.

    The app only reads public policy. Missing/unreadable selected storage must
    never turn an explicit selection into mutable latest delivery.
    """
    root = Path(config_dir or os.environ.get('DC_OVERVIEW_CONFIG_DIR', '/etc/dc-overview'))
    refusal = 'Selected worker lifecycle is managed by the authoritative host CLI: run dc-overview upgrade (or dc-overview setup for a new worker).'
    if os.environ.get('DC_RELEASE_SELECTION_REQUIRED') == '1':
        return refusal
    try:
        path = root / 'fleet-config.yaml'
        try:
            path.stat()
        except FileNotFoundError:
            present = False
        else:
            present = True
        if present:
            value = yaml.safe_load(path.read_bytes()) or {}
            if not isinstance(value, dict):
                return refusal
            selection = value.get('release_selection') or {}
            if not isinstance(selection, dict):
                return refusal
            if selection.get('selection_id') or selection.get('selection_sha256') or selection.get('components'):
                return refusal
            store = Path(selection.get('release_selection_dir') or root / 'releases')
        else:
            store = root / 'releases'
        if (store / 'selection.json').exists() or (store / '.lifecycle-publication.json').exists():
            return refusal
    except (OSError, ValueError, TypeError, yaml.YAMLError):
        return refusal
    return None


def _preflight_worker_privilege(ssh, options, names, *, mode='update'):
    # Exercise the exact noninteractive bounded Bash runner used by installers;
    # root in this readonly payload is a privilege proof, never a sudo grant.
    script = 'set -e\n[ "$(id -u)" = 0 ]\n'
    script += 'for tool in bash timeout base64 curl sha256sum systemctl flock mktemp cp mv chmod chown stat tar getent useradd grep sed; do command -v "$tool" >/dev/null; done\n'
    script += '[ -d /run/systemd/system ]\n'
    for name in names:
        binary, service = PATHS[name]
        script += f'''load=$(systemctl show {shlex.quote(service)} --property=LoadState --value)
case "$load" in loaded|masked|not-found) ;; *) exit 1;; esac
active=$(systemctl is-active {shlex.quote(service)}) || [ "$active" = inactive ] || [ "$active" = failed ] || [ "$active" = unknown ]
case "$active" in active|inactive|failed|unknown) ;; *) exit 1;; esac
enabled=$(systemctl is-enabled {shlex.quote(service)}) || [ "$enabled" = disabled ] || [ "$enabled" = masked ] || [ "$enabled" = masked-runtime ] || [ "$enabled" = not-found ]
case "$enabled" in enabled|enabled-runtime|disabled|masked|masked-runtime|not-found|static|indirect|generated|linked|linked-runtime|alias) ;; *) exit 1;; esac
'''
        script += f'[ -d {shlex.quote(str(Path(binary).parent))} ]\n'
        if mode == 'update':
            script += f'[ "$load" != not-found ]\n[ -x {shlex.quote(binary)} ]\n'
            if name == 'dc-watchdog-agent':
                from .web_watchdog import watchdog_update_prerequisites
                script += watchdog_update_prerequisites()
    script += 'echo WORKER_PREFLIGHT=verified\n'
    commands = []
    if any(name != 'dc-watchdog-agent' for name in names):
        commands.append(build_dc_exporter_remote_command(script, sudo=options['username'] != 'root'))
    if 'dc-watchdog-agent' in names:
        from .web_watchdog import watchdog_remote_runner
        payload = shlex.quote(base64.b64encode(script.encode()).decode())
        commands.append(f"printf '%s' {payload} | base64 --decode | " + watchdog_remote_runner(sudo=options['username'] != 'root'))
    for command in commands:
        result = ssh.run_command(command=command, timeout=30, **options)
        if not result.success or 'WORKER_PREFLIGHT=verified' not in result.output.splitlines():
            raise ValueError('worker noninteractive privilege/prerequisite preflight failed; no suite mutation authorized')


def worker_target(plan, name, platform):
    component = plan.manifest.data['components'][name]
    artifact = component['artifacts'].get(platform)
    if artifact is None:
        raise ValueError('unsupported worker artifact platform')
    policy = plan.selection['components'][name]
    if policy['origin'] == 'customer-pin' and policy['pin'] != artifact_identity(artifact):
        raise ValueError('worker pin_conflict')
    return {**artifact, 'release':component['release'], 'owner':component['owner'],
            'platform':platform, 'origin':policy['origin']}


def preflight_workers(config, plan, *, mode='update'):
    """Read worker platforms and validate owner support before suite mutations."""
    names = [name for name, target in plan.targets.items() if target['owner'] == 'dc-worker']
    if not names:
        return {}
    if not config.servers:
        raise ValueError('required worker inventory is missing')
    if mode == 'install' and 'dc-watchdog-agent' in names and not config.watchdog.api_key:
        raise ValueError('required Watchdog worker registration authority is unavailable')
    ssh = SSHManager(config.config_dir)
    inventory = {}
    for server in config.servers:
        credentials = config.get_server_ssh_creds(server)
        options = {'host':server.server_ip, 'username':credentials.username,
                   'port':credentials.port, 'key_path':credentials.key_path or config.ssh.key_path, 'sudo':False}
        if mode == 'install' and credentials.auth_method == AuthMethod.PASSWORD and credentials.password:
            options['password'] = credentials.password
        try:
            result = ssh.run_command(command='uname -s -m', timeout=15, **options)
            platform = {'Linux x86_64':'linux/amd64', 'Linux aarch64':'linux/arm64'}.get(result.output.strip()) if result.success else None
        except (OSError, RuntimeError):
            platform = None
        if platform is None:
            raise ValueError('worker platform prerequisite is unreachable or unsupported')
        inventory[server.name] = {}
        for name in names:
            target = worker_target(plan, name, platform)
            if name == 'dc-exporter':
                build_dc_exporter_install_script(selected_artifact=target, mode=mode)
            elif name == 'node-exporter':
                build_node_exporter_install_script(selected_artifact=target, mode=mode)
            else:
                from .exporters import validate_selected_worker_artifact
                validate_selected_worker_artifact(name, target)
            inventory[server.name][name] = target
        _preflight_worker_privilege(ssh, options, names, mode=mode)
    return inventory


def _probe_command(name, *, sudo=False):
    binary, service = PATHS[name]
    probe = f'''set -e
sha=$(sha256sum {shlex.quote(binary)})
load=$(systemctl show {shlex.quote(service)} --property=LoadState --value)
[ "$load" = loaded ] || [ "$load" = masked ]
state=$(systemctl is-active {shlex.quote(service)}) || [ "$state" = inactive ]
printf 'WORKER_ARTIFACT=%s\\nWORKER_SERVICE=%s\\n' "${{sha%% *}}" "$state"
'''
    if name == 'dc-watchdog-agent':
        # The installer already checked config-derived health/metrics inside
        # its recovery window. This outer probe proves final binary/unit/state.
        probe += 'echo WORKER_HEALTH=verified\n'
        from .web_watchdog import watchdog_remote_runner
        payload = shlex.quote(base64.b64encode(probe.encode()).decode())
        return f"printf '%s' {payload} | base64 --decode | " + watchdog_remote_runner(sudo=sudo)
    return build_dc_exporter_remote_command(probe, sudo=sudo)


def upgrade_workers(config, plan, *, mode='update'):
    names = [name for name,target in plan.targets.items() if target['owner'] == 'dc-worker']
    outcomes = {name:{'owner':'dc-worker','success':False,'state':'unknown','workers':{}} for name in names}
    ssh = SSHManager(config.config_dir)
    for server in config.servers:
        credentials = config.get_server_ssh_creds(server)
        options = {'host':server.server_ip,'username':credentials.username,'port':credentials.port,
                   'key_path':credentials.key_path or config.ssh.key_path,'sudo':False}
        try:
            observation = ssh.run_command(command='uname -s -m', timeout=15, **options)
            platform = {'Linux x86_64':'linux/amd64','Linux aarch64':'linux/arm64'}.get(observation.output.strip()) if observation.success else None
        except (OSError, RuntimeError):
            platform = None
        for name in names:
            result = {'owner':'dc-worker','success':False,'state':'unknown','observed':None,
                      'reason':'worker unreachable or unsupported platform'}
            if platform:
                try:
                    target = worker_target(plan, name, platform)
                    result['desired'] = artifact_identity(target)
                    _preflight_worker_privilege(ssh, options, [name], mode=mode)
                    if name == 'dc-exporter':
                        script = build_dc_exporter_install_script(mode=mode, selected_artifact=target)
                    elif name == 'node-exporter':
                        script = build_node_exporter_install_script(selected_artifact=target, mode=mode)
                    elif name == 'dc-watchdog-agent':
                        from .web_watchdog import get_site_id, install_watchdog_agent_remote
                        host = SimpleNamespace(name=server.name, server_ip=server.server_ip, ssh_user=credentials.username,
                                               ssh_port=credentials.port, ssh_password=credentials.password,
                                               ssh_known_hosts_path=str(ssh.known_hosts_path),
                                               ssh_key=SimpleNamespace(key_path=str(credentials.key_path or config.ssh.key_path or ssh.key_path)))
                        settings = {}
                        if mode == 'install':
                            settings = {
                                'site_id': get_site_id({'ssl': {'domain': config.ssl.domain},
                                                        'master_ip': config.master_ip or 'default'}),
                                'heartbeat_interval': config.watchdog.ping_interval,
                                'use_mtr': config.watchdog.agent_use_mtr,
                            }
                        success, error = install_watchdog_agent_remote(host, config.watchdog.api_key or '',
                                                                       selected_artifact=target, watchdog_url=config.watchdog.server_url,
                                                                       mode=mode, **settings)
                        if not success:
                            raise RuntimeError('worker agent installation failed')
                        script = None
                    else:
                        raise ValueError('unsupported worker owner')
                    if script is not None:
                        command = build_dc_exporter_remote_command(script, sudo=credentials.username != 'root')
                        installed = ssh.run_command(command=command, timeout=DC_EXPORTER_CALLER_TIMEOUT_SECONDS, **options)
                        marker = 'DC_EXPORTER_INSTALL_SUCCESS' if name == 'dc-exporter' else 'NODE_EXPORTER_INSTALL_SUCCESS'
                        if not installed.success or marker not in installed.output:
                            raise RuntimeError('worker install did not verify')
                    expected_binary = target['sha256']
                    if name == 'node-exporter':
                        candidate_digest = re.search(r'^NODE_EXPORTER_CANDIDATE_SHA256=([0-9a-f]{64})$', installed.output, re.M)
                        archive_digest = re.search(r'^NODE_EXPORTER_ARTIFACT_SHA256=([0-9a-f]{64})$', installed.output, re.M)
                        if not candidate_digest or not archive_digest or archive_digest.group(1) != target['sha256']:
                            raise RuntimeError('node archive/extracted binary proof did not verify')
                        expected_binary = candidate_digest.group(1)
                    probe = _probe_command(name, sudo=credentials.username != 'root')
                    observed = ssh.run_command(command=probe, timeout=30, **options)
                    digest = re.search(r'^WORKER_ARTIFACT=([0-9a-f]{64})$', observed.output, re.M)
                    state = re.search(r'^WORKER_SERVICE=(active|inactive)$', observed.output, re.M)
                    health = name != 'dc-watchdog-agent' or 'WORKER_HEALTH=verified' in observed.output.splitlines()
                    if not observed.success or not digest or digest.group(1) != expected_binary or not state or not health:
                        raise RuntimeError('worker artifact/service probe did not verify')
                    result = {'owner':'dc-worker','success':True,'state':'verified','desired':target['sha256'],
                              'observed':target['sha256'], 'observed_binary_sha256':digest.group(1),
                              'service_state':state.group(1), 'release':target['release']}
                    if name == 'dc-watchdog-agent':
                        result['observed_agent_version'] = getattr(host, 'watchdog_agent_version', None)
                except (ValueError, RuntimeError, OSError, TypeError, KeyError):
                    result.update(success=False,state='failed',reason='selected artifact installation/probe failed; previous observations retained')
            outcomes[name]['workers'][server.name] = result
    for value in outcomes.values():
        value['success'] = bool(value['workers']) and all(result['success'] for result in value['workers'].values())
        value['state'] = 'verified' if value['success'] else 'failed'
        if not value['workers']:
            value['reason'] = 'required worker inventory is missing'
    return outcomes
