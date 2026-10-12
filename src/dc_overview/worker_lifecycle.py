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
    refusal = 'Selected worker lifecycle is managed by the authoritative host CLI: run dc-overview upgrade or dc-overview add-machine WORKER_IP --name WORKER_NAME for enrollment.'
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


def _preflight_worker_privilege(ssh, options, names, *, mode='update', identity_guard=None):
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
        component_mode = mode.get(name, 'update') if isinstance(mode, dict) else mode
        if component_mode in ('update', 'noop'):
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
        if identity_guard:
            identity_guard()
        result = ssh.run_command(command=command, timeout=30, **options)
        if not result.success or 'WORKER_PREFLIGHT=verified' not in result.output.splitlines():
            raise ValueError('worker noninteractive privilege/prerequisite preflight failed; no suite mutation authorized')


def _observe_worker_components(ssh, options, targets, *, identity_guard=None):
    """Positive absence/presence and selected bytes; never infer install from error."""
    script = 'set -e\n[ "$(id -u)" = 0 ]\n'
    for name, target in targets.items():
        binary, service = PATHS[name]
        script += f'''load=$(systemctl show {shlex.quote(service)} --property=LoadState --value)
active=$(systemctl is-active {shlex.quote(service)}) || :
enabled=$(systemctl is-enabled {shlex.quote(service)}) || :
[ ! -L {shlex.quote(binary)} ]
digest=-
if [ -e {shlex.quote(binary)} ]; then
    [ -f {shlex.quote(binary)} ] && [ -x {shlex.quote(binary)} ]
    digest=$(sha256sum {shlex.quote(binary)}); digest=${{digest%% *}}
fi
printf 'WORKER_COMPONENT={name}|%s|%s|%s|%s\\n' "$load" "$active" "$enabled" "$digest"
'''
        if name == 'node-exporter':
            member = f'node_exporter-{target["release"]}.{target["platform"].replace("/", "-")}/node_exporter'
            script += f'''if [ "$digest" != - ]; then
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    curl --fail --silent --show-error --location --max-time 60 {shlex.quote(target['url'])} -o "$work/archive"
    printf '%s  %s\\n' {shlex.quote(target['sha256'])} "$work/archive" | sha256sum -c - >/dev/null
    tar -xOf "$work/archive" {shlex.quote(member)} > "$work/binary"
    selected=$(sha256sum "$work/binary"); selected=${{selected%% *}}
    printf 'WORKER_SELECTED_BINARY=node-exporter|%s\\n' "$selected"
    rm -rf "$work"; trap - EXIT
fi
'''
    command = build_dc_exporter_remote_command(script, sudo=options['username'] != 'root')
    if identity_guard:
        identity_guard()
    result = ssh.run_command(command=command, timeout=120, **options)
    if not result.success:
        raise ValueError('worker presence prerequisite could not be proven')
    records = {}; selected_node = None
    for line in result.output.splitlines():
        match = re.fullmatch(r'WORKER_COMPONENT=([a-z-]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(-|[0-9a-f]{64})', line)
        node = re.fullmatch(r'WORKER_SELECTED_BINARY=node-exporter\|([0-9a-f]{64})', line)
        if match and match[1] in targets and match[1] not in records:
            records[match[1]] = match.groups()[1:]
        elif node and selected_node is None:
            selected_node = node[1]
        else:
            raise ValueError('worker presence output is malformed or duplicated')
    if set(records) != set(targets):
        raise ValueError('worker presence output is incomplete')
    modes = {}
    enabled_states = {'enabled','enabled-runtime','disabled','masked','masked-runtime','static','indirect','generated','linked','linked-runtime','alias'}
    for name, (load, active, enabled, digest) in records.items():
        if load == 'not-found' and active in ('unknown','inactive') and enabled == 'not-found' and digest == '-':
            modes[name] = 'install'
        elif load in ('loaded','masked') and active in ('active','inactive','failed') and enabled in enabled_states and digest != '-':
            selected_digest = selected_node if name == 'node-exporter' else targets[name]['sha256']
            if not selected_digest:
                raise ValueError('worker presence lacks exact selected archive proof')
            modes[name] = 'noop' if digest == selected_digest and active in ('active','inactive') else 'update'
            targets[name]['presence_binary_sha256'] = digest
        else:
            raise ValueError('worker presence is inconsistent; no install fallback permitted')
    return modes


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
        if getattr(config.components, 'worker_exporters', False):
            return {}
        raise ValueError('required worker inventory is missing')
    if mode == 'install' and 'dc-watchdog-agent' in names and not config.watchdog.api_key:
        raise ValueError('required Watchdog worker registration authority is unavailable')
    if mode not in ('install', 'update', 'reconcile'):
        raise ValueError('unsupported worker delivery mode')
    identity_guard = getattr(config, '_enrollment_identity_guard', None)
    ssh = SSHManager(config.config_dir)
    inventory = {}
    for server in config.servers:
        credentials = config.get_server_ssh_creds(server)
        options = {'host':server.server_ip, 'username':credentials.username,
                   'port':credentials.port, 'key_path':credentials.key_path or config.ssh.key_path, 'sudo':False,
                   'selected_identity':True}
        if mode == 'install' and credentials.auth_method == AuthMethod.PASSWORD and credentials.password:
            options['password'] = credentials.password
            # Fresh password bootstrap has its own explicit transport authority.
            options['selected_identity'] = False
        try:
            if identity_guard:
                identity_guard()
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
                build_dc_exporter_install_script(selected_artifact=target, mode='update' if mode == 'reconcile' else mode)
            elif name == 'node-exporter':
                build_node_exporter_install_script(selected_artifact=target, mode='update' if mode == 'reconcile' else mode)
            else:
                from .exporters import validate_selected_worker_artifact
                validate_selected_worker_artifact(name, target)
            inventory[server.name][name] = target
        modes = _observe_worker_components(ssh, options, inventory[server.name], identity_guard=identity_guard) if mode == 'reconcile' else {name:mode for name in names}
        if modes.get('dc-watchdog-agent') == 'install' and not config.watchdog.api_key:
            raise ValueError('required Watchdog worker registration authority is unavailable')
        _preflight_worker_privilege(ssh, options, names, mode=modes, identity_guard=identity_guard)
        for name, delivery_mode in modes.items():
            inventory[server.name][name]['delivery_mode'] = delivery_mode
            if delivery_mode == 'noop':
                if identity_guard:
                    identity_guard()
                probe = ssh.run_command(command=_probe_command(name, sudo=options['username'] != 'root', repeat=True), timeout=30, **options)
                digest = re.search(r'^WORKER_ARTIFACT=([0-9a-f]{64})$', probe.output, re.M)
                state = re.search(r'^WORKER_SERVICE=(active|inactive)$', probe.output, re.M)
                if (not probe.success or not digest or not state
                        or digest[1] != inventory[server.name][name]['presence_binary_sha256']):
                    raise ValueError('worker presence repeat proof failed')
                inventory[server.name][name]['observed_binary_sha256'] = digest[1]
                inventory[server.name][name]['service_state'] = state[1]
    return inventory


def _probe_command(name, *, sudo=False, repeat=False):
    binary, service = PATHS[name]
    probe = f'''set -e
sha=$(sha256sum {shlex.quote(binary)})
load=$(systemctl show {shlex.quote(service)} --property=LoadState --value)
[ "$load" = loaded ] || [ "$load" = masked ]
state=$(systemctl is-active {shlex.quote(service)}) || [ "$state" = inactive ]
printf 'WORKER_ARTIFACT=%s\\nWORKER_SERVICE=%s\\n' "${{sha%% *}}" "$state"
'''
    if repeat:
        probe += f'''if [ "$state" = active ]; then
pid=$(systemctl show {shlex.quote(service)} --property=MainPID --value)
[[ "$pid" =~ ^[1-9][0-9]*$ ]]
running=$(sha256sum "/proc/$pid/exe"); running=${{running%% *}}
[ "$running" = "${{sha%% *}}" ]
fi
'''
        if name == 'dc-watchdog-agent':
            probe += '''[ -s /etc/dc-watchdog/agent.yaml ]
grep -Eq '^api_key:[[:space:]]*[^[:space:]]+' /etc/dc-watchdog/agent.yaml
grep -Eq '^server_url:[[:space:]]*[^[:space:]]+' /etc/dc-watchdog/agent.yaml
port=$(sed -nE 's/^health_port:[[:space:]]*([0-9]+)[[:space:]]*$/\\1/p' /etc/dc-watchdog/agent.yaml)
[[ "$port" =~ ^[0-9]{1,5}$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || exit 1
if [ "$state" = active ]; then
curl -fsS --max-time 5 "http://127.0.0.1:$port/health" | grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"'
fi
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
    identity_guard = getattr(config, '_enrollment_identity_guard', None)
    inventory = preflight_workers(config, plan, mode=mode) if mode == 'reconcile' else None
    names = [name for name,target in plan.targets.items() if target['owner'] == 'dc-worker']
    outcomes = {name:{'owner':'dc-worker','success':False,'state':'unknown','workers':{}} for name in names}
    ssh = SSHManager(config.config_dir)
    for server in config.servers:
        credentials = config.get_server_ssh_creds(server)
        options = {'host':server.server_ip,'username':credentials.username,'port':credentials.port,
                   'key_path':credentials.key_path or config.ssh.key_path,'sudo':False,'selected_identity':True}
        try:
            if identity_guard:
                identity_guard()
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
                    delivery_mode = inventory[server.name][name]['delivery_mode'] if inventory else mode
                    result['desired'] = artifact_identity(target)
                    _preflight_worker_privilege(ssh, options, [name], mode=delivery_mode, identity_guard=identity_guard)
                    if inventory:
                        repeat = _observe_worker_components(ssh, options, {name:target}, identity_guard=identity_guard)
                        if repeat[name] != delivery_mode:
                            raise ValueError('worker presence changed after preflight')
                    if delivery_mode == 'noop':
                        result = {'owner':'dc-worker','success':True,'state':'verified','action':'noop',
                                  'desired':target['sha256'],'observed':target['sha256'],
                                  'observed_binary_sha256':inventory[server.name][name]['observed_binary_sha256'],
                                  'service_state':inventory[server.name][name]['service_state'],
                                  'release':target['release']}
                        outcomes[name]['workers'][server.name] = result
                        continue
                    if name == 'dc-exporter':
                        script = build_dc_exporter_install_script(mode=delivery_mode, selected_artifact=target)
                    elif name == 'node-exporter':
                        script = build_node_exporter_install_script(selected_artifact=target, mode=delivery_mode)
                    elif name == 'dc-watchdog-agent':
                        from .web_watchdog import get_site_id, install_watchdog_agent_remote
                        host = SimpleNamespace(name=server.name, server_ip=server.server_ip, ssh_user=credentials.username,
                                               ssh_port=credentials.port, ssh_password=credentials.password,
                                               ssh_known_hosts_path=str(ssh.known_hosts_path),
                                               ssh_key=SimpleNamespace(key_path=str(credentials.key_path or config.ssh.key_path or ssh.key_path)),
                                               _selected_ssh_key_strict=True,
                                               _selected_effective_key_path=str(credentials.key_path or config.ssh.key_path or ssh.key_path))
                        settings = {}
                        if delivery_mode == 'install':
                            settings = {
                                'site_id': get_site_id({'ssl': {'domain': config.ssl.domain},
                                                        'master_ip': config.master_ip or 'default'}),
                                'heartbeat_interval': config.watchdog.ping_interval,
                                'use_mtr': config.watchdog.agent_use_mtr,
                            }
                        if identity_guard:
                            identity_guard()
                        success, error = install_watchdog_agent_remote(host, config.watchdog.api_key or '',
                                                                       selected_artifact=target, watchdog_url=config.watchdog.server_url,
                                                                       mode=delivery_mode, **settings)
                        if not success:
                            raise RuntimeError('worker agent installation failed')
                        script = None
                    else:
                        raise ValueError('unsupported worker owner')
                    if script is not None:
                        command = build_dc_exporter_remote_command(script, sudo=credentials.username != 'root')
                        if identity_guard:
                            identity_guard()
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
                    if identity_guard:
                        identity_guard()
                    observed = ssh.run_command(command=probe, timeout=30, **options)
                    digest = re.search(r'^WORKER_ARTIFACT=([0-9a-f]{64})$', observed.output, re.M)
                    state = re.search(r'^WORKER_SERVICE=(active|inactive)$', observed.output, re.M)
                    health = name != 'dc-watchdog-agent' or 'WORKER_HEALTH=verified' in observed.output.splitlines()
                    if not observed.success or not digest or digest.group(1) != expected_binary or not state or not health:
                        raise RuntimeError('worker artifact/service probe did not verify')
                    if delivery_mode == 'install' and state.group(1) != 'active':
                        raise RuntimeError('new worker service is not active after installation')
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


def _api_json(client, method, base_url, path, **kwargs):
    import requests
    try:
        response = client.request(method, base_url.rstrip('/') + '/dc/api/' + path,
                                  timeout=30, allow_redirects=False, **kwargs)
        value = response.json()
    except (requests.RequestException, ValueError):
        raise RuntimeError('Fleet inventory response is unconfirmed; retain registered identity and retry') from None
    if response.status_code != 200:
        if response.status_code == 409:
            raise RuntimeError('Fleet worker identity or SSH authority changed/conflicts; current identity retained')
        if response.status_code >= 500:
            raise RuntimeError('Fleet observations/discovery remain unconfirmed; registered identity and committed observations retained. Retry enrollment.')
        raise RuntimeError('Fleet inventory access failed; current authorized login is required')
    return value


def _matching_worker(rows, server):
    if not isinstance(rows, list) or any(not isinstance(row, dict)
            or type(row.get('id')) is not int or row['id'] <= 0
            or not isinstance(row.get('name'), str) or not row['name']
            or not isinstance(row.get('server_ip'), str) or not row['server_ip'] for row in rows):
        raise ValueError('Fleet inventory readback is malformed')
    matches = [row for row in rows if row.get('name') == server.name or row.get('server_ip') == server.server_ip]
    if not matches:
        return None
    if (len(matches) != 1 or matches[0].get('name') != server.name
            or matches[0].get('server_ip') != server.server_ip
            or type(matches[0].get('id')) is not int or matches[0]['id'] <= 0
            or matches[0].get('bmc_ip') != server.bmc_ip):
        raise ValueError('Fleet worker identity conflict; no identity will be replaced')
    return matches[0]


def _identity_query(identity=None):
    from urllib.parse import urlencode
    import json
    values = {'selected_enrollment':'1'}
    if identity is not None:
        values['expected_identity'] = json.dumps(identity, sort_keys=True, separators=(',', ':'))
    return '?' + urlencode(values)


def _revalidate_worker(client, server, registered, *, base_url):
    identity = registered['enrollment_identity']
    authority = _api_json(client, 'GET', base_url,
                          f"servers/{registered['id']}/ssh-config" + _identity_query(identity))
    if authority.get('enrollment_identity') != identity:
        raise ValueError('Fleet worker SSH identity changed; current inventory retained')


def register_worker(client, server, config, *, base_url, ssh_key_id=None):
    """Use the public server owner; exact readback resolves 409/lost 201."""
    import requests
    rows = _api_json(client, 'GET', base_url, 'servers')
    registered = _matching_worker(rows, server)
    credentials = config.get_server_ssh_creds(server)
    if registered is None:
        payload = {'name':server.name, 'server_ip':server.server_ip,
                   'ssh_user':credentials.username, 'ssh_port':credentials.port}
        if ssh_key_id is not None:
            payload['ssh_key_id'] = ssh_key_id
        try:
            response = client.request('POST', base_url.rstrip('/') + '/dc/api/servers',
                                      json=payload, timeout=30, allow_redirects=False)
            if response.status_code not in (201, 409):
                raise RuntimeError('Fleet rejected worker registration; no worker installation attempted')
        except requests.RequestException:
            # The owner may have committed before the transport failed.
            pass
        registered = _matching_worker(_api_json(client, 'GET', base_url, 'servers'), server)
        if registered is None:
            raise RuntimeError('Fleet worker registration is unconfirmed; retry enrollment without deleting inventory')
    authority = _api_json(client, 'GET', base_url, f"servers/{registered['id']}/ssh-config" + _identity_query())
    if (not isinstance(authority, dict) or authority.get('ssh_user') != credentials.username
            or authority.get('ssh_port') != credentials.port
            or (ssh_key_id is not None and authority.get('ssh_key_id') != ssh_key_id)
            or authority.get('has_password') is not False):
        raise ValueError('Fleet worker SSH authority conflict; use the ordinary SSH configuration owner before retrying')
    if authority.get('auth_method') != 'key':
        raise ValueError('Fleet container SSH key authority is unavailable; provision the existing registered key and trust references before retrying')
    identity = authority.get('enrollment_identity')
    if (not isinstance(identity, dict) or identity.get('server_id') != registered['id']
            or identity.get('name') != server.name or identity.get('server_ip') != server.server_ip
            or not isinstance(identity.get('inventory_server_id'), str) or not identity['inventory_server_id']
            or identity.get('inventory_server_id') != registered.get('inventory_server_id')):
        raise ValueError('Fleet worker identity changed during registration; current inventory retained')
    registered['enrollment_identity'] = identity
    transport = _api_json(client, 'POST', base_url, f"servers/{registered['id']}/ssh-test" + _identity_query(identity))
    if (not isinstance(transport, dict) or transport.get('connected') is not True
            or transport.get('auth_method') != 'key' or transport.get('ssh_user') != credentials.username
            or transport.get('ssh_port') != credentials.port or transport.get('server_ip') != server.server_ip
            or transport.get('key_path') != identity.get('effective_key_path')
            or transport.get('enrollment_identity') != identity):
        raise ValueError('Fleet container SSH key/trust reachability could not be verified; registered worker retained')
    return registered


def _fleet_login(base_url, username, password, *, ca_file=None):
    """Authenticate through the existing HTTPS login using the operator's current password."""
    from urllib.parse import urlsplit
    import requests
    url = urlsplit(base_url)
    if (url.scheme != 'https' or not url.hostname or url.username or url.password
            or url.path not in ('', '/') or url.query or url.fragment):
        raise ValueError('Fleet URL must be an HTTPS origin')
    client = requests.Session()
    client.verify = str(ca_file) if ca_file else True
    try:
        page = client.get(base_url.rstrip('/') + '/auth/login', timeout=30, allow_redirects=False)
        if page.status_code != 200 or 'name="confirm_password"' in page.text:
            raise RuntimeError('Existing Fleet login is required; enrollment cannot create or reset an account')
        logged = client.post(base_url.rstrip('/') + '/auth/login',
                             data={'username':username,'password':password}, timeout=30, allow_redirects=False)
        if logged.status_code != 302 or logged.headers.get('Location') != '/':
            raise RuntimeError('Current Fleet login failed or password change is required')
        # This existing route requires a current administrator, not installer credentials.
        check = client.get(base_url.rstrip('/') + '/auth/api/users', timeout=30, allow_redirects=False)
        if check.status_code != 200 or not isinstance(check.json(), (dict, list)):
            raise RuntimeError('Current Fleet administrator authority is required')
    except (requests.RequestException, ValueError):
        client.close()
        raise RuntimeError('Current Fleet HTTPS login could not be verified') from None
    except RuntimeError:
        client.close()
        raise
    return client


def enroll_selected_worker(config, server, *, base_url, username, password, ca_file=None, ssh_key_id=None):
    """Enroll exactly one worker without running any controller deployment path."""
    import copy
    from .controller_adoption import ensure_mutation_allowed
    from .fleet_upgrade import (release_store, required_components, validate_configured_roles,
                                verify_running_cli, proxy_capabilities, _require_proxy_update_authority)
    ensure_mutation_allowed(config.config_dir)
    public = config.config_dir / 'fleet-config.yaml'
    expected = public.read_bytes()
    scoped = copy.copy(config)
    matching = [item for item in config.servers if item.name == server.name or item.server_ip == server.server_ip]
    if matching:
        if len(matching) != 1 or matching[0].name != server.name or matching[0].server_ip != server.server_ip:
            raise ValueError('configured worker identity conflict')
        current = matching[0]
        effective = config.get_server_ssh_creds(current)
        for field, actual in (('ssh_user', effective.username), ('ssh_port', effective.port), ('ssh_key_path', effective.key_path)):
            requested = getattr(server, field)
            if requested is not None and requested != actual:
                raise ValueError('configured worker SSH reference conflict')
        server = current
    scoped.ssh = copy.copy(config.ssh)
    scoped.ssh.auth_method = AuthMethod.KEY
    scoped.ssh.password = None
    scoped_server = copy.copy(server)
    scoped_server.ssh_password = None
    scoped.servers = [scoped_server]
    if not scoped.get_server_ssh_creds(server).key_path:
        # SSHManager's canonical fleet key is the existing reference, never generated here.
        scoped.ssh.key_path = str(config.config_dir / 'fleet_key')
    store = release_store(config)
    if (store.root / '.lifecycle-publication.json').exists():
        raise RuntimeError('release publication recovery is required before worker enrollment')
    _require_proxy_update_authority(proxy_capabilities())
    selected = config.release_selection
    if not selected.selection_id or not selected.selection_sha256:
        raise ValueError('existing exact selected release is required')
    plan = store.load(expected_id=selected.selection_id, expected_sha256=selected.selection_sha256,
                      required_components=required_components(scoped))
    validate_configured_roles(scoped, plan)
    verify_running_cli(plan.targets['dc-overview-cli'])
    worker_names = {name for name,value in plan.targets.items() if value['owner'] == 'dc-worker'}
    if not {'dc-exporter','node-exporter'} <= worker_names:
        raise ValueError('worker roles are disabled; explicitly enable worker_exporters and selected policies, then run ordinary upgrade before enrollment')
    selection_before = (store.root / 'selection.json').read_bytes()
    client = _fleet_login(base_url, username, password, ca_file=ca_file)
    try:
        # Lock covers CAS, API enrollment and delivery so ordinary lifecycle cannot change the vector.
        with config.lifecycle_lock():
            ensure_mutation_allowed(config.config_dir)
            if public.read_bytes() != expected or (store.root / 'selection.json').read_bytes() != selection_before:
                raise RuntimeError('configuration or release changed during worker enrollment')
            registered = register_worker(client, server, scoped, base_url=base_url, ssh_key_id=ssh_key_id)
            scoped._enrollment_identity_guard = lambda: _revalidate_worker(client, server, registered, base_url=base_url)
            scoped._enrollment_identity_guard()
            preflight_workers(scoped, plan, mode='reconcile')
            scoped._enrollment_identity_guard()
            config.persist_worker_entry(server, expected_public=expected, _locked=True)
            scoped._enrollment_identity_guard()
            outcomes = upgrade_workers(scoped, plan, mode='reconcile')
        success = bool(outcomes) and all(value.get('success') is True for value in outcomes.values())
        if success:
            # Existing owner derives installed/enabled fields from real live probes and reconciles discovery.
            scoped._enrollment_identity_guard()
            observed = _api_json(client, 'GET', base_url, f"servers/{registered['id']}/check" + _identity_query(registered['enrollment_identity']))
            if (not isinstance(observed, dict) or observed.get('server_id') != registered['id']
                    or observed.get('server_name') != server.name or observed.get('server_ip') != server.server_ip
                    or observed.get('enrollment_identity') != registered['enrollment_identity']):
                raise RuntimeError('installed worker inventory observations remain unconfirmed; retry enrollment')
            fields = {'node-exporter':'node_exporter', 'dc-exporter':'dc_exporter', 'dc-watchdog-agent':'watchdog_agent'}
            for name, outcome in outcomes.items():
                component = observed.get(fields[name])
                worker = outcome['workers'][server.name]
                if (not isinstance(component, dict) or component.get('installed') is not True
                        or component.get('running') is not (worker['service_state'] == 'active')):
                    raise RuntimeError('registered worker live observations disagree with selected delivery; retry enrollment')
        scoped._enrollment_identity_guard()
        return {'success':success, 'server_id':registered['id'], 'inventory':registered.get('inventory'),
                'components':outcomes, 'reason':None if success else 'worker registration retained; partial delivery is resumable'}
    finally:
        client.close()
