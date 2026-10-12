"""Use Fleet's durable updater from the host CLI without a second lifecycle owner."""
import json
import re
import subprocess
import time
import copy
import yaml

PROXY_REPLACEMENT_POLICY = 'host-adoption-required-v1'


def _require_proxy_update_authority(capabilities):
    if (not isinstance(capabilities, dict) or type(capabilities.get('selection_contract')) is not int
            or capabilities.get('selection_contract') != 1
            or capabilities.get('proxy_replacement_policy') != PROXY_REPLACEMENT_POLICY):
        raise RuntimeError('Proxy updater authority prerequisite: install the compatible published cryptolabs-proxy package, '
                           'then use cryptolabs-proxy configuration plan and cryptolabs-proxy configuration adopt '
                           'to migrate the existing proxy before retrying. The running updater must advertise '
                           'selection contract 1 and proxy_replacement_policy=host-adoption-required-v1; '
                           'no update was submitted or release changes applied.')


def _updater(*arguments, container='cryptolabs-proxy'):
    command = ['docker', 'exec', container, 'env', 'PYTHONPATH=/app/src',
               'python3', '-m', 'cryptolabs_proxy.updates', *arguments]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            value = json.loads(result.stdout)
            return value if isinstance(value, dict) else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        pass
    return None


def run_fleet_upgrade(branch, timeout=1800, *, selection_id=None, selection_sha256=None):
    if branch not in ('main', 'dev'):
        raise ValueError('Expected main or dev channel')
    arguments = ['submit', '--branch', branch, '--service', 'all', '--action', 'update']
    if selection_id is not None or selection_sha256 is not None:
        if branch != 'main' or not isinstance(selection_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}', selection_id) or not isinstance(selection_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', selection_sha256):
            raise ValueError('Explicit release selection requires main, a selection ID and exact hash')
        arguments.extend(['--selection-id', selection_id, '--selection-sha256', selection_sha256])
    _require_proxy_update_authority(proxy_capabilities())
    job = _updater(*arguments)
    job_id = job.get('id') if job else None
    if not isinstance(job_id, str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}', job_id):
        raise RuntimeError('Fleet updater unavailable. Install the current proxy updater before upgrading; no services were replaced by this CLI.')
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = _updater('status', job_id)
        if result and result.get('state') in ('completed', 'failed', 'interrupted', 'blocked'):
            return result
        time.sleep(2)
    raise RuntimeError(f'Fleet update {job_id} is still unconfirmed. Check its status in Fleet before retrying.')


def release_store(config):
    from .release_catalog import ReleaseStore
    return ReleaseStore(config.release_selection.release_selection_dir or config.config_dir/'releases')


def required_components(config):
    required = {'cryptolabs-proxy', 'dc-overview-cli'}
    if config.components.dc_overview:
        required.update({'dc-overview', 'prometheus', 'grafana'})
    for flag, name in [('ipmi_monitor','ipmi-monitor'), ('vast_exporter','vastai-exporter'),
                       ('runpod_exporter','runpod-exporter'), ('vast_price_manager','vast-price-manager')]:
        if getattr(config.components, flag):
            required.add(name)
    if config.servers:
        required.update({'node-exporter', 'dc-exporter'})
    if config.components.dc_watchdog and config.watchdog.install_agent:
        required.add('dc-watchdog-agent')
    return required


def validate_configured_roles(config, plan):
    enabled = required_components(config)
    conflicts = set(plan.targets) - enabled
    if conflicts:
        raise ValueError('selection enables intentionally disabled configured components: ' + ', '.join(sorted(conflicts)))


def _container_absent(inspected, name):
    """Only a complete named-container diagnostic proves runtime absence."""
    return (inspected.returncode == 1 and isinstance(inspected.stdout, str)
            and inspected.stdout.strip() in {'', '[]'}
            and isinstance(inspected.stderr, str)
            and re.fullmatch(r'(?:error(?::| response from daemon:)\s*)?no such (?:object|container): '
                             + re.escape(name), inspected.stderr.strip(), flags=re.IGNORECASE) is not None)


def proxy_capabilities(*, fresh_setup=False, container_id=None):
    if container_id is not None:
        if not isinstance(container_id, str) or not re.fullmatch(r'[0-9a-f]{64}', container_id):
            raise RuntimeError('live proxy container identity unavailable')
        return _updater('capabilities', container=container_id)
    if fresh_setup:
        try:
            inspected = subprocess.run(['docker','container','inspect','cryptolabs-proxy','--format','{{json .State}}'],
                                       capture_output=True, text=True, timeout=15)
        except FileNotFoundError:
            raise RuntimeError('Docker prerequisite: install and verify Docker Engine and Compose from official upstream before approved selected setup; proxy runtime absence is unproven.') from None
        except (OSError, subprocess.TimeoutExpired):
            return None
        if inspected.returncode == 0:
            # Repeat setup must prove the live runtime; a new host wheel cannot
            # retroactively repair its old updater or source-image helper.
            return _updater('capabilities')
        # Docker CLI/daemon absence diagnostics differ in capitalization/prefix.
        # Only a complete named-container absence can authorize host fallback;
        # denied/unknown errors and conflicting output cannot prove fresh state.
        if not _container_absent(inspected, 'cryptolabs-proxy'):
            return None
        try:
            from cryptolabs_proxy.updates import get_capabilities
            return get_capabilities()
        except (ImportError, AttributeError, OSError, RuntimeError, TypeError, ValueError):
            return None
    return _updater('capabilities')


def verify_running_cli(target):
    """Require the exact installed wheel; never replace this running process."""
    from importlib.metadata import distribution, PackageNotFoundError
    from . import __version__
    try:
        installed = distribution('dc-overview')
        provenance = json.loads(installed.read_text('direct_url.json') or '{}')
        hashes = provenance.get('archive_info', {}).get('hashes', {})
        verified = (__version__ == target['release'] and installed.version == target['release']
                    and provenance.get('url') == target['url'] and hashes.get('sha256') == target['sha256'])
    except (PackageNotFoundError, ValueError, TypeError, KeyError):
        verified = False
    if not verified:
        raise RuntimeError('requires_cli_upgrade: install the verified exact wheel from the selected manifest using the documented package-manager step, then rerun this command')
    return {'success':True, 'state':'verified', 'owner':'host-cli',
            'desired':target['url']+'#sha256='+target['sha256'],
            'observed':target['url']+'#sha256='+target['sha256']}


def load_release(config, *, platform=None):
    store = release_store(config)
    if (store.root / '.lifecycle-publication.json').exists():
        with config.lifecycle_lock():
            store.recover_publication(config.config_dir / 'fleet-config.yaml')
    selected = config.release_selection
    if not selected.selection_id and not selected.selection_sha256 and not (store.root/'selection.json').exists():
        return None
    if bool(selected.selection_id) != bool(selected.selection_sha256):
        raise ValueError('selection ID and hash must be supplied together')
    plan = store.load(platform=platform, expected_id=selected.selection_id,
                      expected_sha256=selected.selection_sha256, required_components=required_components(config))
    validate_configured_roles(config, plan)
    return plan


def adopt_existing_policies(config, manifest, policies):
    """Unlabelled installed images require a customer pin before baseline adoption."""
    result = dict(policies)
    for name, component in manifest.data['components'].items():
        if name in result or component['owner'] != 'proxy-updater':
            continue
        try:
            inspected = subprocess.run(['docker','container','inspect',name,'--format','{{json .}}'], capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError('existing component ownership inventory is unavailable') from None
        if inspected.returncode != 0:
            if _container_absent(inspected, name):
                continue
            raise RuntimeError('existing component ownership inventory is unavailable')
        try:
            value = json.loads(inspected.stdout)
            installed = value['Config']['Image']
            labels = value['Config'].get('Labels') or {}
            if labels.get('io.cryptolabs.update.origin') == 'baseline':
                continue
            if '@sha256:' not in installed:
                image = subprocess.run(['docker','image','inspect',value['Image'],'--format','{{json .RepoDigests}}'], capture_output=True, text=True, timeout=15)
                candidates = json.loads(image.stdout) if image.returncode == 0 else []
                repository = next(iter(component['artifacts'].values()))['reference'].split('@')[0]
                matches = [reference for reference in candidates if reference.startswith(repository+'@sha256:')]
                if len(matches) != 1:
                    raise ValueError('immutable installed image is ambiguous')
                installed = matches[0]
            result[name] = {'origin':'customer-pin','enabled':name in required_components(config),'pin':installed}
        except (KeyError, TypeError, ValueError, OSError, subprocess.TimeoutExpired):
            raise RuntimeError('installed component identity needs explicit customer pin/adoption policy') from None
    return result


def preflight_release(config, manifest_path=None, *, platform=None, fresh_setup=False):
    """Read/validate policy and consumer prerequisites before the first write."""
    from .controller_adoption import ensure_mutation_allowed
    ensure_mutation_allowed(config.config_dir, setup=fresh_setup)
    store = release_store(config)
    public_path = config.config_dir / 'fleet-config.yaml'
    config._lifecycle_public_snapshot = public_path.read_bytes() if public_path.exists() else b''
    selection_path = store.root / 'selection.json'
    config._lifecycle_selection_snapshot = selection_path.read_bytes() if selection_path.exists() else None
    if manifest_path is None:
        selected = config.release_selection
        if (fresh_setup and not selected.selection_id and not selected.selection_sha256
                and not selection_path.exists() and not (store.root / '.lifecycle-publication.json').exists()):
            return None
        _require_proxy_update_authority(proxy_capabilities(fresh_setup=fresh_setup))
        plan = load_release(config, platform=platform)
        if plan is None:
            return None
    else:
        # Parse before probing consumers; preserve explicit customer configuration.
        from .release_catalog import Manifest
        from pathlib import Path
        manifest = Manifest.from_bytes(Path(manifest_path).read_bytes())
        _require_proxy_update_authority(proxy_capabilities(fresh_setup=fresh_setup))
        if 'dc-overview-cli' not in manifest.data['components']:
            raise RuntimeError('requires_cli_upgrade: release manifest is missing the approved host CLI wheel')
        policies = dict(config.release_selection.components)
        if not (store.root/'selection.json').exists():
            policies = adopt_existing_policies(config, manifest, policies)
        if config.components.vast_price_manager and config.vast_price_manager.image and 'vast-price-manager' not in policies:
            policies['vast-price-manager'] = {'origin':'customer-pin', 'enabled':True, 'pin':config.vast_price_manager.image}
        plan = store.prepare(manifest_path, platform=platform, policies=policies,
                             required_components=required_components(config), enabled_components=required_components(config))
    _require_proxy_update_authority(proxy_capabilities(fresh_setup=fresh_setup))
    if 'dc-overview-cli' not in plan.targets:
        raise RuntimeError('requires_cli_upgrade: the manifest must provide the enabled host CLI wheel')
    validate_configured_roles(config, plan)
    verify_running_cli(plan.targets['dc-overview-cli'])
    if not fresh_setup:
        result = subprocess.run(['docker','inspect','cryptolabs-proxy','--format','{{json .Mounts}}'],
                                capture_output=True, text=True, timeout=15)
        try:
            mounts = json.loads(result.stdout) if result.returncode == 0 else []
            wired = any(m.get('Source') == str(store.root) and m.get('Destination') == '/etc/cryptolabs/releases' and m.get('RW') is False for m in mounts)
        except (ValueError, TypeError):
            wired = False
        if not wired:
            raise RuntimeError('proxy release mount prerequisite: repeat supported setup before selecting/upgrading this baseline')
    if 'vast-price-manager' in plan.targets:
        vpm_spec(config, plan.targets['vast-price-manager'])
        if config.vast_price_manager.layout:
            from .vpm_service import VPMLayout
            VPMLayout(**config.vast_price_manager.layout)
    if config.components.dc_overview and not getattr(config, '_controller_preservation_hold', False):
        from .fleet_manager import FleetManager
        manager = FleetManager(config)
        manager.release_plan = plan
        # Construction must succeed before durable selection/controller writes.
        # Rendering may describe a fresh secret mount without creating custody.
        manager._render_only = True
        manager._generate_docker_compose()
        prepared_monitoring = manager._prepare_baseline_monitoring()
        if not manager._validate_baseline_prometheus(prepared_monitoring['prometheus']):
            raise RuntimeError('selected Prometheus validation failed before release selection writes')
    if any(target['owner'] == 'dc-worker' for target in plan.targets.values()):
        from .worker_lifecycle import preflight_workers
        preflight_workers(config, plan, mode='install' if fresh_setup else 'update')
    return plan


def commit_release(config, plan):
    from .controller_adoption import ensure_mutation_allowed
    ensure_mutation_allowed(config.config_dir)
    public_path = config.config_dir / 'fleet-config.yaml'
    previous = getattr(config, '_lifecycle_public_snapshot', public_path.read_bytes() if public_path.exists() else b'')
    with config.lifecycle_lock():
        store = release_store(config)
        store.recover_publication(public_path)
        if (public_path.read_bytes() if public_path.exists() else b'') != previous:
            raise RuntimeError('public configuration changed after release preflight')
        selection_path = store.root / 'selection.json'
        current = selection_path.read_bytes() if selection_path.exists() else None
        if current != getattr(config, '_lifecycle_selection_snapshot', current):
            raise RuntimeError('release selection changed after preflight')
        store.begin_publication(plan, previous)
        prior_reference = copy.deepcopy(config.release_selection)
        try:
            store.commit(plan)
            config.release_selection.selection_id = plan.selection['selection_id']
            config.release_selection.selection_sha256 = plan.selection_sha256
            config.release_selection.components = plan.selection['components']
            config.persist_lifecycle(expected_public=previous, _locked=True)
            if (selection_path.read_bytes() != plan.selection_raw or
                    yaml.safe_load(public_path.read_bytes())['release_selection']['selection_sha256'] != plan.selection_sha256):
                raise RuntimeError('release publication changed during transaction; reconcile before retry')
            store.finish_publication()
            config._lifecycle_public_snapshot = public_path.read_bytes()
            config._lifecycle_selection_snapshot = plan.selection_raw
        except BaseException:
            store.recover_publication(public_path)
            if (selection_path.read_bytes() if selection_path.exists() else None) == current:
                config.release_selection = prior_reference
            raise


def vpm_spec(config, target):
    from .vpm_service import VPMServiceSpec
    value = config.vast_price_manager
    return VPMServiceSpec(image=target['reference'], allowed_host=config.ssl.domain or '',
                          master_key_file=value.master_key_file, expected_account_id=value.expected_account_id,
                          writes_enabled=value.writes_enabled, data_source=value.data_source, data_kind=value.data_kind,
                          credential_mode=value.credential_mode, credential_reference=value.credential_reference,
                          database_relative_path=value.database_relative_path)


def dispatch_vpm(config, target, *, setup=False):
    from .vpm_service import VPMServiceManager, VPMLayout
    manager = VPMServiceManager(config.config_dir)
    desired = target['reference']
    public_path = config.config_dir / 'fleet-config.yaml'
    original_public = public_path.read_bytes() if public_path.exists() else b''
    try:
        spec = vpm_spec(config, target)
        adopted_layout = None
        if config.vast_price_manager.layout:
            adopted_layout = VPMLayout(**config.vast_price_manager.layout)
            if manager.is_adopted(adopted_layout) is True:
                spec = manager.adopted_spec(spec, adopted_layout)
                with manager.operation_lock():
                    manager.install(spec)
            else:
                proof = manager.adopt(spec, adopted_layout)
                if proof.get('status') not in ('adopted', 'already-adopted') or proof.get('state_preserved') is not True:
                    raise RuntimeError('VPM adoption did not produce continuity proof')
                spec = manager.adopted_spec(spec, adopted_layout)
        else:
            with manager.operation_lock():
                if not setup and manager.current_managed_image() is None:
                    raise RuntimeError('required VPM is not installed; use supported setup before upgrade')
                manager.install(spec, promote_route=manager.enable_proxy_route) if setup else manager.install(spec)
        observed = manager.current_managed_image()
        if observed != desired:
            raise RuntimeError('VPM image identity remains unverified')
        if adopted_layout is not None:
            value = config.vast_price_manager
            for field in ('data_source', 'data_kind', 'master_key_file', 'credential_mode', 'credential_reference', 'database_relative_path'):
                setattr(value, field, getattr(spec, field))
            value.image = desired
            value.layout = None
            config.persist_lifecycle(expected_public=original_public)
        return {'success':True, 'state':'verified', 'owner':'dc-vpm', 'desired':desired, 'observed':observed}
    except (ValueError, RuntimeError, OSError, TypeError):
        return {'success':False, 'state':'failed', 'owner':'dc-vpm', 'desired':desired,
                'observed':None, 'reason':'VPM update/adoption did not verify; inspect the manager recovery evidence'}


def run_selected_upgrade(config, plan, *, timeout=1800):
    from .controller_adoption import ensure_mutation_allowed
    ensure_mutation_allowed(config.config_dir)
    from .worker_lifecycle import preflight_workers
    preflight_workers(config, plan)
    job = run_fleet_upgrade('main', timeout=timeout, selection_id=plan.selection['selection_id'], selection_sha256=plan.selection_sha256)
    proxy = {}
    external = {}
    for name, target in plan.targets.items():
        if target['owner'] == 'proxy-updater':
            proxy[name] = job.get('results', {}).get(name, {'success':False,'state':'unknown','reason':'required proxy result missing'})
    ready = bool(job.get('success')) and all(value.get('success') is True for value in proxy.values())
    workers = {name:target for name,target in plan.targets.items() if target['owner'] == 'dc-worker'}
    for name, target in plan.targets.items():
        if target['owner'] == 'host-cli':
            external[name] = verify_running_cli(target)
        elif target['owner'] == 'dc-vpm':
            external[name] = dispatch_vpm(config, target) if ready else {'success':False,'state':'blocked','owner':'dc-vpm','reason':'proxy roles did not verify'}
    if workers:
        from .worker_lifecycle import upgrade_workers
        outcomes = upgrade_workers(config, plan) if ready else {name:{'success':False,'state':'blocked','owner':'dc-worker','reason':'proxy roles did not verify'} for name in workers}
        external.update(outcomes)
    complete = ready and all(value.get('success') is True for value in external.values())
    return {**job, 'scope':'suite', 'success':complete, 'suite_complete':complete,
            'selection_id':plan.selection['selection_id'], 'selection_sha256':plan.selection_sha256,
            'manifest_sha256':plan.manifest.sha256, 'results':proxy, 'external_owners':external}


def observe_component(name, target):
    """Report runtime identity independently from desired selection."""
    if target['owner'] == 'host-cli':
        try:
            result = verify_running_cli(target)
            return {'identity':target['sha256'], 'state':'verified', 'matches':result['success']}
        except RuntimeError:
            return {'identity':None, 'state':'requires_cli_upgrade', 'matches':False}
    if target['owner'] not in ('proxy-updater', 'dc-vpm'):
        return {'identity':None, 'state':'unknown', 'matches':None}
    try:
        result = subprocess.run(['docker', 'inspect', name, '--format', '{{json .}}'], capture_output=True, text=True, timeout=15)
        value = json.loads(result.stdout) if result.returncode == 0 else {}
        identity = value.get('Config', {}).get('Image')
        running = value.get('State', {}).get('Running')
        return {'identity':identity, 'state':'running' if running is True else 'stopped' if running is False else 'unknown',
                'matches':identity == target['reference'] if identity else None}
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        return {'identity':None, 'state':'unknown', 'matches':None}
