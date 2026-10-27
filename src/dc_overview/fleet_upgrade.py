# TRACEWEAVER: file-role=release-owner; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
"""Use Fleet's durable updater from the host CLI without a second lifecycle owner."""
import json
import re
import subprocess
import time
import copy
import yaml
import os
from contextlib import contextmanager, nullcontext
from pathlib import Path

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
    if config.servers or config.components.worker_exporters:
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


def commit_release(config, plan, *, selection_only=False, precommit=None, _locked=False):
    from .controller_adoption import ensure_mutation_allowed
    ensure_mutation_allowed(config.config_dir)
    public_path = config.config_dir / 'fleet-config.yaml'
    previous = getattr(config, '_lifecycle_public_snapshot', public_path.read_bytes() if public_path.exists() else b'')
    with nullcontext() if _locked else config.lifecycle_lock():
        store = release_store(config)
        store.recover_publication(public_path)
        if (public_path.read_bytes() if public_path.exists() else b'') != previous:
            raise RuntimeError('public configuration changed after release preflight')
        selection_path = store.root / 'selection.json'
        current = selection_path.read_bytes() if selection_path.exists() else None
        if current != getattr(config, '_lifecycle_selection_snapshot', current):
            raise RuntimeError('release selection changed after preflight')
        if precommit is not None:
            precommit()
            if (public_path.read_bytes() if public_path.exists() else b'') != previous:
                raise RuntimeError('public configuration changed after release preflight')
            if (selection_path.read_bytes() if selection_path.exists() else None) != current:
                raise RuntimeError('release selection changed after preflight')
        store.begin_publication(plan, previous, operation_id=getattr(config, '_release_operation_id', None))
        prior_reference = copy.deepcopy(config.release_selection)
        try:
            store.commit(plan)
            config.release_selection.selection_id = plan.selection['selection_id']
            config.release_selection.selection_sha256 = plan.selection_sha256
            config.release_selection.components = plan.selection['components']
            if selection_only:
                config.persist_lifecycle(expected_public=previous, _locked=True, selection_only=True)
            else:
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



def _scoped_inspect(identity):
    """Bounded read-only Engine inventory, never a lifecycle operation."""
    try:
        result = subprocess.run(['docker', 'inspect', identity, '--format', '{{json .}}'],
                                capture_output=True, text=True, timeout=15)
        value = json.loads(result.stdout) if result.returncode == 0 else None
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
        raise RuntimeError('scoped selection requires available installed container/image identity') from None


def _scoped_updater_directory(proxy):
    """Resolve the actual updater store on a local Engine; no helper or job."""
    import platform
    if platform.system() != 'Linux':
        raise RuntimeError('scoped selection requires the local Linux Docker Engine host')
    result = subprocess.run(['docker', 'context', 'inspect', '--format', '{{json .Endpoints.docker.Host}}'],
                            capture_output=True, text=True, timeout=15)
    try:
        endpoint = json.loads(result.stdout)
        if not os.environ.get('DOCKER_CONTEXT'):
            endpoint = os.environ.get('DOCKER_HOST') or endpoint
        if result.returncode or endpoint not in ('unix:///var/run/docker.sock', 'unix:///run/docker.sock'):
            raise ValueError()
        from cryptolabs_proxy.updates import JOBS_DIR, get_capabilities
        _require_proxy_update_authority(get_capabilities())
        relative = Path(JOBS_DIR).relative_to('/data/auth')
        if relative != Path('update-jobs'):
            raise ValueError()
        mounts = [m for m in proxy['Mounts'] if m.get('Destination') == '/data/auth' and m.get('RW') is True]
        if len(mounts) != 1 or mounts[0].get('Type') not in ('bind', 'volume'):
            raise ValueError()
        source = Path(mounts[0]['Source'])
        if not source.is_absolute() or not source.is_dir():
            raise ValueError()
        return source / relative
    except (ImportError, KeyError, TypeError, ValueError):
        raise RuntimeError('scoped selection requires the compatible host proxy package and local writable updater mount') from None


def _scoped_private(path, *, directory=False):
    """Reject links, shared records and writable/foreign updater custody."""
    import stat
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise PermissionError('unsafe scoped updater custody')
    info = path.lstat()
    if (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1)):
        raise PermissionError('unsafe scoped updater custody')
    return info


def _scoped_idle(directory):
    """Read records directly: status polling may mutate interrupted jobs."""
    from .release_catalog import _json
    _scoped_private(directory, directory=True)
    if os.path.lexists(directory / 'controller-adoption.json'):
        raise RuntimeError('controller recovery required before scoped selection')
    active = directory / 'active.json'
    if os.path.lexists(active):
        _scoped_private(active)
        value = _json(active.read_bytes())
        job_id = value.get('id')
        if not isinstance(job_id, str) or not re.fullmatch('[0-9a-f]{32}', job_id):
            raise RuntimeError('updater active record is invalid')
        path = directory / (job_id + '.json')
        _scoped_private(path)
        job = _json(path.read_bytes())
        if (job.get('id') != job_id or job.get('state') not in ('completed', 'failed', 'blocked')
                or any(r.get('state') == 'recovery_required' for r in job.get('results', {}).values())):
            raise RuntimeError('updater active/recovery work must finish before scoped selection')


@contextmanager
def _scoped_updater_guard(directory):
    """Hold the same inodes/order as dispatch and worker execution; fail busy."""
    import fcntl
    _scoped_private(directory, directory=True)
    descriptors = []
    try:
        for name in ('dispatch.lock', 'operation.lock'):
            path = directory / name
            before = _scoped_private(path)
            descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            descriptors.append((path, descriptor, before))
            actual = os.fstat(descriptor)
            if (before.st_dev, before.st_ino) != (actual.st_dev, actual.st_ino):
                raise RuntimeError('updater custody changed during scoped selection')
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('updater is busy; retry scoped selection after it finishes') from None
        def check():
            for path, descriptor, before in descriptors:
                actual = _scoped_private(path)
                if (before.st_dev, before.st_ino) != (actual.st_dev, actual.st_ino):
                    raise RuntimeError('updater lock changed during scoped selection')
            _scoped_idle(directory)
        check()
        yield check
    finally:
        for path, descriptor, before in reversed(descriptors):
            os.close(descriptor)


def _scoped_proxy(config, proxy_id=None):
    proxy = _scoped_inspect('cryptolabs-proxy')
    if (not isinstance(proxy.get('Id'), str) or not re.fullmatch('[0-9a-f]{64}', proxy['Id'])
            or proxy.get('State', {}).get('Running') is not True):
        raise RuntimeError('running proxy identity is required for scoped selection')
    if proxy_id is not None and proxy['Id'] != proxy_id:
        raise RuntimeError('proxy changed during scoped selection')
    _require_proxy_update_authority(proxy_capabilities(container_id=proxy['Id']))
    root = release_store(config).root
    if not any(m.get('Source') == str(root) and m.get('Destination') == '/etc/cryptolabs/releases'
               and m.get('RW') is False for m in proxy.get('Mounts', [])):
        raise RuntimeError('proxy read-only release mount prerequisite')
    return proxy


def _scoped_runtime(config, plan, components, source_images, proxy_id=None):
    """Observe exact source identities without inventing registry provenance."""
    proxy = _scoped_proxy(config, proxy_id)
    from .release_catalog import COMPONENTS
    identities, local_only = {}, {}
    for name in components:
        live = proxy if name == 'cryptolabs-proxy' else _scoped_inspect(name)
        if (not isinstance(live.get('Id'), str) or not re.fullmatch('[0-9a-f]{64}', live['Id'])
                or live.get('State', {}).get('Running') is not True):
            raise RuntimeError('scoped component must already be installed and running: ' + name)
        image_id = live.get('Image', '')
        if not isinstance(image_id, str) or not re.fullmatch('sha256:[0-9a-f]{64}', image_id):
            raise RuntimeError('scoped component image identity unavailable: ' + name)
        if name in source_images and source_images[name] != image_id:
            raise RuntimeError('explicit scoped source image does not match: ' + name)
        image = _scoped_inspect(image_id)
        platform = image.get('Os', '') + '/' + image.get('Architecture', '')
        repository = COMPONENTS[name][1]
        references = image.get('RepoDigests', [])
        if image.get('Id') != image_id or platform != plan.platform or not isinstance(references, list):
            raise RuntimeError('scoped component immutable platform identity unavailable: ' + name)
        registry_known = any(isinstance(ref, str) and re.fullmatch(re.escape(repository) + '@sha256:[0-9a-f]{64}', ref) for ref in references)
        if not registry_known:
            if references or source_images.get(name) != image_id:
                raise RuntimeError('scoped component immutable platform identity unavailable: ' + name)
            local_only[name] = image_id
        identities[name] = (live['Id'], image_id)
    return proxy, identities, local_only


# TRACEWEAVER: entrypoint=select_release_components; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
def select_release_components(config, manifest_path, components, *, record_cli=False,
                              adopt_existing_selection=False, source_images=(), platform=None,
                              expected_selection_id=None, expected_selection_sha256=None, operation_id=None):
    """Select explicit installed roles, preserving all other roles and intent."""
    from .controller_adoption import ensure_mutation_allowed
    from .release_catalog import COMPONENTS, Manifest, artifact_identity, _require_root
    _require_root()
    components = tuple(components)
    if (not components or len(set(components)) != len(components)
            or any(name not in COMPONENTS or COMPONENTS[name][0] != 'proxy-updater' for name in components)):
        raise ValueError('scoped selection requires explicit unique proxy-updater components')
    expected_sources = {}
    for entry in source_images:
        if not isinstance(entry, str) or '=' not in entry:
            raise ValueError('--source-image requires COMPONENT=sha256:IMAGE_ID')
        name, image_id = entry.split('=', 1)
        if name not in components or name in expected_sources or not re.fullmatch('sha256:[0-9a-f]{64}', image_id):
            raise ValueError('--source-image requires a unique scoped component and exact local image ID')
        expected_sources[name] = image_id
    ensure_mutation_allowed(config.config_dir)
    store = release_store(config)
    public_path = config.config_dir / 'fleet-config.yaml'
    public = public_path.read_bytes()
    values = yaml.safe_load(public)
    if not isinstance(values, dict):
        raise ValueError('public configuration must be a mapping')
    selected = config.release_selection
    adopting = 'release_selection' not in values
    if adopting:
        if (not adopt_existing_selection or selected.selection_id or selected.selection_sha256 or selected.components
                or store.root != config.config_dir / 'releases'):
            raise ValueError('existing selected store requires --adopt-existing-selection for an absent public reference')
    else:
        reference = values['release_selection']
        if (not isinstance(reference, dict) or not reference.get('selection_id') or not reference.get('selection_sha256')
                or not isinstance(reference.get('components'), dict)):
            raise ValueError('partial/conflicting public selection reference cannot be adopted')
        if (reference.get('selection_id') != selected.selection_id
                or reference.get('selection_sha256') != selected.selection_sha256
                or reference.get('components') != selected.components):
            raise RuntimeError('public configuration/selection snapshot is stale')
    # Resolve actual mounted updater custody read-only before any journal write.
    proxy = _scoped_proxy(config)
    directory = _scoped_updater_directory(proxy)
    # Match controller adoption order: lifecycle exclusion, then updater locks.
    with config.lifecycle_lock():
        with _scoped_updater_guard(directory) as check_idle:
            ensure_mutation_allowed(config.config_dir)
            if public_path.read_bytes() != public:
                raise RuntimeError('public configuration changed after release preflight')
            current_proxy = _scoped_proxy(config, proxy['Id'])
            if _scoped_updater_directory(current_proxy) != directory:
                raise RuntimeError('updater mount changed during scoped selection')
            check_idle()
            store.recover_publication(public_path)
            previous = store.load(platform=platform,
                                  expected_id=None if adopting else selected.selection_id,
                                  expected_sha256=None if adopting else selected.selection_sha256)
            if ((expected_selection_id is not None and previous.selection['selection_id'] != expected_selection_id)
                    or (expected_selection_sha256 is not None and previous.selection_sha256 != expected_selection_sha256)):
                raise RuntimeError('selection changed after release preview')
            if not adopting and selected.components != previous.selection['components']:
                raise RuntimeError('public configuration/selection snapshot is stale')
            manifest = Manifest.from_bytes(Path(manifest_path).read_bytes())
            if manifest.data['selection_contract'] == 2:
                from cryptolabs_proxy.updates import get_capabilities
                for capability in (get_capabilities(), proxy_capabilities(container_id=current_proxy['Id'])):
                    if 2 not in capability.get('supported_selection_contracts', []):
                        raise RuntimeError('installed and live owner selection contract 2 required')
            old = previous.manifest.data['components']; new = manifest.data['components']
            before_channels = previous.manifest.data.get('component_channels', {})
            after_channels = manifest.data.get('component_channels', {})
            if any(before_channels.get(name) != after_channels.get(name) for name in old if name not in components):
                raise ValueError('unscoped component channels must remain unchanged')
            if set(old) - set(new):
                raise ValueError('scoped selection cannot remove existing catalog roles')
            if 'dc-overview-cli' in new and 'dc-overview-cli' not in old and not record_cli:
                raise ValueError('new CLI selection record requires --record-cli')
            policy = copy.deepcopy(previous.selection['components'])
            changed = set(components) | ({'dc-overview-cli'} if record_cli else set())
            for name in components:
                if name not in previous.targets or name not in new:
                    raise ValueError('scoped target must already be selected and enabled: ' + name)
            for name in old:
                if old[name]['owner'] != new[name]['owner']:
                    raise ValueError('scoped selection cannot change lifecycle owners')
                if name not in changed and old[name] != new[name]:
                    raise ValueError('unscoped artifact identity/release must remain unchanged: ' + name)
            for name in set(new) - set(old):
                policy[name] = {'origin': 'baseline', 'enabled': False}
            cli_target = None
            if 'dc-overview-cli' in new:
                item = new['dc-overview-cli']
                cli_target = {**item['artifacts']['any'], 'release': item['release'], 'owner': item['owner']}
                verify_running_cli(cli_target)
            elif record_cli:
                raise ValueError('--record-cli requires the exact installed CLI wheel in the manifest')
            for name in changed:
                if name not in new:
                    raise ValueError('explicit scoped target missing from manifest: ' + name)
                if name in policy and policy[name]['origin'] == 'customer-pin':
                    artifacts = new[name]['artifacts']
                    artifact = artifacts.get(previous.platform, artifacts.get('any'))
                    if artifact is None:
                        raise ValueError('missing scoped artifact platform')
                    policy[name]['pin'] = artifact_identity(artifact)
            plan = store.prepare(manifest_path, platform=previous.platform, policies=policy, enabled_components=())
            if plan.manifest.raw != manifest.raw:
                raise RuntimeError('manifest changed during scoped preparation')
            config._lifecycle_public_snapshot = public
            config._lifecycle_selection_snapshot = previous.selection_raw
            _, runtime, local_only = _scoped_runtime(config, plan, components, expected_sources, proxy['Id'])
            def precommit():
                ensure_mutation_allowed(config.config_dir)
                check_idle()
                current_proxy, current_runtime, current_local = _scoped_runtime(config, plan, components, expected_sources, proxy['Id'])
                if (_scoped_updater_directory(current_proxy) != directory or current_runtime != runtime
                        or current_local != local_only):
                    raise RuntimeError('scoped runtime changed during selection')
                if cli_target is not None:
                    verify_running_cli(cli_target)
            config._release_operation_id = operation_id
            commit_release(config, plan, selection_only=True, precommit=precommit, _locked=True)
    return {'state': 'pending-deployment', 'scope': list(components), 'tooling_recorded': bool(record_cli),
            'reference_adopted': adopting, 'local_only_sources': local_only,
            'suite_complete': False, 'selection_id': plan.selection['selection_id'],
            'selection_sha256': plan.selection_sha256, 'manifest_sha256': plan.manifest.sha256}

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
    if workers and not config.servers and config.components.worker_exporters:
        external.update({name:{'success':True, 'state':'not_applicable', 'owner':'dc-worker',
                               'reason':'worker role explicitly enabled; no workers enrolled'} for name in workers})
    elif workers:
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


def reconcile_release_operation(config, operation_id):
    """Resolve only this broker's existing publication under the original lock order."""
    from .release_catalog import _json, _check_root_path, _require_root
    _require_root()
    store = release_store(config)
    journal = store.root/'.lifecycle-publication.json'
    if not journal.exists():
        return
    proxy = _scoped_proxy(config)
    directory = _scoped_updater_directory(proxy)
    with config.lifecycle_lock():
        with _scoped_updater_guard(directory) as check_idle:
            _check_root_path(journal)
            if _json(journal.read_bytes()).get('operation_id') != operation_id:
                raise RuntimeError('publication belongs to another operation; recovery required')
            check_idle()
            store.recover_publication(config.config_dir/'fleet-config.yaml')
