"""Synthetic selected hosts; real publication/CAS, no live Docker mutations."""
import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml

from dc_overview import fleet_upgrade as upgrade, release_catalog as catalog
from dc_overview.fleet_config import FleetConfig, Server

SCOPED = ('cryptolabs-proxy', 'dc-overview', 'runpod-exporter', 'vastai-exporter')
OLD_VAST = '5c709' + '0' * 59
NEW_VAST = '99bc' + '0' * 60


def encode(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


@pytest.fixture(params=['ltx', 'charlotte'])
def selected_host(request, tmp_path, monkeypatch):
    # Root custody is separately exercised; macOS unit fixtures use our real uid.
    monkeypatch.setattr(catalog, '_require_root', lambda: None)
    monkeypatch.setattr(catalog.os, 'chown', lambda *a: None)
    monkeypatch.setattr(catalog.os, 'fchown', lambda *a: None)
    monkeypatch.setattr(catalog, 'current_platform', lambda: 'linux/amd64')
    def custody(path, **kwargs):
        info = Path(path).lstat()
        if Path(path).is_symlink() or info.st_mode & 0o022:
            raise PermissionError('unsafe fixture custody')
        if kwargs.get('directory') and not Path(path).is_dir():
            raise PermissionError('not directory')
    monkeypatch.setattr(catalog, '_check_root_path', custody)
    config = FleetConfig(config_dir=tmp_path / 'config')
    config.config_dir.mkdir()
    config.components.vast_price_manager = request.param == 'charlotte'
    config.components.vast_exporter = request.param == 'ltx'
    config.components.worker_exporters = request.param == 'charlotte'
    config.watchdog.install_agent = request.param == 'charlotte'
    config.components.dc_watchdog = request.param == 'charlotte'
    if request.param == 'charlotte':
        config.servers = [Server(name='synthetic-worker-' + str(i), server_ip='192.0.2.' + str(i+1)) for i in range(43)]
    config.vast_price_manager.master_key_file = '/etc/customer/master.key'
    config.vast_price_manager.credential_reference = '/etc/customer/vpm.cred'
    roles = [*SCOPED, 'prometheus', 'grafana', 'ipmi-monitor', 'vast-price-manager']
    data = {'schema_version': 1, 'selection_contract': 1, 'baseline_id': 'old', 'components': {}}
    for name in roles:
        owner, repository, kind = catalog.COMPONENTS[name]
        digest = OLD_VAST if name == 'vastai-exporter' else 'a' * 64
        data['components'][name] = {'owner': owner, 'release': 'old', 'artifacts': {'linux/amd64': {'kind': kind, 'reference': repository + '@sha256:' + digest}}}
    source = tmp_path / 'old.json'; source.write_bytes(encode(data))
    store = upgrade.release_store(config)
    policies = {name: {'origin': 'baseline', 'enabled': True} for name in roles}
    # Native policy shape: monitoring/VPM/exporter pins; Charlotte also pins DC.
    pinned = {'grafana', 'prometheus', 'ipmi-monitor', 'vast-price-manager', 'runpod-exporter'}
    if request.param == 'charlotte':
        pinned.add('dc-overview')
    for name in pinned:
        policies[name] = {'origin': 'customer-pin', 'enabled': True, 'pin': data['components'][name]['artifacts']['linux/amd64']['reference']}
    policies['vastai-exporter'] = {'origin': 'customer-pin', 'enabled': True, 'pin': data['components']['vastai-exporter']['artifacts']['linux/amd64']['reference']}
    previous = store.prepare(source, platform='linux/amd64', policies=policies)
    store.commit(previous)
    config.release_selection.selection_id = previous.selection['selection_id']
    config.release_selection.selection_sha256 = previous.selection_sha256
    config.release_selection.components = previous.selection['components']
    # Include opaque public intent that lifecycle persistence must preserve.
    public = config._to_dict(include_secrets=False)
    public['customer_opaque'] = {'workers': list(range(43)), 'held': True}
    (config.config_dir / 'fleet-config.yaml').write_text(yaml.safe_dump(public))
    candidate = copy.deepcopy(data); candidate['baseline_id'] = 'candidate'
    for name in SCOPED:
        candidate['components'][name]['release'] = 'candidate'
        candidate['components'][name]['artifacts']['linux/amd64']['reference'] = catalog.COMPONENTS[name][1] + '@sha256:' + (NEW_VAST if name == 'vastai-exporter' else 'b' * 64)
    candidate['components']['node-exporter'] = {'owner': 'dc-worker', 'release': 'dormant', 'artifacts': {'linux/amd64': {'kind': 'binary', 'url': 'https://github.com/prometheus/node_exporter/releases/download/v1/node.tar.gz', 'sha256': 'c'*64}}}
    manifest = tmp_path / 'candidate.json'; manifest.write_bytes(encode(candidate))
    jobs = tmp_path / 'auth' / 'update-jobs'; jobs.mkdir(parents=True, mode=0o700)
    for name in ('dispatch.lock', 'operation.lock'):
        (jobs / name).touch(mode=0o600)
    # Keep lock/active/recovery logic real; only adapt mount discovery and Engine IO.
    monkeypatch.setattr(upgrade, '_scoped_updater_directory', lambda proxy: jobs)
    monkeypatch.setattr(upgrade.os, 'geteuid', lambda: os.stat(jobs).st_uid)
    caps = {'selection_contract': 1, 'proxy_replacement_policy': upgrade.PROXY_REPLACEMENT_POLICY}
    monkeypatch.setattr(upgrade, 'proxy_capabilities', lambda **kw: caps)
    def docker(command, **kwargs):
        assert command[:2] == ['docker', 'inspect']
        name = command[2]
        if name.startswith('sha256:'):
            value = {'Id': name, 'Os': 'linux', 'Architecture': 'amd64', 'RepoDigests': [catalog.COMPONENTS[n][1] + '@sha256:' + (NEW_VAST if n == 'vastai-exporter' else 'a'*64) for n in SCOPED]}
        else:
            value = {'Id': 'd'*64, 'Image': 'sha256:' + 'e'*64, 'State': {'Running': True}, 'Config': {'Image': catalog.COMPONENTS[name][1] + '@sha256:' + (NEW_VAST if name == 'vastai-exporter' else 'a'*64)}, 'Mounts': [{'Source': str(store.root), 'Destination': '/etc/cryptolabs/releases', 'RW': False}]}
        return SimpleNamespace(returncode=0, stdout=json.dumps(value), stderr='')
    monkeypatch.setattr(upgrade.subprocess, 'run', docker)
    for name in ('run_fleet_upgrade', 'run_selected_upgrade', 'dispatch_vpm', 'vpm_spec', 'adopt_existing_policies'):
        monkeypatch.setattr(upgrade, name, Mock(side_effect=AssertionError('forbidden lifecycle call: ' + name)))
    from dc_overview import worker_lifecycle, fleet_manager
    for name in ('preflight_workers', 'upgrade_workers'):
        monkeypatch.setattr(worker_lifecycle, name, Mock(side_effect=AssertionError('forbidden worker lifecycle')))
    monkeypatch.setattr(fleet_manager, 'FleetManager', Mock(side_effect=AssertionError('forbidden compose/monitoring rendering')))
    return SimpleNamespace(config=config, store=store, previous=previous, candidate=candidate, manifest=manifest, jobs=jobs, public=public, caps=caps)


def select(host, **kwargs):
    return upgrade.select_release_components(host.config, host.manifest, SCOPED, platform='linux/amd64', **kwargs)


def test_exact_installed_eight_roles_and_explicit_pin_move(selected_host):
    host = selected_host
    result = select(host)
    current = host.store.load(platform='linux/amd64')
    assert result['scope'] == list(SCOPED)
    assert result['state'] == 'pending-deployment' and result['suite_complete'] is False
    assert current.selection['components']['vastai-exporter']['origin'] == 'customer-pin'
    assert current.selection['components']['vastai-exporter']['pin'].endswith(NEW_VAST)
    for name in set(host.previous.targets) - set(SCOPED):
        assert current.targets[name] == host.previous.targets[name]
        assert current.selection['components'][name] == host.previous.selection['components'][name]
    assert current.selection['components']['node-exporter'] == {'origin': 'baseline', 'enabled': False}
    after = yaml.safe_load((host.config.config_dir / 'fleet-config.yaml').read_bytes())
    for key in host.public.keys() - {'release_selection'}:
        assert after[key] == host.public[key]
    with pytest.raises(ValueError):
        upgrade.load_release(host.config, platform='linux/amd64')


@pytest.mark.parametrize('bad', ['unscoped', 'removed', 'owner', 'disabled', 'missing', 'worker', 'vpm', 'unknown'])
def test_semantic_refusal_before_writes(selected_host, bad):
    host = selected_host; scope = SCOPED
    if bad == 'unscoped': host.candidate['components']['prometheus']['artifacts']['linux/amd64']['reference'] = 'prom/prometheus@sha256:' + 'f'*64
    if bad == 'removed': del host.candidate['components']['grafana']
    if bad == 'owner': host.candidate['components']['dc-overview']['owner'] = 'dc-worker'
    if bad == 'disabled':
        host.previous.selection['components']['dc-overview']['enabled'] = False
        raw = encode(host.previous.selection); (host.store.root/'selection.json').write_bytes(raw)
        host.config.release_selection.selection_sha256 = hashlib.sha256(raw).hexdigest()
        host.config.release_selection.components = host.previous.selection['components']
        host.config.persist_lifecycle(expected_public=(host.config.config_dir/'fleet-config.yaml').read_bytes())
    if bad == 'missing': del host.candidate['components']['dc-overview']
    if bad in ('worker', 'vpm', 'unknown'): scope = (dict(worker='node-exporter', vpm='vast-price-manager', unknown='unknown')[bad],)
    host.manifest.write_bytes(encode(host.candidate))
    before = (host.store.root/'selection.json').read_bytes()
    with pytest.raises((ValueError, RuntimeError)):
        upgrade.select_release_components(host.config, host.manifest, scope, platform='linux/amd64')
    assert (host.store.root/'selection.json').read_bytes() == before
    assert not (host.store.root/'.lifecycle-publication.json').exists()


@pytest.mark.parametrize('hold', ['queued', 'running', 'interrupted', 'controller', 'capability', 'custody'])
def test_updater_and_recovery_holds(selected_host, hold):
    host = selected_host
    if hold in ('queued', 'running', 'interrupted'):
        job_id = 'f'*32
        (host.jobs/'active.json').write_bytes(encode({'id': job_id})); (host.jobs/(job_id+'.json')).write_bytes(encode({'id': job_id, 'state': hold}))
        (host.jobs/'active.json').chmod(0o600); (host.jobs/(job_id+'.json')).chmod(0o600)
    if hold == 'controller': (host.jobs/'controller-adoption.json').touch(mode=0o600)
    if hold == 'capability': host.caps['selection_contract'] = 0
    if hold == 'custody': (host.store.root/'selection.json').chmod(0o666)
    before = (host.store.root/'selection.json').read_bytes()
    with pytest.raises((ValueError, RuntimeError, PermissionError)):
        select(host)
    assert (host.store.root/'selection.json').read_bytes() == before


def test_real_publication_rollback_and_retry(selected_host, monkeypatch):
    host = selected_host; original = host.config.persist_lifecycle
    monkeypatch.setattr(host.config, 'persist_lifecycle', Mock(side_effect=OSError('simulated disk failure')))
    with pytest.raises(OSError): select(host)
    assert (host.store.root/'selection.json').read_bytes() == host.previous.selection_raw
    assert not (host.store.root/'.lifecycle-publication.json').exists()
    monkeypatch.setattr(host.config, 'persist_lifecycle', original)
    result = select(host)
    assert host.store.load(platform='linux/amd64').selection_sha256 == result['selection_sha256']


def test_public_command_json_and_explicit_scope(selected_host, monkeypatch):
    from click.testing import CliRunner
    from dc_overview import cli
    monkeypatch.setattr(cli, 'DOCKER_CONFIG_DIR', selected_host.config.config_dir)
    # CLI loads public config; reuse exact installed object for synthetic fixture.
    monkeypatch.setattr(cli.FleetConfig, 'load', lambda path: selected_host.config)
    args = ['release', 'select', '--release-manifest', str(selected_host.manifest)]
    result = CliRunner().invoke(cli.main, args)
    assert result.exit_code != 0
    for name in SCOPED: args += ['--component', name]
    result = CliRunner().invoke(cli.main, args)
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)['suite_complete'] is False


def test_selection_persistence_preserves_absent_vpm_and_all_opaque_keys(tmp_path, monkeypatch):
    config = FleetConfig(config_dir=tmp_path)
    public = {'components': {'vast_price_manager': False}, 'servers': [{'private': 'opaque'}], 'customer': {'held': True}}
    path = tmp_path/'fleet-config.yaml'; path.write_text(yaml.safe_dump(public))
    config.release_selection.selection_id = 'synthetic'
    monkeypatch.setattr('dc_overview.fleet_config.os.fchown', lambda *args: None)
    config.persist_lifecycle(expected_public=path.read_bytes(), selection_only=True)
    after = yaml.safe_load(path.read_bytes())
    assert {key: value for key, value in after.items() if key != 'release_selection'} == public


@pytest.mark.parametrize('kind', ['public', 'selection', 'manifest'])
def test_actual_compare_and_swap_rejects_late_edits(selected_host, monkeypatch, kind):
    host = selected_host
    original = upgrade._scoped_updater_directory
    calls = []
    def race(proxy):
        calls.append(True)
        if len(calls) < 3:
            return original(proxy)
        if kind == 'public':
            path = host.config.config_dir/'fleet-config.yaml'; path.write_bytes(path.read_bytes()+b'\n# concurrent edit\n')
        elif kind == 'selection':
            path = host.store.root/'selection.json'; path.write_bytes(path.read_bytes()+b'\n')
        else:
            host.manifest.write_bytes(host.manifest.read_bytes()+b'\n')
        return original(proxy)
    monkeypatch.setattr(upgrade, '_scoped_updater_directory', race)
    if kind == 'manifest':
        # A source edit after exact bytes have been prepared cannot alter committed bytes.
        assert select(host)['state'] == 'pending-deployment'
        assert host.store.load(platform='linux/amd64').manifest.raw == encode(host.candidate)
    else:
        with pytest.raises(RuntimeError, match='changed after'):
            select(host)
        assert not (host.store.root/'.lifecycle-publication.json').exists()


@pytest.mark.parametrize('lock_name', ['dispatch.lock', 'operation.lock'])
def test_real_flock_contention_refuses_without_publication(selected_host, lock_name):
    import fcntl
    host = selected_host
    with open(host.jobs/lock_name, 'rb') as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(RuntimeError, match='busy'):
            select(host)
    assert host.store.load(platform='linux/amd64').selection_raw == host.previous.selection_raw


@pytest.mark.parametrize('unsafe', ['lock-symlink', 'lock-mode', 'directory-mode', 'store-symlink', 'manifest-symlink'])
def test_actual_filesystem_custody_holds(selected_host, unsafe):
    host = selected_host
    if unsafe == 'lock-symlink':
        path = host.jobs/'operation.lock'; path.unlink(); path.symlink_to(host.jobs/'dispatch.lock')
    if unsafe == 'lock-mode': (host.jobs/'dispatch.lock').chmod(0o666)
    if unsafe == 'directory-mode': host.jobs.chmod(0o755)
    if unsafe == 'store-symlink':
        original = host.store.root; renamed = original.with_name('real-releases'); original.rename(renamed); original.symlink_to(renamed)
    if unsafe == 'manifest-symlink':
        path = next((host.store.root/'manifests').glob('*.json')); renamed = path.with_suffix('.saved'); path.rename(renamed); path.symlink_to(renamed)
    with pytest.raises((PermissionError, RuntimeError)):
        select(host)


def test_exact_installed_cli_requires_explicit_record_and_stays_dormant(selected_host, monkeypatch):
    host = selected_host
    target = {'owner': 'host-cli', 'release': '1.6.5', 'artifacts': {'any': {'kind': 'wheel', 'url': 'https://github.com/cryptolabsza/dc-overview/releases/download/v1.6.5/dc_overview-1.6.5.whl', 'sha256': 'c'*64}}}
    host.candidate['components']['dc-overview-cli'] = target
    host.manifest.write_bytes(encode(host.candidate))
    verified = Mock(side_effect=RuntimeError('requires_cli_upgrade'))
    monkeypatch.setattr(upgrade, 'verify_running_cli', verified)
    with pytest.raises(RuntimeError, match='requires_cli_upgrade'):
        select(host, record_cli=True)
    verified.side_effect = None
    result = select(host, record_cli=True)
    assert result['tooling_recorded'] is True
    assert host.store.load(platform='linux/amd64').selection['components']['dc-overview-cli'] == {'origin': 'baseline', 'enabled': False}
    assert verified.call_count == 3


def test_stale_public_selection_snapshot_rejected(selected_host):
    host = selected_host
    host.config.release_selection.components['grafana']['enabled'] = False
    with pytest.raises(RuntimeError, match='stale'):
        select(host)


@pytest.mark.parametrize('fault', ['stopped', 'identity', 'image-id', 'platform', 'digest', 'mount'])
def test_scoped_runtime_refuses_unproven_identity(selected_host, monkeypatch, fault):
    original = upgrade.subprocess.run
    def run(command, **kwargs):
        result = original(command, **kwargs); value = json.loads(result.stdout)
        if command[2] == 'dc-overview':
            if fault == 'stopped': value['State']['Running'] = False
            if fault == 'identity': value['Id'] = None
        if command[2].startswith('sha256:'):
            if fault == 'image-id': value['Id'] = 'sha256:' + 'f'*64
            if fault == 'platform': value['Architecture'] = 'arm64'
            if fault == 'digest': value['RepoDigests'] = []
        if fault == 'mount' and command[2] == 'cryptolabs-proxy': value['Mounts'][0]['RW'] = True
        return SimpleNamespace(returncode=0, stdout=json.dumps(value), stderr='')
    monkeypatch.setattr(upgrade.subprocess, 'run', run)
    with pytest.raises(RuntimeError): select(selected_host)


def test_dc_controller_recovery_blocks_selection(selected_host):
    from dc_overview.controller_adoption import Journal
    Journal(selected_host.config.config_dir/'controller-recovery').write({'state': 'forward-repair-required'})
    with pytest.raises(RuntimeError, match='recovery'):
        select(selected_host)


def test_installed_cli_exact_metadata_not_version_only(monkeypatch):
    import importlib.metadata
    from dc_overview import __version__
    url = 'https://github.com/cryptolabsza/dc-overview/releases/download/v'+__version__+'/dc_overview.whl'
    target = {'release': __version__, 'url': url, 'sha256': 'a'*64}
    provenance = {'url': url, 'archive_info': {'hashes': {'sha256': 'b'*64}}}
    installed = SimpleNamespace(version=__version__, read_text=lambda path: json.dumps(provenance))
    monkeypatch.setattr(importlib.metadata, 'distribution', lambda name: installed)
    with pytest.raises(RuntimeError, match='requires_cli_upgrade'):
        upgrade.verify_running_cli(target)
    provenance['archive_info']['hashes']['sha256'] = 'a'*64
    assert upgrade.verify_running_cli(target)['state'] == 'verified'


@pytest.mark.parametrize('case', ['local', 'remote', 'context-overrides-host', 'missing-package', 'incompatible-package', 'wrong-jobs-root', 'mismatched-jobs-subdirectory'])
def test_resolve_actual_host_updater_mount_and_installed_package(tmp_path, monkeypatch, case):
    import sys
    import platform
    from types import ModuleType
    monkeypatch.setattr(platform, 'system', lambda: 'Linux')
    monkeypatch.delenv('DOCKER_HOST', raising=False); monkeypatch.delenv('DOCKER_CONTEXT', raising=False)
    source = tmp_path/'actual-volume'; source.mkdir()
    proxy = {'Mounts': [{'Source': str(source), 'Destination': '/data/auth', 'RW': True, 'Type': 'volume'}]}
    package = ModuleType('cryptolabs_proxy'); module = ModuleType('cryptolabs_proxy.updates')
    module.JOBS_DIR = Path('/data/auth/update-jobs')
    module.get_capabilities = lambda: {'selection_contract': 0 if case == 'incompatible-package' else 1, 'proxy_replacement_policy': upgrade.PROXY_REPLACEMENT_POLICY}
    monkeypatch.setitem(sys.modules, 'cryptolabs_proxy', package)
    monkeypatch.setitem(sys.modules, 'cryptolabs_proxy.updates', None if case == 'missing-package' else module)
    if case == 'wrong-jobs-root': module.JOBS_DIR = Path('/other/jobs')
    if case == 'mismatched-jobs-subdirectory': module.JOBS_DIR = Path('/data/auth/different-jobs')
    endpoint = 'tcp://remote:2376' if case in ('remote', 'context-overrides-host') else 'unix:///var/run/docker.sock'
    monkeypatch.setattr(upgrade.subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=0, stdout=json.dumps(endpoint)))
    if case == 'context-overrides-host':
        monkeypatch.setenv('DOCKER_CONTEXT', 'remote'); monkeypatch.setenv('DOCKER_HOST', 'unix:///var/run/docker.sock')
    if case == 'local':
        assert upgrade._scoped_updater_directory(proxy) == source/'update-jobs'
    else:
        with pytest.raises(RuntimeError): upgrade._scoped_updater_directory(proxy)


def unlink_public_selection(host):
    path = host.config.config_dir/'fleet-config.yaml'
    public = yaml.safe_load(path.read_bytes()); public.pop('release_selection')
    path.write_text(yaml.safe_dump(public))
    host.config = FleetConfig.load(host.config.config_dir)
    return public


def crash_after_selection(host):
    policies = copy.deepcopy(host.previous.selection['components'])
    for name in SCOPED:
        if policies[name]['origin'] == 'customer-pin':
            policies[name]['pin'] = host.candidate['components'][name]['artifacts']['linux/amd64']['reference']
    plan = host.store.prepare(host.manifest, platform='linux/amd64', policies=policies, enabled_components=())
    host.store.begin_publication(plan, (host.config.config_dir/'fleet-config.yaml').read_bytes())
    host.store.commit(plan)


def test_adversarial_busy_updater_cannot_recover_crash_journal(selected_host):
    import fcntl
    host = selected_host; crash_after_selection(host)
    paths = [host.store.root/'selection.json', host.store.root/'.lifecycle-publication.json', host.config.config_dir/'fleet-config.yaml']
    snapshots = [path.read_bytes() for path in paths]
    with open(host.jobs/'operation.lock', 'rb') as operation:
        fcntl.flock(operation, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(RuntimeError, match='busy'): select(host)
        assert [path.read_bytes() for path in paths] == snapshots
    assert select(host)['state'] == 'pending-deployment'
    assert not paths[1].exists()


def test_adversarial_new_cli_requires_explicit_record_flag(selected_host, monkeypatch):
    host = selected_host
    host.candidate['components']['dc-overview-cli'] = {'owner': 'host-cli', 'release': '1.6.5', 'artifacts': {'any': {'kind': 'wheel', 'url': 'https://github.com/cryptolabsza/dc-overview/releases/download/v1.6.5/dc_overview.whl', 'sha256': 'c'*64}}}
    host.manifest.write_bytes(encode(host.candidate))
    monkeypatch.setattr(upgrade, 'verify_running_cli', lambda target: None)
    with pytest.raises(ValueError, match='record-cli'): select(host)
    assert 'dc-overview-cli' not in host.store.load(platform='linux/amd64').selection['components']


def test_native_absent_public_reference_explicit_adoption_and_repeat(selected_host):
    host = selected_host; public = unlink_public_selection(host)
    with pytest.raises(ValueError): select(host)
    result = select(host, adopt_existing_selection=True)
    assert result['reference_adopted'] is True
    current = yaml.safe_load((host.config.config_dir/'fleet-config.yaml').read_bytes())
    assert {key: value for key, value in current.items() if key != 'release_selection'} == public
    assert host.store.load(platform='linux/amd64').selection_sha256 == current['release_selection']['selection_sha256']
    assert select(host, adopt_existing_selection=True)['reference_adopted'] is False


LOCAL_SOURCE = 'sha256:36e845bf7d7ed98a120b9e364368246c5cdac3660bf52511e0bac313afa62525'


def local_source_image(monkeypatch):
    original = upgrade.subprocess.run
    def docker(command, **kwargs):
        if command[2] == 'dc-overview':
            value = {'Id': '6c90e9185d799a4b2ae0eb62be3ec41d7795997bac96084bb99d740e1cc86d87', 'Image': LOCAL_SOURCE, 'State': {'Running': True}, 'Config': {'Image': 'ghcr.io/cryptolabsza/dc-overview:latest'}}
            return SimpleNamespace(returncode=0, stdout=json.dumps(value))
        if command[2] == LOCAL_SOURCE:
            return SimpleNamespace(returncode=0, stdout=json.dumps({'Id': LOCAL_SOURCE, 'Os': 'linux', 'Architecture': 'amd64', 'RepoDigests': []}))
        return original(command, **kwargs)
    monkeypatch.setattr(upgrade.subprocess, 'run', docker)


def test_native_ltx_local_image_requires_explicit_source_identity(selected_host, monkeypatch):
    host = selected_host; local_source_image(monkeypatch)
    with pytest.raises(RuntimeError): select(host)
    result = select(host, source_images=('dc-overview='+LOCAL_SOURCE,))
    assert result['local_only_sources'] == {'dc-overview': LOCAL_SOURCE}
    assert result['suite_complete'] is False
    assert host.store.load(platform='linux/amd64').targets['dc-overview']['reference'].endswith('b'*64)


@pytest.mark.parametrize('section', [None, {}, {'selection_id': 'wrong'}, {'selection_id': 'old', 'selection_sha256': 'f'*64, 'components': {}}])
def test_explicit_adoption_never_overwrites_present_conflicting_metadata(selected_host, section):
    host = selected_host; path = host.config.config_dir/'fleet-config.yaml'
    value = yaml.safe_load(path.read_bytes()); value['release_selection'] = section
    path.write_text(yaml.safe_dump(value)); host.config = FleetConfig.load(host.config.config_dir)
    before = path.read_bytes()
    with pytest.raises((RuntimeError, ValueError)):
        select(host, adopt_existing_selection=True)
    assert path.read_bytes() == before
    assert host.store.load(platform='linux/amd64').selection_raw == host.previous.selection_raw


@pytest.mark.parametrize('expectations', [('dc-overview=sha256:'+'f'*64,), ('dc-overview='+LOCAL_SOURCE, 'dc-overview='+LOCAL_SOURCE), ('grafana='+LOCAL_SOURCE,), ('unknown='+LOCAL_SOURCE,), ('dc-overview=latest',)])
def test_source_expectations_wrong_duplicate_or_unscoped_rejected(selected_host, monkeypatch, expectations):
    local_source_image(monkeypatch)
    with pytest.raises((RuntimeError, ValueError)):
        select(selected_host, source_images=expectations)
    assert selected_host.store.load(platform='linux/amd64').selection_raw == selected_host.previous.selection_raw


def test_native_public_cli_loader_adoption_and_source_flags_json(selected_host, monkeypatch):
    from click.testing import CliRunner
    from dc_overview import cli
    host = selected_host; unlink_public_selection(host); local_source_image(monkeypatch)
    monkeypatch.setattr(cli, 'DOCKER_CONFIG_DIR', host.config.config_dir)
    args = ['release', 'select', '--release-manifest', str(host.manifest), '--adopt-existing-selection', '--source-image', 'dc-overview='+LOCAL_SOURCE]
    for name in SCOPED: args += ['--component', name]
    result = CliRunner().invoke(cli.main, args)
    assert result.exit_code == 0, result.output
    value = json.loads(result.output)
    assert value['reference_adopted'] is True and value['local_only_sources'] == {'dc-overview': LOCAL_SOURCE}


def test_local_source_concurrent_container_replacement_fails_before_write(selected_host, monkeypatch):
    host = selected_host; local_source_image(monkeypatch)
    original = upgrade.subprocess.run; observed = []
    def docker(command, **kwargs):
        result = original(command, **kwargs)
        if command[2] == 'dc-overview':
            observed.append(True)
            if len(observed) > 1:
                value = json.loads(result.stdout); value['Id'] = 'f'*64
                result.stdout = json.dumps(value)
        return result
    monkeypatch.setattr(upgrade.subprocess, 'run', docker)
    with pytest.raises(RuntimeError, match='runtime changed'):
        select(host, source_images=('dc-overview='+LOCAL_SOURCE,))
    assert host.store.load(platform='linux/amd64').selection_raw == host.previous.selection_raw


def test_adopted_reference_publication_failure_rolls_back_and_retries(selected_host, monkeypatch):
    host = selected_host; unlink_public_selection(host)
    path = host.config.config_dir/'fleet-config.yaml'; before = path.read_bytes()
    original = host.config.persist_lifecycle
    monkeypatch.setattr(host.config, 'persist_lifecycle', Mock(side_effect=OSError('synthetic disk failure')))
    with pytest.raises(OSError): select(host, adopt_existing_selection=True)
    assert path.read_bytes() == before
    assert host.store.load(platform='linux/amd64').selection_raw == host.previous.selection_raw
    assert not (host.store.root/'.lifecycle-publication.json').exists()
    monkeypatch.setattr(host.config, 'persist_lifecycle', original)
    assert select(host, adopt_existing_selection=True)['reference_adopted'] is True
