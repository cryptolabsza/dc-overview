"""Ordinary monitoring producer/caller contracts; synthetic Engine, no Docker."""
import copy
import fcntl
import json
import os
import stat
import subprocess
import sys
import tempfile
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from contextlib import contextmanager

import pytest
import yaml

from dc_overview import controller_adoption as adoption, fleet_manager, monitoring, web_prometheus
from dc_overview.fleet_config import FleetConfig
from dc_overview.fleet_manager import FleetManager
from test_dc_customer_runtime_repairs import images
from test_controller_adoption import bind, container, volume, FakeEngine


@pytest.fixture
def customer(tmp_path, monkeypatch):
    # Model chown only; actual Linux UID acceptance remains a separate gate.
    parent = Path(tempfile.mkdtemp(prefix='dc-public-path-', dir='/private/tmp')); parent.chmod(0o755)
    private = parent / 'dc-overview'; private.mkdir(mode=0o700)
    config = FleetConfig(config_dir=private); config.components.ipmi_monitor = False
    manager = FleetManager(config); manager.release_plan = images()
    manager.monitoring_plan = {'prometheus': manager._product_prometheus_config(),
        'grafana': {'prometheus_datasource_uid': 'prometheus', 'existing_datasource': None}}
    monkeypatch.setattr(os, 'chown', lambda *a: None)
    monkeypatch.setattr(os, 'fchown', lambda *a: None)
    monkeypatch.setattr(monitoring, 'validate_product_monitoring_custody', lambda *a: None)
    monkeypatch.setattr(adoption, 'probe_controller_inventory', lambda: {r: None for r in adoption.ROLES})
    # Explicit mounted-file archive adapter. Individual-bind retained-inode
    # replacement is separately exercised with a held FD in review repairs.
    monkeypatch.setattr(adoption.InstalledEngine, '__init__', lambda self, engine=None: setattr(self, 'engine', engine or SimpleNamespace()))
    def live_file(self, role, target, **kwargs):
        observed = adoption.probe_controller_inventory()
        value = observed.get(role) or next(v for v in observed.values() if v and v['Id']==role)
        mounts = [m for m in value['Mounts'] if target == m['Destination'] or target.startswith(m['Destination'] + '/')]
        mount = max(mounts, key=lambda m: len(m['Destination']))
        source = Path(mount['Source'])
        if target != mount['Destination']: source = source / Path(target).relative_to(mount['Destination'])
        metadata = source.stat()
        return {'bytes':source.read_bytes().hex(), 'uid':metadata.st_uid, 'gid':metadata.st_gid, 'mode':stat.S_IMODE(metadata.st_mode), 'inode':metadata.st_ino, 'device':metadata.st_dev,'parents':{}}
    monkeypatch.setattr(adoption.InstalledEngine, 'file_state', live_file)
    monkeypatch.setattr(adoption.InstalledEngine, 'running_file_state', live_file)
    monkeypatch.setattr(manager, '_validate_baseline_prometheus', lambda mapping: True)
    return manager


def compose_inventory(manager):
    manager.config.ssl.use_existing_proxy = True
    spec = yaml.safe_load(manager._generate_docker_compose())['services']
    result = {}
    for role in adoption.ROLES:
        service = spec.get(role, {})
        mounts = []
        for row in service.get('volumes', []):
            source, target, *options = row.split(':')
            if source.startswith('./'): source = str(manager.config.config_dir / source[2:])
            mounts.append(bind(source, target, 'ro' not in options) if source.startswith('/') else volume(source, target))
        result[role] = container(role, mounts)
        result[role]['Config']['Env'] = service.get('environment', [])
    return result


def test_fresh_writer_roundtrip_ownership_compose_and_normal_upgrade(customer, monkeypatch):
    manager = customer
    class Produced(Exception): pass
    monkeypatch.setattr(fleet_manager, '_ensure_docker_network', lambda: (_ for _ in ()).throw(Produced()))
    old = os.umask(0o077)
    try:
        with pytest.raises(Produced): manager._deploy_prometheus_grafana()
    finally: os.umask(old)
    directory = manager.config.config_dir.with_name('dc-overview-monitoring')
    assert directory.is_dir() and stat.S_IMODE(directory.stat().st_mode) == 0o755
    assert stat.S_IMODE(manager.config.config_dir.stat().st_mode) == 0o700
    for name in ('prometheus.yml', 'recording_rules.yml', 'ownership.json'):
        assert stat.S_IMODE((directory / name).stat().st_mode) == 0o644
    assert stat.S_IMODE((directory / 'prometheus.yml.lock').stat().st_mode) == 0o600
    monkeypatch.setenv('PROMETHEUS_OWNERSHIP_PATH', str(directory / 'ownership.json'))
    ownership = web_prometheus._adopted_ownership()
    assert ownership['managed_jobs'] == ['dc-managed']
    existing = yaml.safe_load((directory / 'prometheus.yml').read_bytes())
    merged = monitoring.merge_prometheus_config(existing, {'scrape_configs': [{'job_name': 'dc-managed', 'static_configs': []}]},
        legacy_managed_jobs=ownership['managed_jobs'], adopted_file_references=ownership['file_references'])
    assert {r['job_name'] for r in existing['scrape_configs']} - {'dc-managed'} <= {r['job_name'] for r in merged['scrape_configs']}
    monkeypatch.setenv('PROMETHEUS_CONFIG_PATH', str(directory / 'prometheus.yml'))
    server = SimpleNamespace(name='ordinary-worker', monitoring_name=None, server_ip='192.0.2.60',
        node_exporter_installed=True, node_exporter_enabled=True, dc_exporter_installed=False, dc_exporter_enabled=False,
        dcgm_exporter_installed=False, dcgm_exporter_enabled=False, watchdog_agent_installed=False, watchdog_agent_enabled=False)
    lock_inode = (directory / 'prometheus.yml.lock').stat().st_ino
    assert web_prometheus.update_prometheus_yml_targets([server], reload_callback=lambda: True)
    updated = yaml.safe_load((directory / 'prometheus.yml').read_bytes())
    assert {r['job_name'] for r in existing['scrape_configs']} == {r['job_name'] for r in updated['scrape_configs']}
    assert updated['rule_files'] == existing['rule_files']
    assert (directory / 'prometheus.yml.lock').stat().st_ino == lock_inode
    inventory = compose_inventory(manager)
    monkeypatch.setattr(adoption, 'probe_controller_inventory', lambda: inventory)
    assert adoption.upgrade_requires_adoption() is False
    from dc_overview import fleet_upgrade
    monkeypatch.setattr(fleet_upgrade, 'observe_component', lambda *a: {'state':'unknown'})
    assert manager._prepare_baseline_monitoring()['source_path'] == directory / 'prometheus.yml'
    selected = images(); selected.selection = {'selection_id':'fresh-normal-upgrade'}; selected.selection_sha256='c'*64
    selected.manifest=SimpleNamespace(sha256='d'*64)
    monkeypatch.setattr(fleet_upgrade, 'run_fleet_upgrade', lambda *a, **k: {'success':True,'results':{n:{'success':True} for n in selected.targets}})
    assert fleet_upgrade.run_selected_upgrade(manager.config, selected)['success']


@pytest.mark.parametrize('role,target', [('dc-overview','/var/lib/dc-monitoring/prometheus.yml'),
    ('prometheus','/etc/prometheus/prometheus.yml'), ('prometheus','/etc/prometheus/ownership.json')])
def test_selected_runtime_shadow_bind_holds_before_monitoring_write(customer, monkeypatch, role, target):
    class Produced(Exception): pass
    monkeypatch.setattr(fleet_manager, '_ensure_docker_network', lambda: (_ for _ in ()).throw(Produced()))
    with pytest.raises(Produced): customer._deploy_prometheus_grafana()
    inventory = compose_inventory(customer)
    foreign = customer.config.config_dir / 'foreign'; foreign.write_bytes(b'private unchanged')
    inventory[role]['Mounts'].append(bind(foreign, target))
    monkeypatch.setattr(adoption, 'probe_controller_inventory', lambda: inventory)
    with pytest.raises(ValueError, match='overlap|shadow'):
        customer._monitoring_directory()
    assert foreign.read_bytes() == b'private unchanged'


def test_noncanonical_private_public_parent_holds_before_setup_writes(customer, monkeypatch):
    parent = customer.config.config_dir.parent / 'private-parent'; parent.mkdir(mode=0o700)
    customer.config.config_dir = parent / 'config'; customer.config.config_dir.mkdir(mode=0o700)
    before = parent.stat().st_mode
    monkeypatch.setattr(customer, '_validate_baseline_prometheus', lambda *a: pytest.fail('private parent must hold first'))
    with pytest.raises(ValueError, match='traversable'):
        customer._deploy_prometheus_grafana()
    assert parent.stat().st_mode == before
    assert not customer.config.config_dir.with_name('config-monitoring').exists()


def test_actual_validator_creates_customer_child_mountpoint(customer, monkeypatch, tmp_path):
    manager = customer; customer_dir = tmp_path / 'customer'; customer_dir.mkdir()
    manager.config.prometheus.customer_config_dir = str(customer_dir)
    manager._validate_baseline_prometheus = FleetManager._validate_baseline_prometheus.__get__(manager)
    def run(command, **kwargs):
        parent = Path(command[command.index('-v') + 1].split(':')[0])
        assert (parent / 'customer').is_dir(), 'runc needs a mountpoint inside the read-only parent'
        assert stat.S_IMODE((parent / 'customer').stat().st_mode) == 0o755
        return subprocess.CompletedProcess(command, 0, '', '')
    monkeypatch.setattr(fleet_manager.subprocess, 'run', run)
    assert manager._validate_baseline_prometheus(manager.monitoring_plan['prometheus'])


def test_fresh_runtime_public_parent_contains_customer_mountpoint(customer, monkeypatch, tmp_path):
    customer.config.prometheus.customer_config_dir = str(tmp_path)
    class Produced(Exception): pass
    monkeypatch.setattr(fleet_manager, '_ensure_docker_network', lambda: (_ for _ in ()).throw(Produced()))
    with pytest.raises(Produced): customer._deploy_prometheus_grafana()
    child = customer.config.config_dir.with_name('dc-overview-monitoring') / 'customer'
    assert child.is_dir() and stat.S_IMODE(child.stat().st_mode) == 0o755


def test_standalone_launch_uses_same_fresh_writer_and_ownership(customer, monkeypatch):
    manager = customer; calls = []
    def run(argv, **kwargs):
        calls.append(argv); return subprocess.CompletedProcess(argv, 0, '', '')
    monkeypatch.setattr(fleet_manager.subprocess, 'run', run)
    monkeypatch.setattr(manager, '_wait_for_container', lambda *a, **k: True)
    monkeypatch.setattr(manager, '_populate_dc_overview_servers', lambda: None)
    manager._deploy_dc_overview_container()
    actual = next(row for row in calls if row[:3] == ['docker', 'run', '-d'])
    assert str(manager.config.config_dir.with_name('dc-overview-monitoring')) + ':/var/lib/dc-monitoring' in actual
    assert 'PROMETHEUS_CONFIG_PATH=/var/lib/dc-monitoring/prometheus.yml' in actual
    assert 'PROMETHEUS_OWNERSHIP_PATH=/var/lib/dc-monitoring/ownership.json' in actual


def test_fresh_already_public_env_repair_uses_one_source_product_lock(customer, monkeypatch):
    manager = customer
    class Produced(Exception): pass
    monkeypatch.setattr(fleet_manager, '_ensure_docker_network', lambda: (_ for _ in ()).throw(Produced()))
    with pytest.raises(Produced): manager._deploy_prometheus_grafana()
    inventory = compose_inventory(manager)
    inventory['dc-overview']['Config']['Env'] = [v for v in inventory['dc-overview']['Config']['Env'] if not v.startswith('PROMETHEUS_OWNERSHIP_PATH=')]
    public = manager.config.config_dir.with_name('dc-overview-monitoring')
    declaration = {'schema_version':1, 'product_directory':str(public), 'dc_destination':'/var/lib/dc-monitoring', 'managed_jobs':['dc-managed'],
        'session_routes':['proxy-sso'], 'maintenance_owners':['compose'], 'public_inputs':[]}
    inputs = (inventory, declaration, (public / 'prometheus.yml').read_bytes(),
        {'effective_source':{'dc-overview':True,'prometheus':True}, 'reference_files':{'/etc/prometheus/recording_rules.yml':(public / 'recording_rules.yml').read_bytes()}})
    result = adoption.build_plan(*inputs)
    original_stat = Path.stat
    def custody(path, *a, **k):
        value = original_stat(path, *a, **k)
        if path != public / 'ownership.json': return value
        values = list(value); values[4:6] = [1000, 1000]; return os.stat_result(values)
    monkeypatch.setattr(Path, 'stat', custody)
    adapter = adoption.InstalledEngine(engine=SimpleNamespace())
    adapter.require_guard_capability = lambda: None; adapter.collect = lambda *a: inputs
    adapter.inspect = lambda role: inventory[role]
    class Guard:
        def __call__(self): pass
    @contextmanager
    def guard(*a, **k): yield Guard()
    adapter.controller_guard = guard
    adapter.validate_staged = lambda *a: (_ for _ in ()).throw(Produced())
    monkeypatch.setattr(adoption, 'read_private_plan', lambda *a: result)
    monkeypatch.setattr(adoption, '_maintenance_proof', lambda *a: {})
    real_lock = adoption.bounded_lock
    monkeypatch.setattr(adoption, 'bounded_lock', lambda path: real_lock(path, timeout=.02))
    with pytest.raises(Produced): adoption.host_adopt(manager.config.config_dir, 'fixture-plan', 'fixture-proof', adapter=adapter)
    monkeypatch.setattr(adoption.ControllerAdoption, 'recover', lambda *a, **k: (_ for _ in ()).throw(Produced()))
    with pytest.raises(Produced): adoption.host_recover(manager.config.config_dir, adapter=adapter)


def predecessor(customer, tmp_path):
    manager = customer
    source = manager.config.config_dir / 'prometheus'; source.mkdir()
    config = yaml.safe_dump(manager._product_prometheus_config(), sort_keys=False).encode()
    (source / 'prometheus.yml').write_bytes(config)
    rules = manager._generate_recording_rules().encode(); (source / 'recording_rules.yml').write_bytes(rules)
    inventory = {r: container(r) for r in adoption.ROLES}
    inventory['dc-overview']['Mounts'] = [bind(manager.config.config_dir, '/etc/dc-overview'), bind(source, '/etc/dc-overview/prometheus', True), volume('original-data', '/data')]
    inventory['prometheus']['Mounts'] = [bind(source, '/etc/prometheus'), volume('original-tsdb', '/prometheus')]
    declaration = {'schema_version': 1, 'product_directory': str(manager.config.config_dir.parent / 'adopted-monitoring'), 'dc_destination': '/var/lib/dc-monitoring',
        'managed_jobs': ['dc-managed'], 'session_routes': ['proxy-sso'], 'maintenance_owners': ['external-compose'], 'public_inputs': []}
    adapter = adoption.InstalledEngine(engine=SimpleNamespace())
    adapter.inspect = lambda r: copy.deepcopy(inventory[r])
    adapter.changes = lambda r: []
    adapter.prove_effective_source = lambda *a: True
    adapter.engine.image = lambda ident: {'Id': ident, 'Os': 'linux', 'Architecture': 'amd64', 'RepoDigests': ['retained@' + ident]}
    def file_state(role, path):
        file = source / Path(path).name; metadata = file.stat()
        return {'bytes': file.read_bytes().hex(), 'uid': metadata.st_uid, 'gid': metadata.st_gid, 'mode': stat.S_IMODE(metadata.st_mode)}
    adapter.file_state = file_state
    adapter.running_file_state = lambda *a, **k: adapter.file_state(*a, **k)
    adapter.reference_state = lambda role, path: {**adapter.file_state(role, path), 'parents': {}}
    return adapter, inventory, declaration, source


def test_ordinary_directory_producer_collect_plan_and_preserved_reference(customer, tmp_path):
    adapter, inventory, declaration, source = predecessor(customer, tmp_path)
    inputs = adapter.collect(declaration)
    result = adoption.build_plan(*inputs)
    dc = result.requests['dc-overview']['HostConfig']['Mounts']
    prom = result.requests['prometheus']['HostConfig']['Mounts']
    assert not any(m['Target'] == '/etc/dc-overview/prometheus' for m in dc)
    assert any(m['Source'] == str(customer.config.config_dir) and m['Target'] == '/etc/dc-overview' for m in dc)
    assert any(m['Source'] == str(source / 'recording_rules.yml') and m['Target'] == '/etc/prometheus/recording_rules.yml' and m['ReadOnly'] for m in prom)
    assert any(m['Source'] == declaration['product_directory'] and m['Target'] == '/etc/prometheus' for m in prom)
    assert result.matches(*[inputs[i] for i in (0, 2, 3)])
    (source / 'unknown').write_bytes(b'not accounted')
    with pytest.raises(adoption.AdoptionError, match='directory|member|custody'): adapter.collect(declaration)


def test_directory_adoption_stages_mountpoint_for_retained_original_rule(customer, tmp_path):
    adapter, inventory, declaration, source = predecessor(customer, tmp_path)
    result = adoption.build_plan(*adapter.collect(declaration))
    adoption.stage_product_directory(result)
    public = Path(declaration['product_directory'])
    assert (public / 'recording_rules.yml').is_file(), 'runc needs an empty file mountpoint beneath the RO new root'
    assert (public / 'recording_rules.yml').read_bytes() == b''
    assert (source / 'recording_rules.yml').read_bytes() == result.evidence['reference_files']['/etc/prometheus/recording_rules.yml']


@pytest.mark.parametrize('change', ['unknown', 'symlink', 'credential', 'subdirectory', 'overlap', 'prefix-overlap', 'glob', 'inline', 'custody'])
def test_directory_predecessor_holds_unaccounted_shapes_before_staging(customer, tmp_path, change):
    adapter, inventory, declaration, source = predecessor(customer, tmp_path)
    if change == 'unknown': (source / 'unknown').write_bytes(b'unknown')
    if change == 'symlink': (source / 'recording_rules.yml').unlink(); (source / 'recording_rules.yml').symlink_to(source / 'prometheus.yml')
    if change == 'credential': (source / 'token').write_bytes(b'private synthetic credential')
    if change == 'subdirectory': (source / 'customer').mkdir()
    if change == 'overlap': inventory['prometheus']['Mounts'].append(bind(source / 'recording_rules.yml', '/etc/prometheus/recording_rules.yml'))
    if change == 'prefix-overlap': inventory['prometheus']['Mounts'].append(bind(source / 'recording_rules.yml', '/etc/prometheus/customer-other'))
    if change == 'glob': (source / 'prometheus.yml').write_text('scrape_configs: []\nrule_files: [/etc/prometheus/*.yml]\n')
    if change == 'inline': (source / 'prometheus.yml').write_text('scrape_configs: [{job_name: private, bearer_token: private}]\n')
    if change == 'custody':
        original = adapter.file_state
        adapter.file_state = lambda *a: {**original(*a), 'uid': 4242}
    with pytest.raises(adoption.AdoptionError):
        inputs = adapter.collect(declaration); result = adoption.build_plan(*inputs); adoption.stage_product_directory(result)
    assert not Path(declaration['product_directory']).exists()


@pytest.mark.parametrize('drift', ['bytes', 'member', 'mode'])
def test_directory_drift_after_validation_holds_before_any_service_stop(customer, monkeypatch, tmp_path, drift):
    adapter, inventory, declaration, source = predecessor(customer, tmp_path)
    result = adoption.build_plan(*adapter.collect(declaration))
    path = customer.config.config_dir / 'plan.json'; adoption.save_private_plan(path, result)
    adapter.require_guard_capability = lambda: None
    adapter.stop = lambda *a: pytest.fail('source drift reached service mutation')
    class Guard:
        def __call__(self): pass
        def complete(self): pytest.fail('drift cannot release updater guard')
    @contextmanager
    def guard(*a, **k): yield Guard()
    adapter.controller_guard = guard
    def validate(plan, guard):
        guard()
        if drift == 'bytes': (source / 'prometheus.yml').write_bytes(b'scrape_configs: []\n')
        if drift == 'member': (source / 'unknown').write_bytes(b'new unaccounted file')
        if drift == 'mode': (source / 'prometheus.yml').chmod(0o640)
    adapter.validate_staged = validate
    monkeypatch.setattr(adoption, '_maintenance_proof', lambda *a: {})
    with pytest.raises(adoption.AdoptionError, match='drift|directory'):
        adoption.host_adopt(customer.config.config_dir, path, 'synthetic-proof', adapter=adapter)


def test_directory_adoption_then_normal_configuration_and_update_preserves_stores(customer, monkeypatch, tmp_path):
    adapter, inventory, declaration, source = predecessor(customer, tmp_path)
    inputs = adapter.collect(declaration); result = adoption.build_plan(*inputs)
    public = Path(declaration['product_directory'])
    original_stat = Path.stat
    def custody(path, *args, **kwargs):
        metadata = original_stat(path, *args, **kwargs)
        if path != public and path != public / 'ownership.json': return metadata
        values = list(metadata); values[4:6] = [1000, 1000]
        return os.stat_result(values)
    monkeypatch.setattr(Path, 'stat', custody)  # Declared Linux UID adapter only.
    engine = FakeEngine(inventory)
    adapter.inspect = engine.inspect
    def maybe_inspect(name):
        try: return engine.inspect(name)
        except StopIteration: return None
    adapter.maybe_inspect = maybe_inspect
    for name in ('stop', 'disconnect', 'rename', 'create', 'start', 'readiness', 'connect'):
        setattr(adapter, name, getattr(engine, name))
    def mounted_file(role, destination):
        mounts = [m for m in engine.inspect(role)['Mounts'] if destination == m['Destination'] or destination.startswith(m['Destination'] + '/')]
        mount = max(mounts, key=lambda m: len(m['Destination']))
        file = Path(mount['Source'])
        if destination != mount['Destination']: file = file / Path(destination).relative_to(mount['Destination'])
        metadata = file.stat()
        return {'bytes':file.read_bytes().hex(), 'uid':metadata.st_uid, 'gid':metadata.st_gid, 'mode':stat.S_IMODE(metadata.st_mode)}
    adapter.file_state = mounted_file
    adapter.require_guard_capability = lambda: None
    adapter.validate_staged = lambda p, guard: guard()
    completed = []
    class Guard:
        def __call__(self): engine.guard()
        def complete(self): completed.append(True)
    @contextmanager
    def guard(*a, **k): yield Guard()
    adapter.controller_guard = guard
    monkeypatch.setattr(adoption, '_maintenance_proof', lambda *a: {})
    plan_path = customer.config.config_dir / 'plan.json'; adoption.save_private_plan(plan_path, result)
    assert adoption.host_adopt(customer.config.config_dir, plan_path, 'synthetic-proof', adapter=adapter)['state'] == 'adopted'
    assert completed == [True]
    monkeypatch.setattr(adoption, 'probe_controller_inventory', lambda: {r: engine.inspect(r) for r in adoption.ROLES})
    assert adoption.upgrade_requires_adoption() is False
    monkeypatch.setattr('dc_overview.fleet_upgrade.observe_component', lambda *a: {'state':'unknown'})
    monkeypatch.setattr(customer, '_reload_baseline_prometheus', lambda *a: True)
    old = {p: p.read_bytes() for p in (source / 'prometheus.yml', source / 'recording_rules.yml')}
    for _ in range(2):
        prepared = customer._prepare_baseline_monitoring(); assert prepared['source_path'] == public / 'prometheus.yml'
        customer._configure_prometheus_targets()
    assert all(p.read_bytes() == payload for p, payload in old.items())
    assert any(m['Name'] == 'original-data' for m in engine.inspect('dc-overview')['Mounts'] if m['Type'] == 'volume')
    assert any(m['Name'] == 'original-tsdb' for m in engine.inspect('prometheus')['Mounts'] if m['Type'] == 'volume')
    # The ordinary updater caller accepts the now-sanctioned topology; transport
    # outcomes are declared synthetic and do not establish Docker acceptance.
    from dc_overview import fleet_upgrade
    selected = images(); selected.selection = {'selection_id': 'changed-vector'}; selected.selection_sha256 = 'c' * 64; selected.manifest = SimpleNamespace(sha256='d' * 64)
    # Exercise the actual ordinary release preflight caller as well. Artifact
    # loader/CLI verification and Docker transport are explicit owner-boundary
    # adapters; the monitoring path/render/validator pipeline is real source.
    selected.targets['dc-overview-cli'] = {'owner':'host-cli','sha256':'e'*64}
    monkeypatch.setattr(fleet_upgrade, 'load_release', lambda *a, **k: selected)
    monkeypatch.setattr(fleet_upgrade, 'verify_running_cli', lambda *a: {'success':True})
    monkeypatch.setattr(fleet_upgrade, 'proxy_capabilities', lambda **k: {'selection_contract':1,'proxy_replacement_policy':'host-adoption-required-v1'})
    validated = []
    def docker(command, **kwargs):
        if command[:3] == ['docker','inspect','cryptolabs-proxy']:
            return subprocess.CompletedProcess(command, 0, json.dumps([{'Source':str(fleet_upgrade.release_store(customer.config).root),'Destination':'/etc/cryptolabs/releases','RW':False}]), '')
        assert command[:2] == ['docker','run'] and '/bin/promtool' in command
        assert str(source / 'recording_rules.yml') + ':/etc/prometheus/recording_rules.yml:ro' in command
        validated.append(command)
        return subprocess.CompletedProcess(command, 0, '', '')
    monkeypatch.setattr(fleet_manager.subprocess, 'run', docker)
    assert fleet_upgrade.preflight_release(customer.config) is selected
    assert len(validated) == 1
    monkeypatch.setattr('dc_overview.worker_lifecycle.preflight_workers', lambda *a, **k: True)
    monkeypatch.setattr(fleet_upgrade, 'run_fleet_upgrade', lambda *a, **k: {'success': True, 'results': {n: {'success': True} for n in selected.targets}})
    assert fleet_upgrade.run_selected_upgrade(customer.config, selected)['success']


def test_directory_adoption_and_recovery_lock_source_inode_before_staging(customer, monkeypatch, tmp_path):
    adapter, inventory, declaration, source = predecessor(customer, tmp_path)
    result = adoption.build_plan(*adapter.collect(declaration))
    lock = source / 'prometheus.yml.lock'; lock.touch(mode=0o600)
    stages = []
    monkeypatch.setattr(adoption, 'read_private_plan', lambda *a: result)
    monkeypatch.setattr(adoption, '_maintenance_proof', lambda *a: {})
    monkeypatch.setattr(adoption, 'ensure_mutation_allowed', lambda *a: None)
    monkeypatch.setattr(adoption, 'stage_product_directory', lambda *a: stages.append('stage'))
    adapter.require_guard_capability = lambda: None
    class Guard:
        def __call__(self): pass
        def complete(self): pytest.fail('source lock busy cannot release guard')
    @contextmanager
    def guard(*a, **k): yield Guard()
    adapter.controller_guard = guard
    original = adoption.bounded_lock
    monkeypatch.setattr(adoption, 'bounded_lock', lambda path: original(path, timeout=.02))
    before = lock.stat().st_ino
    # Real second process holds the actual existing source inode. No shell,
    # sockets, Docker or remote transport participates in this control.
    owner = subprocess.Popen([sys.executable, '-I', '-c', 'import fcntl,sys; f=open(sys.argv[1],"a+b"); fcntl.flock(f,fcntl.LOCK_EX); print("locked",flush=True); sys.stdin.read()', str(lock)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert owner.stdout.readline().strip() == 'locked'
        with pytest.raises(adoption.AdoptionError, match='lock busy'):
            adoption.host_adopt(customer.config.config_dir, 'synthetic-plan', 'synthetic-proof', adapter=adapter)
        with pytest.raises(adoption.AdoptionError, match='lock busy'):
            adoption.host_recover(customer.config.config_dir, adapter=adapter)
    finally:
        owner.communicate('', timeout=5)
        assert owner.returncode == 0
    assert lock.stat().st_ino == before and stages == []


def test_bound_lock_guard_refuses_replaced_coordination_inode(tmp_path):
    path = tmp_path / 'prometheus.yml.lock'
    with adoption.bounded_lock(path) as verify:
        path.unlink(); path.touch(mode=0o600)
        with pytest.raises(adoption.AdoptionError, match='lock.*drift|inode'):
            verify()


def test_after_adoption_normal_configuration_uses_live_path(customer, monkeypatch, tmp_path):
    manager = customer
    new = manager.config.config_dir.parent / 'adopted'; new.mkdir()
    (new / 'recording_rules.yml').write_text(manager._generate_recording_rules())
    raw = b'global: {scrape_interval: 37s}\nscrape_configs: [{job_name: customer, static_configs: [{targets: ["customer:9100"]}]}]\n'
    (new / 'prometheus.yml').write_bytes(raw)
    (new / 'ownership.json').write_text(json.dumps({'schema_version': 1, 'managed_jobs': ['dc-managed'], 'file_references': []}))
    obsolete = manager.config.config_dir / 'prometheus'; obsolete.mkdir(); (obsolete / 'prometheus.yml').write_bytes(b'broken: [')
    inventory = {r: container(r) for r in adoption.ROLES}
    inventory['dc-overview']['Config']['Env'] += ['PROMETHEUS_CONFIG_PATH=/var/lib/dc-monitoring/prometheus.yml', 'PROMETHEUS_OWNERSHIP_PATH=/var/lib/dc-monitoring/ownership.json']
    inventory['dc-overview']['Mounts'] = [bind(new, '/var/lib/dc-monitoring', True)]
    inventory['prometheus']['Mounts'] = [bind(new, '/etc/prometheus')]
    monkeypatch.setattr(adoption, 'probe_controller_inventory', lambda: inventory)
    monkeypatch.setattr('dc_overview.fleet_upgrade.observe_component', lambda *a: {'state': 'unknown'})
    monkeypatch.setattr(manager, '_reload_baseline_prometheus', lambda *a: True)
    assert adoption.upgrade_requires_adoption() is False
    prepared = manager._prepare_baseline_monitoring()
    assert prepared['source_path'] == new / 'prometheus.yml' and prepared['source_bytes'] == raw
    manager._configure_prometheus_targets(); first = (new / 'prometheus.yml').read_bytes()
    manager._configure_prometheus_targets(); assert (new / 'prometheus.yml').read_bytes() == first
    assert (obsolete / 'prometheus.yml').read_bytes() == b'broken: ['


@pytest.mark.parametrize('failure', ['coldstart', 'unauthorized', 'malformed', 'timeout'])
def test_normal_preparation_waits_for_grafana_ownership_without_auth_fallback(customer, monkeypatch, failure):
    manager = customer
    monkeypatch.setattr('dc_overview.fleet_upgrade.observe_component', lambda *a: {'state': 'running'})
    elapsed = [0]; calls = []
    monkeypatch.setattr(fleet_manager.time, 'monotonic', lambda: elapsed[0])
    monkeypatch.setattr(fleet_manager.time, 'sleep', lambda delay: elapsed.__setitem__(0, elapsed[0] + delay))
    def request(path, **kwargs):
        calls.append(path)
        if failure == 'unauthorized': raise urllib.error.HTTPError('http://fixture', 401, 'denied', {}, None)
        if failure == 'malformed': return {'unexpected': True}
        if failure == 'timeout' or elapsed[0] < 40: raise urllib.error.URLError(ConnectionRefusedError('starting'))
        if path == '/api/health': return {'database': 'ok'}
        if path == '/api/datasources': return [{'type': 'prometheus', 'uid': 'retained', 'isDefault': True}]
        if path == '/api/search?type=dash-db': return []
        pytest.fail('unexpected ownership endpoint')
    monkeypatch.setattr(manager, '_grafana_request', request)
    if failure == 'coldstart':
        prepared = manager._prepare_baseline_monitoring()
        assert prepared['grafana']['prometheus_datasource_uid'] == 'retained'
        assert elapsed[0] >= 40 and calls[-2:] == ['/api/datasources', '/api/search?type=dash-db']
    else:
        with pytest.raises(RuntimeError, match='Grafana'): manager._prepare_baseline_monitoring()
        assert elapsed[0] <= 120
        if failure in ('unauthorized', 'malformed'): assert elapsed[0] == 0
        if failure == 'timeout': assert elapsed[0] == 120


def test_grafana_readiness_request_timeouts_share_total_deadline(customer, monkeypatch):
    elapsed = [0]
    monkeypatch.setattr(fleet_manager.time, 'monotonic', lambda: elapsed[0])
    monkeypatch.setattr(fleet_manager.time, 'sleep', lambda n: elapsed.__setitem__(0, elapsed[0] + n))
    def stalled_request(path, *, timeout):
        assert 0 < timeout <= 15
        elapsed[0] += timeout
        raise TimeoutError('synthetic stalled HTTP')
    monkeypatch.setattr(customer, '_grafana_request', stalled_request)
    with pytest.raises(RuntimeError, match='Grafana.*timed out'):
        customer._grafana_monitoring_ownership()
    assert elapsed[0] == 120


def test_adopted_validator_retains_static_rules_and_declared_credential_mounts(customer, monkeypatch):
    manager = customer; parent = manager.config.config_dir.parent
    product = parent / 'new'; product.mkdir()
    (product / 'prometheus.yml').write_bytes(b'scrape_configs: []\n')
    rules = manager.config.config_dir / 'rules.yml'; rules.write_text(manager._generate_recording_rules())
    creds = manager.config.config_dir / 'customer'; creds.mkdir(); (creds / 'token').write_bytes(b'private unchanged')
    (product / 'ownership.json').write_text(json.dumps({'schema_version': 1, 'managed_jobs': ['dc-managed'],
        'file_references': ['/etc/prometheus/recording_rules.yml', '/etc/prometheus/customer/token']}))
    inventory = {r: container(r) for r in adoption.ROLES}
    inventory['dc-overview']['Config']['Env'] = ['PROMETHEUS_CONFIG_PATH=/var/lib/dc-monitoring/prometheus.yml', 'PROMETHEUS_OWNERSHIP_PATH=/var/lib/dc-monitoring/ownership.json']
    inventory['dc-overview']['Mounts'] = [bind(product, '/var/lib/dc-monitoring', True)]
    inventory['prometheus']['Mounts'] = [bind(product, '/etc/prometheus'), bind(rules, '/etc/prometheus/recording_rules.yml'), bind(creds, '/etc/prometheus/customer')]
    monkeypatch.setattr(adoption, 'probe_controller_inventory', lambda: inventory)
    manager._validate_baseline_prometheus = FleetManager._validate_baseline_prometheus.__get__(manager)
    def run(command, **kwargs):
        assert str(rules) + ':/etc/prometheus/recording_rules.yml:ro' in command
        assert str(creds) + ':/etc/prometheus/customer:ro' in command
        candidate = Path(command[command.index('-v') + 1].split(':')[0])
        assert (candidate / 'customer').is_dir() and (candidate / 'recording_rules.yml').is_file()
        assert not (candidate / 'customer' / 'token').exists()
        return subprocess.CompletedProcess(command, 0, '', '')
    monkeypatch.setattr(fleet_manager.subprocess, 'run', run)
    mapping = manager._product_prometheus_config()
    mapping['scrape_configs'][0]['bearer_token_file'] = '/etc/prometheus/customer/token'
    assert manager._validate_baseline_prometheus(mapping)
