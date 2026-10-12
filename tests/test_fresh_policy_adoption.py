"""Real fresh preflight/adoption with inert verified public producer inputs.

The manifest fixture is exact public DC1.5.1 bytes, SHA256
b2b9311c301c925262839342b8f0368a6b96309f1e4cc1bc9c58498ec994c2f4.
The producer fixture extracts only the pure get_capabilities function and its
literal constants from public proxy1.3.1 wheel f3a37ce47ec847f865462f7bc4c933d52bd05dfb8a01efb7cf8dc1e91fe5cd9a.
No package execution, network, daemon, custody or provider access is involved.
"""
import hashlib
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

from dc_overview import controller_adoption, fleet_upgrade
from dc_overview.fleet_config import FleetConfig
from dc_overview.release_catalog import Manifest


FIXTURES = Path(__file__).parent / 'fixtures'
# Docker29 real generic formatted State probe, 2026-10-12. Missing-object
# diagnostics are independent of the successful-output format. Container-only
# formatted full-object inventory remains an actual lab/customer acceptance gate.
CAPTURED_FORMATTED_ABSENCE = (1, '\n', 'error: no such object: cryptolabs-proxy\n')
SUPPORTED_ABSENCE = [
    CAPTURED_FORMATTED_ABSENCE,
    (1, '[]\n', 'error: no such object: cryptolabs-proxy\n'),
    (1, '', 'Error response from daemon: No such container: cryptolabs-proxy\n'),
]


def outcome(rc, stdout, stderr):
    return SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)


@pytest.fixture
def fresh_preflight(tmp_path, monkeypatch):
    raw = (FIXTURES / 'fresh_policy_adoption_manifest.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == 'b2b9311c301c925262839342b8f0368a6b96309f1e4cc1bc9c58498ec994c2f4'
    path = tmp_path / 'manifest.json'
    path.write_bytes(raw)
    config = FleetConfig(config_dir=tmp_path / 'config')
    for name in ('dc_overview', 'ipmi_monitor', 'vast_exporter', 'runpod_exporter', 'vast_price_manager', 'dc_watchdog'):
        setattr(config.components, name, False)
    producer = json.loads((FIXTURES / 'fresh_policy_adoption_producer.json').read_text())
    namespace = {'selection': SimpleNamespace(SELECTION_CONTRACT=producer['selection_contract']),
                 'PROXY_REPLACEMENT_POLICY': producer['proxy_replacement_policy']}
    exec(compile(producer['function_source'], producer['wheel_url'], 'exec'), namespace)
    package = ModuleType('cryptolabs_proxy')
    package.__path__ = []
    updates = ModuleType('cryptolabs_proxy.updates')
    getter = Mock(side_effect=namespace['get_capabilities'])
    updates.get_capabilities = getter
    monkeypatch.setitem(sys.modules, 'cryptolabs_proxy', package)
    monkeypatch.setitem(sys.modules, 'cryptolabs_proxy.updates', updates)
    store = fleet_upgrade.release_store(config)
    prepare = Mock(wraps=store.prepare)
    monkeypatch.setattr(store, 'prepare', prepare)
    monkeypatch.setattr(fleet_upgrade, 'release_store', lambda _: store)
    verify = Mock()
    monkeypatch.setattr(fleet_upgrade, 'verify_running_cli', verify)
    mutation = Mock(side_effect=AssertionError('preflight must not mutate'))
    monkeypatch.setattr(fleet_upgrade, 'commit_release', mutation)
    monkeypatch.setattr(config, 'persist_lifecycle', mutation)
    monkeypatch.setattr(fleet_upgrade, '_updater', Mock(side_effect=AssertionError('absent runtime')))
    return config, path, getter, prepare, verify, mutation


def docker_inventory(monkeypatch, *, first_inventory=None, installed=None,
                     controller_inventory=None, fresh_setup=True, release_root=None):
    """Model the controller guard separately from later role/policy inventory."""
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        assert kwargs == {'capture_output': True, 'text': True, 'timeout': 15}
        if fresh_setup and len(calls) <= len(controller_adoption.ROLES):
            role = controller_adoption.ROLES[len(calls)-1]
            assert command == ['docker', 'container', 'inspect', role, '--format', '{{json .}}']
            value = (controller_inventory or {}).get(role, (1, '\n', f'error: no such object: {role}\n'))
            if isinstance(value, Exception):
                raise value
            return outcome(*value)
        if command[-1] == '{{json .Mounts}}':
            assert command == ['docker', 'inspect', 'cryptolabs-proxy', '--format', '{{json .Mounts}}']
            assert release_root is not None
            return outcome(0, json.dumps([{'Source': str(release_root), 'Destination': '/etc/cryptolabs/releases', 'RW': False}]), '')
        assert command[:3] == ['docker', 'container', 'inspect']
        target = command[command.index('inspect') + 1]
        if command[-1] == '{{json .State}}':
            return outcome(*CAPTURED_FORMATTED_ABSENCE)
        assert command[-1] == '{{json .}}'
        if first_inventory is not None:
            value = first_inventory
            if isinstance(value, Exception):
                raise value
            return outcome(*value)
        if installed is not None and target == 'cryptolabs-proxy':
            return outcome(0, json.dumps({'Config': {'Image': installed, 'Labels': {}}}), '')
        return outcome(1, '\n', f'error: no such object: {target}\n')
    monkeypatch.setattr(fleet_upgrade.subprocess, 'run', run)
    return calls


def assert_fresh_controller_inventory(calls):
    assert calls[:len(controller_adoption.ROLES)] == [
        ['docker', 'container', 'inspect', role, '--format', '{{json .}}']
        for role in controller_adoption.ROLES]


@pytest.mark.parametrize('diagnostic', SUPPORTED_ABSENCE)
def test_fresh_manifest_real_preflight_adoption_and_prepare_accept_exact_absence(fresh_preflight, monkeypatch, diagnostic):
    config, path, getter, prepare, verify, mutation = fresh_preflight
    # Explicit disabled policies skip other inventory, keeping the exact captured
    # target diagnostic while preserving the real twelve-component manifest.
    manifest = Manifest.from_bytes(path.read_bytes())
    config.release_selection.components = {name: {'origin': 'baseline', 'enabled': False}
        for name in manifest.data['components'] if name not in {'cryptolabs-proxy', 'dc-overview-cli'}}
    calls = docker_inventory(monkeypatch, first_inventory=diagnostic,
        controller_inventory={'cryptolabs-proxy': diagnostic})
    plan = fleet_upgrade.preflight_release(config, path, fresh_setup=True, platform='linux/amd64')
    assert set(plan.targets) == {'cryptolabs-proxy', 'dc-overview-cli'}
    assert plan.selection['components']['cryptolabs-proxy'] == {'origin': 'baseline', 'enabled': True}
    assert_fresh_controller_inventory(calls)
    assert calls[len(controller_adoption.ROLES)+1] == ['docker', 'container', 'inspect', 'cryptolabs-proxy', '--format', '{{json .}}']
    assert getter.call_count == 2
    prepare.assert_called_once()
    verify.assert_called_once_with(plan.targets['dc-overview-cli'])
    mutation.assert_not_called()
    assert not config.config_dir.exists()


UNPROVEN_INVENTORY = [
    (1, '', 'Cannot connect to Docker daemon'),
    (1, '', 'permission denied while trying to connect to Docker socket'),
    (1, '', 'error: no such object: unrelated'),
    (1, '', 'error: no such object: cryptolabs-proxy-shadow'),
    (1, '', 'No such object'),
    (1, '', 'permission denied: No such object: cryptolabs-proxy'),
    (1, '', 'No such object: cryptolabs-proxy\npermission denied'),
    (1, '', 'No such container: cryptolabs-proxy (daemon unavailable)'),
    (1, '{"Config":{"Image":"existing"}}', 'No such object: cryptolabs-proxy'),
    (1, 'null', 'No such object: cryptolabs-proxy'),
    (1, '[{"Id":"existing"}]', 'No such object: cryptolabs-proxy'),
    (2, '', 'No such object: cryptolabs-proxy'),
    (125, '', 'No such object: cryptolabs-proxy'),
    FileNotFoundError('docker disappeared after capability proof'),
    PermissionError('synthetic denied'),
    OSError('synthetic unavailable'),
    fleet_upgrade.subprocess.TimeoutExpired('docker', 15),
]


@pytest.mark.parametrize('inventory', UNPROVEN_INVENTORY + [
    (0, '{}', ''), (0, 'null', ''), (0, '[]', ''), (0, 'malformed', ''), (0, '{"Id":""}', '')])
def test_unknown_controller_holds_before_capability_or_role_policy_inventory(fresh_preflight, monkeypatch, inventory):
    config, path, getter, prepare, verify, mutation = fresh_preflight
    calls = docker_inventory(monkeypatch, controller_inventory={'cryptolabs-proxy': inventory})
    before = {str(p): p.read_bytes() for p in path.parent.rglob('*') if p.is_file()}
    with pytest.raises(controller_adoption.AdoptionError, match='controller inventory.*no writes allowed'):
        fleet_upgrade.preflight_release(config, path, fresh_setup=True, platform='linux/amd64')
    assert_fresh_controller_inventory(calls)
    assert len(calls) == len(controller_adoption.ROLES)
    getter.assert_not_called(); prepare.assert_not_called(); verify.assert_not_called(); mutation.assert_not_called()
    assert before == {str(p): p.read_bytes() for p in path.parent.rglob('*') if p.is_file()}
    assert not config.config_dir.exists()


@pytest.mark.parametrize('role', controller_adoption.ROLES)
def test_existing_controller_holds_fresh_setup_before_capability_or_preparation(fresh_preflight, monkeypatch, role):
    config, path, getter, prepare, verify, mutation = fresh_preflight
    calls = docker_inventory(monkeypatch, controller_inventory={role: (0, json.dumps({'Id': 'a'*64}), '')})
    with pytest.raises(controller_adoption.AdoptionError, match='existing controller.*setup cannot replace'):
        fleet_upgrade.preflight_release(config, path, fresh_setup=True, platform='linux/amd64')
    assert_fresh_controller_inventory(calls)
    assert len(calls) == len(controller_adoption.ROLES)
    getter.assert_not_called(); prepare.assert_not_called(); verify.assert_not_called(); mutation.assert_not_called()
    assert not config.config_dir.exists()


@pytest.mark.parametrize('state,released', [('prepared', True), ('adopted', False)])
def test_unreleased_controller_recovery_holds_upgrade_before_policy_inputs(fresh_preflight, monkeypatch, state, released):
    config, path, getter, prepare, verify, mutation = fresh_preflight
    recovery = config.config_dir / 'controller-recovery'
    recovery.mkdir(parents=True, mode=0o700)
    record = recovery / 'operation.json'
    record.write_text(json.dumps({'state': state, 'exclusion_released': released}))
    record.chmod(0o600)
    calls = docker_inventory(monkeypatch, fresh_setup=False)
    before = {str(p): p.read_bytes() for p in path.parent.rglob('*') if p.is_file()}
    with pytest.raises(controller_adoption.AdoptionError, match='controller recovery required'):
        fleet_upgrade.preflight_release(config, path, platform='linux/amd64')
    assert calls == []
    getter.assert_not_called(); prepare.assert_not_called(); verify.assert_not_called(); mutation.assert_not_called()
    assert before == {str(p): p.read_bytes() for p in path.parent.rglob('*') if p.is_file()}


@pytest.mark.parametrize('inventory', UNPROVEN_INVENTORY)
def test_inventory_uncertainty_holds_after_capability_proof_before_prepare_or_mutation(fresh_preflight, monkeypatch, inventory):
    config, path, getter, prepare, verify, mutation = fresh_preflight
    calls = docker_inventory(monkeypatch, first_inventory=inventory)
    before = {str(p): p.read_bytes() for p in path.parent.rglob('*') if p.is_file()}
    with pytest.raises(RuntimeError, match='ownership inventory is unavailable'):
        fleet_upgrade.preflight_release(config, path, fresh_setup=True, platform='linux/amd64')
    getter.assert_called_once_with()
    assert_fresh_controller_inventory(calls)
    prepare.assert_not_called()
    verify.assert_not_called()
    mutation.assert_not_called()
    assert before == {str(p): p.read_bytes() for p in path.parent.rglob('*') if p.is_file()}
    assert not config.config_dir.exists()


def test_empty_policies_adopt_every_absent_public_component_without_writes(fresh_preflight, monkeypatch):
    config, path, getter, prepare, verify, mutation = fresh_preflight
    calls = docker_inventory(monkeypatch)
    plan = fleet_upgrade.preflight_release(config, path, fresh_setup=True, platform='linux/amd64')
    expected = {name for name, value in plan.manifest.data['components'].items() if value['owner'] == 'proxy-updater'}
    assert_fresh_controller_inventory(calls)
    assert {call[3] for call in calls[len(controller_adoption.ROLES):] if call[-1] == '{{json .}}'} == expected
    assert config.release_selection.components == {}
    assert set(plan.targets) == {'cryptolabs-proxy', 'dc-overview-cli'}
    prepare.assert_called_once(); mutation.assert_not_called()
    assert not config.config_dir.exists()


def test_explicit_customer_policy_is_preserved_without_role_policy_inventory(fresh_preflight, monkeypatch):
    config, path, getter, prepare, verify, mutation = fresh_preflight
    manifest = Manifest.from_bytes(path.read_bytes())
    reference = manifest.data['components']['cryptolabs-proxy']['artifacts']['linux/amd64']['reference']
    policy = {'origin': 'customer-pin', 'enabled': True, 'pin': reference}
    config.release_selection.components = {'cryptolabs-proxy': policy}
    calls = docker_inventory(monkeypatch)
    plan = fleet_upgrade.preflight_release(config, path, fresh_setup=True, platform='linux/amd64')
    assert plan.selection['components']['cryptolabs-proxy'] == policy
    assert config.release_selection.components['cryptolabs-proxy'] == policy
    assert_fresh_controller_inventory(calls)
    assert all(call[-1] != '{{json .}}' or call[3] != 'cryptolabs-proxy' for call in calls[len(controller_adoption.ROLES):])
    mutation.assert_not_called()


@pytest.mark.parametrize('conflict', [False, True])
def test_installed_immutable_image_stays_customer_pin_and_conflict_holds(fresh_preflight, monkeypatch, conflict):
    config, path, getter, prepare, verify, mutation = fresh_preflight
    manifest = Manifest.from_bytes(path.read_bytes())
    reference = manifest.data['components']['cryptolabs-proxy']['artifacts']['linux/amd64']['reference']
    installed = reference.split('@')[0] + '@sha256:' + 'c' * 64 if conflict else reference
    # Existing controllers use the ordinary lifecycle after supported adoption,
    # not fresh setup. Preserve the real guard and prove its released journal.
    recovery = config.config_dir / 'controller-recovery'
    recovery.mkdir(parents=True, mode=0o700)
    record = recovery / 'operation.json'
    record.write_text(json.dumps({'state': 'adopted', 'exclusion_released': True}))
    record.chmod(0o600)
    before = {str(p): p.read_bytes() for p in path.parent.rglob('*') if p.is_file()}
    live = Mock(return_value={'selection_contract': 1, 'proxy_replacement_policy': 'host-adoption-required-v1'})
    monkeypatch.setattr(fleet_upgrade, '_updater', live)
    calls = docker_inventory(monkeypatch, installed=installed, fresh_setup=False,
        release_root=config.config_dir / 'releases')
    if conflict:
        with pytest.raises(ValueError, match='pin_conflict'):
            fleet_upgrade.preflight_release(config, path, platform='linux/amd64')
        verify.assert_not_called()
    else:
        plan = fleet_upgrade.preflight_release(config, path, platform='linux/amd64')
        assert plan.selection['components']['cryptolabs-proxy'] == {'origin': 'customer-pin', 'enabled': True, 'pin': installed}
        assert calls[-1][-1] == '{{json .Mounts}}'
        assert live.call_args_list == [(('capabilities',), {}), (('capabilities',), {})]
    assert calls[0][3] == 'cryptolabs-proxy'
    getter.assert_not_called()
    mutation.assert_not_called()
    assert before == {str(p): p.read_bytes() for p in path.parent.rglob('*') if p.is_file()}
