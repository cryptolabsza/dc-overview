"""Synthetic customer state exercises the supported VPM lifecycle contract."""
import json
import sqlite3
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from dc_overview.vpm_service import VPMServiceManager, VPMServiceSpec

PIN = 'ghcr.io/cryptolabsza/vast-price-manager@sha256:' + 'a' * 64


class Host:
    def __init__(self):
        self.calls = []
        self.unit_dir = None
        self.unit_metadata = {}
        self.credential_metadata = {}
        self.extra_units = []
        self.states = {
            'vast-price-manager-sync.timer': {'enabled': True, 'active': False},
            'vast-price-manager-cycle.timer': {'enabled': False, 'active': True},
            'vast-price-manager-horizon.timer': {'enabled': False, 'active': False},
        }

    def __call__(self, command, **kwargs):
        self.calls.append(command)
        rc, output = 0, ''
        if command[:3] == ['systemctl', 'is-active', '--quiet']:
            rc = 3
        elif command[:2] == ['systemctl', 'is-enabled']:
            rc = 0 if self.states.get(command[2], {}).get('enabled') else 1
        elif command[:2] == ['systemctl', 'is-active']:
            rc = 0 if self.states.get(command[2], {}).get('active') else 3
        elif command[:2] == ['systemctl', 'show']:
            name = command[2]
            fragment = self.unit_dir / name if self.unit_dir else None
            exists = fragment is not None and fragment.is_file()
            content = fragment.read_text() if exists else ''
            values = {'Id':name, 'Names':name, 'LoadState':'loaded' if exists else 'not-found',
                'FragmentPath':str(fragment) if exists else '',
                'DropInPaths':' '.join(str(path) for path in (self.unit_dir / (name + '.d')).glob('*.conf')) if self.unit_dir else '',
                'NeedDaemonReload':'no',
                'ActiveState':'active' if self.states.get(name,{}).get('active') else 'inactive',
                'UnitFileState':'enabled' if self.states.get(name,{}).get('enabled') else 'disabled',
                'ExecStart':'', 'ExecStop':'', 'Triggers':'', 'User':'', 'Group':'', 'SupplementaryGroups':'', 'LoadCredentialEncrypted':''}
            for line in content.splitlines():
                key, sep, value = line.partition('=')
                if not sep:
                    continue
                if key in {'ExecStart','ExecStop'}:
                    values[key] = '{ path=' + value.split()[0] + ' ; argv[]=' + value + ' ; ignore_errors=no ; }' if value else ''
                elif key == 'Unit':
                    values['Triggers'] = value
                elif key in values:
                    values[key] = value
            values.update(self.unit_metadata.get(name,{}))
            output = '\n'.join(key + '=' + str(value) for key,value in values.items())
        elif command[:4] == ['busctl', '--json=short', 'call', 'org.freedesktop.systemd1']:
            name = command[-1]
            output = json.dumps({'type': 'o', 'data': ['/org/freedesktop/systemd1/unit/' +
                name.replace('-', '_2d').replace('.', '_2e')]})
        elif command[:4] == ['busctl', '--json=short', 'get-property', 'org.freedesktop.systemd1']:
            name = command[4].rsplit('/', 1)[1].replace('_2d', '-').replace('_2e', '.')
            key = command[-1]
            fragment = self.unit_dir / name
            rows = [line.partition('=')[2].split(':', 1) for line in fragment.read_text().splitlines()
                    if line.startswith(key + '=')] if fragment.is_file() else []
            output = json.dumps(self.credential_metadata.get((name, key), {
                'type': 'as' if key == 'ImportCredential' else 'a(ss)', 'data': rows}))
        elif command[:2] == ['systemctl','enable']:
            for name in command[2:]:
                self.states.setdefault(name,{})['enabled'] = True
        elif command[:2] == ['systemctl','disable']:
            for name in command[2:]:
                if name == '--now':
                    continue
                self.states.setdefault(name,{})['enabled'] = False
                if '--now' in command:
                    self.states[name]['active'] = False
        elif command[:2] in (['systemctl','start'], ['systemctl','restart'], ['systemctl','stop']):
            for name in command[2:]:
                self.states.setdefault(name,{})['active'] = command[1] != 'stop'
        elif command[:2] == ['docker', 'inspect']:
            output = 'healthy'
        return SimpleNamespace(returncode=rc, stdout=output, stderr='')


def manager(tmp_path, existing=True):
    host = Host()
    service = VPMServiceManager(tmp_path, unit_dir=tmp_path / 'units', runner=host)
    host.unit_dir = service.unit_dir
    service._validate_master_key = lambda spec: None
    service._has_existing_managed_vpm = lambda: existing
    service._require_vast_exporter_for_first_install = lambda: None
    service._assert_data_binding = lambda spec: None
    service._continuity = lambda *args: {'ok': True, 'schema': 'a' * 64, 'controls': 'a' * 64,
        'key': 'a' * 64, 'ciphertexts': 'a' * 64, 'expected_account': 'a' * 64, 'account_authority':'a' * 64, 'writes_enabled': False, 'automation_paused': True}
    service._data_recovery = lambda *args: None
    service._verify_auth_boundary = lambda: True
    return service, host


def test_maintenance_preserves_each_timer_enabled_and_running_state(tmp_path):
    service, host = manager(tmp_path)
    service.install(VPMServiceSpec(PIN, 'dc.example.com'))
    assert ['systemctl', 'enable', '--now', *service.timer_names] not in host.calls
    assert ['systemctl', 'enable', service.timer_names[0]] in host.calls
    assert ['systemctl', 'start', service.timer_names[1]] in host.calls
    assert ['systemctl', 'start', service.timer_names[0]] not in host.calls
    assert ['systemctl', 'enable', service.timer_names[1]] not in host.calls


def test_fresh_install_leaves_all_timers_disabled_and_stopped(tmp_path):
    service, host = manager(tmp_path, existing=False)
    service.install(VPMServiceSpec(PIN, 'dc.example.com'))
    assert not any(call[:2] in (['systemctl', 'enable'], ['systemctl', 'start']) for call in host.calls)


def test_render_preserves_declared_bind_data_and_encrypted_custody(tmp_path):
    spec = VPMServiceSpec(PIN, 'dc.example.com', data_source=str(tmp_path / 'data'),
                          data_kind='bind', credential_mode='systemd-encrypted',
                          credential_reference='/etc/credstore.encrypted/customer-vpm.key')
    rendered = VPMServiceManager.render(spec)
    assert f'{tmp_path}/data:/data' in rendered.compose
    assert 'LoadCredentialEncrypted=vpm-master.key:/etc/credstore.encrypted/customer-vpm.key' in rendered.units['vast-price-manager-container.service']
    assert '/run/credentials/vast-price-manager-container.service/vpm-master.key:/run/secrets/vpm-master.key:ro' in rendered.compose
    assert 'cp ' not in ''.join(rendered.units.values())
    assert 'watchtower.enable: "false"' in rendered.compose


def test_layout_rejects_unsafe_or_duplicate_declared_owners(tmp_path):
    from dc_overview.vpm_service import VPMLayout
    with pytest.raises(ValueError):
        VPMLayout('legacy', 'vast-price-manager', str(tmp_path / 'compose.yml'),
                  str(tmp_path / 'data'), 'bind', '/key', timer_names=('a.timer', 'a.timer', 'b.timer'))
    with pytest.raises(ValueError):
        VPMLayout('legacy', 'vast-price-manager', '../compose.yml', '/data', 'bind', '/key')


def layout_fixture(tmp_path, encrypted=False):
    from dc_overview.vpm_service import VPMLayout
    data = tmp_path / 'existing-data'
    data.mkdir()
    database = sqlite3.connect(data / 'vpm.sqlite3')
    database.executescript('''
        CREATE TABLE settings(singleton INTEGER PRIMARY KEY, automation_paused INTEGER, writes_enabled INTEGER, account_id TEXT);
        INSERT INTO settings VALUES(1,1,1,'customer-account');
        CREATE TABLE policies(machine_id TEXT PRIMARY KEY, state TEXT, floor_price REAL);
        INSERT INTO policies VALUES('gpu-1','auto',0.42);
        CREATE TABLE setup_state(singleton INTEGER PRIMARY KEY, account_id TEXT, allow_writes INTEGER);
        INSERT INTO setup_state VALUES(1,'customer-account',1);
        CREATE TABLE credential_slots(kind TEXT, slot TEXT, active INTEGER);
        INSERT INTO credential_slots VALUES('reader','a',1);
    ''')
    database.commit()
    database.close()
    from cryptography.fernet import Fernet
    key = Fernet.generate_key()
    master = tmp_path / 'runtime-master.key'
    master.write_bytes(key)
    (data / 'credentials').mkdir()
    (data / 'credentials' / 'reader-a.enc').write_bytes(Fernet(key).encrypt(b'synthetic-api-key'))
    compose = tmp_path / 'assembly.yml'
    compose.write_text('services:\n  vast-price-manager:\n    image: old\n')
    units = tmp_path / 'units'
    units.mkdir()
    timers = ('legacy-sync.timer', 'legacy-cycle.timer', 'legacy-horizon.timer')
    for name in timers:
        (units / name).write_text('[Timer]\nOnCalendar=daily\nPersistent=false\nUnit=' + name.replace('.timer', '.service') + '\n')
        (units / name.replace('.timer','.service')).write_text('[Service]\nExecStart=/synthetic/legacy-vpm work\n')
    (units / 'legacy-owner.service').write_text('[Unit]\nAfter=obsolete-auth.service\n')
    (units / 'obsolete-auth.service').write_text('[Service]\nExecStart=/synthetic/auth serve\n')
    encrypted_ref = tmp_path / 'encrypted.cred'
    encrypted_ref.write_bytes(b'synthetic-encrypted-custody')
    layout = VPMLayout('customer-assembly', 'vast-price-manager', str(compose), str(data), 'bind', str(master),
                       owner_unit='legacy-owner.service', timer_names=timers,
                       obsolete_auth_unit='obsolete-auth.service',
                       credential_mode='systemd-encrypted' if encrypted else 'file',
                       credential_reference=str(encrypted_ref) if encrypted else None)
    return layout, data, master


def adoption_host(tmp_path, layout, data, master, expected_account_id='customer-account'):
    from dc_overview.vpm_service import _VPM_CONTINUITY_PROBE, _VPM_DATA_RECOVERY_PROGRAM
    host = Host()
    host.states.update({layout.timer_names[0]: {'enabled': True, 'active': False},
                        layout.timer_names[1]: {'enabled': False, 'active': True},
                        layout.timer_names[2]: {'enabled': False, 'active': False},
                        layout.owner_unit: {'enabled': True, 'active': True},
                        layout.obsolete_auth_unit: {'enabled': True, 'active': True}})
    for name in VPMServiceManager.timer_names:
        host.states[name] = {'enabled':False,'active':False}
    original = host.__call__
    def run(command, **kwargs):
        if command[:2] == ['docker', 'ps']:
            host.calls.append(command)
            return SimpleNamespace(returncode=0, stdout=(service.container_name if service.compose_file.is_file() else layout.container_name) + '\n', stderr='')
        if command[:2] == ['systemctl', 'list-units']:
            host.calls.append(command)
            return SimpleNamespace(returncode=0, stdout='\n'.join([layout.owner_unit,*host.extra_units]), stderr='')
        if command[:2] == ['systemctl','list-unit-files']:
            host.calls.append(command)
            return SimpleNamespace(returncode=0, stdout='\n'.join(path.name for path in service.unit_dir.iterdir() if path.name.endswith(('.service','.timer'))), stderr='')
        if command[:3] == ['docker', 'inspect', '-f'] and '{{json .Mounts}}' in command[3]:
            host.calls.append(command)
            mounts = [{'Type': 'bind', 'Source': str(data), 'Destination': layout.data_target, 'RW': True},
                      {'Type': 'bind', 'Source': str(master), 'Destination': '/run/secrets/vpm-master.key', 'RW': False}]
            canonical = service.compose_file.is_file()
            if canonical and layout.credential_mode == 'systemd-encrypted':
                mounts[1]['Source'] = '/run/credentials/vast-price-manager-container.service/vpm-master.key'
            if command[3] == '{{json .Mounts}}':
                return SimpleNamespace(returncode=0, stdout=json.dumps(mounts), stderr='')
            return SimpleNamespace(returncode=0, stdout=json.dumps({'name': '/' + (service.container_name if canonical else layout.container_name), 'project': service.project_name if canonical else layout.project_name,
                'service': 'vast-price-manager' if canonical else layout.service_name, 'image': PIN, 'mounts': mounts}), stderr='')
        if command[-1] == _VPM_CONTINUITY_PROBE:
            import os
            env = dict(os.environ, VPM_TEST_DATA=str(data), VPM_TEST_KEY=str(master))
            program = _VPM_CONTINUITY_PROBE.replace('from vast_price_manager.config import Settings',
                'from types import SimpleNamespace\nfrom pathlib import Path\nimport os\nclass Settings:\n @staticmethod\n def from_env(): return SimpleNamespace(data_dir=Path(os.environ["VPM_TEST_DATA"]), database_path=Path(os.environ["VPM_TEST_DATA"])/"vpm.sqlite3", credential_master_key_file=Path(os.environ["VPM_TEST_KEY"]), writes_enabled=True, expected_account_id=' + repr(expected_account_id) + ')')
            host.calls.append(command)
            return subprocess.run(['python3', '-c', program], capture_output=True, text=True, env=env)
        if command[-1] == _VPM_DATA_RECOVERY_PROGRAM:
            import os
            env = dict(os.environ)
            for index, part in enumerate(command):
                if part == '--env':
                    key, value = command[index + 1].split('=', 1)
                    env[key] = value
            env['VPM_RECOVERY_DATA'] = str(data)
            # Map only the controlled synthetic host backup mount.
            mount = next(command[i + 1] for i, p in enumerate(command) if p == '--volume' and ':/recovery' in command[i + 1])
            env['VPM_RECOVERY_ROOT'] = mount.split(':/recovery')[0]
            host.calls.append(command)
            return subprocess.run(['python3', '-c', _VPM_DATA_RECOVERY_PROGRAM], capture_output=True, text=True, env=env)
        return original(command, **kwargs)
    service = VPMServiceManager(tmp_path / 'managed', unit_dir=tmp_path / 'units', runner=run)
    host.unit_dir = service.unit_dir
    service._validate_master_key = lambda spec: None
    service._verify_auth_boundary = lambda: True
    service._has_existing_managed_vpm = lambda: False
    return service, host


@pytest.mark.parametrize('encrypted', [False, True])
def test_adoption_keeps_data_key_controls_timer_cadence_and_recovery_history(tmp_path, encrypted):
    layout, data, master = layout_fixture(tmp_path, encrypted)
    service, host = adoption_host(tmp_path, layout, data, master)
    before_key = master.read_bytes()
    result = service.adopt(VPMServiceSpec(PIN, 'dc.example.com', writes_enabled=True, expected_account_id='customer-account'), layout)
    assert result['status'] == 'adopted'
    assert result['state_preserved'] is True
    assert str(data) + ':/data' in service.compose_file.read_text()
    assert master.read_bytes() == before_key
    assert (tmp_path / 'assembly.yml').exists()
    assert (tmp_path / 'units' / 'legacy-owner.service').exists()
    assert 'OnCalendar=daily' in (tmp_path / 'units' / service.timer_names[0]).read_text()
    assert 'Persistent=false' in (tmp_path / 'units' / service.timer_names[0]).read_text()
    assert ['systemctl', 'enable', service.timer_names[0]] in host.calls
    assert ['systemctl', 'start', service.timer_names[1]] in host.calls
    assert ['systemctl', 'start', service.timer_names[0]] not in host.calls
    assert ['systemctl', 'disable', '--now', layout.obsolete_auth_unit] in host.calls
    assert list((service.root / 'recovery').glob('*/data/vpm.sqlite3'))
    assert b'synthetic-api-key' not in json.dumps(result).encode()


@pytest.mark.parametrize('failure', ['auth', 'health', 'key', 'schema'])
def test_failed_adoption_restores_real_snapshot_before_old_owner_restart(tmp_path, failure):
    layout, data, master = layout_fixture(tmp_path)
    service, host = adoption_host(tmp_path, layout, data, master)
    original_launch = service._launch
    def launch(spec):
        original_launch(spec)
        with sqlite3.connect(data / 'vpm.sqlite3') as database:
            database.execute('UPDATE policies SET floor_price=9')
            if failure == 'schema':
                database.execute('ALTER TABLE policies ADD COLUMN migrated TEXT')
        if failure == 'key':
            (data / 'credentials' / 'reader-a.enc').write_bytes(b'bad-ciphertext')
    service._launch = launch
    if failure == 'auth':
        service._verify_auth_boundary = lambda: False
    if failure == 'health':
        service._wait_for_health = lambda: (_ for _ in ()).throw(RuntimeError('synthetic unhealthy'))
    with pytest.raises(RuntimeError):
        service.adopt(VPMServiceSpec(PIN, 'dc.example.com', writes_enabled=True, expected_account_id='customer-account'), layout)
    with sqlite3.connect(data / 'vpm.sqlite3') as database:
        assert database.execute('SELECT floor_price FROM policies').fetchone()[0] == .42
        assert 'migrated' not in {row[1] for row in database.execute('PRAGMA table_info(policies)')}
    assert ['systemctl', 'disable', '--now', layout.obsolete_auth_unit] not in host.calls
    assert ['systemctl', 'start', layout.owner_unit] in host.calls


def test_plan_duplicate_container_owners_fail_before_mutation(tmp_path):
    layout, data, master = layout_fixture(tmp_path)
    service, host = adoption_host(tmp_path, layout, data, master)
    original = service.runner
    def duplicate(command, **kwargs):
        if command[:2] == ['docker', 'ps']:
            return SimpleNamespace(returncode=0, stdout='vast-price-manager\nunknown-vpm\n', stderr='')
        return original(command, **kwargs)
    service.runner = duplicate
    with pytest.raises(RuntimeError, match='owner'):
        service.plan_adoption(VPMServiceSpec(PIN, 'dc.example.com'), layout)
    assert not any(call[:2] == ['systemctl', 'disable'] for call in host.calls)


def test_repeat_adoption_validates_identity_without_mutating_owners(tmp_path):
    layout, data, master = layout_fixture(tmp_path)
    service, host = adoption_host(tmp_path, layout, data, master)
    spec = VPMServiceSpec(PIN, 'dc.example.com', writes_enabled=True, expected_account_id='customer-account')
    service.adopt(spec, layout)
    host.calls.clear()
    result = service.adopt(spec, layout)
    assert result['status'] == 'already-adopted'
    assert not any(call[:2] in (['systemctl', 'disable'], ['systemctl', 'restart']) for call in host.calls)


def test_recovery_failure_never_restarts_prior_image_or_timers(tmp_path):
    layout, data, master = layout_fixture(tmp_path)
    service, host = adoption_host(tmp_path, layout, data, master)
    original = service._data_recovery
    def recovery(spec, path, action):
        if action == 'restore':
            raise RuntimeError('synthetic snapshot unreadable')
        return original(spec, path, action)
    service._data_recovery = recovery
    service._wait_for_health = lambda: (_ for _ in ()).throw(RuntimeError('synthetic unhealthy'))
    with pytest.raises(RuntimeError, match='forward repair'):
        service.adopt(VPMServiceSpec(PIN, 'dc.example.com', writes_enabled=True, expected_account_id='customer-account'), layout)
    assert ['systemctl', 'start', layout.owner_unit] not in host.calls
    assert not any(call[:2] == ['systemctl', 'start'] for call in host.calls)


def test_normal_update_restores_schema_snapshot_before_prior_image(tmp_path):
    layout, data, master = layout_fixture(tmp_path)
    service, host = adoption_host(tmp_path, layout, data, master)
    service._has_existing_managed_vpm = lambda: True
    service.managed_runtime_state = lambda: {'writes_enabled': True, 'automation_paused': True}
    service.root.mkdir(parents=True)
    spec = VPMServiceSpec(PIN, 'dc.example.com', writes_enabled=True, data_kind='bind', data_source=str(data), master_key_file=str(master))
    service.compose_file.write_text(service.render(spec).compose)
    original_launch = service._launch
    launched = []
    def launch(target):
        original_launch(target)
        if launched:
            return
        launched.append(True)
        with sqlite3.connect(data / 'vpm.sqlite3') as database:
            database.execute('ALTER TABLE policies ADD COLUMN new_schema TEXT')
            database.execute('UPDATE policies SET floor_price=9')
    service._launch = launch
    service._wait_for_health = lambda: (_ for _ in ()).throw(RuntimeError('synthetic unhealthy'))
    with pytest.raises(RuntimeError):
        service.install(spec)
    with sqlite3.connect(data / 'vpm.sqlite3') as database:
        assert database.execute('SELECT floor_price FROM policies').fetchone()[0] == .42
        assert 'new_schema' not in {row[1] for row in database.execute('PRAGMA table_info(policies)')}


def test_encrypted_owner_makes_runtime_credential_readable_by_vpm_uid(tmp_path):
    spec = VPMServiceSpec(PIN, 'dc.example.com', credential_mode='systemd-encrypted',
                          credential_reference='/etc/credstore.encrypted/customer-vpm.key')
    unit = VPMServiceManager.render(spec).units['vast-price-manager-container.service']
    assert 'User=999\nGroup=999\nSupplementaryGroups=docker\n' in unit


def test_declared_source_mount_can_be_retired_but_unknown_mount_fails(tmp_path):
    from dataclasses import replace
    layout, data, master = layout_fixture(tmp_path)
    layout = replace(layout, retired_mount_targets=('/app/src',))
    service, host = adoption_host(tmp_path, layout, data, master)
    original = service.runner
    def with_source(command, **kwargs):
        result = original(command, **kwargs)
        if command[:3] == ['docker', 'inspect', '-f'] and '"mounts"' in command[3]:
            info = json.loads(result.stdout)
            info['mounts'].append({'Type': 'bind', 'Source': '/synthetic/source', 'Destination': '/app/src', 'RW': False})
            result.stdout = json.dumps(info)
        return result
    service.runner = with_source
    assert service.inspect_layout(layout)['ownership_verified'] is True
    with pytest.raises(RuntimeError, match='custody binding'):
        service.inspect_layout(replace(layout, retired_mount_targets=()))


def test_shared_obsolete_auth_dependency_fails_before_quiescing(tmp_path):
    layout, data, master = layout_fixture(tmp_path)
    service, host = adoption_host(tmp_path, layout, data, master)
    original = service.runner
    def consumers(command, **kwargs):
        if command[:2] == ['systemctl', 'list-dependencies']:
            return SimpleNamespace(returncode=0, stdout=layout.owner_unit + '\nother-product.service\n', stderr='')
        return original(command, **kwargs)
    service.runner = consumers
    with pytest.raises(RuntimeError, match='shared|consumer'):
        service.plan_adoption(VPMServiceSpec(PIN, 'dc.example.com', writes_enabled=True, expected_account_id='customer-account'), layout)
    assert not any(call[:2] == ['systemctl', 'disable'] for call in host.calls)


@pytest.mark.parametrize('status, expected', [(401, True), (200, False), (503, False), (302, False)])
def test_auth_probe_enforces_denial_and_refuses_redirects_without_credentials(tmp_path, status, expected):
    import contextlib
    import io
    from urllib.error import HTTPError
    from urllib.request import HTTPRedirectHandler, ProxyHandler, Request
    from dc_overview.vpm_service import _VPM_AUTH_BOUNDARY_PROBE
    requests = []
    class Endpoint:
        def open(self, request, timeout):
            requests.append((request.full_url, request.get_header('Cookie')))
            if status != 200:
                raise HTTPError(request.full_url, status, 'synthetic', {}, None)
            return SimpleNamespace(status=200)
    def build_opener(*handlers):
        assert isinstance(handlers[0], ProxyHandler)
        assert handlers[0].proxies == {}
        assert isinstance(handlers[1], HTTPRedirectHandler)
        assert handlers[1].redirect_request(None, None, 302, '', {}, '/redirect') is None
        return Endpoint()
    def runner(command, **kwargs):
        program = _VPM_AUTH_BOUNDARY_PROBE.replace('from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener', '')
        namespace = dict(HTTPRedirectHandler=HTTPRedirectHandler, ProxyHandler=ProxyHandler,
                         Request=Request, build_opener=build_opener)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exec(program, namespace)
        return SimpleNamespace(returncode=0, stdout=output.getvalue(), stderr='')
    service = VPMServiceManager(tmp_path, runner=runner)
    assert service._verify_auth_boundary() is expected
    assert requests == [('http://cryptolabs-proxy:8081/auth/vast-price-manager/session', None)]


def test_timer_restore_failure_is_not_reported_as_success(tmp_path):
    service, host = manager(tmp_path)
    original = service.runner
    def cannot_enable(command, **kwargs):
        if command[:2] == ['systemctl', 'enable']:
            return SimpleNamespace(returncode=1, stdout='', stderr='synthetic denied')
        return original(command, **kwargs)
    service.runner = cannot_enable
    with pytest.raises(RuntimeError):
        service.install(VPMServiceSpec(PIN, 'dc.example.com'))


def test_pre_snapshot_control_failure_restores_source_timer_states(tmp_path):
    layout, data, master = layout_fixture(tmp_path)
    service, host = adoption_host(tmp_path, layout, data, master)
    original = service._continuity
    count = []
    def changed(*args):
        count.append(True)
        if len(count) == 2:
            raise RuntimeError('synthetic unavailable state after quiesce')
        return original(*args)
    service._continuity = changed
    with pytest.raises(RuntimeError):
        service.adopt(VPMServiceSpec(PIN, 'dc.example.com', writes_enabled=True, expected_account_id='customer-account'), layout)
    assert ['systemctl', 'enable', layout.timer_names[0]] in host.calls
    assert ['systemctl', 'start', layout.timer_names[1]] in host.calls


def test_adoption_refuses_to_drop_existing_expected_account_authority(tmp_path):
    layout, data, master = layout_fixture(tmp_path)
    service, host = adoption_host(tmp_path, layout, data, master)
    with pytest.raises(RuntimeError, match='expected account'):
        service.plan_adoption(VPMServiceSpec(PIN, 'dc.example.com', writes_enabled=True), layout)


def test_repeat_adoption_rejects_replaced_valid_key_and_ciphertext(tmp_path):
    from cryptography.fernet import Fernet
    layout, data, master = layout_fixture(tmp_path)
    service, host = adoption_host(tmp_path, layout, data, master)
    spec = VPMServiceSpec(PIN, 'dc.example.com', writes_enabled=True, expected_account_id='customer-account')
    service.adopt(spec, layout)
    master.write_bytes(Fernet.generate_key())
    (data / 'credentials' / 'reader-a.enc').write_bytes(Fernet(master.read_bytes()).encrypt(b'synthetic-api-key'))
    with pytest.raises(RuntimeError, match='continuity|identity'):
        service.adopt(spec, layout)


def test_normal_update_preserves_custom_timer_cadence(tmp_path):
    service, host = manager(tmp_path)
    service.unit_dir.mkdir()
    timer = service.unit_dir / service.timer_names[0]
    timer.write_text('[Timer]\nOnCalendar=*-*-* 03:12:00\nPersistent=false\nUnit=vast-price-manager-sync.service\n')
    service.install(VPMServiceSpec(PIN, 'dc.example.com'))
    assert 'OnCalendar=*-*-* 03:12:00' in timer.read_text()
    assert 'Persistent=false' in timer.read_text()


def test_adopted_timer_keeps_cadence_without_obsolete_unit_dependency(tmp_path):
    layout, data, master = layout_fixture(tmp_path)
    service, host = adoption_host(tmp_path, layout, data, master)
    path = service.unit_dir / layout.timer_names[0]
    path.write_text('[Unit]\nAfter=obsolete-auth.service\n[Timer]\nOnCalendar=*-*-* 03:12:00\nPersistent=false\nUnit=legacy-sync.service\n')
    service.adopt(VPMServiceSpec(PIN, 'dc.example.com', writes_enabled=True, expected_account_id='customer-account'), layout)
    timer = (service.unit_dir / service.timer_names[0]).read_text()
    assert 'OnCalendar=*-*-* 03:12:00' in timer
    assert 'obsolete-auth.service' not in timer


def test_undeclared_timer_dropin_fails_before_owner_mutation(tmp_path):
    layout, data, master = layout_fixture(tmp_path)
    service, host = adoption_host(tmp_path, layout, data, master)
    directory = service.unit_dir / (layout.timer_names[0] + '.d')
    directory.mkdir()
    (directory / 'override.conf').write_text('[Timer]\nOnCalendar=minutely\n')
    with pytest.raises(RuntimeError, match='drop-in|dropin'):
        service.adopt(VPMServiceSpec(PIN, 'dc.example.com', writes_enabled=True, expected_account_id='customer-account'), layout)
    assert not any(call[:2] == ['systemctl', 'disable'] for call in host.calls)


def test_failed_timer_quiesce_blocks_normal_update_launch(tmp_path):
    service, host = manager(tmp_path)
    original = service.runner
    def cannot_disable(command, **kwargs):
        if command[:2] == ['systemctl', 'disable']:
            return SimpleNamespace(returncode=1, stdout='', stderr='synthetic disable failed')
        return original(command, **kwargs)
    service.runner = cannot_disable
    with pytest.raises(RuntimeError):
        service.install(VPMServiceSpec(PIN, 'dc.example.com'))
    assert not any(call[-2:] == ['up', '-d'] for call in host.calls)


def test_forward_hold_disables_encrypted_container_owner_as_well_as_timers(tmp_path):
    service, host = manager(tmp_path)
    service.unit_dir.mkdir()
    (service.unit_dir / 'vast-price-manager-container.service').write_text('[Service]\nRemainAfterExit=yes\n')
    service._hold_candidate_for_forward_repair()
    assert ['systemctl', 'disable', '--now', 'vast-price-manager-container.service'] in host.calls


def test_repeat_adoption_preserves_later_operator_policy_and_pause_changes(tmp_path):
    layout, data, master = layout_fixture(tmp_path)
    service, host = adoption_host(tmp_path, layout, data, master)
    spec = VPMServiceSpec(PIN, 'dc.example.com', writes_enabled=True, expected_account_id='customer-account')
    service.adopt(spec, layout)
    with sqlite3.connect(data / 'vpm.sqlite3') as database:
        database.execute('UPDATE settings SET automation_paused=0')
        database.execute('UPDATE policies SET floor_price=.75')
    result = service.adopt(spec, layout)
    assert result['status'] == 'already-adopted'
    with sqlite3.connect(data / 'vpm.sqlite3') as database:
        assert database.execute('SELECT automation_paused FROM settings').fetchone()[0] == 0
        assert database.execute('SELECT floor_price FROM policies').fetchone()[0] == .75


def test_stopped_pause_proof_requests_only_database_path_environment_inputs(tmp_path):
    calls = []
    def runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout='VPM_DATA_DIR=/data\nVPM_DATABASE_PATH=/data/vpm.sqlite3\n', stderr='')
    service = VPMServiceManager(tmp_path, runner=runner)
    assert service._stopped_managed_database_path() == '/data/vpm.sqlite3'
    template = calls[0][3]
    assert 'VPM_DATA_DIR' in template
    assert 'VPM_DATABASE_PATH' in template
    assert '{{range .Config.Env}}{{println .}}{{end}}' not in template


def test_is_adopted_validates_canonical_binding_and_key_authority_without_mutation(tmp_path):
    layout, data, master = layout_fixture(tmp_path)
    service, host = adoption_host(tmp_path, layout, data, master)
    assert service.is_adopted(layout) is False
    service.adopt(VPMServiceSpec(PIN, 'dc.example.com', writes_enabled=True, expected_account_id='customer-account'), layout)
    host.calls.clear()
    assert service.is_adopted(layout) is True
    assert not any(call[:2] in (['systemctl', 'disable'], ['systemctl', 'restart']) for call in host.calls)
    original = service.runner
    def replaced_binding(command, **kwargs):
        result = original(command, **kwargs)
        if command[:3] == ['docker', 'inspect', '-f'] and '"mounts"' in command[3]:
            info = json.loads(result.stdout)
            info['mounts'][0]['Source'] = '/different-data'
            result.stdout = json.dumps(info)
        return result
    service.runner = replaced_binding
    with pytest.raises(RuntimeError, match='binding'):
        service.is_adopted(layout)


def test_public_adopted_spec_persists_canonical_encrypted_runtime_reference(tmp_path):
    layout, data, master = layout_fixture(tmp_path, encrypted=True)
    spec = VPMServiceSpec(PIN, 'dc.example.com', writes_enabled=True, expected_account_id='customer-account')
    result = VPMServiceManager.adopted_spec(spec, layout)
    assert result.master_key_file == '/run/credentials/vast-price-manager-container.service/vpm-master.key'
    assert result.credential_reference == layout.credential_reference
    assert result.data_source == layout.data_source


@pytest.mark.parametrize('unit_kind, metadata', [
    ('canonical-service', {'DropInPaths':'/run/systemd/system/service.d/inherited.conf'}),
    ('canonical-timer', {'DropInPaths':'/usr/lib/systemd/system/timer.d/vendor.conf'}),
    ('canonical-owner', {'Names':'vast-price-manager-container.service private-owner.service'}),
    ('source-owner', {'FragmentPath':'/run/systemd/system/legacy-owner.service'}),
    ('source-service', {'DropInPaths':'/run/systemd/system/legacy-.service.d/override.conf'}),
])
def test_repair_effective_inactive_unit_overrides_refuse_before_mutation(tmp_path, unit_kind, metadata):
    layout,data,master = layout_fixture(tmp_path)
    service,host = adoption_host(tmp_path,layout,data,master)
    names = {'canonical-service':service.service_names[1], 'canonical-timer':service.timer_names[0],
        'canonical-owner':'vast-price-manager-container.service', 'source-owner':layout.owner_unit,
        'source-service':layout.timer_names[0].replace('.timer','.service')}
    host.unit_metadata[names[unit_kind]] = metadata
    with pytest.raises(RuntimeError,match='ownership|override|alias|fragment|drop-in'):
        service.adopt(VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True,expected_account_id='customer-account'),layout)
    assert not any(call[:2] in (['systemctl','disable'],['systemctl','stop']) for call in host.calls)


def test_repair_canonical_disk_dropin_is_retained_and_refused(tmp_path):
    layout,data,master = layout_fixture(tmp_path)
    service,host = adoption_host(tmp_path,layout,data,master)
    override=service.unit_dir/(service.service_names[1]+'.d')/'override.conf'
    override.parent.mkdir()
    override.write_text('[Service]\nExecStart=\nExecStart=/synthetic/private cycle\n')
    with pytest.raises(RuntimeError,match='drop-in|ownership'):
        service.adopt(VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True,expected_account_id='customer-account'),layout)
    assert override.exists()
    assert not any(call[:2] == ['systemctl','disable'] for call in host.calls)


def test_repair_loaded_canonical_override_after_reload_blocks_launch(tmp_path):
    layout,data,master = layout_fixture(tmp_path)
    service,host = adoption_host(tmp_path,layout,data,master)
    original=service.runner
    def injected(command,**kwargs):
        result=original(command,**kwargs)
        if command == ['systemctl','daemon-reload']:
            host.unit_metadata[service.service_names[1]]={'DropInPaths':'/run/systemd/system/service.d/racing.conf'}
        return result
    service.runner=injected
    with pytest.raises(RuntimeError):
        service.adopt(VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True,expected_account_id='customer-account'),layout)
    assert not any(call[-2:]==['up','-d'] and '-p' in call and call[call.index('-p')+1]==service.project_name for call in host.calls)
    assert not (service.root/'adoption.json').exists()


@pytest.mark.parametrize('api',['is_adopted','repeat'])
def test_repair_unpinned_actual_account_rotation_is_rejected(tmp_path,api):
    layout,data,master=layout_fixture(tmp_path)
    service,host=adoption_host(tmp_path,layout,data,master,expected_account_id=None)
    spec=VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True)
    service.adopt(spec,layout)
    with sqlite3.connect(data/'vpm.sqlite3') as db:
        db.execute("UPDATE settings SET account_id='replacement-account'")
        db.execute("UPDATE setup_state SET account_id='replacement-account'")
    with pytest.raises(RuntimeError,match='authority|identity|continuity'):
        service.is_adopted(layout) if api=='is_adopted' else service.adopt(spec,layout)


def test_repair_inconsistent_account_rows_hold_before_mutation(tmp_path):
    layout,data,master=layout_fixture(tmp_path)
    service,host=adoption_host(tmp_path,layout,data,master,expected_account_id=None)
    with sqlite3.connect(data/'vpm.sqlite3') as db:
        db.execute("UPDATE setup_state SET account_id='other-account'")
    with pytest.raises(RuntimeError,match='continuity'):
        service.adopt(VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True),layout)
    assert not any(call[:2]==['systemctl','disable'] for call in host.calls)


def test_repair_mutable_pause_policy_and_provider_slot_rotation_stays_allowed(tmp_path):
    from cryptography.fernet import Fernet
    layout,data,master=layout_fixture(tmp_path)
    service,host=adoption_host(tmp_path,layout,data,master,expected_account_id=None)
    spec=VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True)
    service.adopt(spec,layout)
    (data/'credentials'/'reader-b.enc').write_bytes(Fernet(master.read_bytes()).encrypt(b'synthetic-rotated-key'))
    with sqlite3.connect(data/'vpm.sqlite3') as db:
        db.execute('UPDATE settings SET automation_paused=0')
        db.execute('UPDATE policies SET floor_price=.9')
        db.execute("UPDATE credential_slots SET slot='b'")
    assert service.is_adopted(layout) is True
    assert service.adopt(spec,layout)['status']=='already-adopted'


@pytest.mark.parametrize('enabled,active',[(True,True),(False,True),(True,False),(False,False)])
def test_repair_late_timer_failure_restores_auth_before_old_owner(tmp_path,enabled,active):
    layout,data,master=layout_fixture(tmp_path)
    service,host=adoption_host(tmp_path,layout,data,master)
    host.states[layout.obsolete_auth_unit]={'enabled':enabled,'active':active}
    original=service.runner
    failed=[]
    def injected(command,**kwargs):
        if command==['systemctl','start',service.timer_names[1]] and not failed:
            failed.append(True)
            return SimpleNamespace(returncode=1,stdout='',stderr='synthetic late timer failure')
        return original(command,**kwargs)
    service.runner=injected
    with pytest.raises(RuntimeError,match='recovered'):
        service.adopt(VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True,expected_account_id='customer-account'),layout)
    assert host.states[layout.obsolete_auth_unit]=={'enabled':enabled,'active':active}
    if active:
        assert host.calls.index(['systemctl','start',layout.obsolete_auth_unit]) < host.calls.index(['systemctl','start',layout.owner_unit])
    assert ['systemctl','is-active',layout.obsolete_auth_unit] in host.calls


def test_repair_failed_auth_restoration_holds_old_owner(tmp_path):
    layout,data,master=layout_fixture(tmp_path)
    service,host=adoption_host(tmp_path,layout,data,master)
    original=service.runner
    failed=[]
    def injected(command,**kwargs):
        if command==['systemctl','start',service.timer_names[1]] and not failed:
            failed.append(True)
            return SimpleNamespace(returncode=1,stdout='',stderr='synthetic late timer failure')
        if command==['systemctl','start',layout.obsolete_auth_unit]:
            return SimpleNamespace(returncode=1,stdout='',stderr='synthetic auth restore failure')
        return original(command,**kwargs)
    service.runner=injected
    with pytest.raises(RuntimeError,match='forward repair'):
        service.adopt(VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True,expected_account_id='customer-account'),layout)
    assert ['systemctl','start',layout.owner_unit] not in host.calls


def test_repair_encrypted_owner_uses_supported_standalone_compose(tmp_path,monkeypatch):
    layout,data,master=layout_fixture(tmp_path,encrypted=True)
    service,host=adoption_host(tmp_path,layout,data,master)
    monkeypatch.setattr('dc_overview.vpm_service.shutil.which',lambda name:'/usr/local/bin/docker-compose' if name=='docker-compose' else None)
    service.adopt(VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True,expected_account_id='customer-account'),layout)
    owner=(service.unit_dir/'vast-price-manager-container.service').read_text()
    assert 'ExecStart=/usr/local/bin/docker-compose -p vast-price-manager ' in owner


def test_repair_marker_publication_failure_restores_auth_and_leaves_no_marker(tmp_path,monkeypatch):
    import os
    layout,data,master=layout_fixture(tmp_path)
    service,host=adoption_host(tmp_path,layout,data,master)
    original=os.replace
    def failed_marker(source,target):
        if Path(target)==service.root/'adoption.json':
            raise OSError('synthetic marker publication failure')
        return original(source,target)
    monkeypatch.setattr('dc_overview.vpm_service.os.replace',failed_marker)
    with pytest.raises(RuntimeError,match='recovered'):
        service.adopt(VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True,expected_account_id='customer-account'),layout)
    assert host.states[layout.obsolete_auth_unit]=={'enabled':True,'active':True}
    assert host.calls.index(['systemctl','start',layout.obsolete_auth_unit]) < host.calls.index(['systemctl','start',layout.owner_unit])
    assert not (service.root/'adoption.json').exists()


def test_repair_auth_command_success_without_active_state_is_unverified(tmp_path):
    layout,data,master=layout_fixture(tmp_path)
    service,host=adoption_host(tmp_path,layout,data,master)
    original=service.runner
    failed=[]
    def injected(command,**kwargs):
        if command==['systemctl','start',service.timer_names[1]] and not failed:
            failed.append(True)
            return SimpleNamespace(returncode=1,stdout='',stderr='synthetic timer failure')
        if command==['systemctl','start',layout.obsolete_auth_unit]:
            host.calls.append(command)
            return SimpleNamespace(returncode=0,stdout='',stderr='')
        return original(command,**kwargs)
    service.runner=injected
    with pytest.raises(RuntimeError,match='forward repair'):
        service.adopt(VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True,expected_account_id='customer-account'),layout)
    assert ['systemctl','start',layout.owner_unit] not in host.calls


@pytest.mark.parametrize('api',['is_adopted','repeat'])
@pytest.mark.parametrize('target',['service','timer'])
def test_repair_post_adoption_base_owner_tamper_rejects_read_only_and_repeat(tmp_path,api,target):
    layout,data,master=layout_fixture(tmp_path)
    service,host=adoption_host(tmp_path,layout,data,master)
    spec=VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True,expected_account_id='customer-account')
    service.adopt(spec,layout)
    path=service.unit_dir/(service.service_names[1] if target=='service' else service.timer_names[1])
    path.write_text('[Service]\nExecStart=/synthetic/private cycle\n' if target=='service' else '[Timer]\nOnCalendar=daily\nUnit=private.service\n')
    host.calls.clear()
    with pytest.raises(RuntimeError,match='ownership'):
        service.is_adopted(layout) if api=='is_adopted' else service.adopt(spec,layout)
    assert not any(call[:2] in (['systemctl','disable'],['systemctl','restart']) for call in host.calls)


def test_repair_loaded_execution_uid_mismatch_after_reload_blocks_launch(tmp_path):
    layout,data,master=layout_fixture(tmp_path)
    service,host=adoption_host(tmp_path,layout,data,master)
    original=service.runner
    def injected(command,**kwargs):
        result=original(command,**kwargs)
        if command==['systemctl','daemon-reload']:
            host.unit_metadata[service.service_names[1]]={'User':'private-owner'}
        return result
    service.runner=injected
    with pytest.raises(RuntimeError):
        service.adopt(VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True,expected_account_id='customer-account'),layout)
    assert not any(call[-2:]==['up','-d'] and '-p' in call and call[call.index('-p')+1]==service.project_name for call in host.calls)


def test_repair_unknown_inactive_installed_vpm_owner_fails_before_mutation(tmp_path):
    layout,data,master=layout_fixture(tmp_path)
    service,host=adoption_host(tmp_path,layout,data,master)
    host.extra_units=['vpm-unknown.service loaded inactive dead Unknown']
    with pytest.raises(RuntimeError,match='owner'):
        service.adopt(VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True,expected_account_id='customer-account'),layout)
    assert not any(call[:2]==['systemctl','disable'] for call in host.calls)


def test_repair_timer_interval_persistent_and_jitter_are_preserved(tmp_path):
    layout,data,master=layout_fixture(tmp_path)
    service,host=adoption_host(tmp_path,layout,data,master)
    source=service.unit_dir/layout.timer_names[0]
    source.write_text('[Timer]\nOnUnitActiveSec=71min\nRandomizedDelaySec=17min\nAccuracySec=13s\nPersistent=false\nUnit=legacy-sync.service\n')
    service.adopt(VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True,expected_account_id='customer-account'),layout)
    target=(service.unit_dir/service.timer_names[0]).read_text()
    for value in ('OnUnitActiveSec=71min','RandomizedDelaySec=17min','AccuracySec=13s','Persistent=false'):
        assert value in target
    assert host.states[service.timer_names[0]]=={'enabled':True,'active':False}
    assert host.states[service.timer_names[1]]=={'enabled':False,'active':True}


def test_repair_pending_effective_override_reload_holds_before_mutation(tmp_path):
    layout,data,master=layout_fixture(tmp_path)
    service,host=adoption_host(tmp_path,layout,data,master)
    host.unit_metadata[layout.owner_unit]={'NeedDaemonReload':'yes'}
    with pytest.raises(RuntimeError,match='reload|ownership'):
        service.adopt(VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True,expected_account_id='customer-account'),layout)
    assert not any(call[:2]==['systemctl','disable'] for call in host.calls)


def test_repair_unavailable_source_owner_state_holds_before_mutation(tmp_path):
    layout,data,master=layout_fixture(tmp_path)
    service,host=adoption_host(tmp_path,layout,data,master)
    original=service.runner
    def unavailable(command,**kwargs):
        if command==['systemctl','is-active',layout.owner_unit]:
            return SimpleNamespace(returncode=1,stdout='',stderr='synthetic state unavailable')
        return original(command,**kwargs)
    service.runner=unavailable
    with pytest.raises(RuntimeError,match='state'):
        service.adopt(VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True,expected_account_id='customer-account'),layout)
    assert not any(call[:2]==['systemctl','disable'] for call in host.calls)


def test_repair_late_recovery_verifies_units_before_recreating_absent_old_container(tmp_path):
    layout,data,master=layout_fixture(tmp_path)
    service,host=adoption_host(tmp_path,layout,data,master)
    original=service.runner
    present=[True]
    failed=[]
    def stateful(command,**kwargs):
        if command[:2]==['docker','ps'] and not present[0]:
            host.calls.append(command)
            return SimpleNamespace(returncode=0,stdout='',stderr='')
        if command==['systemctl','start',service.timer_names[1]] and not failed:
            failed.append(True)
            return SimpleNamespace(returncode=1,stdout='',stderr='synthetic timer failure')
        result=original(command,**kwargs)
        if 'rm' in command and '-f' in command:
            present[0]=False
        elif command==['systemctl','start',layout.owner_unit] or ('up' in command and '-d' in command):
            present[0]=True
        return result
    service.runner=stateful
    with pytest.raises(RuntimeError,match='recovered'):
        service.adopt(VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True,expected_account_id='customer-account'),layout)
    assert present[0] is True
    assert host.states[layout.obsolete_auth_unit]=={'enabled':True,'active':True}
    assert host.states[layout.owner_unit]=={'enabled':True,'active':True}
    assert host.states[layout.timer_names[0]]=={'enabled':True,'active':False}
    assert host.states[layout.timer_names[1]]=={'enabled':False,'active':True}


def test_repair_normal_update_rollback_cannot_launch_unverified_loaded_owner(tmp_path):
    layout,data,master=layout_fixture(tmp_path)
    service,host=adoption_host(tmp_path,layout,data,master)
    service._has_existing_managed_vpm=lambda:True
    spec=VPMServiceSpec(PIN,'dc.example.com',data_kind='bind',data_source=str(data),master_key_file=str(master))
    service.root.mkdir(parents=True)
    service.compose_file.write_text(service.render(spec).compose)
    service._install_units(service.render(spec))
    original=service.runner
    reloads=[]
    launches=[]
    def injected(command,**kwargs):
        result=original(command,**kwargs)
        if command==['systemctl','daemon-reload']:
            reloads.append(True)
            if len(reloads)==2:
                host.unit_metadata[service.service_names[0]]={'DropInPaths':'/run/systemd/system/service.d/private.conf'}
        if command[-2:]==['up','-d']:
            launches.append(True)
        return result
    service.runner=injected
    service._wait_for_health=lambda:(_ for _ in ()).throw(RuntimeError('synthetic candidate unhealthy'))
    with pytest.raises(RuntimeError,match='forward repair'):
        service.install(spec)
    assert len(launches)==1


def test_repair_legacy_named_container_health_is_checked_after_rollback(tmp_path):
    from dataclasses import replace
    layout,data,master=layout_fixture(tmp_path)
    layout=replace(layout,container_name='customer-vpm-original',service_name='pricing-worker')
    service,host=adoption_host(tmp_path,layout,data,master)
    original=service.runner
    failed=[]
    def injected(command,**kwargs):
        if command==['systemctl','start',service.timer_names[1]] and not failed:
            failed.append(True)
            return SimpleNamespace(returncode=1,stdout='',stderr='synthetic timer failure')
        return original(command,**kwargs)
    service.runner=injected
    with pytest.raises(RuntimeError,match='recovered'):
        service.adopt(VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True,expected_account_id='customer-account'),layout)
    owner_start=host.calls.index(['systemctl','start',layout.owner_unit])
    assert ['docker','inspect','-f','{{.State.Health.Status}}',layout.container_name] in host.calls[owner_start:]


def test_repair_failed_hold_delivery_never_claims_owners_held_stopped(tmp_path):
    layout,data,master=layout_fixture(tmp_path)
    service,host=adoption_host(tmp_path,layout,data,master)
    original=service.runner
    failed=[]
    def injected(command,**kwargs):
        if command==['systemctl','start',service.timer_names[1]] and not failed:
            failed.append(True)
            return SimpleNamespace(returncode=1,stdout='',stderr='synthetic late timer failure')
        if command in (['systemctl','start',layout.obsolete_auth_unit],['systemctl','stop',layout.owner_unit]):
            return SimpleNamespace(returncode=1,stdout='',stderr='synthetic failed delivery')
        return original(command,**kwargs)
    service.runner=injected
    with pytest.raises(RuntimeError,match='forward repair') as failure:
        service.adopt(VPMServiceSpec(PIN,'dc.example.com',writes_enabled=True,expected_account_id='customer-account'),layout)
    assert 'owners held stopped' not in str(failure.value)
    assert 'unverified' in str(failure.value)


def test_effective_owner_file_custody_rejects_enabled_inactive_canonical_container(tmp_path):
    layout, data, master = layout_fixture(tmp_path)
    service, host = adoption_host(tmp_path, layout, data, master)
    name = 'vast-price-manager-container.service'
    (service.unit_dir / name).write_text('[Service]\nExecStart=/synthetic/private-vpm serve\n')
    host.states[name] = {'enabled': True, 'active': False}
    with pytest.raises(RuntimeError, match='undeclared|ownership'):
        service.adopt(VPMServiceSpec(PIN, 'dc.example.com', writes_enabled=True,
                                    expected_account_id='customer-account'), layout)
    assert host.states[name] == {'enabled': True, 'active': False}
    assert not any(call[:2] in (['systemctl', 'disable'], ['systemctl', 'stop'],
                               ['docker', 'pull']) for call in host.calls)
    assert not service.compose_file.exists()


@pytest.mark.parametrize('triggers', ['customer-pricing-worker.service', '',
                                   'legacy-sync.service customer-pricing-worker.service'])
def test_effective_owner_source_timer_requires_exact_declared_worker_before_effects(tmp_path, triggers):
    layout, data, master = layout_fixture(tmp_path)
    service, host = adoption_host(tmp_path, layout, data, master)
    name = 'customer-pricing-worker.service'
    (service.unit_dir / name).write_text('[Service]\nExecStart=/synthetic/private-vpm work\n')
    host.states[name] = {'enabled': True, 'active': True}
    host.extra_units = [name + ' loaded active running']
    host.unit_metadata[layout.timer_names[0]] = {'Triggers': triggers}
    with pytest.raises(RuntimeError, match='timer.*ownership'):
        service.adopt(VPMServiceSpec(PIN, 'dc.example.com', writes_enabled=True,
                                    expected_account_id='customer-account'), layout)
    assert host.states[name]['active'] is True
    assert not any(call[:2] in (['systemctl', 'disable'], ['systemctl', 'stop'],
                               ['docker', 'pull']) for call in host.calls)
    assert not service.compose_file.exists()


@pytest.mark.parametrize('encrypted', [False, True])
def test_effective_owner_actual_unprintable_text_uses_typed_credential_references(tmp_path, encrypted):
    service, host = manager(tmp_path)
    reference = '/etc/credstore.encrypted/customer-vpm.key'
    spec = VPMServiceSpec(PIN, 'dc.example.com', credential_mode='systemd-encrypted' if encrypted else 'file',
                          credential_reference=reference if encrypted else None)
    rendered = service.render(spec)
    service._install_units(rendered)
    for name in rendered.units:
        if name.endswith('.service'):
            host.unit_metadata[name] = {'LoadCredential': '[unprintable]', 'LoadCredentialEncrypted': '[unprintable]'}
    service._verify_loaded_product_units(rendered)
    assert any(call[:3] == ['busctl', '--json=short', 'get-property'] for call in host.calls)


@pytest.mark.parametrize('property_name,metadata', [
    ('ImportCredential', {'type': 'as', 'data': ['extra']}),
    ('LoadCredentialEncrypted', {'type': 'a(ss)', 'data': [['extra', '/etc/extra.cred']]}),
    ('LoadCredential', {'type': 'a(ss)', 'data': [['plain', '/etc/plain.key']]}),
    ('LoadCredentialEncrypted', {'type': 'as', 'data': []}),
    ('LoadCredentialEncrypted', {'type': 'a(ss)', 'data': [['vpm-master.key']]}),
    ('LoadCredentialEncrypted', {'type': 'a(ss)', 'data': [['id', None]]}),
    ('LoadCredentialEncrypted', {'type': 'a(ss)', 'data': 'not-an-array'}),
    ('LoadCredentialEncrypted', {'type': 'a(ss)', 'data': [], 'extra': True}),
])
def test_effective_owner_typed_ordinary_custody_rejects_extra_or_malformed(tmp_path, property_name, metadata):
    service, host = manager(tmp_path)
    rendered = service.render(VPMServiceSpec(PIN, 'dc.example.com'))
    service._install_units(rendered)
    host.credential_metadata[(service.service_names[0], property_name)] = metadata
    with pytest.raises(RuntimeError, match='credential|custody'):
        service._verify_loaded_product_units(rendered)


@pytest.mark.parametrize('rows', [[], [['vpm-master.key', '/etc/wrong.cred']],
    [['vpm-master.key', '/etc/customer.cred'], ['extra', '/etc/extra.cred']],
    [['vpm-master.key', '/etc/customer.cred'], ['vpm-master.key', '/etc/customer.cred']]])
def test_effective_owner_encrypted_custody_requires_exact_complete_reference(tmp_path, rows):
    service, host = manager(tmp_path)
    rendered = service.render(VPMServiceSpec(PIN, 'dc.example.com', credential_mode='systemd-encrypted',
                                            credential_reference='/etc/customer.cred'))
    service._install_units(rendered)
    host.credential_metadata[('vast-price-manager-container.service', 'LoadCredentialEncrypted')] = {
        'type': 'a(ss)', 'data': rows}
    with pytest.raises(RuntimeError, match='credential|custody'):
        service._verify_loaded_product_units(rendered)


def test_effective_owner_ordinary_install_rejects_undeclared_container_before_effects(tmp_path):
    service, host = manager(tmp_path)
    service.unit_dir.mkdir()
    name = 'vast-price-manager-container.service'
    (service.unit_dir / name).write_text('[Service]\nExecStart=/synthetic/private-vpm serve\n')
    host.states[name] = {'enabled': True, 'active': False}
    with pytest.raises(RuntimeError, match='undeclared|ownership'):
        service.install(VPMServiceSpec(PIN, 'dc.example.com'))
    assert not any(call[:2] in (['systemctl', 'disable'], ['systemctl', 'stop']) for call in host.calls)


def test_effective_owner_generated_verification_rejects_omitted_container(tmp_path):
    service, host = manager(tmp_path)
    rendered = service.render(VPMServiceSpec(PIN, 'dc.example.com'))
    service._install_units(rendered)
    (service.unit_dir / 'vast-price-manager-container.service').write_text('[Service]\nExecStart=/synthetic/private serve\n')
    with pytest.raises(RuntimeError, match='undeclared|ownership'):
        service._verify_loaded_product_units(rendered)
