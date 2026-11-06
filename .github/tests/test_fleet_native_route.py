# TRACEWEAVER: file-role=native-route-verification; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
# TRACEWEAVER: verifies=VER-FLEETUPDATE-001; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001
"""Bounded security contract for the explicit native QA route; no guest execution."""

import ast
import base64
import importlib.util
import hashlib
import json
import os
import runpy
import selectors
import subprocess
import shutil
import sys
import tempfile
import tomllib
import traceback
import types
import unittest
import sqlite3
import zipfile
from contextlib import ExitStack, contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/fleet-release-native-qa.yml"
SCRIPT = ROOT / "scripts/verify_fleet_release_native.py"
# Frozen external contract: runner_caches.py at 912762eb4b16f0fb956a3b4247f98dfedd96fa3f,
# independently retained promotion recipe SHA256 f4ab2dbc2108c13306443fbbb5b5d1dfa3ee727c1e06f5c6609055226b655738.
GUEST_HOSTS = (
    b'server = "https://ghcr.io"\n\n[host."https://192.168.1.101:5444"]\n'
    b'  capabilities = ["pull", "resolve"]\n'
    b'  ca = "/etc/docker/certs.d/192.168.1.101:5444/ca.crt"\n'
)


@contextmanager
def private_owner_temp(module):
    """Use a private fixture with ancestry accepted by the real custody policy."""
    parent = None
    if module.platform.system() == "Linux":
        parent = Path.home()
        if parent.lstat().st_uid != os.geteuid():
            raise ValueError("observation fixture home must belong to the current user")
        module.observation_directories(parent, private=False)
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        module.observation_directories(Path(directory))
        yield directory


@contextmanager
def owner_file_read_audit(module, limits, *, grow=None):
    """Observe real descriptor reads; short reads/growth defeat stat-only bounds."""
    opened, attempts = {}, []
    original_open, original_read, original_stat, original_loads = os.open, os.read, os.fstat, json.loads
    grown = set()
    def opening(name, *args, **kwargs):
        descriptor = original_open(name, *args, **kwargs)
        opened.pop(descriptor, None)  # Descriptor numbers can be reused for another record.
        if isinstance(name, (str, bytes, os.PathLike)) and Path(name) in limits:
            item = {"path": Path(name), "limit": limits[Path(name)], "total": 0, "requests": []}
            attempts.append(item); opened[descriptor] = item
        return descriptor
    def stating(descriptor):
        info = original_stat(descriptor)
        item = opened.get(descriptor)
        if item and item["path"] == grow and grow not in grown:
            with open(grow, "ab") as stream:
                stream.write(b" ")
            grown.add(grow)
        return info
    def reading(descriptor, count):
        item = opened.get(descriptor)
        if item:
            assert type(count) is int and 0 < count <= item["limit"] + 1 - item["total"]
            item["requests"].append(count)
        raw = original_read(descriptor, min(count, 8191) if item else count)
        if item:
            item["total"] += len(raw)
            assert item["total"] <= item["limit"] + 1
        return raw
    def parsing(raw, *args, **kwargs):
        assert len(raw) <= max(limits.values()), "overflow must be rejected before JSON parsing"
        return original_loads(raw, *args, **kwargs)
    with patch.object(module.os, "open", side_effect=opening), patch.object(module.os, "read", side_effect=reading), patch.object(module.os, "fstat", side_effect=stating), patch.object(module.json, "loads", side_effect=parsing):
        yield attempts


@contextmanager
def owner_inspect_boundary(module, payload, mode="ok"):
    """Only low-level child/clock/selector/read substitutes; no process is launched."""
    clock = [100.0]
    audit = {"requests": [], "total": 0, "waits": [], "events": []}
    stdout = SimpleNamespace(fileno=lambda: 77, close=unittest.mock.Mock())
    exited = [False]
    def waiting(timeout):
        assert type(timeout) in (int, float) and 0 < timeout <= (105 if audit["killed"] or exited[0] else 104) - clock[0]
        audit["waits"].append((clock[0], timeout))
        if mode == "cleanup-timeout" or (mode == "eof-live" and not audit["killed"]):
            clock[0] += timeout
            raise subprocess.TimeoutExpired("PRIVATE", timeout)
        exited[0] = True
        return 17 if mode == "nonzero" else 0
    audit["killed"] = False
    def killing():
        audit["killed"] = True
    child = SimpleNamespace(stdout=stdout, poll=lambda: (0 if exited[0] else None), wait=unittest.mock.Mock(side_effect=waiting), kill=unittest.mock.Mock(side_effect=killing))
    def spawning(argv, **kwargs):
        self_expected = {"shell": False, "stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE,
                         "stderr": subprocess.DEVNULL, "bufsize": 0, "close_fds": True}
        assert argv == ["docker", "inspect", "cryptolabs-proxy"] and kwargs == self_expected
        clock[0] += 0.25  # Spawn time belongs to the same absolute deadline.
        if mode == "spawn-error":
            raise OSError("PRIVATE_SPAWN")
        return child
    def selecting(timeout):
        assert 0 < timeout <= 104 - clock[0]
        audit["events"].append(("select", clock[0], timeout))
        if mode == "timeout":
            clock[0] += timeout
            return []
        clock[0] += 0.00001
        return [(SimpleNamespace(fd=77, fileobj=stdout), selectors.EVENT_READ)]
    selector = SimpleNamespace(register=unittest.mock.Mock(), unregister=unittest.mock.Mock(), close=unittest.mock.Mock(), select=unittest.mock.Mock(side_effect=selecting))
    def reading(descriptor, count):
        assert descriptor == 77
        assert count == min(65536, 1048577 - audit["total"]) and count > 0
        audit["requests"].append(count)
        if mode == "read-error":
            raise OSError("PRIVATE_READ")
        if mode == "short" and len(audit["requests"]) == 1:
            raise BlockingIOError()
        raw = payload[audit["total"]:audit["total"] + min(count, 8191)]
        audit["total"] += len(raw)
        assert audit["total"] <= 1048577
        return raw
    setup = OSError("PRIVATE_SELECTOR") if mode == "setup-error" else None
    forbidden = AssertionError("unbounded/general command runner forbidden")
    with patch.object(module.subprocess, "Popen", side_effect=spawning) as spawn, patch.object(selectors, "DefaultSelector", side_effect=setup, return_value=selector), patch.object(module, "selectors", selectors, create=True), patch.object(module.os, "read", side_effect=reading), patch.object(module.os, "set_blocking", side_effect=lambda fd, enabled: (_ for _ in ()).throw(AssertionError("must be own nonblocking descriptor")) if (fd, enabled) != (77, False) else None), patch.object(module.time, "monotonic", side_effect=lambda: clock[0]), patch.object(module, "run", side_effect=forbidden), patch.object(module, "docker", side_effect=forbidden), patch.object(module, "inspect", side_effect=forbidden):
        yield audit
    assert spawn.call_count == 1
    if mode != "spawn-error":
        assert stdout.close.called
        assert child.wait.called
        if mode != "setup-error":
            assert selector.close.called
    assert clock[0] <= 105
    audit["child"] = child


class FleetNativeRouteTest(unittest.TestCase):
    # TRACEWEAVER: verifies=VER-AUTOADVANCE-008; req=REQ-AUTOADVANCE-008; trace=TRACE-AUTOADVANCE-008
    def test_selector_observer_coordinates_match_reviewed_broker(self):
        broker = ast.parse((ROOT / 'src/dc_overview/release_broker.py').read_text())
        operation = next(n for n in ast.walk(broker)
                         if isinstance(n, ast.FunctionDef) and n.name == 'run_operation')
        calls = [n.lineno for n in ast.walk(operation)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                 and n.func.id == 'select_release_components']
        self.assertEqual(len(calls), 1)
        verifier = ast.parse(SCRIPT.read_text())
        observer = next(n for n in ast.walk(verifier)
                        if isinstance(n, ast.FunctionDef) and n.name == 'observe_broker_owner_failures')
        coordinates = [n.comparators[0].value for n in ast.walk(observer)
                       if isinstance(n, ast.Compare) and isinstance(n.left, ast.Attribute)
                       and n.left.attr == 'tb_lineno' and len(n.comparators) == 1
                       and isinstance(n.comparators[0], ast.Constant)]
        self.assertEqual(coordinates, calls)

    # TRACEWEAVER: verifies=VER-AUTOADVANCE-008; req=REQ-AUTOADVANCE-008; trace=TRACE-AUTOADVANCE-008
    def test_approved_policy_source_pair_passes_real_guard_and_tampering_fails(self):
        module = self.native_module()
        proxy = ROOT.parent / "proxy"
        self.assertTrue(proxy.is_dir(), "Run with the reviewed Proxy checkout beside DC as proxy")
        proxy_sha = subprocess.check_output(["git", "-C", str(proxy), "rev-parse", "HEAD"]).decode().strip()
        self.assertEqual(proxy_sha, "6e5186401e78cc8ba7b6ffe18eb24712ef9263b1")
        workflow = yaml.safe_load(WORKFLOW.read_text())
        self.assertEqual(workflow["env"]["PROXY_SOURCE_SHA"], proxy_sha)
        required = {
            "src/dc_overview/release_policy.py",
            "src/dc_overview/templates/systemd/dc-overview-release-refresh.service",
            "src/dc_overview/templates/systemd/dc-overview-release-refresh.timer",
        }
        self.assertTrue(required <= module.FROZEN_PRODUCT_HASHES["dc"].keys())
        tree = ast.parse(SCRIPT.read_text())
        preflight = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "preflight")
        guard = next(n for n in ast.walk(preflight) if isinstance(n, ast.For)
                     and isinstance(n.target, ast.Tuple)
                     and [getattr(v, "id", None) for v in n.target.elts] == ["source", "expected", "product"])
        code = compile(ast.Module(body=[guard], type_ignores=[]), str(SCRIPT), "exec")
        with tempfile.TemporaryDirectory() as temporary:
            roots = {product: Path(temporary) / product for product in ("dc", "proxy")}
            for product, source in (("dc", ROOT), ("proxy", proxy)):
                for name in module.FROZEN_PRODUCT_HASHES[product]:
                    destination = roots[product] / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source / name, destination)
            args = SimpleNamespace(dc_source=roots["dc"], dc_sha="a" * 40,
                                   proxy_source=roots["proxy"], proxy_sha=proxy_sha)
            def git_identity(*arguments):
                self.assertEqual(arguments[0], "git")
                return SimpleNamespace(stdout=(args.dc_sha if arguments[2] == roots["dc"] else proxy_sha).encode())
            context = dict(self=SimpleNamespace(args=args), run=git_identity,
                           FROZEN_PRODUCT_HASHES=module.FROZEN_PRODUCT_HASHES,
                           digest=lambda value: hashlib.sha256(value).hexdigest())
            exec(code, context)
            for product, name in (("dc", "src/dc_overview/release_policy.py"),
                                  ("proxy", "src/cryptolabs_proxy/release_client.py")):
                path = roots[product] / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n# altered source\n")
                with self.assertRaisesRegex(RuntimeError, "frozen product source hash mismatch"):
                    exec(code, context)
                path.write_bytes(original)
            exec(code, context)

    def assert_bootstrap_failure_shape(self, metadata):
        failure = metadata.get("bootstrap_failure")
        self.assertIsInstance(failure, dict, "inner bootstrap diagnostics must survive the existing collector")
        self.assertEqual(set(failure), {"bootstrap_step", "code_label", "source_line", "guard_line",
                                        "error_kind", "command_outcome", "command_returncode", "scoped_select_diagnostic",
                                        "scoped_select_inner_diagnostic"})
        self.assertIs(type(failure["scoped_select_diagnostic"]), str)
        inner = failure['scoped_select_inner_diagnostic']
        self.assertIs(type(inner), dict)
        self.assertEqual(set(inner), {'guards', 'condition', 'require_capability', 'continuity_equal'})
        self.assertTrue(inner['continuity_equal'] == 'unknown' or
                        (type(inner['continuity_equal']) is dict and
                         set(inner['continuity_equal']) == set(self.native_module().CONTINUITY_FIELDS) and
                         all(type(v) is bool for v in inner['continuity_equal'].values())))
        self.assertIs(type(inner['guards']), list)
        for name in ('condition', 'require_capability'):
            self.assertTrue(type(inner[name]) is bool or (type(inner[name]) is str and inner[name] == 'unknown'))
        self.assertIn(failure["bootstrap_step"], {
            "legacy-runtime-inspect", "legacy-updater-probe", "legacy-capabilities-probe",
            "synthetic-runtime-inspect", "synthetic-db-seed", "synthetic-read-aggregate",
            "synthetic-root-custody", "synthetic-protection-helper", "legacy-job-seed",
            "compatible-wheel-install", "legacy-owner-rejection", "legacy-reconcile",
            "legacy-reconcile-replay", "scoped-select", "proxy-plan", "proxy-adopt", "proxy-health", "unknown",
        })
        self.assertIn(failure["code_label"], {"legacy-bootstrap", "synthetic-seed", "synthetic-helper", "native-command", "unknown"})
        self.assertIn(failure["error_kind"], {"assertion-error", "file-not-found", "permission-error", "os-error", "runtime-error", "unknown"})
        self.assertIn(failure["command_outcome"], {"nonzero-exit", "timeout", "spawn-error", "none", "unknown"})
        for field in ("source_line", "guard_line"):
            if failure[field] is not None:
                self.assertIs(type(failure[field]), int)
                self.assertGreater(failure[field], 0)
        if failure["command_returncode"] is not None:
            self.assertIs(type(failure["command_returncode"]), int)
            self.assertTrue(-255 <= failure["command_returncode"] <= 255)
        return failure

    def native_module(self):
        spec = importlib.util.spec_from_file_location("fleet_native_diagnostics", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_proxy_adoption_finish_retains_original_failure_without_replay(self):
        """Execute the real adoption prefix and finish/status failure path."""
        module = self.native_module()
        tree = ast.parse(SCRIPT.read_text())
        klass = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'NativeQA')
        method = next(n for n in klass.body if isinstance(n, ast.FunctionDef) and n.name == 'proxy_adopt')
        stop = next(i for i, n in enumerate(method.body) if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == 'final' for t in n.targets))
        prefix = compile(ast.Module(body=method.body[1:stop + 1], type_ignores=[]), str(SCRIPT), 'exec')
        identity = '00000000-0000-4000-8000-000000000011'
        params, preview, body = {'operation_kind': 'proxy-adopt'}, {'disconnect_expected': True}, {'operation_id': identity}
        for layout, reply, expected_branch in (
                ('named-volume', {'ok': True, 'result': {'state': 'recovery-required'}}, 'terminal-state'),
                ('named-volume', {'ok': False, 'error': {'status': 503, 'message': 'PRIVATE'}}, 'status-rejected'),
                ('bind', {'ok': True, 'result': {'state': 'recovery-required'}}, None)):
            with self.subTest(layout=layout, branch=expected_branch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                qa = module.NativeQA(SimpleNamespace(evidence_dir=root / 'evidence'))
                qa.layout, qa.auth = layout, root
                (root / 'users.json').write_bytes(b'PRIVATE')
                qa.preview = unittest.mock.Mock(return_value=(params, preview))
                qa.apply = unittest.mock.Mock(return_value=(identity, body))
                qa.proxy_adoption_observation = unittest.mock.Mock(return_value={'qualification': 'unknown'})
                qa.record = unittest.mock.Mock()
                with patch.object(module, 'raw_request', return_value=reply) as request:
                    try:
                        exec(prefix, {'self': qa, 'inspect': lambda name: {'Id': 'a' * 64}, 'digest': module.digest})
                    except RuntimeError as error:
                        original = error
                    else:
                        self.fail('original failing owner operation was accepted')
                self.assertEqual(str(original), 'owner operation held: recovery-required' if reply['ok'] else 'installed status unavailable')
                self.assertEqual(request.call_args_list, [unittest.mock.call('status', {'operation_id': identity})])
                qa.apply.assert_called_once_with(params, preview)
                if expected_branch is None:
                    qa.record.assert_not_called()
                    qa.proxy_adoption_observation.assert_not_called()
                    continue
                self.assertEqual(qa.record.call_count, 1, 'the named-volume failure currently loses its original branch')
                self.assertEqual(qa.record.call_args.args, ('proxy-adoption-observation',))
                packet = qa.record.call_args.kwargs
                self.assertEqual(packet['finish_branch'], expected_branch)
                self.assertEqual(packet['status_ok'], reply['ok'])
                self.assertEqual(packet['owner_state'], 'recovery-required' if reply['ok'] else 'unknown')
                self.assertEqual(packet['error_kind'], 'runtime-error')
                self.assertEqual(qa.proxy_adoption_observation.call_count, 1)
                self.assertNotIn('PRIVATE', json.dumps(packet))

    def test_proxy_adoption_collector_failure_keeps_exception_identity_and_trace(self):
        module = self.native_module()
        for failed_boundary in ('projection', 'record'):
            with self.subTest(failed_boundary=failed_boundary), tempfile.TemporaryDirectory() as directory:
                qa = module.NativeQA(SimpleNamespace(evidence_dir=Path(directory)))
                qa.layout = 'named-volume'
                original = RuntimeError('PRIVATE_ORIGINAL')
                qa.status = unittest.mock.Mock(side_effect=original)
                captured = []
                def project(*args):
                    self.assertIs(sys.exception(), original)
                    captured.append(original.__traceback__)
                    if failed_boundary == 'projection':
                        raise RuntimeError('PRIVATE_COLLECTOR')
                    return {'qualification': 'unknown'}
                qa.proxy_adoption_observation = unittest.mock.Mock(side_effect=project)
                qa.record = unittest.mock.Mock(side_effect=RuntimeError('PRIVATE_RECORD') if failed_boundary == 'record' else None)
                # The opt-in is part of the bounded verifier, never product API.
                try:
                    qa.finish('00000000-0000-4000-8000-000000000011', adoption_expected={})
                except TypeError:
                    self.fail('finish must support the source-scoped adoption diagnostic without changing its failure')
                except RuntimeError as caught:
                    self.assertIs(caught, original)
                    self.assertIs(caught.__traceback__.tb_next, captured[0],
                                  'explicit raise(error) would add a duplicate finish traceback frame')
                else:
                    self.fail('original exception must escape')
                self.assertEqual(qa.status.call_count, 1)
                self.assertEqual(qa.proxy_adoption_observation.call_count, 1)

    def test_proxy_adoption_original_wait_deadline_is_observed_without_retry(self):
        module = self.native_module()
        with tempfile.TemporaryDirectory() as directory:
            qa = module.NativeQA(SimpleNamespace(evidence_dir=Path(directory)))
            qa.layout = 'named-volume'
            qa.status = unittest.mock.Mock(return_value={'state': 'adopting'})
            qa.proxy_adoption_observation = unittest.mock.Mock(return_value={'qualification': 'unknown'})
            qa.record = unittest.mock.Mock()
            original = RuntimeError('actual owner operation did not finish')
            def timed_out(predicate, **kwargs):
                self.assertEqual(kwargs, {'timeout': 420, 'message': 'actual owner operation did not finish'})
                self.assertIsNone(predicate())
                raise original
            with patch.object(module, 'wait', side_effect=timed_out) as waiting:
                try:
                    qa.finish('00000000-0000-4000-8000-000000000011', adoption_expected={})
                except TypeError:
                    self.fail('missing bounded adoption diagnostic')
                except RuntimeError as caught:
                    self.assertIs(caught, original)
                else:
                    self.fail('original deadline failure must escape')
            waiting.assert_called_once()
            qa.status.assert_called_once()
            qa.proxy_adoption_observation.assert_called_once()
            self.assertEqual(qa.record.call_args.kwargs['finish_branch'], 'waiting')
            self.assertEqual(qa.record.call_args.kwargs['owner_state'], 'adopting')

    def test_proxy_adoption_transport_keeps_original_wait_retry_and_deadline(self):
        module = self.native_module()
        with tempfile.TemporaryDirectory() as directory:
            qa = module.NativeQA(SimpleNamespace(evidence_dir=Path(directory)))
            qa.layout = 'named-volume'
            qa.proxy_adoption_observation = unittest.mock.Mock(return_value={'qualification': 'unknown'})
            qa.record = unittest.mock.Mock()
            # Original wait deliberately absorbs OSError and eventually emits
            # its own deadline error. Advance only its clock; keep that code.
            with patch.object(module, 'raw_request', side_effect=OSError('PRIVATE_TRANSPORT')) as request, \
                 patch.object(module.time, 'monotonic', side_effect=[0.0, 0.0, 421.0]), \
                 patch.object(module.time, 'sleep'):
                try:
                    qa.finish('00000000-0000-4000-8000-000000000011', adoption_expected={})
                except TypeError:
                    self.fail('missing bounded adoption diagnostic')
                except RuntimeError as caught:
                    self.assertEqual(str(caught), 'actual owner operation did not finish')
                else:
                    self.fail('original wait must exhaust its 420-second deadline')
            request.assert_called_once_with('status', {'operation_id': '00000000-0000-4000-8000-000000000011'})
            qa.proxy_adoption_observation.assert_called_once()
            packet = qa.record.call_args.kwargs
            self.assertEqual(packet['finish_branch'], 'status-call')
            self.assertEqual(packet['status_error_kind'], 'os-error')
            self.assertEqual(packet['error_kind'], 'runtime-error')
            self.assertIsNone(packet['status_ok'])
            self.assertNotIn('PRIVATE', json.dumps(packet))

    def test_proxy_adoption_malformed_status_keeps_original_exception(self):
        module = self.native_module()
        with tempfile.TemporaryDirectory() as directory:
            qa = module.NativeQA(SimpleNamespace(evidence_dir=Path(directory)))
            qa.layout = 'named-volume'
            qa.proxy_adoption_observation = unittest.mock.Mock(return_value={'qualification': 'unknown'})
            qa.record = unittest.mock.Mock()
            for value in ([], None, 7, 'PRIVATE'):
                with self.subTest(value_type=type(value).__name__):
                    # The original final predicate indexes the response. Retain
                    # its precise exception and args even when it is malformed.
                    try:
                        value['state']
                    except TypeError as original:
                        expected_args = original.args
                    qa.status = unittest.mock.Mock(return_value=value)
                    qa.proxy_adoption_observation.reset_mock(); qa.record.reset_mock()
                    with self.assertRaises(TypeError) as caught:
                        qa.finish('00000000-0000-4000-8000-000000000011', adoption_expected={})
                    self.assertEqual(caught.exception.args, expected_args)
                    qa.status.assert_called_once()
                    qa.proxy_adoption_observation.assert_called_once()
                    qa.record.assert_called_once()
                    self.assertEqual(qa.record.call_args.kwargs['owner_state'], 'unknown')
                    self.assertNotIn('PRIVATE', json.dumps(qa.record.call_args.kwargs))

    def test_proxy_adoption_diagnostic_uses_closed_original_source_roles(self):
        module = self.native_module()
        self.assertTrue(hasattr(module, 'ADOPTION_CODE_SPECS'), 'adoption guards need a separate bounded original-code lane')
        specs = module.ADOPTION_CODE_SPECS
        self.assertLessEqual(len(specs) + len(module.BROKER_CODE_LABELS), 32)
        self.assertEqual(len(module.SELECTOR_CODE_SPECS), 13, 'do not borrow or replace selector roles')
        self.assertTrue(any(path == 'dc_overview.release_broker' and ancestry == ('InstalledOwner', 'adopt')
                            for _, path, ancestry in specs))
        self.assertTrue(any(path == 'cryptolabs_proxy.standard_adoption' and ancestry == ('StandardAdoption', 'adopt')
                            for _, path, ancestry in specs))
        module.sysconfig.get_config_vars()
        with private_owner_temp(module) as directory:
            prefix = Path(directory).resolve() / 'legacy-host-venv'
            site = prefix / ('lib/python' + str(sys.version_info.major) + '.' + str(sys.version_info.minor)) / 'site-packages'
            installed = {}
            for _, name, ancestry in specs:
                if name not in installed:
                    role = 'dc' if name.startswith('dc_overview.') else 'proxy'
                    original = (ROOT if role == 'dc' else ROOT.parent / 'proxy') / 'src' / (name.replace('.', '/') + '.py')
                    raw = original.read_bytes()
                    self.assertEqual(module.digest(raw), module.FROZEN_PRODUCT_HASHES[role]['src/' + name.replace('.', '/') + '.py'])
                    path = site / (name.replace('.', '/') + '.py')
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(raw)
                    loaded = types.ModuleType(name)
                    loaded.__file__ = str(path)
                    installed[name] = (loaded, compile(raw, str(path), 'exec'), path)
                loaded, expected, _ = installed[name]
                owner = loaded
                for item in ancestry[:-1]:
                    expected = next(code for code in expected.co_consts if type(code) is types.CodeType and code.co_name == item)
                    if not hasattr(owner, item):
                        setattr(owner, item, type(item, (), {}))
                    owner = getattr(owner, item)
                code = next(code for code in expected.co_consts if type(code) is types.CodeType and code.co_name == ancestry[-1])
                setattr(owner, ancestry[-1], types.FunctionType(code, {}))
            modules = {name: item[0] for name, item in installed.items()}
            with patch.dict(sys.modules, modules), patch.object(module.sys, 'prefix', str(prefix)):
                codes = module.naturally_loaded_adoption_codes(module.time.monotonic() + 1)
                self.assertEqual({label for label, _ in codes}, {label for label, _, _ in specs})
                original = installed['dc_overview.release_broker'][0].InstalledOwner.adopt
                self.assertTrue(any(code is original.__code__ for _, code in codes))
                def foreign(*args):
                    raise RuntimeError('PRIVATE')
                installed['dc_overview.release_broker'][0].InstalledOwner.adopt = foreign
                refused = module.naturally_loaded_adoption_codes(module.time.monotonic() + 1)
                self.assertFalse(any(label == next(label for label, name, ancestry in specs
                                                  if name == 'dc_overview.release_broker' and ancestry == ('InstalledOwner', 'adopt'))
                                     for label, _ in refused))
                installed['dc_overview.release_broker'][0].InstalledOwner.adopt = original
                path = installed['dc_overview.release_broker'][2]
                path.write_bytes(path.read_bytes() + b'\n')
                refused = module.naturally_loaded_adoption_codes(module.time.monotonic() + 1)
                self.assertFalse(any(label in {label for label, name, _ in specs if name == 'dc_overview.release_broker'}
                                     for label, _ in refused))

    def test_fixture_broker_execstart_uses_layout_selected_interpreter(self):
        """Execute the actual drop-in statements; no Engine or systemd calls."""
        tree = ast.parse(SCRIPT.read_text())
        klass = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'NativeQA')
        fixture = next(n for n in klass.body if isinstance(n, ast.FunctionDef) and n.name == 'fixture')
        start = next(i for i, n in enumerate(fixture.body) if isinstance(n, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id == 'dropin' for t in n.targets))
        statements = fixture.body[start:start + 2]
        for layout in ('named-volume', 'bind'):
            with self.subTest(layout=layout), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                qa = SimpleNamespace(recovery=SimpleNamespace(host_env=root / 'legacy-host-venv'))
                writes = []
                namespace = {'Path': Path, 'SERVICE': 'synthetic-broker.service', 'sys': sys,
                             'self': qa, 'layout': layout, 'write': lambda *args: writes.append(args)}
                exec(compile(ast.Module(body=statements, type_ignores=[]), str(SCRIPT), 'exec'), namespace)
                self.assertEqual(len(writes), 1)
                expected = str(qa.recovery.host_env / 'bin/python') if layout == 'named-volume' else sys.executable
                self.assertEqual(writes[0][1], (
                    '[Service]\nExecStart=\nExecStart=' + expected +
                    ' /opt/fleet-native-qa/verify_fleet_release_native.py --broker-child\n').encode())
                self.assertEqual(writes[0][2], 0o644)

    def test_selected_host_proof_uses_real_installed_layout_and_provenance_guard(self):
        """Real isolated Python prefix/full code/metadata, with no system services."""
        import shutil
        tree = ast.parse(SCRIPT.read_text())
        klass = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'LegacyRecoveryFixture')
        method = next(n for n in klass.body if isinstance(n, ast.FunctionDef) and n.name == 'install_compatible_host')
        proof = next((n for n in method.body if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == 'installed_layout_proof' for t in n.targets)), None)
        self.assertIsNotNone(proof, 'native fixture must qualify the actual selected interpreter and wheel provenance')
        source = ast.literal_eval(proof.value)
        with private_owner_temp(self.native_module()) as directory:
            root = Path(directory).resolve()
            prefix = root / 'legacy-host-venv'
            subprocess.run([sys.executable, '-m', 'venv', '--without-pip', '--system-site-packages', str(prefix)],
                           check=True, capture_output=True, timeout=30)
            python = prefix / 'bin/python'
            site = Path(subprocess.run([str(python), '-I', '-c', 'import sysconfig; print(sysconfig.get_path("purelib"))'],
                                      check=True, capture_output=True, text=True, timeout=10).stdout.strip())
            # Keep dependencies available without shadowing this prefix's product.
            dependency_sites = [p for p in sys.path if p.endswith('site-packages') and Path(p).is_dir()]
            (site / 'test-dependencies.pth').write_text('\n'.join(dependency_sites) + '\n')
            package = site / 'dc_overview'
            package.mkdir()
            # Minimal installed package shell avoids importing CLI dependencies
            # absent from the route-unit job. The complete selector module and
            # every source/hash/provenance predicate remain the original code.
            # The native proof still imports the actual complete wheel package.
            (package / '__init__.py').write_text('__version__ = "1.6.4"\n')
            shutil.copyfile(ROOT / 'src/dc_overview/fleet_upgrade.py', package / 'fleet_upgrade.py')
            distribution = site / 'dc_overview-1.6.4.dist-info'
            distribution.mkdir()
            (distribution / 'METADATA').write_text('Metadata-Version: 2.4\nName: dc-overview\nVersion: 1.6.4\n')
            target = {'release': '1.6.4', 'url': 'https://github.com/cryptolabsza/dc-overview/releases/download/native-fixture/selected.whl',
                      'sha256': 'a' * 64}
            provenance = distribution / 'direct_url.json'
            provenance.write_text(json.dumps({'url': target['url'], 'archive_info': {'hashes': {'sha256': target['sha256']}}}))
            argv = [str(python), '-I', '-c', source, str(prefix), str(root), str(SCRIPT), json.dumps(target)]
            passed = subprocess.run(argv, capture_output=True, text=True, timeout=20)
            self.assertEqual(passed.returncode, 0, passed.stderr)
            self.assertEqual(json.loads(passed.stdout), {'interpreter': 'compatible-host-venv', 'selector_source': True,
                                                       'cli_provenance': True})
            provenance.write_text(json.dumps({'url': 'file:///synthetic/original-local.whl',
                                             'archive_info': {'hashes': {'sha256': target['sha256']}}}))
            refused = subprocess.run(argv, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(refused.returncode, 0, 'same version/hash cannot bypass the real HTTPS URL predicate')
            self.assertIn('requires_cli_upgrade:', refused.stderr)
            self.assertEqual(refused.stdout, '')

    def test_selector_failure_stage_is_a_closed_non_authorizing_witness(self):
        module = self.native_module()
        value = module.selector_failure_details(RuntimeError('PRIVATE'), (), {}, module.time.monotonic() + 1)
        self.assertEqual(value.get('source_stage'), 'failure-sample')
        self.assertTrue(module.selector_details_valid(value))
        for stage in ('unknown', 'broker-source', 'selector-discovery', 'proxy-discovery', 'selector-required', 'failure-sample'):
            self.assertTrue(module.selector_details_valid({**value, 'source_stage': stage}))
        for stage in ('PRIVATE/path', '', 1, True, None):
            self.assertFalse(module.selector_details_valid({**value, 'source_stage': stage}))
        self.assertEqual(value['qualification'], 'innermost-unknown')
        self.assertEqual(value['frames'], [])
        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_actual_broker_observer_emits_attempted_source_stage_without_guard_bypass(self):
        module = self.native_module()
        with private_owner_temp(module) as directory:
            root = Path(directory).resolve()
            prefix = root / 'legacy-host-venv'
            source = prefix / 'dc_overview/release_broker.py'
            source.parent.mkdir(parents=True)
            frozen = (ROOT / 'src/dc_overview/release_broker.py').read_bytes()
            identity = '00000000-0000-4000-8000-000000000001'
            actor = {'kind': 'host-peer', 'uid': 0}
            request = {'candidate_ids': ['synthetic-candidate'], 'components': ['ipmi-monitor'],
                       'expected_selection_id': 'synthetic-selected', 'expected_selection_sha256': 'a' * 64,
                       'operation_kind': 'services-update'}
            canonical = lambda v: json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
            manifest = canonical({'components': {}})
            preview = {'preview_id': '00000000-0000-4000-8000-000000000002', 'actor': actor, 'request': request,
                       'manifest': base64.b64encode(manifest).decode(), 'selection_sha256': 'b' * 64,
                       'selection_id': 'synthetic-next', 'manifest_sha256': module.digest(manifest), 'generation': 1,
                       'owner_plan': None, 'owner_declaration': None, 'public_sha256': 'c' * 64,
                       'owner_identity': {'updater_directory': str(root / 'named-volume/jobs'), 'device': 1, 'inode': 2,
                                          'proxy_config_dir': str(root / 'proxy'), 'declaration_path': str(root / 'declaration')},
                       'policy_sha256': 'd' * 64, 'channel': 'main'}
            apply = {'operation_id': identity, 'preview_id': preview['preview_id'],
                     'preview_sha256': module.digest(canonical(preview)),
                     'expected_selection_id': request['expected_selection_id'],
                     'expected_selection_sha256': request['expected_selection_sha256']}
            record = {**preview, **apply, 'request_fingerprint': module.digest(canonical({'params': apply, 'actor': actor})),
                      'state': 'selecting', 'phase': 'selection', 'components': ['ipmi-monitor'],
                      'operation_kind': 'services-update'}
            self.assertEqual(module.selector_operation(record, identity), {'components': {}})
            for changed, expected in ((True, 'broker-source'), (False, 'selector-required')):
                with self.subTest(changed=changed):
                    source.write_bytes(frozen + (b'\n' if changed else b''))
                    saved = []
                    broker = types.ModuleType('synthetic_broker_boundary')
                    broker.__file__ = str(source)
                    broker.private_write = lambda *args, **kwargs: 'original-write-result'
                    namespace = {}
                    # A synthetic exception at the fixed observer coordinate;
                    # neither a real broker guard nor historical cause proof.
                    code = '\n' * 915 + ('def fail(broker, path, record):\n'
                        '    try:\n'
                        '        raise RuntimeError("PRIVATE")\n'
                        '    except RuntimeError:\n'
                        '        return broker.private_write(path, record)\n')
                    exec(compile(code, '<synthetic-observer-boundary>', 'exec'), namespace)
                    boundary = namespace['fail']
                    with patch.object(module.sys, 'prefix', str(prefix)), patch.object(module, 'ROOT', root), \
                         patch.dict(sys.modules, {'dc_overview.fleet_upgrade': None, 'cryptolabs_proxy.updates': None}), \
                         patch.object(module, 'write_owner_observation', side_effect=lambda *args: saved.append(args)):
                        original = broker.private_write
                        with module.observe_broker_owner_failures(broker, root / 'operations', (('broker-operation', boundary.__code__),)):
                            self.assertEqual(boundary(broker, root / 'operations' / (identity + '.json'), record), 'original-write-result')
                        self.assertIs(broker.private_write, original)
                    self.assertEqual(len(saved), 1)
                    detail = saved[0][1]['selector']
                    self.assertEqual(detail.get('source_stage'), expected)
                    self.assertEqual(detail['qualification'], 'source-refused')
                    self.assertEqual(detail['frames'], [])
                    self.assertTrue(all(detail[k] is None for k in ('module_version_match', 'distribution_version_match', 'url_match', 'hash_match')))
                    self.assertTrue(module.observation_failure_valid(saved[0][1]))
                    self.assertNotIn('PRIVATE', json.dumps(saved))

    def test_synthetic_seed_generated_volume_reaches_helper_filesystem_guard(self):
        module = self.native_module()
        helper_path = ROOT / "scripts/fixtures/legacy-selected-state-protection.py"
        class SeedCaptured(Exception):
            pass
        class FilesystemGuardReached(Exception):
            pass
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "data"; data.mkdir()
            config = root / "servers.yaml"; config.write_text("servers: []\n")
            with sqlite3.connect(data / "ipmi_events.db") as db:
                for sql in (
                    "CREATE TABLE system_settings(key TEXT PRIMARY KEY,value TEXT)",
                    "CREATE TABLE cloud_sync(id INTEGER PRIMARY KEY,license_key TEXT,sync_enabled INTEGER,subscription_valid INTEGER,site_id TEXT,site_name TEXT)",
                    "CREATE TABLE server(id INTEGER PRIMARY KEY,bmc_ip TEXT,server_name TEXT,status TEXT,updated_at TEXT)",
                    "CREATE TABLE server_status(bmc_ip TEXT PRIMARY KEY,server_name TEXT,last_check TEXT)",
                ):
                    db.execute(sql)
                db.execute("INSERT INTO cloud_sync(id,site_id,site_name) VALUES (1,?,?)",
                           ('synthetic-fleet-native-site', 'SYNTHETIC Fleet native fixture'))
            volume = "native-fleet-named-volume-123-data"
            observed = {"Id": "a" * 64, "Image": "sha256:" + "b" * 64,
                        "State": {"Running": True}, "Config": {"Labels": {"io.cryptolabs.native-qa.run": "123"}},
                        "Mounts": [{"Destination": "/app/data", "Type": "volume", "Name": volume, "Source": str(data)},
                                   {"Destination": "/app/config/servers.yaml", "Type": "bind", "Source": str(config)}]}
            qa = module.NativeQA(SimpleNamespace(evidence_dir=root / "evidence", protection_helper=helper_path))
            qa.recovery.backup_root = root / "owned-backup-root"
            qa.volumes = [volume]
            qa.network = "native-fleet-named-volume-123"
            qa.label = "io.cryptolabs.native-qa.run=123"
            # A missing/wrong initialization must fail before even account seed writes.
            with sqlite3.connect(data / "ipmi_events.db") as db:
                db.execute("UPDATE cloud_sync SET site_name='wrong'")
            with patch.object(module, "inspect", return_value=observed):
                with self.assertRaises(AssertionError):
                    qa.recovery.seed_synthetic_selected_state()
            with sqlite3.connect(data / "ipmi_events.db") as db:
                self.assertEqual(db.execute('SELECT count(*) FROM system_settings').fetchone()[0], 0)
                self.assertEqual(db.execute('SELECT license_key,site_name FROM cloud_sync').fetchall(), [(None, 'wrong')])
                db.execute('UPDATE cloud_sync SET site_name=?', ('SYNTHETIC Fleet native fixture',))
            captured = {}
            original_spec = importlib.util.spec_from_file_location
            def capture_spec(name, path):
                spec = original_spec(name, path)
                execute = spec.loader.exec_module
                def load(helper):
                    execute(helper)
                    # Native root-chain custody is not a macOS test capability;
                    # constrain this pre-creation boundary to our temporary FS.
                    helper.safe_chain = lambda path: path.stat()
                    captured["helper"] = helper
                    def stop(site):
                        captured["pin"] = helper.PINS[site]
                        raise SeedCaptured()
                    captured["main"] = helper.main
                    helper.main = stop
                spec.loader.exec_module = load
                return spec
            with patch.object(module, "inspect", return_value=observed), patch.object(module, "docker", side_effect=AssertionError("Engine mutation forbidden")), patch.object(importlib.util, "spec_from_file_location", side_effect=capture_spec):
                with self.assertRaises(SeedCaptured):
                    qa.recovery.seed_synthetic_selected_state()
            helper = captured["helper"]
            with sqlite3.connect(data / "ipmi_events.db") as db:
                self.assertEqual(db.execute('SELECT site_id,site_name FROM cloud_sync').fetchall(),
                                 [('synthetic-fleet-native-site', 'SYNTHETIC Fleet native fixture')])
            self.assertEqual(captured["pin"]["mounts"], observed["Mounts"])
            self.assertEqual(captured["pin"]["container_id"], observed["Id"])
            # The producer and runtime identity checks remain real. Stop the
            # actual helper exactly at its first filesystem guard after mounts.
            with patch.object(helper.os, "geteuid", return_value=0), patch.object(helper.os, "umask"), patch.object(helper.signal, "signal"), patch.object(helper.signal, "alarm"), patch.object(helper.subprocess, "check_output", return_value=json.dumps([observed]).encode()), patch.object(helper, "safe_chain", side_effect=FilesystemGuardReached):
                foreign = json.loads(json.dumps(observed))
                foreign["Mounts"][0]["Name"] = "foreign-unowned-volume"
                with patch.object(helper.subprocess, "check_output", return_value=json.dumps([foreign]).encode()):
                    with self.assertRaisesRegex(RuntimeError, "runtime-full-mount-records"):
                        captured["main"]("ltx")
                with self.assertRaises(FilesystemGuardReached):
                    captured["main"]("ltx")
                with patch.dict(captured["pin"], {"data_volume_name": None}):
                    with self.assertRaisesRegex(RuntimeError, "data-mount"):
                        captured["main"]("ltx")
            # Run the actual seed/read-only helper up to its custody guard.
            # Temporary ancestry is not root-private; no privileged paths or
            # helper main entrypoint are reached and no helper code is replaced.
            qa.recovery.backup_root = root / "diagnostic-parent" / "backup"
            def fixture_boundary():
                qa.recovery.seed_synthetic_selected_state()
            with patch.object(module, "inspect", return_value=observed), patch.object(module, "docker", side_effect=AssertionError("Engine mutation forbidden")):
                try:
                    fixture_boundary()
                except RuntimeError as error:
                    metadata = module.native_phase_failure_metadata(error, "fixture", (("fixture", fixture_boundary.__code__),))
                else:
                    self.fail("the real helper custody predicate must reject temporary ancestry")
            failure = self.assert_bootstrap_failure_shape(metadata)
            self.assertEqual(failure["bootstrap_step"], "synthetic-root-custody")
            self.assertEqual(failure["code_label"], "synthetic-helper")
            self.assertEqual(failure["error_kind"], "runtime-error")
            helper_tree = ast.parse(helper_path.read_text())
            custody = next(n for n in helper_tree.body if isinstance(n, ast.FunctionDef) and n.name == "safe_chain")
            self.assertIn(failure["guard_line"], range(custody.lineno, custody.end_lineno + 1))
            self.assertEqual(failure["command_outcome"], "none")
            self.assertIsNone(failure["command_returncode"])

    def test_synthetic_site_initialization_orders_real_fixture_and_holds_failures(self):
        """Real fixture/orchestration; only Engine and unavailable root FS custody substituted."""
        module = self.native_module()
        tree = ast.parse(SCRIPT.read_text())
        klass = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'NativeQA')
        fixture = next(n for n in klass.body if isinstance(n, ast.FunctionDef) and n.name == 'fixture')
        def assignment(node, name):
            return isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
        start = next(i for i, n in enumerate(fixture.body) if assignment(n, 'empty'))
        stop = next(i for i, n in enumerate(fixture.body) if assignment(n, 'socket_mount'))
        code = compile(ast.fix_missing_locations(ast.Module(body=fixture.body[start:stop], type_ignores=[])), str(SCRIPT), 'exec')
        scenarios = ('pass', 'bind', 'foreign-volume', 'nonempty', 'preexisting-empty', 'existing-runtime', 'stopped-writer',
                     'wrong-image', 'wrong-site-name', 'create-timeout', 'start-failed', 'wait-timeout',
                     'nonzero', 'still-running', 'wrong-terminal-id', 'deadline', 'changed-volume',
                     'config-swap', 'symlink-volume', 'cleanup-foreign', 'volume-create-timeout',
                     'cleanup-volume-label', 'cleanup-volume-inode', 'truncated-before-create',
                     'malformed-before-create', 'truncated-after-create', 'malformed-after-create',
                     'same-prefix-writer')
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                data = root / 'data'; data.mkdir()
                preexisting = scenario in ('foreign-volume', 'nonempty', 'preexisting-empty')
                if scenario in ('foreign-volume', 'nonempty'):
                    (data / 'prior.db').write_bytes(b'SYNTHETIC retained data')
                initial_volume_inode = data.stat().st_ino
                volume = 'native-fleet-named-volume-123-data'
                if scenario == 'symlink-volume':
                    (root / 'alias').symlink_to(data, target_is_directory=True)
                qa = module.NativeQA(SimpleNamespace(evidence_dir=root / 'evidence'))
                qa.data = root
                qa.label = 'io.cryptolabs.native-qa.run=123'
                qa.refs = {'ipmi-old': 'ghcr.io/cryptolabsza/ipmi-monitor@sha256:' + 'c' * 64}
                image_id, identity = 'sha256:' + 'b' * 64, 'a' * 64
                foreign_identity = identity[:12] + 'd' * 52
                clock, calls, timeouts = [100.0], [], []
                state = dict(created=False, started=False, exited=False, removed=False, runtime=False,
                             volume_exists=preexisting)
                volume_labels = {'io.cryptolabs.native-qa.run': 'foreign' if scenario == 'foreign-volume' else '123'}
                value = {}
                def reply(output=b''):
                    return SimpleNamespace(returncode=0, stdout=output, stderr=b'')
                def record_json(item):
                    return reply(json.dumps([item]).encode())
                def engine(*args, **kwargs):
                    calls.append(args)
                    if 'timeout' in kwargs:
                        timeouts.append(kwargs['timeout'])
                        self.assertGreater(kwargs['timeout'], 0)
                        self.assertLessEqual(kwargs['timeout'], 60)
                    clock[0] += 1
                    if args[:2] == ('volume', 'ls'):
                        return reply(volume.encode() if state['volume_exists'] else b'')
                    if args[:2] == ('volume', 'create'):
                        # Engine create is idempotent: existing data and labels survive it.
                        if not state['volume_exists']:
                            volume_labels.update(dict(args[i + 1].split('=', 1) for i, arg in enumerate(args) if arg == '--label'))
                            state['volume_exists'] = True
                        if scenario == 'volume-create-timeout':
                            raise module.NativeCommandFailure('timeout')
                        return reply(volume.encode())
                    if args[:2] == ('image', 'inspect'):
                        return record_json({'Id': ('sha256:' + 'd' * 64 if scenario == 'wrong-image' and args[2] != module.IPMI_OLD else image_id),
                            'RepoDigests': [args[2]], 'Os': 'linux', 'Architecture': 'amd64',
                            'Config': {'Labels': {'org.opencontainers.image.revision': 'a5cfd4ea0d6e43c6346f641693fcb6eef449433b'}}})
                    if args[:2] == ('volume', 'inspect'):
                        return record_json({'Name': volume, 'Driver': 'local', 'Options': None,
                            'Labels': dict(volume_labels),
                            'Mountpoint': str(root / 'alias' if scenario == 'symlink-volume' else data)})
                    if args[0] == 'ps':
                        if state['removed']:
                            return reply()
                        if args == ('ps', '-aq', '--no-trunc'):
                            if scenario == ('truncated-after-create' if state['created'] else 'truncated-before-create'):
                                return reply(identity[:12].encode())
                            if scenario == ('malformed-after-create' if state['created'] else 'malformed-before-create'):
                                return reply(b'g' * 64)
                        if state['created']:
                            if scenario == 'same-prefix-writer':
                                return reply(('\n'.join((identity, foreign_identity)) if '--no-trunc' in args
                                              else '\n'.join((identity[:12], foreign_identity[:12]))).encode())
                            return reply((identity if '--no-trunc' in args else identity[:12]).encode())
                        foreign = 'f' * 64 if scenario in ('existing-runtime', 'stopped-writer') else ''
                        return reply((foreign if '--no-trunc' in args else foreign[:12]).encode())
                    if args[0] == 'create':
                        name = args[args.index('--name') + 1]
                        self.assertIn(name, qa.site_initializers)
                        self.assertIsNone(qa.site_initializers[name]['id'])
                        self.assertIn(volume, qa.volumes)
                        mounts = [args[i + 1] for i, arg in enumerate(args) if arg == '--mount']
                        self.assertEqual(mounts, [f'type=volume,src={volume},dst=/app/data', f'type=bind,src={root}/servers.yaml,dst=/app/config/servers.yaml,readonly'])
                        value.update(Id=identity, Name='/' + name, Image=image_id,
                            Config={'Labels': {'io.cryptolabs.native-qa.run': '123'}, 'Image': args[-3],
                                'Entrypoint': [args[args.index('--entrypoint') + 1]], 'Cmd': list(args[-2:]),
                                'Env': [args[i + 1] for i, arg in enumerate(args) if arg == '-e']},
                            HostConfig={'NetworkMode': args[args.index('--network') + 1], 'Privileged': False},
                            Mounts=[{'Destination': '/app/data', 'Type': 'volume', 'Name': volume, 'Source': str(data), 'RW': True},
                                {'Destination': '/app/config/servers.yaml', 'Type': 'bind', 'Source': str(root / 'servers.yaml'), 'RW': False}],
                            State={'Running': False, 'Status': 'created'})
                        if scenario == 'wrong-site-name':
                            value['Config']['Env'][-1] = 'SITE_NAME=wrong'
                        state['created'] = True
                        if scenario == 'create-timeout':
                            raise module.NativeCommandFailure('timeout')
                        return reply(identity.encode())
                    if args[0] == 'inspect':
                        if args[1] == foreign_identity:
                            return record_json({'Id': foreign_identity, 'Name': '/foreign-writer',
                                'State': {'Running': False}, 'Mounts': [{'Name': volume, 'Source': str(data)}]})
                        if args[1] in ('f' * 64, 'f' * 12):
                            return record_json({'Name': '/ipmi-monitor' if scenario == 'existing-runtime' else '/stopped',
                                'State': {'Running': False}, 'Mounts': [{'Name': volume}]})
                        self.assertIn(args[1], (identity, identity[:12]))
                        if scenario == 'wrong-terminal-id' and state['exited']:
                            return record_json(dict(value, Id='e' * 64))
                        return record_json(value)
                    if args[0] == 'start':
                        self.assertEqual(qa.site_initializers[value['Name'][1:]]['id'], identity)
                        self.assertEqual(args[1], identity)
                        state['started'] = True
                        if scenario == 'start-failed':
                            raise module.NativeCommandFailure('nonzero-exit', 1)
                        if scenario == 'deadline':
                            clock[0] += 60
                        return reply()
                    if args[0] == 'wait':
                        self.assertTrue(state['started'])
                        if scenario == 'wait-timeout':
                            raise module.NativeCommandFailure('timeout')
                        state['exited'] = True
                        value['State'] = {'Running': scenario == 'still-running', 'Status': 'running' if scenario == 'still-running' else 'exited', 'ExitCode': 0}
                        if scenario == 'changed-volume':
                            data.rename(root / 'old-data'); data.mkdir()
                        if scenario == 'config-swap':
                            (root / 'servers.yaml').rename(root / 'old-config')
                            (root / 'servers.yaml').write_text('servers: []\n')
                        return reply(b'7' if scenario == 'nonzero' else b'0')
                    if args[0] == 'run':
                        self.assertIn('ipmi-monitor', args)
                        if scenario != 'bind':
                            self.assertTrue(state['exited'])
                            self.assertIs(value['State']['Running'], False)
                            self.assertEqual(args[-3:], ('-e', 'SITE_NAME=SYNTHETIC Fleet native fixture', image_id))
                        else:
                            self.assertFalse(state['created'])
                            self.assertEqual(args[-1], qa.refs['ipmi-old'])
                            self.assertNotIn('SITE_NAME=SYNTHETIC Fleet native fixture', args)
                        state['runtime'] = True
                    if args[:2] == ('rm', '-f'):
                        self.assertEqual(args[2], identity)
                        state['removed'] = True
                    if args[:2] == ('volume', 'rm'):
                        if not preexisting:
                            self.assertTrue(state['removed'])
                        # Model successful Engine removal with actual temporary data deletion,
                        # so the rejection/reset composition observes harm, not just argv.
                        for child in data.iterdir():
                            child.unlink()
                        data.rmdir()
                        state['volume_exists'] = False
                    return reply()
                scope = dict(module.__dict__, self=qa, layout='bind' if scenario == 'bind' else 'named-volume', network='native-fleet-named-volume-123')
                # Root-only ancestry/file ownership is unavailable in portable CI.
                # Keep actual no-follow path identities/content and replacement checks.
                def directories(path):
                    return [(str(path), module.trust_identity(path.lstat()))]
                def read_config(path):
                    with path.open('rb') as stream:
                        return stream.read(), os.fstat(stream.fileno())
                with patch.object(module, 'docker', side_effect=engine), patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(module, 'trust_directories', side_effect=directories), patch.object(module, 'trust_read', side_effect=read_config):
                    scope['docker'] = module.docker
                    if preexisting:
                        original_error = None
                        try:
                            exec(code, scope)
                        except (AssertionError, module.NativeCommandFailure) as error:
                            original_error = error
                        qa.consume_child_failure = lambda: None
                        qa.recovery.reset = lambda: None
                        cleanup_error = None
                        with patch.object(module, 'run'), patch.object(module.shutil, 'rmtree'):
                            try:
                                qa.reset_fixture()
                            except Exception as error:
                                cleanup_error = error
                        # Inspect survival before checking the original refusal. Initial
                        # candidate accepts the empty same-label case, then deletes it too.
                        self.assertTrue(data.is_dir(), 'actual reset deleted a preexisting volume; '
                            f'initial={type(original_error).__name__}, cleanup={type(cleanup_error).__name__}')
                        self.assertEqual(data.stat().st_ino, initial_volume_inode)
                        if scenario != 'preexisting-empty':
                            self.assertEqual((data / 'prior.db').read_bytes(), b'SYNTHETIC retained data')
                        self.assertTrue(state['volume_exists'])
                        self.assertFalse(state['runtime'])
                        self.assertIsInstance(original_error, (AssertionError, module.NativeCommandFailure))
                        self.assertFalse(any(args[:2] == ('volume', 'rm') for args in calls))
                        continue
                    if scenario in ('pass', 'bind', 'cleanup-foreign', 'cleanup-volume-label', 'cleanup-volume-inode'):
                        exec(code, scope)
                        self.assertTrue(state['runtime'])
                    else:
                        with self.assertRaises((AssertionError, module.NativeCommandFailure)):
                            exec(code, scope)
                        self.assertFalse(state['runtime'])
                    self.assertEqual(timeouts, sorted(timeouts, reverse=True))
                    if scenario == 'pass':
                        scans = [args for args in calls if args[0] == 'ps']
                        self.assertEqual(scans, [('ps', '-aq', '--no-trunc')] * 2)
                        before_start = calls[:next(i for i, args in enumerate(calls) if args[0] == 'start')]
                        self.assertEqual([args for args in before_start if args[0] == 'inspect'], [('inspect', identity)])
                    if scenario.startswith(('truncated-', 'malformed-')):
                        self.assertFalse(state['started'])
                        inspected = [args[1] for args in calls if args[0] == 'inspect']
                        self.assertNotIn(identity[:12], inspected)
                        self.assertNotIn('g' * 64, inspected)
                        self.assertEqual(state['created'], scenario.endswith('after-create'))
                    if scenario == 'same-prefix-writer':
                        self.assertEqual(identity[:12], foreign_identity[:12])
                        self.assertNotEqual(identity, foreign_identity)
                        self.assertIn(('inspect', foreign_identity), calls)
                        self.assertFalse(state['started'])
                    if scenario in ('pass', 'create-timeout', 'cleanup-foreign', 'volume-create-timeout',
                                    'cleanup-volume-label', 'cleanup-volume-inode'):
                        qa.consume_child_failure = lambda: None
                        qa.recovery.reset = lambda: None
                        if scenario == 'cleanup-foreign':
                            value['Config']['Labels']['io.cryptolabs.native-qa.run'] = 'foreign'
                        if scenario == 'cleanup-volume-label':
                            volume_labels['io.cryptolabs.native-qa.volume'] = 'foreign-nonce'
                        if scenario == 'cleanup-volume-inode':
                            data.rename(root / 'retained-owned-volume'); data.mkdir()
                            (data / 'prior.db').write_bytes(b'SYNTHETIC replacement data')
                        cleanup_inode = data.stat().st_ino
                        with patch.object(module, 'run'), patch.object(module.shutil, 'rmtree'):
                            if scenario == 'volume-create-timeout':
                                with self.assertRaisesRegex(RuntimeError, 'volume creation custody uncertain'):
                                    qa.reset_fixture()
                                self.assertFalse(state['created'])
                                self.assertTrue(state['volume_exists'])
                                self.assertTrue(data.is_dir())
                                self.assertEqual(data.stat().st_ino, cleanup_inode)
                                self.assertFalse(any(args[:2] == ('volume', 'rm') for args in calls))
                            elif scenario in ('cleanup-volume-label', 'cleanup-volume-inode'):
                                with self.assertRaises(AssertionError):
                                    qa.reset_fixture()
                                self.assertTrue(state['removed'], 'the exact owned one-shot may be removed')
                                self.assertTrue(state['volume_exists'])
                                self.assertTrue(data.is_dir())
                                self.assertEqual(data.stat().st_ino, cleanup_inode)
                                if scenario == 'cleanup-volume-inode':
                                    self.assertEqual((data / 'prior.db').read_bytes(), b'SYNTHETIC replacement data')
                                    self.assertTrue((root / 'retained-owned-volume').is_dir())
                                self.assertFalse(any(args[:2] == ('volume', 'rm') for args in calls))
                            elif scenario == 'cleanup-foreign':
                                with self.assertRaises(AssertionError):
                                    qa.reset_fixture()
                                self.assertFalse(state['removed'])
                                self.assertFalse(any(args[:2] == ('volume', 'rm') for args in calls))
                            else:
                                qa.reset_fixture()
                                self.assertTrue(state['removed'])
                                self.assertEqual(qa.site_initializers, {})

    def test_rejected_preexisting_backup_root_survives_actual_reset(self):
        module = self.native_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheels = root / "wheels"; wheels.mkdir()
            expected = {}
            for name, version in (("dc-overview", "1.8.0"), ("cryptolabs-proxy", "1.5.4")):
                path = wheels / (name + ".whl")
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr(name.replace("-", "_") + ".dist-info/METADATA", "Name: " + name + "\nVersion: " + version + "\n")
                expected[name] = (version, hashlib.sha256(path.read_bytes()).hexdigest())
            qa = module.NativeQA(SimpleNamespace(evidence_dir=root / "evidence", legacy_wheel_dir=wheels, wheel_dir=wheels,
                                                protection_helper=ROOT / "scripts/fixtures/legacy-selected-state-protection.py"))
            recovery = qa.recovery
            recovery.host_env = root / "unoccupied-host-env"
            recovery.backup_root = root / "preexisting-empty-backup"
            recovery.backup_root.mkdir()
            before = recovery.backup_root.stat().st_ino
            # Only the unrelated package input digest boundary is substituted;
            # occupied-path validation and reset execute their actual code.
            with patch.object(module, "LEGACY_WHEELS", expected), patch.object(module, "run", side_effect=AssertionError("runtime forbidden")):
                with self.assertRaisesRegex(RuntimeError, "fresh disposable guest fixture path occupied"):
                    recovery.validate_inputs()
                def local_path(value):
                    return root / "unoccupied-cli-link" if str(value) == "/usr/local/bin/dc-overview" else Path(value)
                with patch.object(module, "Path", side_effect=local_path):
                    recovery.reset()
            self.assertTrue(recovery.backup_root.is_dir(), "rejected foreign root must survive cleanup")
            self.assertEqual(recovery.backup_root.stat().st_ino, before)
            recovery.backup_root = root / "owned-positive"
            with patch.object(module, "Path", side_effect=local_path):
                recovery.claim_backup_root()
                recovery.reset()
            self.assertFalse(recovery.backup_root.exists())
            recovery.backup_root = root / "owned-before-replacement"
            recovery.claim_backup_root()
            retained = root / "retained-owned-root"
            recovery.backup_root.rename(retained)
            recovery.backup_root.mkdir(mode=0o700)
            replacement_inode = recovery.backup_root.stat().st_ino
            with patch.object(module, "Path", side_effect=local_path):
                with self.assertRaises(AssertionError):
                    recovery.reset()
            self.assertEqual(recovery.backup_root.stat().st_ino, replacement_inode)
            self.assertTrue(retained.is_dir())

    def test_recovery_rejects_unfrozen_inputs_before_guest_commands(self):
        module = self.native_module()
        with patch.object(module, "RECOVERY_INPUTS_FROZEN", False), patch.object(module, "run", side_effect=AssertionError("guest command forbidden")):
            with self.assertRaisesRegex(RuntimeError, "recovery inputs"):
                module.check_recovery_inputs("a" * 40)
        with patch.object(module, "RECOVERY_INPUTS_FROZEN", True):
            module.check_recovery_inputs("a" * 40)
            with self.assertRaisesRegex(RuntimeError, "published reviewed proxy"):
                module.check_recovery_inputs("ROOT_MUST_SET_REVIEWED_RECOVERY_PROXY_SHA")

    def test_reconcile_fixture_requires_only_receipt_and_unchanged_native_history(self):
        module = self.native_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = "a" * 32
            job = json.dumps({"id": identity, "state": "failed"}).encode()
            active = json.dumps({"id": identity}).encode()
            for name, raw in ((identity + ".json", job), ("active.json", active), ("dispatch.lock", b""), ("operation.lock", b"")):
                (root / name).write_bytes(raw)
            before = module.recovery_store_snapshot(root)
            receipt = {"job_sha256": hashlib.sha256(job).hexdigest(), "active_sha256": hashlib.sha256(active).hexdigest(), "original_container_id": "b" * 64}
            receipt_path = root / ("service-recovery-" + identity + ".json")
            receipt_path.write_text(json.dumps(receipt))
            receipt_path.chmod(0o600)
            self.assertEqual(module.verify_recovery_store(root, before, identity, "b" * 64), receipt_path.read_bytes())
            receipt_path.chmod(0o644)
            with self.assertRaises(AssertionError):
                module.verify_recovery_store(root, before, identity, "b" * 64)
            receipt_path.chmod(0o600)
            (root / "active.json").write_bytes(b"{}")
            with self.assertRaises(AssertionError):
                module.verify_recovery_store(root, before, identity, "b" * 64)
            (root / "active.json").write_bytes(active)
            (root / "unexpected.json").write_bytes(b"{}")
            with self.assertRaises(AssertionError):
                module.verify_recovery_store(root, before, identity, "b" * 64)

    def test_service_snapshot_exports_only_closed_fields(self):
        module = self.native_module()
        valid = b"ActiveState=active\nSubState=running\nResult=success\nMainPID=123\nExecMainStatus=0\n"
        self.assertEqual(module.service_state(valid), {
            "ActiveState": "active", "SubState": "running", "Result": "success",
            "MainPID": 123, "ExecMainStatus": 0,
        })
        hostile = (b"ActiveState=PRIVATE_TOKEN\nSubState=/private/key\nResult=arbitrary\n"
                   b"MainPID=-1\nExecMainStatus=9999999999999\nEnvironment=SECRET\n")
        self.assertEqual(module.service_state(hostile), {
            "ActiveState": "unknown", "SubState": "unknown", "Result": "unknown",
            "MainPID": None, "ExecMainStatus": None,
        })
        self.assertEqual(module.service_state(b"MainPID=1\nMainPID=2\n")["MainPID"], None)

    def test_kill_records_numeric_failure_and_never_restarts_or_masks_it(self):
        module = self.native_module()
        for code, collector_fails in ((0, False), (1, False), (5, True)):
            with self.subTest(code=code, collector_fails=collector_fails), tempfile.TemporaryDirectory() as d:
                guest = module.NativeQA(SimpleNamespace(evidence_dir=Path(d)))
                guest.layout = "bind"
                calls = []
                def command(*args, calls=calls, code=code, collector_fails=collector_fails, **kwargs):
                    calls.append(args)
                    if args[1] == "--help":
                        self.assertEqual(kwargs, {"check": False, "timeout": 10})
                        return SimpleNamespace(returncode=0, stdout=b" --kill-whom=WHO")
                    if args[1] == "show":
                        self.assertEqual(args[-1], module.SERVICE)
                        self.assertFalse(kwargs["check"])
                        state = b"ActiveState=active\nSubState=running\nMainPID=123\n"
                        if any(call[1] == "kill" for call in calls):
                            if collector_fails:
                                raise RuntimeError("PRIVATE diagnostic failure")
                            state = b"ActiveState=inactive\nSubState=dead\nMainPID=0\n"
                        return SimpleNamespace(returncode=0, stdout=state)
                    self.assertEqual(args, ("systemctl", "kill", "--kill-whom=main", "--signal=KILL", module.SERVICE))
                    self.assertEqual(kwargs, {"check": False})
                    return SimpleNamespace(returncode=code)
                def identity(pid, calls=calls):
                    return None if any(call[1] == "kill" for call in calls) else (77, "S")
                with patch.object(module, "run", side_effect=command), patch.object(module, "process_identity", side_effect=identity, create=True):
                    if code:
                        with self.assertRaisesRegex(RuntimeError, rf"systemctl failed \(exit {code}\)"):
                            guest.kill_broker("service_update")
                    else:
                        self.assertEqual(guest.kill_broker("service_update"), (123, 77))
                self.assertEqual(sum(args[1] == "kill" for args in calls), 1)
                self.assertNotIn("start", [args[1] for args in calls])
                event = guest.events[-1]
                self.assertEqual(event["kill_exit_code"], code)
                self.assertEqual(event["phase"], "service_update")
                self.assertEqual(event["layout"], "bind")
                self.assertNotIn("PRIVATE", json.dumps(event))
                # Evidence failure must leave the actual nonzero kill verdict intact.
                calls.clear()
                with patch.object(module, "run", side_effect=command), patch.object(module, "process_identity", side_effect=identity, create=True), patch.object(guest, "record", side_effect=ValueError("PRIVATE")):
                    if code:
                        with self.assertRaisesRegex(RuntimeError, f"exit {code}"):
                            guest.kill_broker("service_update")
                    else:
                        guest.kill_broker("service_update")
                original = RuntimeError("original kill failure")
                active = module.service_state(b"ActiveState=active\nSubState=running\nMainPID=123\n")
                with patch.object(guest, "broker_state", return_value=active), patch.object(module, "process_identity", return_value=(77, "S")), patch.object(module, "run", side_effect=[SimpleNamespace(returncode=0, stdout=b"--kill-whom=WHO"), original]):
                    with self.assertRaisesRegex(RuntimeError, "original kill failure") as caught:
                        guest.kill_broker("interrupted_adoption")
                self.assertIs(caught.exception, original)

    def test_main_crash_requires_old_identity_death_before_start_and_fresh_broker(self):
        module = self.native_module()
        native = next(node for node in ast.parse(SCRIPT.read_text()).body if isinstance(node, ast.ClassDef) and node.name == "NativeQA")
        method = next(node for node in native.body if isinstance(node, ast.FunctionDef) and node.name == "service_update")
        index = next(i for i, node in enumerate(method.body) if "kill_broker" in ast.unparse(node))
        boundary = compile(ast.Module(body=method.body[index:index + 3], type_ignores=[]), str(SCRIPT), "exec")
        for outcome in ("old-alive", "delayed-death", "auto-restart", "pid-change-old-alive", "zombie-transition", "zombie-no-transition", "auto-missing", "fresh-missing"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as d:
                guest = module.NativeQA(SimpleNamespace(evidence_dir=Path(d)))
                guest.layout = "bind"
                clock, calls = [0.0], []
                guest.finish = lambda identity: "fixture recovery"
                def command(*args, calls=calls, clock=clock, outcome=outcome, **kwargs):
                    calls.append(args)
                    if args[1] == "--help":
                        return SimpleNamespace(returncode=0, stdout=b" --kill-whom=WHO")
                    if args[1] in ("kill", "start"):
                        return SimpleNamespace(returncode=0)
                    pid = 123
                    active, substate = "active", "running"
                    if any(call[1] == "kill" for call in calls):
                        if outcome in ("auto-restart", "pid-change-old-alive", "auto-missing"):
                            pid = 456
                        elif clock[0] >= 0.5 and outcome not in ("old-alive", "zombie-no-transition"):
                            pid, active, substate = 0, "failed", "failed"
                    if any(call[1] == "start" for call in calls):
                        pid, active, substate = 456, "active", "running"
                    return SimpleNamespace(returncode=0, stdout=f"ActiveState={active}\nSubState={substate}\nMainPID={pid}\n".encode())
                def identity(pid, clock=clock, outcome=outcome, calls=calls):
                    if pid == 456:
                        return None if outcome in ("auto-missing", "fresh-missing") else (88, "S")
                    if outcome in ("auto-restart", "auto-missing") and any(call[1] == "kill" for call in calls):
                        return None
                    if outcome == "zombie-no-transition" and any(call[1] == "kill" for call in calls):
                        return (77, "Z")
                    if clock[0] >= 0.5 and outcome in ("delayed-death", "zombie-transition", "fresh-missing"):
                        return (77, "Z") if outcome == "zombie-transition" else None
                    return (77, "S")
                def advance(seconds, clock=clock):
                    clock[0] += seconds
                with patch.object(module, "run", side_effect=command), patch.object(module, "process_identity", side_effect=identity, create=True), patch.object(module.time, "monotonic", side_effect=lambda clock=clock: clock[0]), patch.object(module.time, "sleep", side_effect=advance):
                    if outcome in ("old-alive", "pid-change-old-alive", "zombie-no-transition", "auto-missing"):
                        with self.assertRaisesRegex(RuntimeError, "old broker death"):
                            exec(boundary, {"self": guest, "run": module.run, "SERVICE": module.SERVICE, "identity": "fixture-operation"})
                        self.assertFalse(any(call[1] == "start" for call in calls))
                        self.assertLessEqual(clock[0], 30)
                    elif outcome == "fresh-missing":
                        with self.assertRaisesRegex(RuntimeError, "fresh broker identity"):
                            exec(boundary, {"self": guest, "run": module.run, "SERVICE": module.SERVICE, "identity": "fixture-operation"})
                        self.assertEqual(sum(call[1] == "start" for call in calls), 1)
                        self.assertFalse(any(event.get("case") == "broker-fresh-running" for event in guest.events))
                    else:
                        exec(boundary, {"self": guest, "run": module.run, "SERVICE": module.SERVICE, "identity": "fixture-operation"})
                        self.assertEqual(sum(call[1] == "kill" for call in calls), 1)
                        self.assertEqual(sum(call[1] == "start" for call in calls), 1)
                        self.assertTrue(any(event.get("old_main_retired") is True for event in guest.events))
                        self.assertTrue(any(event.get("case") == "broker-fresh-running" for event in guest.events))
                self.assertNotIn("PRIVATE", json.dumps(guest.events))

    def test_main_crash_rejects_unsupported_or_invalid_live_identity(self):
        module = self.native_module()
        for capability, pid, identity in ((False, 123, (77, "S")), (True, 0, None), (True, None, None), (True, 123, None), (True, 123, (77, "Z"))):
            with self.subTest(capability=capability, pid=pid, identity=identity), tempfile.TemporaryDirectory() as d:
                guest = module.NativeQA(SimpleNamespace(evidence_dir=Path(d)))
                guest.layout = "bind"
                def command(*args, capability=capability, pid=pid, **kwargs):
                    if args[1] == "--help":
                        return SimpleNamespace(returncode=0, stdout=b"--kill-whom=WHO" if capability else b"PRIVATE unsupported")
                    if args[1] == "show":
                        return SimpleNamespace(returncode=0, stdout=f"ActiveState=active\nSubState=running\nMainPID={pid}\n".encode())
                    self.fail("unsupported or invalid identity must never signal or start")
                with patch.object(module, "run", side_effect=command), patch.object(module, "process_identity", return_value=identity, create=True):
                    with self.assertRaises(RuntimeError):
                        guest.kill_broker("service_update")
                self.assertNotIn("PRIVATE", json.dumps(guest.events))

    def test_process_stat_identity_is_bounded_and_validated(self):
        module = self.native_module()
        raw = b"123 (PRIVATE name) with parens)) S " + b"0 " * 18 + b"77\n"
        self.assertEqual(module.parse_process_stat(raw, 123), (77, "S"))
        for invalid in (raw.replace(b"123 (", b"124 (", 1), raw.replace(b"77\n", b"0\n"), raw.replace(b"77\n", b"18446744073709551616\n"), raw.replace(b" S ", b" INVALID "), b"PRIVATE", b"x" * 4097):
            with self.subTest(raw=invalid[:20]):
                with self.assertRaisesRegex(RuntimeError, "process identity unavailable"):
                    module.parse_process_stat(invalid, 123)
        for pid in (0, -1, None, True):
            with self.subTest(pid=pid), self.assertRaises(RuntimeError):
                module.process_identity(pid)

    def test_child_metadata_uses_original_code_identity_and_fixed_error_kind(self):
        module = self.native_module()
        private = "PRIVATE_KEY_ARGUMENT_PATH"
        def trusted():
            raise PermissionError(private)
        def foreign():
            raise RuntimeError(private)
        foreign.__code__ = foreign.__code__.replace(co_filename=trusted.__code__.co_filename, co_name=trusted.__code__.co_name)
        for function, label, kind in ((trusted, "broker-serve", "permission-error"), (foreign, None, "unknown")):
            try:
                function()
            except Exception as error:
                metadata = module.broker_failure_metadata(error, (("broker-serve", trusted.__code__),))
            self.assertEqual(metadata["code_label"], label)
            self.assertEqual(metadata["error_kind"], kind)
            if label:
                self.assertIn(metadata["source_line"], {line for _, _, line in trusted.__code__.co_lines()})
            else:
                self.assertIsNone(metadata["source_line"])
            self.assertNotIn(private, json.dumps(metadata))

        with tempfile.TemporaryDirectory() as directory:
            qa = module.NativeQA(SimpleNamespace(evidence_dir=Path(directory)))
            def fixture_boundary():
                qa.recovery.bootstrap()
            # Actual bootstrap -> inspect -> docker -> run, with only the
            # subprocess boundary substituted. No old product is simulated.
            for returncode in (17, -9, True, 256):
                with self.subTest(returncode=returncode), patch.object(module.subprocess, "run", return_value=SimpleNamespace(returncode=returncode, stdout=private.encode(), stderr=private.encode())):
                    try:
                        fixture_boundary()
                    except RuntimeError as error:
                        metadata = module.native_phase_failure_metadata(error, "fixture", (("fixture", fixture_boundary.__code__),))
                    else:
                        self.fail("checked subprocess failure must escape")
                    self.assertIn(metadata["source_line"], {line for _, _, line in fixture_boundary.__code__.co_lines()})
                    self.assertEqual(metadata["error_kind"], "runtime-error")
                    failure = self.assert_bootstrap_failure_shape(metadata)
                    self.assertEqual(failure["bootstrap_step"], "legacy-runtime-inspect")
                    self.assertIn(failure["code_label"], {"legacy-bootstrap", "native-command"})
                    trusted_lines = {line for code in (module.LegacyRecoveryFixture.bootstrap.__code__, module.run.__code__) for _, _, line in code.co_lines()}
                    self.assertIn(failure["source_line"], trusted_lines)
                    self.assertEqual(failure["command_outcome"], "nonzero-exit")
                    self.assertEqual(failure["command_returncode"], returncode if type(returncode) is int and -255 <= returncode <= 255 else None)
                    self.assertNotIn(private, json.dumps(metadata))

            # Reproduce the reviewed constructed API witness through the real
            # run/bootstrap frames. Current run-created outcomes are literals;
            # this protects the closed contract, not a claimed native leak.
            class EqualString(str):
                def __eq__(self, other):
                    return True
            with self.subTest("constructed hostile outcome"):
                error = module.NativeCommandFailure(EqualString(private), 17)
                with patch.object(module.subprocess, "run", side_effect=error):
                    try:
                        fixture_boundary()
                    except RuntimeError as caught:
                        metadata = module.native_phase_failure_metadata(caught, "fixture", (("fixture", fixture_boundary.__code__),))
                    else:
                        self.fail("the original owned exception must preserve failure")
                self.assertNotIn(private, json.dumps(metadata))
                outcome, _ = module.command_failure_facts(error)
                self.assertIs(type(outcome), str)
                self.assertEqual(outcome, "unknown")
                self.assertEqual(metadata["bootstrap_failure"]["command_outcome"], "unknown")
            for supplied, expected in (("nonzero-exit", "nonzero-exit"), ("timeout", "timeout"), ("spawn-error", "spawn-error"), (None, "unknown")):
                with self.subTest(canonical_outcome=supplied):
                    outcome, _ = module.command_failure_facts(module.NativeCommandFailure(supplied, 17))
                    self.assertIs(type(outcome), str)
                    self.assertEqual(outcome, expected)

            # Judge immutability through public facts after ordinary mutation
            # attempts; arbitrary reflection/object.__setattr__ is out of scope.
            mutations = (
                ("set", lambda error: setattr(error, "_command_returncode", 23)),
                ("delete returncode", lambda error: delattr(error, "_command_returncode")),
                ("delete outcome", lambda error: delattr(error, "_command_outcome")),
                ("reinitialize", lambda error: error.__init__("timeout")),
            )
            for name, mutate in mutations:
                with self.subTest(ordinary_mutation=name):
                    error = module.NativeCommandFailure("nonzero-exit", 17)
                    before = module.command_failure_facts(error)
                    try:
                        mutate(error)
                    except (AttributeError, TypeError):
                        pass
                    try:
                        after = module.command_failure_facts(error)
                    except AttributeError:
                        after = None
                    self.assertEqual(after, before)

            @contextmanager
            def propagation_boundary():
                try:
                    yield
                finally:
                    propagated.append(True)
            propagated = []
            error = module.NativeCommandFailure("nonzero-exit", 17)
            cause = ValueError(private)
            try:
                with propagation_boundary():
                    raise error from cause
            except module.NativeCommandFailure as caught:
                self.assertIs(caught, error)
                self.assertIs(caught.__cause__, cause)
                caught.__traceback__ = caught.__traceback__
                caught.__context__ = cause
                caught.__suppress_context__ = True
                self.assertIs(caught.__context__, cause)
                self.assertEqual(module.command_failure_facts(caught), ("nonzero-exit", 17))
            self.assertEqual(propagated, [True])

            class UntrustedError(RuntimeError):
                @property
                def returncode(self):
                    raise AssertionError("untrusted exception property inspected")
                def __str__(self):
                    raise AssertionError("untrusted exception text inspected")
            def replacement(self):
                raise UntrustedError(private)
            original = module.LegacyRecoveryFixture.bootstrap.__code__
            replacement.__code__ = replacement.__code__.replace(co_filename=original.co_filename, co_name=original.co_name)
            with patch.object(module.LegacyRecoveryFixture, "bootstrap", replacement):
                try:
                    fixture_boundary()
                except RuntimeError as error:
                    metadata = module.native_phase_failure_metadata(error, "fixture", (("fixture", fixture_boundary.__code__),))
                failure = self.assert_bootstrap_failure_shape(metadata)
                self.assertEqual(failure, {"bootstrap_step": "unknown", "code_label": "unknown", "source_line": None,
                                           "guard_line": None, "error_kind": "unknown", "command_outcome": "unknown", "command_returncode": None,
                                           "scoped_select_diagnostic": "unknown",
                                           "scoped_select_inner_diagnostic": module.inner_unknown()})
                self.assertNotIn(private, json.dumps(metadata))

        # Exercise the exact installed-wheel predicate, rather than a replacement
        # selector or mocked distribution. This portable source test cannot
        # establish which interpreter/guard failed in a historical native run.
        import importlib.metadata
        upgrade_path = ROOT / "src/dc_overview/fleet_upgrade.py"
        upgrade_source = upgrade_path.read_text()
        self.assertEqual(hashlib.sha256(upgrade_source.encode()).hexdigest(),
                         "ac7d1e55de5707130b2acbf6e92b861ec960413a8fea4d6ff0097984111b8934")
        node = next(n for n in ast.parse(upgrade_source).body
                    if isinstance(n, ast.FunctionDef) and n.name == "verify_running_cli")
        self.assertEqual(hashlib.sha256(ast.get_source_segment(upgrade_source, node).encode()).hexdigest(),
                         "c830c355e09f81bdbf28f34286116558eebf752d51aab45bdeeaf80d16b5c344")
        init_source = (ROOT / "src/dc_overview/__init__.py").read_text()
        version = next(ast.literal_eval(n.value) for n in ast.parse(init_source).body
                       if isinstance(n, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == "__version__" for t in n.targets))
        package_name = "_fleet_selector_predicate_fixture"
        package = types.ModuleType(package_name)
        package.__version__ = version
        namespace = {"__name__": package_name + ".fleet_upgrade", "__package__": package_name, "json": json}
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(upgrade_path), "exec"), namespace)
        predicate = namespace["verify_running_cli"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package.__path__ = [str(root)]
            distribution = root / ("dc_overview-" + version + ".dist-info")
            distribution.mkdir()
            metadata_path = distribution / "METADATA"
            provenance_path = distribution / "direct_url.json"
            metadata_path.write_text("Metadata-Version: 2.4\nName: dc-overview\nVersion: " + version + "\n")
            target = {"release": version, "url": "https://example.invalid/PRIVATE_SELECTED_WHEEL.whl",
                      "sha256": "a" * 64}
            provenance = {"url": target["url"], "archive_info": {"hashes": {"sha256": target["sha256"]}}}
            with patch.dict(sys.modules, {package_name: package}), patch.object(sys, "path", [str(root)]):
                provenance_path.write_text(json.dumps(provenance))
                installed = importlib.metadata.distribution("dc-overview")
                self.assertEqual(installed.version, version)
                self.assertEqual(json.loads(installed.read_text("direct_url.json")), provenance)
                expected = target["url"] + "#sha256=" + target["sha256"]
                self.assertEqual(predicate(target), {"success": True, "state": "verified", "owner": "host-cli",
                                                    "desired": expected, "observed": expected})
                provenance_path.write_text(json.dumps({"url": "https://example.invalid/PRIVATE_OTHER_WHEEL.whl",
                                                       "archive_info": {"hashes": {"sha256": "b" * 64}}}))
                before = {p: p.read_bytes() for p in (metadata_path, provenance_path)}
                try:
                    predicate(target)
                except RuntimeError as error:
                    original_kind, original_args = type(error), error.args
                    trace = error.__traceback__
                    observed = module.broker_failure_metadata(error, (("dc-running-cli", predicate.__code__),))
                    self.assertIs(type(error), original_kind)
                    self.assertEqual(error.args, original_args)
                    self.assertIs(error.__traceback__, trace)
                    line = None
                    while trace is not None:
                        if trace.tb_frame.f_code is predicate.__code__:
                            line = trace.tb_lineno
                        trace = trace.tb_next
                    self.assertEqual(line, 141, "the real original provenance refusal must be exercised")
                    self.assertTrue(str(error).startswith("requires_cli_upgrade:"))
                else:
                    self.fail("version equality must not bypass original URL/hash provenance checks")
                self.assertEqual({p: p.read_bytes() for p in before}, before)
                self.assertEqual(upgrade_path.read_text(), upgrade_source)
                for private in ("PRIVATE", str(root), target["url"], target["sha256"]):
                    self.assertNotIn(private, json.dumps(observed))
                self.assertEqual(observed["code_label"], "dc-running-cli",
                                 "the original selector predicate is currently lost behind its outer broker frame")
                self.assertEqual(observed["source_line"], line)
                self.assertEqual(observed["error_kind"], "runtime-error")

        # Exercise the same bounded reader/loaded-code qualifier in a private
        # installed-layout fixture. Only exact original function bodies are
        # compiled; no immutable Proxy code or product module is imported.
        module.sysconfig.get_config_vars()  # Load stdlib build data before restricting metadata discovery.
        with private_owner_temp(module) as directory:
            root = Path(directory)
            prefix = root / "legacy-host-venv"
            site = prefix / ("lib/python" + str(sys.version_info.major) + "." + str(sys.version_info.minor)) / "site-packages"
            package_path = site / "dc_overview"
            package_path.mkdir(parents=True, mode=0o700)
            init_path = package_path / "__init__.py"
            init_path.write_text(init_source)
            installed_upgrade = package_path / "fleet_upgrade.py"
            installed_upgrade.write_text(upgrade_source)
            installed_package = types.ModuleType("dc_overview")
            installed_package.__file__ = str(init_path)
            installed_package.__version__ = version
            installed_module = types.ModuleType("dc_overview.fleet_upgrade")
            installed_module.__file__ = str(installed_upgrade)
            installed_module.__package__ = "dc_overview"
            installed_module.json = json
            imports = [n for n in ast.parse(upgrade_source).body if isinstance(n, (ast.Import, ast.ImportFrom))]
            exec(compile(ast.Module(body=[*imports, node], type_ignores=[]), str(installed_upgrade), "exec"), vars(installed_module))
            original_predicate = installed_module.verify_running_cli
            distribution = site / ("dc_overview-" + version + ".dist-info")
            distribution.mkdir(mode=0o700)
            metadata_path = distribution / "METADATA"
            provenance_path = distribution / "direct_url.json"
            metadata_path.write_text("Metadata-Version: 2.4\nName: dc-overview\nVersion: " + version + "\n")
            provenance_path.write_text(json.dumps({"url": "https://example.invalid/PRIVATE_OTHER_WHEEL.whl",
                                                 "archive_info": {"hashes": {"sha256": "b" * 64}}}))
            selected_manifest = {"components": {"dc-overview-cli": {"owner": "host-cli", "release": version,
                "artifacts": {"any": {"kind": "wheel", "url": target["url"], "sha256": target["sha256"]}}}}}
            with patch.dict(sys.modules, {"dc_overview": installed_package, "dc_overview.fleet_upgrade": installed_module}), patch.object(sys, "path", [str(site)]), patch.object(sys, "prefix", str(prefix)), patch.object(module, "ROOT", root):
                # The predicate-only fixture below cannot prove the observer's
                # required selector role. Qualify the complete unchanged module
                # first, without calling its selector, guards or owner APIs.
                full_module = types.ModuleType("dc_overview.fleet_upgrade")
                full_module.__file__ = str(installed_upgrade)
                full_module.__package__ = "dc_overview"
                full_code = compile(upgrade_source, str(installed_upgrade), "exec")
                exec(full_code, vars(full_module))
                original_selector = full_module.select_release_components.__code__
                with patch.dict(sys.modules, {"dc_overview.fleet_upgrade": full_module}):
                    full_codes = module.naturally_loaded_selector_codes(module.time.monotonic() + 1)
                required = [code for label, code in full_codes if label == "dc-scoped-selector"]
                self.assertEqual(len(required), 1, "full frozen source must qualify exactly one original selector")
                self.assertIs(required[0], original_selector)
                self.assertEqual(installed_upgrade.read_text(), upgrade_source)
                deadline = module.time.monotonic() + 1
                codes = module.naturally_loaded_selector_codes(deadline)
                self.assertEqual(codes, (("dc-running-cli", original_predicate.__code__),))
                before = {p: p.read_bytes() for p in (metadata_path, provenance_path, installed_upgrade)}
                try:
                    original_predicate(target)
                except RuntimeError as error:
                    with owner_file_read_audit(module, {metadata_path: 65536, provenance_path: 65536}) as reads:
                        detail = module.selector_failure_details(error, codes, selected_manifest, module.time.monotonic() + 1)
                    self.assertEqual([item["path"] for item in reads], [metadata_path, provenance_path])
                    self.assertEqual(detail["frames"], [{"role": "dc-running-cli", "line": 141}])
                    self.assertEqual(detail["qualification"], "qualified")
                    self.assertEqual(detail["actual_interpreter"], "compatible-host-venv")
                    self.assertEqual([detail[k] for k in ("module_version_match", "distribution_version_match", "url_match", "hash_match")], [True, True, False, False])
                    self.assertTrue(module.selector_details_valid(detail))
                    self.assertNotIn("PRIVATE", json.dumps(detail))
                    self.assertNotIn(str(root), json.dumps(detail))
                    self.assertLessEqual(len(module.encoded(detail)), 4096)
                    with self.assertRaises(module.ObservationRefused):
                        module.selector_failure_details(error, codes, selected_manifest, module.time.monotonic() - 1)
                    installed_module.__file__ = str(prefix / "foreign/dc_overview/fleet_upgrade.py")
                    self.assertEqual(module.naturally_loaded_selector_codes(module.time.monotonic() + 1), ())
                    installed_module.__file__ = str(installed_upgrade)
                    installed_package.__file__ = str(prefix / "foreign/dc_overview/__init__.py")
                    self.assertEqual(module.selector_failure_details(error, codes, selected_manifest,
                        module.time.monotonic() + 1)["qualification"], "source-refused")
                    installed_package.__file__ = str(init_path)
                    # A source-identical filename/name does not qualify foreign code.
                    installed_module.verify_running_cli = foreign
                    self.assertEqual(module.naturally_loaded_selector_codes(module.time.monotonic() + 1), ())
                    installed_module.verify_running_cli = original_predicate
                    installed_upgrade.write_text(upgrade_source + "\n")
                    self.assertEqual(module.naturally_loaded_selector_codes(module.time.monotonic() + 1), ())
                    installed_upgrade.write_text(upgrade_source)
                    alias = distribution / "retained-metadata"
                    metadata_path.rename(alias)
                    metadata_path.symlink_to(alias)
                    with self.assertRaises(module.ObservationRefused):
                        module.selector_failure_details(error, codes, selected_manifest, module.time.monotonic() + 1)
                    metadata_path.unlink(); alias.rename(metadata_path)
                    provenance_path.write_bytes(b"x" * 65537)
                    with self.assertRaises(module.ObservationRefused):
                        module.selector_failure_details(error, codes, selected_manifest, module.time.monotonic() + 1)
                    provenance_path.write_bytes(before[provenance_path])
                else:
                    self.fail("real provenance mismatch must retain its original predicate failure")
                self.assertEqual({p: p.read_bytes() for p in before}, before)

        # Actual frozen parser -> unmapped _json failure: retain context without
        # promoting its recognized outer Manifest frame into the inner cause.
        catalog_path = ROOT / "src/dc_overview/release_catalog.py"
        self.assertEqual(hashlib.sha256(catalog_path.read_bytes()).hexdigest(),
                         "21d4cf4731226c4ca9498cd4999bec1ec90bb9d3628faa615e13f20ccd9a29f6")
        catalog = runpy.run_path(str(catalog_path))
        parser_code = catalog["Manifest"].from_bytes.__func__.__code__
        try:
            catalog["Manifest"].from_bytes(b"PRIVATE_INVALID_JSON")
        except ValueError as error:
            codes = (("catalog-manifest", parser_code),)
            self.assertEqual(module.broker_failure_metadata(error, codes),
                             {"code_label": None, "source_line": None, "error_kind": "unknown"})
            detail = module.selector_failure_details(error, codes, {}, module.time.monotonic() + 1)
            self.assertEqual(detail["qualification"], "innermost-unknown")
            self.assertTrue(detail["frames"])
            self.assertIsNone(detail["url_match"])
            self.assertNotIn("PRIVATE", json.dumps(detail))
        else:
            self.fail("the original strict parser must refuse malformed JSON")

    def test_scoped_select_closed_observation_and_transport(self):
        native = self.native_module()
        PRIVATE = "PRIVATE_SCOPED_ARGUMENT_PATH_OUTPUT"
        product_modules = {name: value for name, value in sys.modules.items() if name == "dc_overview" or name.startswith("dc_overview.") or name == "cryptolabs_proxy" or name.startswith("cryptolabs_proxy.")}
        messages = [
            {
                "category": "cli-provenance-rejected",
                "stderr_utf8_exact": "Error: requires_cli_upgrade: install the verified exact wheel from the selected manifest using the documented package-manager step, then rerun this command\n"
            },
            {
                "category": "recovery-required",
                "stderr_utf8_exact": "Error: native_service_recovery_required\n"
            },
            {
                "category": "updater-busy",
                "stderr_utf8_exact": "Error: updater is busy; retry scoped selection after it finishes\n"
            },
            {
                "category": "updater-custody-changed",
                "stderr_utf8_exact": "Error: updater custody changed during scoped selection\n"
            },
            {
                "category": "updater-store-changed",
                "stderr_utf8_exact": "Error: updater store changed during scoped selection\n"
            },
            {
                "category": "updater-lock-changed",
                "stderr_utf8_exact": "Error: updater lock changed during scoped selection\n"
            },
            {
                "category": "public-reference-stale",
                "stderr_utf8_exact": "Error: public configuration/selection snapshot is stale\n"
            },
            {
                "category": "public-reference-changed",
                "stderr_utf8_exact": "Error: public configuration changed after release preflight\n"
            },
            {
                "category": "proxy-identity-required",
                "stderr_utf8_exact": "Error: running proxy identity is required for scoped selection\n"
            },
            {
                "category": "proxy-identity-changed",
                "stderr_utf8_exact": "Error: proxy changed during scoped selection\n"
            },
            {
                "category": "proxy-release-mount-required",
                "stderr_utf8_exact": "Error: proxy read-only release mount prerequisite\n"
            },
            {
                "category": "updater-mount-changed",
                "stderr_utf8_exact": "Error: updater mount changed during scoped selection\n"
            },
            {
                "category": "manifest-changed",
                "stderr_utf8_exact": "Error: manifest changed during scoped preparation\n"
            },
            {
                "category": "runtime-changed",
                "stderr_utf8_exact": "Error: scoped runtime changed during selection\n"
            },
            {
                "category": "proxy-authority-required",
                "stderr_utf8_exact": "Error: Proxy updater authority prerequisite: install the compatible published cryptolabs-proxy package, then use cryptolabs-proxy configuration plan and cryptolabs-proxy configuration adopt to migrate the existing proxy before retrying. The running updater must advertise selection contract 1 and proxy_replacement_policy=host-adoption-required-v1; no update was submitted or release changes applied.\n"
            }
        ]
        # Baseline privacy is already present and must survive this extension.
        with patch.object(native.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout=PRIVATE.encode(), stderr=PRIVATE.encode())) as child:
            with self.assertRaises(native.NativeCommandFailure) as raised:
                native.run('fixed-cli', PRIVATE)
        self.assertEqual(native.command_failure_facts(raised.exception), ('nonzero-exit', 1))
        self.assertNotIn(PRIVATE, str(raised.exception) + repr(raised.exception) + repr(raised.exception.args))
        self.assertEqual(child.call_count, 1)

        def boundary(flag):
            _bootstrap_step = 'scoped-select'
            native.run('fixed-cli', 'release', 'select', PRIVATE, input_bytes=b'fixed-input', timeout=37,
                       env={'PUBLIC_FIXED': '1'}, scoped_select_diagnostic=flag)

        codes = ((boundary.__code__, 'legacy-bootstrap', native.bootstrap_step_offsets(boundary.__code__)),
                 (native.run.__code__, 'native-command', ()))

        def observation(result, flag=True, step='scoped-select'):
            with patch.object(native.subprocess, 'run', return_value=result) as child:
                try:
                    boundary(flag)
                except native.NativeCommandFailure as error:
                    saved_error = error
                    value = native.bootstrap_failure_metadata(error, codes=codes, bootstrap_codes=(boundary.__code__,))
                except TypeError:
                    self.fail('MISSING_NEW_DIAGNOSTIC: real run wrapper rejects scoped_select_diagnostic=True; baseline RED, not native cause reproduction')
                else:
                    self.fail('original checked command failure was lost')
            self.assertEqual(child.call_count, 1)
            error = saved_error
            self.assertEqual(child.call_args.args, (['fixed-cli', 'release', 'select', PRIVATE],))
            self.assertEqual(child.call_args.kwargs, dict(input=b'fixed-input', capture_output=True, timeout=37, env={'PUBLIC_FIXED': '1'}))
            self.assertEqual(native.command_failure_facts(error), ('nonzero-exit', result.returncode if type(result.returncode) is int and -255 <= result.returncode <= 255 else None))
            self.assertIsNone(value['guard_line'])
            self.assertNotIn(PRIVATE, json.dumps(value) + str(error) + repr(error) + repr(error.args))
            self.assertIn('scoped_select_diagnostic', value)
            self.assertIs(type(value['scoped_select_diagnostic']), str)
            # Untrusted/non-bootstrap frame projections stay unknown.
            self.assertEqual(native.bootstrap_failure_metadata(error, codes=codes, bootstrap_codes=())['scoped_select_diagnostic'], 'unknown')
            return value['scoped_select_diagnostic'], error

        # Fail once at the first absent observable contract before the wider
        # GREEN matrix; avoid redundant baseline failures for the same gap.
        first = messages[0]
        self.assertEqual(observation(SimpleNamespace(returncode=1, stdout=b'', stderr=first['stderr_utf8_exact'].encode()))[0], first['category'])
        for entry in messages:
            raw = entry['stderr_utf8_exact'].encode()
            with self.subTest(category=entry['category']):
                category, error = observation(SimpleNamespace(returncode=1, stdout=b'', stderr=raw))
                self.assertEqual(category, entry['category'])
                # Discover owned diagnostic slot without prescribing its private name.
                new_slots = set(native.NativeCommandFailure.__slots__) - {'_command_outcome', '_command_returncode', '_scoped_select_inner_diagnostic'}
                self.assertEqual(len(new_slots), 1)
                slot = next(iter(new_slots))
                self.assertEqual(type(getattr(error, slot)), str)
                for owned in (slot, '_scoped_select_inner_diagnostic'):
                    saved = getattr(error, owned)
                    for mutation in (lambda: setattr(error, owned, PRIVATE), lambda: delattr(error, owned), lambda: error.__init__('timeout')):
                        with self.assertRaises((AttributeError, TypeError)):
                            mutation()
                    self.assertEqual(getattr(error, owned), saved)
                self.assertEqual(getattr(error, slot), entry['category'])

        raw = messages[0]['stderr_utf8_exact'].encode()
        class BytesSubclass(bytes):
            pass
        class StringTrap:
            def __str__(self):
                raise AssertionError('must not coerce arbitrary output')
        cases = [
            (1, b'', b'prefix ' + raw), (1, b'', raw + b'\n'), (1, b'', raw[:-1]),
            (1, b'', raw + messages[1]['stderr_utf8_exact'].encode()),
            (1, PRIVATE.encode(), raw), (1, b'', b'x' * 513), (1, b'', b'\xff'),
            (1, b'', 'text'), (1, b'', BytesSubclass(raw)), (1, BytesSubclass(b''), raw),
            (1, b'', StringTrap()), (1, b'', b'Error: unknown\n'), (17, b'', raw),
            (-1, b'', raw), (True, b'', raw), (1, None, raw), (1, b'', None),
        ]
        for index, (code, stdout, stderr) in enumerate(cases):
            with self.subTest(negative=index):
                self.assertEqual(observation(SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr))[0], 'unknown')
        for flag in (False, 1, 'True', None):
            with self.subTest(default_off=repr(flag)):
                self.assertEqual(observation(SimpleNamespace(returncode=1, stdout=b'', stderr=raw), flag=flag)[0], 'unknown')
        def nonscoped_boundary():
            _bootstrap_step = 'legacy-runtime-inspect'
            native.run('fixed-cli', scoped_select_diagnostic=True)
        nonscoped_codes = ((nonscoped_boundary.__code__, 'legacy-bootstrap', native.bootstrap_step_offsets(nonscoped_boundary.__code__)),
                           (native.run.__code__, 'native-command', ()))
        with patch.object(native.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout=b'', stderr=raw)):
            with self.assertRaises(native.NativeCommandFailure) as caught:
                nonscoped_boundary()
        self.assertEqual(native.bootstrap_failure_metadata(caught.exception, codes=nonscoped_codes, bootstrap_codes=(nonscoped_boundary.__code__,))['scoped_select_diagnostic'], 'unknown')
        # Projection rejects subclasses and malformed stored categories without coercion.
        class ForeignFailure(native.NativeCommandFailure):
            pass
        malformed = native.NativeCommandFailure('nonzero-exit', 1)
        object.__setattr__(malformed, slot, StringTrap())
        for supplied in (ForeignFailure('nonzero-exit', 1), malformed):
            with patch.object(native.subprocess, 'run', side_effect=supplied):
                with self.assertRaises(native.NativeCommandFailure) as caught:
                    boundary(True)
            value = native.bootstrap_failure_metadata(caught.exception, codes=codes, bootstrap_codes=(boundary.__code__,))
            self.assertEqual(value['scoped_select_diagnostic'], 'unknown')
        # Unchecked/success and system exceptions preserve previous transport outcomes.
        for code, check in ((0, True), (1, False)):
            result = SimpleNamespace(returncode=code, stdout=b'', stderr=raw)
            with patch.object(native.subprocess, 'run', return_value=result) as child:
                self.assertIs(native.run('fixed-cli', check=check, scoped_select_diagnostic=True), result)
                self.assertEqual(child.call_count, 1)
        for side_effect, facts in ((native.subprocess.TimeoutExpired('fixed', 1), ('timeout', None)), (OSError(PRIVATE), ('spawn-error', None))):
            with patch.object(native.subprocess, 'run', side_effect=side_effect) as child:
                with self.assertRaises(native.NativeCommandFailure) as caught:
                    native.run('fixed-cli', scoped_select_diagnostic=True)
                self.assertEqual(native.command_failure_facts(caught.exception), facts)
                self.assertNotIn(PRIVATE, str(caught.exception) + repr(caught.exception.args))
                self.assertEqual(child.call_count, 1)
        self.assertEqual({name: value for name, value in sys.modules.items() if name == 'dc_overview' or name.startswith('dc_overview.') or name == 'cryptolabs_proxy' or name.startswith('cryptolabs_proxy.')}, product_modules)
        # Default-off means the keyword can be omitted, even in a scoped frame.
        def default_boundary():
            _bootstrap_step = 'scoped-select'
            native.run('fixed-cli')
        default_codes = ((default_boundary.__code__, 'legacy-bootstrap', native.bootstrap_step_offsets(default_boundary.__code__)),
                         (native.run.__code__, 'native-command', ()))
        with patch.object(native.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout=b'', stderr=raw)):
            with self.assertRaises(native.NativeCommandFailure) as caught:
                default_boundary()
        self.assertEqual(native.bootstrap_failure_metadata(caught.exception, codes=default_codes, bootstrap_codes=(default_boundary.__code__,))['scoped_select_diagnostic'], 'unknown')
        for size in (511, 512, 513):
            self.assertEqual(observation(SimpleNamespace(returncode=1, stdout=b'', stderr=b'x' * size))[0], 'unknown')
        for stderr in (raw.replace(b'\n', b'\r\n'), raw.rstrip(b'\n'), raw + b' '):
            self.assertEqual(observation(SimpleNamespace(returncode=1, stdout=b'', stderr=stderr))[0], 'unknown')
        for code, stdout in ((1.0, b''), ('1', b''), (1, ''), (1, bytearray())):
            self.assertEqual(observation(SimpleNamespace(returncode=code, stdout=stdout, stderr=raw))[0], 'unknown')

        # A collection fault never substitutes its private exception or loses cleanup.
        cleaned = []
        @contextmanager
        def cleanup_boundary():
            try:
                yield
            finally:
                cleaned.append(True)
        with patch.object(native, 'classify_scoped_select_output', side_effect=RuntimeError(PRIVATE)):
            with cleanup_boundary():
                category, error = observation(SimpleNamespace(returncode=1, stdout=b'', stderr=raw))
        self.assertEqual(category, 'unknown')
        self.assertEqual(native.command_failure_facts(error), ('nonzero-exit', 1))
        self.assertEqual(cleaned, [True])
        self.assertNotIn(PRIVATE, str(error) + repr(error) + repr(error.args))

        # Same filename/name grants no frame identity; missing/hostile slots stay unknown.
        def foreign_boundary(flag):
            _bootstrap_step = 'scoped-select'
            native.run('fixed-cli', scoped_select_diagnostic=flag)
        foreign_boundary.__code__ = foreign_boundary.__code__.replace(co_filename=boundary.__code__.co_filename, co_name=boundary.__code__.co_name)
        with patch.object(native.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout=b'', stderr=raw)):
            with self.assertRaises(native.NativeCommandFailure) as caught:
                foreign_boundary(True)
        self.assertEqual(native.bootstrap_failure_metadata(caught.exception, codes=codes, bootstrap_codes=(boundary.__code__,))['scoped_select_diagnostic'], 'unknown')
        class EqualString(str):
            def __eq__(self, other):
                raise AssertionError('must reject subclasses before equality')
        for category in (PRIVATE, EqualString(PRIVATE), StringTrap()):
            malformed = native.NativeCommandFailure('nonzero-exit', 1)
            object.__setattr__(malformed, slot, category)
            with patch.object(native.subprocess, 'run', side_effect=malformed):
                with self.assertRaises(native.NativeCommandFailure) as caught:
                    boundary(True)
            self.assertEqual(native.bootstrap_failure_metadata(caught.exception, codes=codes, bootstrap_codes=(boundary.__code__,))['scoped_select_diagnostic'], 'unknown')
        missing = native.NativeCommandFailure('nonzero-exit', 1)
        object.__delattr__(missing, slot)
        with patch.object(native.subprocess, 'run', side_effect=missing):
            with self.assertRaises(native.NativeCommandFailure) as caught:
                boundary(True)
        self.assertEqual(native.bootstrap_failure_metadata(caught.exception, codes=codes, bootstrap_codes=(boundary.__code__,))['scoped_select_diagnostic'], 'unknown')


    def test_inner_recovery_observer_bounds_and_original_child_contract(self):
        native = self.native_module()
        private = 'PRIVATE_INNER_EXCEPTION_OR_PATH'
        def require(condition):
            if not condition:
                raise ValueError(private)
        calls = []
        def dependency(*args, require_capability=True):
            calls.append((args, require_capability))
            require(False)
        trusted = ((dependency.__code__, 'proxy-updates', 'service_recovery_dependency'),
                   (require.__code__, 'proxy-recovery', 'require'))
        def failure():
            try:
                dependency('original', require_capability=False)
            except ValueError as error:
                return error
        original = failure()
        value = native.project_inner_failure(original, trusted)
        self.assertTrue(value['guards'])
        self.assertIs(value['condition'], False)
        self.assertIs(value['require_capability'], False)
        self.assertNotIn(private, json.dumps(value))
        self.assertEqual(native.project_inner_failure(original, ()), native.inner_unknown())
        spoof = require.__code__.replace(co_name=require.__code__.co_name)
        self.assertEqual(native.project_inner_failure(original, ((spoof, 'proxy-recovery', 'require'),)), native.inner_unknown())
        class ForeignError(ValueError):
            def __str__(self):
                raise AssertionError('exception text must not be read')
        foreign = ForeignError(private).with_traceback(original.__traceback__)
        self.assertEqual(native.project_inner_failure(foreign, trusted), native.inner_unknown())
        # Exactly the context/frame limits remain usable; overflow/cycles do not.
        contexts = [failure() for _ in range(9)]
        for first, second in zip(contexts, contexts[1:]):
            first.__context__ = second
        self.assertEqual(native.project_inner_failure(contexts[0], trusted), native.inner_unknown())
        contexts[7].__context__ = None
        self.assertTrue(native.project_inner_failure(contexts[0], trusted)['guards'])
        contexts[7].__context__ = contexts[0]
        self.assertEqual(native.project_inner_failure(contexts[0], trusted), native.inner_unknown())
        leaf = original.__traceback__
        while leaf.tb_next is not None:
            leaf = leaf.tb_next
        for count in (32, 33):
            trace = None
            for _ in range(count):
                trace = types.TracebackType(trace, leaf.tb_frame, leaf.tb_lasti, leaf.tb_lineno)
            bounded = ValueError(private).with_traceback(trace)
            self.assertEqual(bool(native.project_inner_failure(bounded, trusted)['guards']), count == 32)
        # Hostile values never cross the finite built-in schema.
        class Trap:
            def __str__(self):
                raise AssertionError('foreign coercion')
            def __eq__(self, other):
                raise AssertionError('foreign comparison')
        invalid = [None, Trap(), {**value, 'private': private}, {**value, 'condition': 1},
                   {**value, 'condition': Trap()}, {**value, 'guards': tuple(value['guards'])},
                   {**value, 'guards': [{'source': 'proxy-recovery', 'guard': 'require', 'line': True}]},
                   {**value, 'guards': [{'source': private, 'guard': 'require', 'line': 1}]}]
        for item in invalid:
            self.assertEqual(native.inner_record(item), native.inner_unknown())
        # The real binding wrapper calls the original once and rethrows the
        # identical failure. A recovered or ambiguous failure is never a cause.
        module = SimpleNamespace(service_recovery_dependency=dependency)
        for recovered, observer_fault, setup_fault, broken_pipe, multiple in (
                (False, False, False, False, False), (True, False, False, False, False),
                (False, True, False, False, False), (False, False, True, False, False),
                (False, False, False, True, False), (False, False, False, False, True)):
            with self.subTest(recovered=recovered, observer_fault=observer_fault, setup_fault=setup_fault,
                              broken_pipe=broken_pipe, multiple=multiple):
                entered, caught, calls = [], [], []
                def console(path, run_name):
                    entered.append((path, run_name, sys.argv[:]))
                    for turn in range(2 if multiple else 1):
                        try:
                            module.service_recovery_dependency('original', require_capability=False)
                        except ValueError as error:
                            caught.append(error)
                            if not recovered and (not multiple or turn == 1):
                                raise
                reader, writer = os.pipe()
                if broken_pipe:
                    os.close(reader)
                try:
                    with patch.object(native, 'inner_trusted_codes', side_effect=RuntimeError(private) if setup_fault else None, return_value=trusted), patch.object(native.importlib, 'import_module', return_value=module), patch.object(runpy, 'run_path', side_effect=console), patch.object(native, 'project_inner_failure', side_effect=RuntimeError(private) if observer_fault else None, wraps=None if observer_fault else native.project_inner_failure):
                        if recovered:
                            native.scoped_select_child(writer, [], ['fixed-console', 'same-arg'])
                        else:
                            try:
                                native.scoped_select_child(writer, [], ['fixed-console', 'same-arg'])
                            except ValueError as error:
                                self.assertIs(error, caught[-1])
                            else:
                                self.fail('original dependency failure must escape')
                    self.assertIs(module.service_recovery_dependency, dependency)
                    self.assertEqual(len(entered), 1)
                    self.assertEqual(entered[0], ('fixed-console', '__main__', ['fixed-console', 'same-arg']))
                    self.assertEqual(calls, [(('original',), False)] * (2 if multiple else 1))
                    with self.assertRaises(OSError):
                        os.fstat(writer)
                    if not broken_pipe:
                        raw = os.read(reader, 8193)
                        self.assertLessEqual(len(raw), 8192)
                        self.assertEqual(os.read(reader, 1), b'')
                        record = json.loads(raw)
                        self.assertNotIn(private, raw.decode())
                        self.assertEqual(bool(record['guards']), not (recovered or observer_fault or setup_fault or multiple))
                finally:
                    if not broken_pipe:
                        os.close(reader)
        # Capture the original traceback nodes before the observer rethrows.
        # Original callers may catch and chain the same exception immediately.
        for mode in ('context', 'cause', 'suppressed'):
            with self.subTest(original_exception_chain=mode):
                state = {}
                original_error, outer_error = ValueError(private), RuntimeError(private)
                def original_dependency():
                    raise original_error
                def capture(error, codes):
                    state['error'] = error
                    state['original_nodes'] = BaseException.__traceback__.__get__(error, type(error)).tb_next
                    state['chain'] = (error.__cause__, error.__context__, error.__suppress_context__)
                    return native.inner_unknown()
                observed_module = SimpleNamespace(service_recovery_dependency=original_dependency)
                def original_console(path, run_name):
                    try:
                        observed_module.service_recovery_dependency()
                    except ValueError as error:
                        self.assertIs(error, state['error'])
                        trace = BaseException.__traceback__.__get__(error, type(error))
                        self.assertIs(trace.tb_frame.f_code, original_console.__code__)
                        self.assertIs(trace.tb_next, state['original_nodes'])
                        self.assertEqual((error.__cause__, error.__context__, error.__suppress_context__), state['chain'])
                        if mode == 'cause':
                            raise outer_error from error
                        if mode == 'suppressed':
                            raise outer_error from None
                        raise outer_error
                reader, writer = os.pipe()
                try:
                    with patch.object(native, 'inner_trusted_codes', return_value=trusted), patch.object(native.importlib, 'import_module', return_value=observed_module), patch.object(runpy, 'run_path', side_effect=original_console), patch.object(native, 'project_inner_failure', side_effect=capture):
                        try:
                            native.scoped_select_child(writer, [], ['fixed-console'])
                        except RuntimeError as error:
                            self.assertIs(error, outer_error)
                        else:
                            self.fail('original contextualized exception must escape')
                    self.assertIs(observed_module.service_recovery_dependency, original_dependency)
                    self.assertIs(outer_error.__context__, original_error)
                    self.assertIs(outer_error.__cause__, original_error if mode == 'cause' else None)
                    self.assertIs(outer_error.__suppress_context__, mode != 'context')
                    self.assertEqual((original_error.__cause__, original_error.__context__, original_error.__suppress_context__), state['chain'])
                    self.assertIs(original_error.__traceback__.tb_next, state['original_nodes'])
                    self.assertEqual(os.read(reader, 8193), native.encoded(native.inner_unknown()))
                finally:
                    os.close(reader)
        # Real subprocess/pipe/console execution: original argv, input, env,
        # streams and success/nonzero/timeout results retain their meanings.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root/'python').symlink_to(sys.executable)
            cli = root/'console'
            cli.write_text("import os,sys\nassert sys.argv[1:]==['same-arg']\nassert sys.stdin.buffer.read()==b'fixed-input'\nassert os.environ['FIXED_PUBLIC']=='1'\nsys.stdout.buffer.write(b'fixed-out')\nsys.stderr.buffer.write(b'fixed-err')\nraise SystemExit(7)\n")
            result = native.run(cli, 'same-arg', input_bytes=b'fixed-input', env={**os.environ, 'FIXED_PUBLIC':'1'},
                                check=False, scoped_select_diagnostic=True, scoped_select_wheels={})
            self.assertEqual((result.returncode, result.stdout, result.stderr), (7, b'fixed-out', b'fixed-err'))
            cli.write_text("import sys\nsys.stderr.write('Error: native_service_recovery_required\\n')\nraise SystemExit(1)\n")
            with self.assertRaises(native.NativeCommandFailure) as caught:
                native.run(cli, scoped_select_diagnostic=True, scoped_select_wheels={})
            self.assertEqual(native.command_failure_facts(caught.exception), ('nonzero-exit', 1))
            self.assertEqual(native.scoped_select_failure_fact(caught.exception), 'recovery-required')
            self.assertEqual(native.scoped_select_inner_fact(caught.exception), native.inner_unknown())
            cli.write_text("import time\ntime.sleep(2)\n")
            with self.assertRaises(native.NativeCommandFailure) as caught:
                native.run(cli, timeout=0.05, scoped_select_diagnostic=True, scoped_select_wheels={})
            self.assertEqual(native.command_failure_facts(caught.exception), ('timeout', None))
            # ADV-001: the interpreter renders the original application nodes,
            # including application-owned runpy, without observer scaffolding.
            counter = root/'calls'
            (root/'application.py').write_text('raise RuntimeError("fixed-public-application")\n')
            cases = {
                'runtime': 'raise RuntimeError("fixed-public-runtime")\n',
                'import': 'import fixed_public_absent_import_for_ADV001\n',
                'context': 'try:\n raise ValueError("fixed-public-context")\nexcept ValueError:\n raise RuntimeError("fixed-public-outer")\n',
                'cause': 'try:\n raise ValueError("fixed-public-cause")\nexcept ValueError as cause:\n raise RuntimeError("fixed-public-outer") from cause\n',
                'suppressed': 'try:\n raise ValueError("fixed-public-suppressed")\nexcept ValueError:\n raise RuntimeError("fixed-public-outer") from None\n',
                'application-runpy': 'import runpy\nrunpy.run_path(str(Path(__file__).with_name("application.py")),run_name="__main__")\n',
            }
            prefix = ('#!'+sys.executable+'\nfrom pathlib import Path\n'
                      'counter=Path('+repr(str(counter))+')\n'
                      'counter.write_text(str(int(counter.read_text())+1))\n'
                      'print("fixed-public-once",flush=True)\n')
            for name, body in cases.items():
                with self.subTest(original_terminal_output=name):
                    cli.write_text(prefix+body)
                    cli.chmod(0o700)
                    kwargs = dict(capture_output=True, timeout=5)
                    counter.write_text('0')
                    direct = subprocess.run([str(cli)], **kwargs)
                    self.assertEqual(counter.read_text(), '1')
                    counter.write_text('0')
                    wrapped, inner = native.scoped_select_subprocess([str(cli)], kwargs, {})
                    self.assertEqual(counter.read_text(), '1')
                    self.assertEqual((wrapped.returncode, wrapped.stdout, wrapped.stderr),
                                     (direct.returncode, direct.stdout, direct.stderr))
                    self.assertEqual((direct.returncode, direct.stdout), (1, b'fixed-public-once\n'))
                    self.assertEqual(inner, native.inner_unknown())
                    if name == 'application-runpy':
                        self.assertIn(b'<frozen runpy>', direct.stderr)
        # The reader accepts one <=8KiB strict object, not concatenation,
        # duplicate fields, overflow or a fault. No additional child runs occur.
        raw = native.encoded(value)
        for payload, qualified in ((raw+b' '*(8192-len(raw)), True), (raw+b' '*(8193-len(raw)), False),
                                   (raw+raw, False), (b'{"guards":[],"guards":[],"condition":"unknown","require_capability":"unknown"}', False)):
            with patch.object(native.subprocess, 'run', return_value=SimpleNamespace(returncode=1)) as child, patch.object(native.os, 'read', side_effect=[payload, b'']):
                _, record = native.scoped_select_subprocess(['fixed-console'], {}, {})
            self.assertEqual(child.call_count, 1)
            self.assertEqual(bool(record['guards']), qualified)

    def test_continuity_projection_is_closed_qualified_and_preserves_transport(self):
        native = self.native_module()
        # Qualification boundary only: the separate immutable Proxy2f contract
        # executes the genuine producer/guard. This fixture isolates hostile
        # locals/global drift without installing product packages or probing IO.
        fields = native.CONTINUITY_FIELDS
        namespace = types.ModuleType('fixed_continuity_projection_fixture')
        source = ('from dataclasses import dataclass\n@dataclass(frozen=True)\n'
                  'class OriginalObservation:\n container_id: str\n image_id: str\n'
                  ' helper_terminated: bool\n healthy: bool\n continuity: dict\n'
                  'def hold():\n raise ValueError("PRIVATE_CONTINUITY_FAILURE")\n'
                  'def require(condition):\n if not condition: hold()\n'
                  'def validate_receipt(value):\n return value\n'
                  'def validate_job(value):\n return value\n'
                  'def validate_continuity(value):\n return value\n'
                  'def _pattern(value, pattern):\n return True\n'
                  'def validate_original_restored(receipt, observation):\n value=validate_receipt(receipt)\n')
        source += '\n' * (227 - source.count('\n'))
        source += ' require(validate_continuity(observation.continuity)==value["continuity"])\n'
        with patch.dict(sys.modules, {namespace.__name__: namespace}):
            exec(compile(source, '<fixed-continuity-boundary>', 'exec'), namespace.__dict__)
        namespace.HASH_KEYS = set(fields[:10])
        namespace.CONTINUITY_KEYS = set(fields) | {'projection', 'saved_identity_field_count', 'stored_key_digest_matches', 'sync_enabled'}
        trusted = tuple((getattr(namespace, name).__code__, 'proxy-recovery', name)
                        for name in ('validate_original_restored', 'validate_receipt', 'validate_job',
                                     'validate_continuity', 'require', 'hold', '_pattern'))
        unbound = trusted
        trusted = native.bind_inner_trusted_context(trusted, namespace)
        genuine_class = namespace.OriginalObservation
        self.assertIs(trusted.observation_class, genuine_class)
        baseline = {key: 'b' * 64 for key in fields[:10]}
        baseline.update(database_device=1, database_inode=2, projection='ipmi-original-continuity-v1',
                        saved_identity_field_count=5, stored_key_digest_matches=True, sync_enabled=False)
        def failure(changed=('database_inode',)):
            before, after = dict(baseline), dict(baseline)
            for key in changed:
                after[key] = 'c' * 64 if key.endswith('_sha256') else after[key] + 1
            observation = namespace.OriginalObservation('1' * 64, 'sha256:' + '2' * 64, True, True, after)
            try:
                namespace.validate_original_restored({'continuity': before}, observation)
            except ValueError as error:
                return error, observation, before
            self.fail('original equality guard must reject fixture')
        for changed in [(key,) for key in fields] + [fields[:2]]:
            with self.subTest(fields=changed):
                error, observation, before = failure(changed)
                record = native.project_inner_failure(error, trusted)
                expected = {key: key not in changed for key in fields}
                self.assertEqual(record['continuity_equal'], expected)
                self.assertIs(record['condition'], False)
                self.assertEqual(native.inner_record(record), record)
                self.assertNotIn('PRIVATE_CONTINUITY_FAILURE', json.dumps(record))
                self.assertLessEqual(len(native.encoded(record)), 8192)
                owned = native.NativeCommandFailure('nonzero-exit', 1, 'recovery-required', record)
                record['continuity_equal']['database_inode'] = not expected['database_inode']
                self.assertEqual(native.scoped_select_inner_fact(owned)['continuity_equal'], expected)
                payload = native.encoded(native.scoped_select_inner_fact(owned))
                with patch.object(native.subprocess, 'run', return_value=SimpleNamespace(returncode=1)) as child, patch.object(native.os, 'read', side_effect=[payload, b'']):
                    _, transported = native.scoped_select_subprocess(['fixed-console'], {}, {})
                self.assertEqual(child.call_count, 1)
                self.assertEqual(transported['continuity_equal'], expected)
                self.assertEqual(before, baseline)
                self.assertEqual(error.args, ('PRIVATE_CONTINUITY_FAILURE',))
        error, _, _ = failure()
        self.assertEqual(native.project_inner_failure(error, unbound)['continuity_equal'], 'unknown')
        calls = {'eq': 0, 'getattr': 0, 'hash': 0}
        class Trap:
            def __hash__(self):
                calls['hash'] += 1
                return 0
            def __eq__(self, other):
                calls['eq'] += 1
                raise AssertionError('foreign equality must not execute')
            def __getattribute__(self, name):
                calls['getattr'] += 1
                raise AssertionError('foreign attributes must not execute')
        class ForeignDict(dict):
            def __eq__(self, other):
                calls['eq'] += 1
                raise AssertionError('foreign dictionary equality must not execute')
        for key, value in [('database_inode', True), ('database_device', -1), ('settings_sha256', Trap()),
                           ('settings_sha256', 'X' * 64), ('projection', Trap()),
                           ('saved_identity_field_count', True), ('stored_key_digest_matches', 1),
                           ('sync_enabled', 0)]:
            with self.subTest(malformed=key, value_type=type(value).__name__):
                error, observation, _ = failure()
                observation.continuity[key] = value
                self.assertEqual(native.project_inner_failure(error, trusted)['continuity_equal'], 'unknown')
                self.assertEqual(calls, {'eq': 0, 'getattr': 0, 'hash': 0})
        for change in ('missing', 'extra', 'foreign-dict', 'foreign-observation', 'all-equal', 'globals', 'class', 'replacement-global', 'replacement-both', 'module', 'schema', 'ambiguous', 'source', 'line'):
            with self.subTest(rejection=change):
                error, observation, before = failure()
                with patch.dict(namespace.__dict__):
                    selected = trusted
                    if change == 'missing': observation.continuity.pop('network_sha256')
                    if change == 'extra': observation.continuity['PRIVATE_EXTRA'] = Trap()
                    if change == 'foreign-dict': object.__setattr__(observation, 'continuity', ForeignDict(observation.continuity))
                    if change == 'foreign-observation':
                        class ForeignObservation(namespace.OriginalObservation):
                            def __getattribute__(self, name):
                                calls['getattr'] += 1
                                raise AssertionError('subclass attribute must not execute')
                        object.__setattr__(observation, '__class__', ForeignObservation)
                    if change == 'all-equal': observation.continuity.update(before)
                    if change == 'globals': namespace.require = lambda condition: None
                    if change == 'class': namespace.OriginalObservation = Trap
                    if change in ('replacement-global', 'replacement-both'):
                        attributes = {key: value for key, value in vars(genuine_class).items()
                                      if key not in ('__dict__', '__weakref__')}
                        replacement = type('OriginalObservation', (), attributes)
                        self.assertIsNot(replacement, genuine_class)
                        namespace.OriginalObservation = replacement
                        if change == 'replacement-both': object.__setattr__(observation, '__class__', replacement)
                    if change == 'module': namespace.__name__ = Trap()
                    if change == 'schema': namespace.HASH_KEYS = set()
                    if change == 'ambiguous': error.__context__ = failure()[0]
                    if change == 'source': selected = tuple(row for row in trusted if row[2] != 'validate_continuity')
                    if change == 'line':
                        trace = error.__traceback__
                        while trace.tb_frame.f_code is not namespace.validate_original_restored.__code__:
                            trace = trace.tb_next
                        error.__traceback__ = types.TracebackType(trace.tb_next, trace.tb_frame, trace.tb_lasti, 227)
                    self.assertEqual(native.project_inner_failure(error, selected)['continuity_equal'], 'unknown')
                    self.assertEqual(calls, {'eq': 0, 'getattr': 0, 'hash': 0})
        error, _, _ = failure()
        method = namespace.OriginalObservation.__setattr__
        constants = method.__code__.co_consts
        index = next(i for i, value in enumerate(constants) if type(value) in (tuple, frozenset))
        hostile = type(constants[index])([Trap()])
        calls.update(eq=0, getattr=0, hash=0)  # Ignore construction; observe only the projector.
        original_code = method.__code__
        try:
            method.__code__ = original_code.replace(co_consts=constants[:index] + (hostile,) + constants[index + 1:])
            self.assertEqual(native.project_inner_failure(error, trusted)['continuity_equal'], 'unknown')
            self.assertEqual(calls, {'eq': 0, 'getattr': 0, 'hash': 0})
        finally:
            method.__code__ = original_code
        record = native.project_inner_failure(error, trusted)
        for value in ({}, {**record['continuity_equal'], 'database_inode': 0},
                      {**record['continuity_equal'], 'PRIVATE_EXTRA': True},
                      {key: True for key in fields}, Trap(), ForeignDict(record['continuity_equal'])):
            self.assertEqual(native.inner_record({**record, 'continuity_equal': value}), native.inner_unknown())
            self.assertEqual(calls, {'eq': 0, 'getattr': 0, 'hash': 0})
        owned = native.NativeCommandFailure('nonzero-exit', 1, 'recovery-required', record)
        raw = owned._scoped_select_inner_diagnostic
        object.__setattr__(owned, '_scoped_select_inner_diagnostic', (*raw[:3], ((Trap(), True),) * 12))
        self.assertEqual(native.scoped_select_inner_fact(owned), native.inner_unknown())
        self.assertEqual(calls, {'eq': 0, 'getattr': 0, 'hash': 0})

    def test_broker_child_preserves_original_exception_when_collection_fails(self):
        module = self.native_module()
        cause = RuntimeError("PRIVATE_CHILD_EXCEPTION_ARGUMENT")
        def serve(broker):
            raise cause
        class Broker:
            def __init__(self, *args, **kwargs):
                pass
            def _reload_policy(self):
                pass
            def dispatch(self):
                pass
            def reconcile(self):
                pass
            def run_operation(self):
                pass
        modules = {
            "dc_overview.fleet_config": SimpleNamespace(FleetConfig=SimpleNamespace(load=lambda path: None)),
            "dc_overview.release_broker": SimpleNamespace(ReleaseBroker=Broker, load_policy=lambda: {}),
            "dc_overview.release_broker_service": SimpleNamespace(serve=serve, serve_connection=lambda: None, response=lambda: None),
        }
        for collector_fails in (False, True):
            with self.subTest(collector_fails=collector_fails), patch.dict(module.sys.modules, modules), patch.object(module.os, "geteuid", return_value=0), patch.object(module.platform, "system", return_value="Linux"), patch.object(module, "write_broker_failure", side_effect=ValueError("PRIVATE_COLLECTOR") if collector_fails else None) as collector:
                try:
                    module.broker_child()
                except RuntimeError as caught:
                    self.assertIs(caught, cause)
                else:
                    self.fail("the actual child exception must escape unchanged")
                metadata = collector.call_args.args[0]
                self.assertEqual(metadata["code_label"], "broker-serve")
                self.assertEqual(metadata["error_kind"], "runtime-error")
                self.assertIn(metadata["source_line"], {line for _, _, line in serve.__code__.co_lines()})
                self.assertNotIn("PRIVATE", json.dumps(metadata))

        # Existing execute/cleanup orchestration must survive a diagnostic
        # collector failure. Only whole phase boundaries are substituted.
        for cleanup_fails in (False, True):
            with self.subTest(cleanup_fails=cleanup_fails), tempfile.TemporaryDirectory() as directory:
                qa = module.NativeQA(SimpleNamespace(evidence_dir=Path(directory)))
                cleaned = []
                def failed_fixture(layout):
                    raise RuntimeError("PRIVATE_BOOTSTRAP_FAILURE")
                def cleanup_boundary():
                    cleaned.append(True)
                    if cleanup_fails:
                        raise RuntimeError("PRIVATE_CLEANUP_CUSTODY_FAILURE")
                with patch.object(qa, "preflight"), patch.object(qa, "images"), patch.object(qa, "units_install"), patch.object(qa, "fixture", side_effect=failed_fixture), patch.object(qa, "cleanup", side_effect=cleanup_boundary), patch.object(module, "native_phase_failure_metadata", side_effect=RuntimeError("PRIVATE_COLLECTOR_FAILURE")):
                    expected = "fixture cleanup held" if cleanup_fails else "native verification failed"
                    with self.assertRaisesRegex(RuntimeError, "^" + expected + "; native gate held$"):
                        qa.execute()
                self.assertEqual(cleaned, [True])
                event = next(event for event in qa.events if event["case"] == "native-flow")
                self.assertEqual(event["result"], "failed")
                self.assertEqual(event["phase"], "fixture")
                self.assertNotIn("PRIVATE", json.dumps(qa.events))
                if cleanup_fails:
                    self.assertTrue(any(event['case'] == 'native-flow' and event.get('phase') == 'cleanup'
                                        for event in qa.events))

    def test_child_file_is_private_bounded_reset_and_consumed_before_cleanup(self):
        module = self.native_module()
        with tempfile.TemporaryDirectory() as d, patch.object(module, "ROOT", Path(d) / "fixture"):
            module.ROOT.mkdir(mode=0o700)
            guest = module.NativeQA(SimpleNamespace(evidence_dir=Path(d) / "evidence"))
            guest.layout = "named-volume"
            guest.reset_child_failure()
            path = module.ROOT / "broker-child-failure.json"
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            value = {"code_label": "broker-serve", "source_line": 42, "error_kind": "runtime-error"}
            module.write_broker_failure(value)
            guest.consume_child_failure()
            self.assertEqual(guest.events[-1]["failure"], value)
            self.assertEqual(path.read_bytes(), b"")
            module.write_broker_failure(value)
            guest.layout = "bind"
            guest.reset_child_failure()
            self.assertEqual(path.read_bytes(), b"")
            for data in (b"x" * 4097, module.encoded({**value, "private": "SECRET"}), module.encoded({**value, "source_line": True}), module.encoded({**value, "code_label": "SECRET"})):
                path.write_bytes(data)
                before = len(guest.events)
                guest.consume_child_failure()
                self.assertEqual(len(guest.events), before)
                self.assertNotIn("SECRET", json.dumps(guest.events))
            path.unlink()
            outside = Path(d) / "outside"
            outside.write_bytes(b"PRIVATE")
            path.symlink_to(outside)
            guest.consume_child_failure()
            self.assertEqual(outside.read_bytes(), b"PRIVATE")
            with self.assertRaises(RuntimeError):
                guest.reset_child_failure()
            path.unlink()
            # Execute failure must consume while the fixture still exists and then clean up.
            events = []
            guest.preflight = lambda: None
            guest.images = lambda: None
            guest.units_install = lambda: None
            guest.fixture = lambda layout: (_ for _ in ()).throw(RuntimeError("PRIVATE"))
            guest.consume_child_failure = lambda: events.append("consume")
            guest.cleanup = lambda: events.append("cleanup")
            with self.assertRaisesRegex(RuntimeError, "native verification failed"):
                guest.execute()
            self.assertEqual(events, ["consume", "cleanup"])

    def test_owner_observation_slot_requires_private_retained_inode_exact_uuid_and_closed_shape(self):
        module = self.native_module()
        identity = "00000000-0000-4000-8000-000000000001"
        other = "00000000-0000-4000-8000-000000000002"
        failure = {"code_label": "broker-operation", "source_line": 924, "error_kind": "os-error"}
        with private_owner_temp(module) as d, patch.object(module, "ROOT", Path(d) / "fixture"):
            module.ROOT.mkdir(mode=0o700)
            qa = module.NativeQA(SimpleNamespace(evidence_dir=Path(d) / "evidence"))
            qa.layout = "bind"
            qa.reset_owner_observation()
            path = module.ROOT / "broker-owner-observation.json"
            inode = path.stat().st_ino
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            module.write_owner_observation(identity, failure)
            raw = path.read_bytes()
            self.assertLessEqual(len(raw), 4096)
            self.assertEqual(qa.read_owner_observation(identity), failure)
            self.assertEqual(path.read_bytes(), raw, "projection must not consume/reset the slot")
            self.assertIsNone(qa.read_owner_observation(other))
            value = json.loads(raw)
            self.assertEqual(set(value), {"schema_version", "operation_id", "failure"})
            for overflow, grows in ((False, False), (True, False), (True, True)):
                content = raw.ljust(4096 + int(overflow and not grows), b" ")
                path.write_bytes(content)
                with owner_file_read_audit(module, {path: 4096}, grow=path if grows else None) as reads:
                    result = qa.read_owner_observation(identity)
                self.assertEqual(result, None if overflow else failure)
                if not overflow or grows:
                    self.assertEqual(len(reads), 1)
                    self.assertEqual(reads[0]["total"], 4096 + int(overflow))
                    self.assertTrue(reads[0]["requests"])
                self.assertEqual(path.read_bytes(), content + (b" " if grows else b""))
            invalid = [b"{", b"x" * 4097, module.encoded({**value, "operation_id": other}),
                       module.encoded({**value, "schema_version": True}),
                       module.encoded({**value, "failure": {**failure, "source_line": True}}),
                       module.encoded({**value, "failure": {**failure, "code_label": "PRIVATE"}}),
                       module.encoded({**value, "private": "PRIVATE"})]
            for data in invalid:
                with self.subTest(data=data[:20]):
                    path.write_bytes(data)
                    self.assertIsNone(qa.read_owner_observation(identity))
                    self.assertEqual(path.read_bytes(), data)
            path.write_bytes(raw)
            alias = module.ROOT / "alias"
            os.link(path, alias)
            self.assertIsNone(qa.read_owner_observation(identity))
            alias.unlink()
            path.chmod(0o644)
            self.assertIsNone(qa.read_owner_observation(identity))
            path.chmod(0o600)
            path.rename(alias)
            path.write_bytes(raw)
            path.chmod(0o600)
            self.assertNotEqual(path.stat().st_ino, inode)
            self.assertIsNone(qa.read_owner_observation(identity))
            path.unlink()
            path.symlink_to(alias)
            self.assertIsNone(qa.read_owner_observation(identity))
            self.assertEqual(alias.read_bytes(), raw)
            self.assertNotIn("PRIVATE", json.dumps(qa.events))

    def test_owner_mapping_projection_reads_only_fixed_private_files_without_owner_calls(self):
        module = self.native_module()
        product_modules = {name: value for name, value in sys.modules.items()
                           if name in ("dc_overview", "cryptolabs_proxy")
                           or name.startswith(("dc_overview.", "cryptolabs_proxy."))}
        release_broker = product_modules.get("dc_overview.release_broker")
        identity = "00000000-0000-4000-8000-000000000001"
        with private_owner_temp(module) as d:
            root = Path(d).resolve()
            qa = module.NativeQA(SimpleNamespace(evidence_dir=root / "evidence"))
            qa.layout = "bind"
            qa.store = SimpleNamespace(root=root / "releases")
            qa.data = root / "bind"
            qa.auth = qa.data / "auth"
            qa.jobs = qa.auth / "update-jobs"
            operations = qa.store.root / "broker" / "operations"
            mapping = qa.jobs / "operations"
            for directory in (qa.store.root, qa.store.root / "broker", operations, qa.data, qa.auth, qa.jobs, mapping):
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            path = operations / (identity + ".json")
            # Emit the record from the pinned producer expressions. Handwriting
            # schema_version here hid the actual producer/observer mismatch.
            broker_path = ROOT / "src/dc_overview/release_broker.py"
            broker_source = broker_path.read_text()
            self.assertEqual(hashlib.sha256(broker_source.encode()).hexdigest(),
                             "5916872d5ec87a2e9b69529c2c8a16f9a871667d9ff0ae27a0f1691fcaa296b7")
            broker_tree = ast.parse(broker_source)
            canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            sha = lambda raw: hashlib.sha256(raw).hexdigest()
            def producer_expression(function, target, checksum):
                node = next(n for n in ast.walk(broker_tree)
                            if isinstance(n, ast.FunctionDef) and n.name == function)
                value = next(n.value for n in ast.walk(node) if isinstance(n, ast.Assign)
                             and any(isinstance(t, ast.Name) and t.id == target for t in n.targets))
                self.assertEqual(hashlib.sha256(ast.get_source_segment(broker_source, value).encode()).hexdigest(), checksum)
                return compile(ast.Expression(body=value), str(broker_path), "eval")
            preview_expression = producer_expression("_preview", "value",
                "795e4f0aab87ef606559be825cb883a2a82d12aa268fc141c7e35fcbb6e8cc58")
            operation_expression = producer_expression("_apply", "operation",
                "b14b3da31a5afad812f29fd8a58d3e3a89ed4145b84e577b121afb6d04a6bc53")
            # Model the unchanged native workflow at the OS boundary: sudo
            # parent is root, checkout ancestry belongs to runner (1001), and
            # the installed current wheel lives in the root-owned native venv.
            checkout = root / "runner-checkout"
            checkout_source = checkout / "src/dc_overview/release_broker.py"
            checkout_source.parent.mkdir(parents=True)
            checkout_source.write_text(broker_source)
            qa.args.dc_source = checkout
            native_prefix = Path("/opt/fleet-native-qa/venv")
            native_site = native_prefix / "lib/python3.12/site-packages"
            native_source = native_site / "dc_overview/release_broker.py"
            installed_source = root / "installed-release-broker.py"
            installed_source.write_text(broker_source)
            original_lstat, fixture_open, original_fstat = Path.lstat, os.open, os.fstat
            def root_info(info, *, runner=False, ancestor=False):
                return SimpleNamespace(**{name: (1001 if runner else 0) if name == "st_uid" else
                    (0o40755 if ancestor else info.st_mode) if name == "st_mode" else getattr(info, name)
                    for name in ("st_uid", "st_gid", "st_mode", "st_dev", "st_ino", "st_nlink",
                                 "st_size", "st_mtime_ns")})
            def native_lstat(name, *args, **kwargs):
                name = Path(name)
                if name == native_source:
                    return root_info(original_lstat(installed_source))
                if name in native_source.parents and name != Path("/"):
                    return root_info(original_lstat(root), ancestor=True)
                return root_info(original_lstat(name, *args, **kwargs),
                    runner=name == checkout or checkout in name.parents, ancestor=name in root.parents)
            def native_open(name, *args, **kwargs):
                return fixture_open(installed_source if Path(name) == native_source else name, *args, **kwargs)
            def native_purelib(name, *args, **kwargs):
                self.assertEqual((name, args, kwargs), ("purelib", (), {"scheme": "posix_prefix",
                    "vars": {"base": str(native_prefix), "platbase": str(native_prefix)}}))
                return str(native_site)
            public = root / "fleet-config.yaml"
            public.write_bytes(b"site_name: PRIVATE_SYNTHETIC_SITE\n")
            actor = {"kind": "host-peer", "uid": 0}
            params = {"candidate_ids": ["PRIVATE_candidate"], "components": ["ipmi-monitor"],
                      "expected_selection_id": "PRIVATE_selected", "expected_selection_sha256": "a" * 64,
                      "operation_kind": "services-update"}
            manifest_raw = canonical({"schema_version": 1, "baseline_id": "PRIVATE_proposed", "selection_contract": 1,
                "components": {"dc-overview-cli": {"owner": "host-cli", "release": "1.6.4",
                    "artifacts": {"any": {"kind": "wheel", "url": "https://example.invalid/PRIVATE.whl", "sha256": "b" * 64}}},
                    "ipmi-monitor": {"owner": "proxy-updater", "release": "1.3.2",
                    "artifacts": {"linux/amd64": {"kind": "oci", "reference": module.IPMI_NEW}}}}})
            owner_identity = {"updater_directory": str(qa.jobs), "device": 1, "inode": 2,
                              "proxy_config_dir": str(root / "proxy"), "declaration_path": str(root / "declaration")}
            namespace = {"self": SimpleNamespace(config=SimpleNamespace(config_dir=root), policy={"writes_enabled": True},
                            owner=SimpleNamespace(identity=lambda: owner_identity)),
                         "preview_id": "00000000-0000-4000-8000-000000000003", "actor": actor, "params": params,
                         "manifest": SimpleNamespace(raw=manifest_raw, sha256=sha(manifest_raw)),
                         "proposed": SimpleNamespace(selection_sha256="c" * 64), "selection": {"selection_id": "PRIVATE_proposed"},
                         "candidates": [SimpleNamespace(index={"generation": 1})], "owner_plan": None, "owner_declaration": None,
                         "entries": {"ipmi-monitor": {"channel": "main"}}, "canonical": canonical, "sha": sha, "base64": base64}
            preview = eval(preview_expression, namespace)
            preview["preview_sha256"] = sha(canonical(preview))
            apply_params = {"operation_id": identity, "preview_id": preview["preview_id"],
                            "preview_sha256": preview["preview_sha256"], "expected_selection_id": params["expected_selection_id"],
                            "expected_selection_sha256": params["expected_selection_sha256"]}
            operation = eval(operation_expression, {"preview": preview, "params": apply_params,
                                                    "fingerprint": sha(canonical({"params": apply_params, "actor": actor}))})
            self.assertNotIn("schema_version", operation)
            self.assertEqual(operation["state"], "prepared")
            self.assertEqual(operation["phase"], "selection")
            operation.update(state="recovery-required", phase="owner",
                             reason="Owner operation interrupted; reconcile retained operation before retry")
            path.write_bytes(module.encoded(operation)); path.chmod(0o600)
            mapped = mapping / (identity + ".json")
            mapped.write_bytes(module.encoded({"operation_id": identity, "job_id": "f" * 32})); mapped.chmod(0o600)
            inspected = [{"Mounts": [{"Source": str(qa.auth), "Destination": "/data/auth", "Type": "bind", "RW": True}],
                          "Config": {"Env": ["PRIVATE_INSPECT"]}}]
            commands = []
            def fixed_inspect():
                commands.append(True)
                return inspected
            forbidden = AssertionError("passive projection called a functional API")
            with ExitStack() as guards, patch.object(module, "inspect_owner_mounts_bounded", side_effect=fixed_inspect), patch.object(module, "run", side_effect=forbidden), patch.object(module, "docker", side_effect=forbidden), patch.object(module, "inspect", side_effect=forbidden), patch.object(qa, "status", side_effect=forbidden):
                guards.enter_context(patch.object(module.os, "geteuid", return_value=0))
                guards.enter_context(patch.object(module.platform, "system", return_value="Linux"))
                guards.enter_context(patch.object(module.sys, "prefix", str(native_prefix)))
                guards.enter_context(patch.object(module.sysconfig, "get_path", side_effect=native_purelib))
                guards.enter_context(patch.object(Path, "lstat", native_lstat))
                guards.enter_context(patch.object(module.os, "open", side_effect=native_open))
                guards.enter_context(patch.object(module.os, "fstat", side_effect=lambda fd: root_info(original_fstat(fd))))
                with self.assertRaises(module.ObservationRefused) as refused:
                    module.selector_read_bytes(checkout_source, 1048576, module.time.monotonic() + 1)
                self.assertEqual(refused.exception.args, ("custody-refused",))
                self.assertEqual(module.selector_read_bytes(native_source, 1048576, module.time.monotonic() + 1), broker_source.encode())
                if release_broker is not None:
                    guards.enter_context(patch.multiple(release_broker.InstalledOwner, **{name: unittest.mock.Mock(side_effect=forbidden) for name in ("capabilities", "identity", "submit", "status", "recover", "adopt")}))
                    guards.enter_context(patch.object(release_broker.ReleaseBroker, "dispatch", side_effect=forbidden))
                    guards.enter_context(patch.object(release_broker.ReleaseBroker, "run_operation", side_effect=forbidden))
                before = {p: p.read_bytes() for p in (path, mapped)}
                with owner_file_read_audit(module, {native_source: 1048576}) as source_reads:
                    value = qa.owner_mapping_observation(identity)
                self.assertEqual([item["path"] for item in source_reads], [native_source])
                self.assertEqual(value["operation_qualification"], "valid")
                self.assertEqual(value["operation"], {"observation": "present", "state": "recovery-required", "phase": "owner", "reason_category": "owner-interrupted", "job_id_present": False})
                self.assertEqual(value["fixture_mapping"], {"observation": "present", "job_id_present": True})
                self.assertEqual(value["current_mapping"], value["fixture_mapping"])
                self.assertEqual(value["owner_store"]["observation"], "same")
                self.assertIs(value["owner_store"]["auth_equal"], True)
                self.assertIs(value["owner_store"]["jobs_equal"], True)
                self.assertEqual(len(commands), 1)
                raw = module.encoded(value)
                for private in (b"PRIVATE", str(root).encode(), b"f" * 32):
                    self.assertNotIn(private, raw)
                self.assertEqual({p: p.read_bytes() for p in before}, before)
                # Exact prefix/purelib and frozen bytes are compulsory. A
                # readable checkout never supplies fallback after a refusal.
                self.assertTrue(hasattr(qa, 'proxy_adoption_observation'),
                                'proxy adoption needs a bounded read of its actual retained operation')
                adopt_id = '00000000-0000-4000-8000-000000000005'
                adopt_request = {**params, 'operation_kind': 'proxy-adopt', 'components': ['cryptolabs-proxy']}
                adopt_preview = {k: v for k, v in preview.items() if k != 'preview_sha256'}
                adopt_preview.update(request=adopt_request, owner_plan={'plan_id': 'e' * 64},
                                     owner_declaration={'canonical_json_base64': 'e30=', 'sha256': 'f' * 64},
                                     owner_identity={**owner_identity, 'updater_directory': str(root / 'named-volume/auth/update-jobs')})
                adopt_preview['preview_sha256'] = sha(canonical(adopt_preview))
                adopt_apply = {**apply_params, 'operation_id': adopt_id,
                               'preview_sha256': adopt_preview['preview_sha256']}
                adoption = eval(operation_expression, {'preview': adopt_preview, 'params': adopt_apply,
                    'fingerprint': sha(canonical({'params': adopt_apply, 'actor': actor}))})
                adoption.update(state='recovery-required', phase='owner',
                                reason='Proxy source or declaration changed after preview')
                adopt_path = operations / (adopt_id + '.json')
                adopt_path.write_bytes(module.encoded(adoption)); adopt_path.chmod(0o600)
                expected = {'apply': adopt_apply, 'request': adopt_request, 'preview': adopt_preview}
                saved_layout = qa.layout
                qa.layout = 'named-volume'
                source_before, operation_before = installed_source.read_bytes(), adopt_path.read_bytes()
                with owner_file_read_audit(module, {native_source: 1048576, adopt_path: 1048576}) as reads:
                    observation = qa.proxy_adoption_observation(adopt_id, expected)
                self.assertEqual([item['path'] for item in reads], [native_source, adopt_path])
                self.assertEqual(observation['qualification'], 'valid')
                self.assertEqual(observation['operation_state'], 'recovery-required')
                self.assertEqual(observation['operation_phase'], 'owner')
                self.assertEqual(observation['reason_category'], 'proxy-preview-plan-changed')
                self.assertIs(observation['owner_plan_matches_preview'], True)
                self.assertIs(observation['owner_declaration_matches_preview'], True)
                self.assertIsNone(observation['failure'])
                for private in ('PRIVATE', str(root), 'e' * 64, 'f' * 64):
                    self.assertNotIn(private, json.dumps(observation))
                self.assertLessEqual(len(module.encoded(observation)), 4096)
                # Execute the unchanged InstalledOwner.adopt plan-conflict
                # guard, then the actual child wrapper/private slot/parent
                # projection. Only the passive plan and persistence boundary
                # are substituted; no product mutation or qualification guard.
                loaded = types.ModuleType('dc_overview.release_broker')
                loaded.__file__ = str(native_source)
                owner_code = next(code for code in compile(broker_source, str(native_source), 'exec').co_consts
                                  if type(code) is types.CodeType and code.co_name == 'InstalledOwner')
                adopt_code = next(code for code in owner_code.co_consts
                                  if type(code) is types.CodeType and code.co_name == 'adopt')
                error_node = next(node for node in broker_tree.body if isinstance(node, ast.ClassDef) and node.name == 'BrokerError')
                error_namespace = {}
                exec(compile(ast.Module(body=[error_node], type_ignores=[]), str(native_source), 'exec'), error_namespace)
                loaded.InstalledOwner = type('InstalledOwner', (), {})
                loaded.InstalledOwner.adopt = types.FunctionType(adopt_code, error_namespace)
                passive_plan = unittest.mock.Mock(return_value={'plan_id': 'different'})
                loaded.InstalledOwner.adoption = lambda self: (SimpleNamespace(plan=passive_plan), {})
                loaded.private_write = unittest.mock.Mock()
                def actual_guard(owner, broker, target, value):
                    try:
                        owner.adopt(value['owner_plan'])
                    except Exception:
                        broker.private_write(target, value)
                        raise
                adopt_node = next(node for node in ast.walk(broker_tree)
                                  if isinstance(node, ast.FunctionDef) and node.name == 'adopt')
                guard_line = next(node.lineno for node in ast.walk(adopt_node) if isinstance(node, ast.Raise))
                role = next(label for label, name, ancestry in module.ADOPTION_CODE_SPECS
                            if name == 'dc_overview.release_broker' and ancestry == ('InstalledOwner', 'adopt'))
                with patch.object(module, 'ROOT', root), patch.dict(sys.modules, {
                        'dc_overview.release_broker': loaded, 'cryptolabs_proxy.standard_adoption': None,
                        'cryptolabs_proxy.update_recovery': None}):
                    qa.reset_owner_observation()
                    for changed in (False, True):
                        with self.subTest(adoption_source_changed=changed):
                            installed_source.write_bytes(source_before + (b'\n' if changed else b''))
                            passive_plan.reset_mock(); loaded.private_write.reset_mock()
                            with module.observe_broker_owner_failures(loaded, operations, (('broker-operation', actual_guard.__code__),)):
                                with self.assertRaises(error_namespace['BrokerError']):
                                    actual_guard(loaded.InstalledOwner(), loaded, adopt_path, adoption)
                            passive_plan.assert_called_once_with({})
                            loaded.private_write.assert_called_once_with(adopt_path, adoption)
                            child = qa.read_owner_observation(adopt_id)
                            self.assertIsInstance(child, dict, 'the actual adoption lane must persist a source-qualified packet')
                            if changed:
                                self.assertEqual(child['adoption']['qualification'], 'source-refused')
                                self.assertIsNone(child['code_label'])
                                continue
                            self.assertEqual(child['adoption']['qualification'], 'qualified')
                            self.assertEqual(child['code_label'], role)
                            self.assertEqual(child['source_line'], guard_line)
                            self.assertEqual(child['adoption']['frames'][-1], {'role': role, 'line': guard_line})
                            observed = qa.proxy_adoption_observation(adopt_id, expected)
                            self.assertEqual(observed['failure'], child)
                            self.assertNotIn('PRIVATE', json.dumps(observed))
                            self.assertNotIn(str(root), json.dumps(observed))
                    installed_source.write_bytes(source_before)
                foreign_expected = {**expected, 'request': {**adopt_request, 'components': ['ipmi-monitor']}}
                self.assertEqual(qa.proxy_adoption_observation(adopt_id, foreign_expected)['qualification'], 'identity-refused')
                installed_source.write_bytes(source_before + b'\n')
                self.assertEqual(qa.proxy_adoption_observation(adopt_id, expected)['qualification'], 'source-refused')
                installed_source.write_bytes(source_before)
                adopt_path.write_bytes(b'x' * 1048577)
                self.assertEqual(qa.proxy_adoption_observation(adopt_id, expected)['qualification'], 'overflow')
                adopt_path.write_bytes(operation_before)
                with patch.object(module.time, 'monotonic', side_effect=[100.0, 102.0]):
                    self.assertEqual(qa.proxy_adoption_observation(adopt_id, expected)['qualification'], 'deadline')
                self.assertEqual(adopt_path.read_bytes(), operation_before)
                self.assertEqual(installed_source.read_bytes(), source_before)
                qa.layout = saved_layout
                for prefix in ("/usr", str(root / "other-venv")):
                    with self.subTest(prefix=prefix), patch.object(module.sys, "prefix", prefix):
                        rejected = qa.owner_mapping_observation(identity)
                    self.assertEqual(rejected["operation_qualification"], "source-refused")
                    self.assertEqual(rejected["operation"]["observation"], "unknown")
                with patch.object(module.sysconfig, "get_path", return_value=str(native_prefix / "foreign")):
                    self.assertEqual(qa.owner_mapping_observation(identity)["operation_qualification"], "source-refused")
                installed_source.write_text(broker_source + "\n")
                self.assertEqual(qa.owner_mapping_observation(identity)["operation_qualification"], "source-refused")
                installed_source.write_text(broker_source)
                for mode in (0o666, 0o644):
                    installed_source.chmod(mode)
                    self.assertEqual(qa.owner_mapping_observation(identity)["operation_qualification"],
                                     "custody-refused" if mode == 0o666 else "valid")
                source_alias = root / "installed-source-alias"
                os.link(installed_source, source_alias)
                self.assertEqual(qa.owner_mapping_observation(identity)["operation_qualification"], "custody-refused")
                source_alias.unlink()
                installed_source.rename(source_alias)
                installed_source.symlink_to(source_alias)
                self.assertEqual(qa.owner_mapping_observation(identity)["operation_qualification"], "custody-refused")
                installed_source.unlink(); source_alias.rename(installed_source)
                self.assertEqual(checkout_source.read_text(), broker_source)
                self.assertEqual(qa.owner_mapping_observation(identity)["operation_qualification"], "valid")
                for target, field, valid in ((path, "operation", module.encoded(operation)), (mapped, "fixture_mapping", mapped.read_bytes())):
                    for overflow, grows in ((False, False), (True, False), (True, True)):
                        content = valid.ljust(1048576 + int(overflow and not grows), b" ")
                        target.write_bytes(content)
                        with owner_file_read_audit(module, {target: 1048576}, grow=target if grows else None) as reads:
                            projected = qa.owner_mapping_observation(identity)
                        self.assertEqual(projected[field]["observation"], "unknown" if overflow else "present")
                        self.assertLessEqual(len(reads), 1, "equal owner directories must be read once")
                        if not overflow or grows:
                            self.assertEqual(len(reads), 1)
                            self.assertEqual(reads[0]["total"], 1048576 + int(overflow))
                            self.assertGreater(len(reads[0]["requests"]), 1)
                        self.assertNotIn("PRIVATE", module.encoded(projected).decode())
                        self.assertEqual(target.read_bytes(), content + (b" " if grows else b""))
                        target.write_bytes(valid)
                mapped.unlink()
                self.assertEqual(qa.owner_mapping_observation(identity)["fixture_mapping"]["observation"], "absent")
                duplicate = module.encoded(operation).rstrip()[:-1] + b',"state":"recovery-required"}'
                for content in (b"{", b"x" * 1048577, duplicate,
                                module.encoded({**operation, "operation_id": "00000000-0000-4000-8000-000000000002"}),
                                module.encoded({**operation, "generation": True}),
                                module.encoded({**operation, "PRIVATE_UNKNOWN_FIELD": "PRIVATE"}),
                                module.encoded({k: v for k, v in operation.items() if k != "manifest_sha256"})):
                    path.write_bytes(content)
                    self.assertEqual(qa.owner_mapping_observation(identity)["operation"]["observation"], "unknown")
                    self.assertEqual(path.read_bytes(), content)
                path.write_bytes(module.encoded({**operation, "state": "PRIVATE_STATE", "phase": "PRIVATE_PHASE", "reason": "PRIVATE_REASON"}))
                unknown = qa.owner_mapping_observation(identity)["operation"]
                self.assertEqual((unknown["state"], unknown["phase"], unknown["reason_category"]), ("unknown", "unknown", "unknown"))
                path.write_bytes(module.encoded(operation))
                original_open = module.os.open
                replaced = []
                def replace_after_open(name, *args, **kwargs):
                    descriptor = original_open(name, *args, **kwargs)
                    if Path(name) == path and not replaced:
                        path.rename(operations / "replaced-original")
                        path.write_bytes(module.encoded(operation)); path.chmod(0o600)
                        replaced.append(True)
                    return descriptor
                with patch.object(module.os, "open", side_effect=replace_after_open):
                    raced = qa.owner_mapping_observation(identity)
                self.assertEqual(replaced, [True])
                self.assertEqual(raced["operation"]["observation"], "unknown")
                # Initial absence and losing an already-open basename are different observations.
                retained = operations / "retained-after-rename"
                original_raw = path.read_bytes()
                path.rename(retained)
                initially_absent = qa.owner_mapping_observation(identity)
                self.assertEqual(initially_absent["operation"]["observation"], "absent")
                self.assertEqual(retained.read_bytes(), original_raw)
                retained.rename(path)
                opened = []
                def rename_away_after_open(name, *args, **kwargs):
                    descriptor = original_open(name, *args, **kwargs)
                    opened.append(Path(name))
                    if Path(name) == path:
                        path.rename(retained)
                    return descriptor
                with patch.object(module.os, "open", side_effect=rename_away_after_open):
                    lost_path = qa.owner_mapping_observation(identity)
                self.assertFalse(path.exists())
                self.assertEqual(retained.read_bytes(), original_raw)
                self.assertEqual(opened.count(path), 1)
                self.assertLessEqual(set(opened), {path, mapped})
                with self.subTest(case="post-open-rename-away-is-unknown"):
                    self.assertEqual(lost_path["operation"]["observation"], "unknown")
                retained.rename(path)
                for mode in (0o644, 0o600):
                    path.chmod(mode)
                    if mode == 0o644:
                        self.assertEqual(qa.owner_mapping_observation(identity)["operation"]["observation"], "unknown")
                alias = operations / "alias"
                os.link(path, alias)
                self.assertEqual(qa.owner_mapping_observation(identity)["operation"]["observation"], "unknown")
                alias.unlink(); path.rename(alias); path.symlink_to(alias)
                self.assertEqual(qa.owner_mapping_observation(identity)["operation"]["observation"], "unknown")
                # A foreign inspect source never licenses reading another directory.
                inspected[0]["Mounts"][0]["Source"] = str(root / "foreign")
                foreign = qa.owner_mapping_observation(identity)
                self.assertEqual(foreign["owner_store"]["observation"], "foreign")
                self.assertEqual(foreign["current_mapping"]["observation"], "unknown")
                self.assertFalse((root / "foreign").exists())
                with patch.object(module, "inspect_owner_mounts_bounded", return_value=None):
                    timed_out = qa.owner_mapping_observation(identity)
                self.assertEqual(timed_out["owner_store"]["observation"], "unknown")
                # A valid correlated failure is independent of unavailable mount metadata.
                failure = {"code_label": "broker-operation", "source_line": 944, "error_kind": "os-error"}
                with patch.object(module, "ROOT", root):
                    qa.reset_owner_observation()
                    module.write_owner_observation(identity, failure)
                    slot = root / "broker-owner-observation.json"
                    original_slot = slot.read_bytes()
                    self.assertEqual(qa.read_owner_observation(identity), failure)
                    foreign_inspect = [{"Mounts": [{"Source": str(root / "foreign"), "Destination": "/data/auth", "Type": "bind", "RW": True}]}]
                    for case, unavailable, store_state in (("inspect-unavailable", None, "unknown"),
                                                            ("foreign-mount", foreign_inspect, "foreign"),
                                                            ("malformed-mounts", [{"Mounts": "PRIVATE_MALFORMED"}], "unknown")):
                        with self.subTest(case=case), patch.object(module, "inspect_owner_mounts_bounded", return_value=unavailable):
                            observed = qa.owner_mapping_observation(identity)
                            self.assertEqual(slot.read_bytes(), original_slot)
                            self.assertEqual(observed["owner_store"]["observation"], store_state)
                            self.assertEqual(observed["current_mapping"]["observation"], "unknown")
                            self.assertNotIn("PRIVATE", module.encoded(observed).decode())
                            self.assertEqual(observed["failure"], failure)
            after_modules = {name: value for name, value in sys.modules.items()
                             if name in ("dc_overview", "cryptolabs_proxy")
                             or name.startswith(("dc_overview.", "cryptolabs_proxy."))}
            self.assertEqual(set(after_modules), set(product_modules))
            self.assertTrue(all(after_modules[name] is value for name, value in product_modules.items()))

    def test_owner_inspect_capture_accepts_exact_limit_short_reads_and_requires_zero_exit(self):
        module = self.native_module()
        data = [{"Mounts": [], "Config": {"Env": ["PRIVATE_INSPECT"]}}]
        raw = json.dumps(data).encode()
        for payload, mode in ((raw, "ok"), (raw.ljust(1048576, b" "), "short"), (raw, "nonzero"), (raw, "spawn-error")):
            with owner_inspect_boundary(module, payload, mode) as audit:
                result = module.inspect_owner_mounts_bounded()
            self.assertEqual(result, data if mode in ("ok", "short") else None)
            if mode in ("ok", "short"):
                self.assertEqual(audit["total"], len(payload))
                self.assertFalse(audit["killed"])

    def test_owner_inspect_capture_stops_at_overflow_without_parse_and_reaps_exact_child(self):
        module = self.native_module()
        with owner_inspect_boundary(module, b"x" * 1052672) as audit, patch.object(module.json, "loads", side_effect=AssertionError("overflow must not parse")):
            result = module.inspect_owner_mounts_bounded()
        self.assertIsNone(result)
        self.assertEqual(audit["total"], 1048577)
        self.assertTrue(audit["killed"])
        self.assertEqual(audit["child"].kill.call_count, 1)

    def test_owner_inspect_capture_deadline_setup_and_read_failures_close_owned_resources(self):
        module = self.native_module()
        for mode in ("timeout", "eof-live", "setup-error", "read-error", "cleanup-timeout"):
            with owner_inspect_boundary(module, b"", mode) as audit:
                result = module.inspect_owner_mounts_bounded()
            self.assertIsNone(result)
            self.assertTrue(audit["killed"])
            self.assertEqual(audit["child"].kill.call_count, 1)

    def test_mapping_wait_failure_observes_once_and_preserves_original_gate(self):
        module = self.native_module()
        identity = "00000000-0000-4000-8000-000000000001"
        for collector_fails in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                qa = module.NativeQA(SimpleNamespace(evidence_dir=Path(directory) / "evidence"))
                qa.jobs = Path(directory) / "update-jobs"
                qa.policy = {"writes_enabled": False}
                qa.layout = "bind"
                # The preceding native policy procedure has its own full contract.
                qa.policy_before_update = unittest.mock.Mock()
                original = RuntimeError("actual owner mapping was not created")
                observed = []
                def collect(operation_id):
                    observed.append(operation_id)
                    if collector_fails:
                        raise OSError("PRIVATE_DIAGNOSTIC")
                    return {"operation": {"observation": "unknown"}}
                with patch.object(module, "inspect", return_value={"Id": "b" * 64}), patch.object(module, "write"), patch.object(qa, "selection", return_value={}), patch.object(qa, "preview", return_value=({}, {})), patch.object(qa, "apply", return_value=(identity, {})), patch.object(qa, "owner_mapping_observation", side_effect=collect), patch.object(module, "wait", side_effect=original) as waiting, patch.object(qa, "status", side_effect=AssertionError("passive failure cannot call status")):
                    with self.assertRaises(RuntimeError) as caught:
                        qa.service_update()
                self.assertIs(caught.exception, original)
                self.assertEqual(observed, [identity])
                self.assertEqual(waiting.call_count, 1)
                self.assertEqual(waiting.call_args.kwargs, {"timeout": 90, "message": "actual owner mapping was not created"})
                self.assertNotIn("PRIVATE", json.dumps(qa.events))

    def test_lost_reply_keeps_request_connected_until_durable_acceptance(self):
        spec = importlib.util.spec_from_file_location("fleet_native_lost_reply", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        import ssl

        def check_outcome(outcome):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                guest = module.NativeQA(SimpleNamespace(evidence_dir=root / "evidence"))
                guest.data = root / "data"
                guest.store = SimpleNamespace(root=root / "store")
                guest.session = SimpleNamespace(cookies={"fleet_session": "fixture-cookie"})
                guest.csrf = "fixture-csrf"
                identity = "00000000-0000-4000-8000-000000000001"
                operation = guest.store.root / "broker/operations" / (identity + ".json")
                operation.parent.mkdir(parents=True)
                params = {
                    "expected_selection_id": "fixture-selection",
                    "expected_selection_sha256": "a" * 64,
                }
                preview = {
                    "preview_id": "fixture-preview",
                    "preview_sha256": "b" * 64,
                    "owner_plan": {"plan_id": "fixture-owner-plan"},
                }
                opened, events, requests = set(), [], []
                clock = [0.0]

                def sendall(request):
                    self.assertEqual(opened, {"raw", "tls"})
                    requests.append(request)
                    events.append("sent")
                    if outcome == "send-failure":
                        raise OSError("fixture send failed")

                def read_reply(*args, **kwargs):
                    self.fail("lost-reply fixture must never read the HTTP response")

                @contextmanager
                def connected(kind):
                    opened.add(kind)
                    events.append(kind + "-open")
                    try:
                        yield SimpleNamespace(
                            sendall=sendall, recv=read_reply, read=read_reply, makefile=read_reply
                        )
                    finally:
                        opened.remove(kind)
                        events.append(kind + "-close")

                def acceptance_step(seconds):
                    # Model asynchronous server acceptance while using the real bounded wait.
                    self.assertEqual(seconds, 0.25)
                    self.assertEqual(
                        opened,
                        {"raw", "tls"},
                        "the client disconnected before durable request acceptance",
                    )
                    self.assertEqual(len(requests), 1)
                    clock[0] += 61
                    if outcome == "accepted":
                        operation.write_bytes(module.encoded({"state": "prepared"}))
                        events.append("durably-accepted")

                tls = SimpleNamespace(wrap_socket=lambda *args, **kwargs: connected("tls"))
                with (
                    patch.object(module.uuid, "uuid4", return_value=identity),
                    patch.object(
                        module.socket,
                        "create_connection",
                        side_effect=lambda *a, **k: connected("raw"),
                    ),
                    patch.object(ssl, "create_default_context", return_value=tls),
                    patch.object(module.time, "monotonic", side_effect=lambda: clock[0]),
                    patch.object(module.time, "sleep", side_effect=acceptance_step) as sleep,
                ):
                    if outcome == "accepted":
                        returned_id, body = guest.apply(params, preview, lose_reply=True)
                        self.assertEqual(returned_id, identity)
                        self.assertEqual(
                            events,
                            [
                                "raw-open",
                                "tls-open",
                                "sent",
                                "durably-accepted",
                                "tls-close",
                                "raw-close",
                            ],
                        )
                        headers, payload = requests[0].split(b"\r\n\r\n", 1)
                        self.assertIn(b"POST /api/releases/apply HTTP/1.1", headers)
                        self.assertIn(b"Origin: " + module.ORIGIN.encode(), headers)
                        self.assertIn(b"X-CSRF-Token: fixture-csrf", headers)
                        self.assertIn(b"Cookie: fleet_session=fixture-cookie", headers)
                        self.assertIn(f"Content-Length: {len(payload)}".encode(), headers)
                        self.assertEqual(json.loads(payload), body)
                        self.assertEqual(body["operation_id"], identity)
                        self.assertEqual(guest.owner_plans, {"fixture-owner-plan"})
                        self.assertTrue(operation.exists())
                    elif outcome == "missing-record":
                        with self.assertRaisesRegex(RuntimeError, "apply was not durably received"):
                            guest.apply(params, preview, lose_reply=True)
                        self.assertFalse(operation.exists())
                        self.assertEqual(sleep.call_count, 3)
                    else:
                        with self.assertRaisesRegex(OSError, "fixture send failed"):
                            guest.apply(params, preview, lose_reply=True)
                        sleep.assert_not_called()
                        self.assertFalse(operation.exists())
                self.assertEqual(opened, set())
                self.assertEqual(events[-2:], ["tls-close", "raw-close"])

        for outcome in ("accepted", "missing-record", "send-failure"):
            with self.subTest(outcome=outcome):
                check_outcome(outcome)

    def test_route_is_exact_public_pr_and_never_inherits_authority(self):
        data = yaml.safe_load(WORKFLOW.read_text())
        self.assertEqual(set(data["on"]), {"pull_request"})
        self.assertEqual(data["on"]["pull_request"]["branches"], ["dev"])
        self.assertEqual(data["permissions"], {"contents": "read"})
        self.assertEqual(set(data["jobs"]), {"native"})
        job = data["jobs"]["native"]
        self.assertEqual(
            job["runs-on"],
            {"group": "ci-build-public-ephemeral", "labels": ["ci-linux-cpu-v1-r1133295682"]},
        )
        self.assertEqual(job["permissions"], {"contents": "read"})
        self.assertLessEqual(job["timeout-minutes"], 45)
        self.assertIn("github.repository_id == '1133295682'", job["if"])
        self.assertIn("github.event.pull_request.head.repo.id == 1133295682", job["if"])
        self.assertIn("github.base_ref == 'dev'", job["if"])
        self.assertIn("github.event_name == 'pull_request'", job["if"])
        for forbidden in (
            "secrets:",
            "secrets.",
            "pull_request_target",
            ": write",
            "continue-on-error",
            "workflow_dispatch",
            "--privileged",
            "--network host",
        ):
            self.assertNotIn(forbidden, WORKFLOW.read_text())
        checkouts = []
        for step in job["steps"]:
            if "uses" in step:
                self.assertRegex(step["uses"], r"@[a-f0-9]{40}$")
                if step["uses"].startswith("actions/checkout@"):
                    self.assertIs(step["with"]["persist-credentials"], False)
                    checkouts.append(step)
        self.assertEqual(len(checkouts), 2)
        self.assertEqual(checkouts[0]["with"]["ref"], "${{ github.event.pull_request.head.sha }}")
        self.assertEqual(checkouts[1]["with"]["repository"], "cryptolabsza/cryptolabs-proxy")
        pin = data["env"]["PROXY_SOURCE_SHA"]
        self.assertEqual(pin, "6e5186401e78cc8ba7b6ffe18eb24712ef9263b1")
        preflight = next(
            i for i, s in enumerate(job["steps"]) if s.get("name") == "Reject unresolved source pin"
        )
        self.assertLess(preflight, job["steps"].index(checkouts[1]))
        self.assertIn("--check-inputs-only", job["steps"][preflight]["run"])
        self.assertEqual(checkouts[1]["with"]["ref"], "${{ env.PROXY_SOURCE_SHA }}")
        build = next(step["run"] for step in job["steps"] if step.get("name") == "Verify route and build exact wheels")
        for version, checksum in (("dc_overview-1.8.0", "72fcf2fde1d765cdfebfd2e4071261e3ff28d202f7ffb1975340e9d362969304"),
                                  ("cryptolabs_proxy-1.5.4", "5e64f0ae59d38ebcf4885d8aa60822bc3187d5a63f9abb8bdd11927d1ffd2b47")):
            self.assertIn(version + "-py3-none-any.whl", build)
            self.assertIn(checksum, build)
        execution = next(step["run"] for step in job["steps"] if step.get("id") == "qa")
        self.assertIn("--legacy-wheel-dir", execution)
        self.assertIn("--protection-helper", execution)

    def test_placeholder_fails_before_guest_commands(self):
        spec = importlib.util.spec_from_file_location("fleet_native_qa", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with self.assertRaisesRegex(RuntimeError, "published reviewed proxy"):
            module.check_source_pin("ROOT_MUST_SET_REVIEWED_PROXY_SHA")
        self.assertEqual(module.check_source_pin("a" * 40), "a" * 40)
        for image in (module.REGISTRY_IMAGE, module.NGINX_BASE, module.IPMI_OLD, module.IPMI_NEW):
            self.assertRegex(image, r"^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$")
        # Execute the real peer-denial probe and assertion without guest fixture setup.
        native = next(
            node
            for node in ast.parse(SCRIPT.read_text()).body
            if isinstance(node, ast.ClassDef) and node.name == "NativeQA"
        )
        fixture = next(
            node
            for node in native.body
            if isinstance(node, ast.FunctionDef) and node.name == "fixture"
        )
        probe_index = next(
            index
            for index, node in enumerate(fixture.body)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "peer_denied"
                for target in node.targets
            )
        )
        self.assertIsInstance(fixture.body[probe_index + 1], ast.Assert)
        probe = compile(
            ast.Module(body=fixture.body[probe_index : probe_index + 2], type_ignores=[]),
            str(SCRIPT),
            "exec",
        )
        denial = module.encoded(
            {"schema_version": 1, "ok": False, "error": {"status": 403}}
        )
        responses = (
            ("complete fragmented 403", [denial[:20], denial[20:], b""], None),
            ("partial JSON", [denial[:20], b""], json.JSONDecodeError),
            ("no response", [b""], json.JSONDecodeError),
            ("reset before complete", [denial[:20], ConnectionResetError()], ConnectionResetError),
            ("reset after complete", [denial, ConnectionResetError()], ConnectionResetError),
            (
                "wrong status",
                [module.encoded({"ok": False, "error": {"status": 503}}), b""],
                AssertionError,
            ),
            (
                "not denied",
                [module.encoded({"ok": True, "error": {"status": 403}}), b""],
                AssertionError,
            ),
        )
        for name, chunks, error in responses:
            with self.subTest("receive-only excluded peer", response=name):
                connection = unittest.mock.MagicMock()
                connection.__enter__.return_value = connection
                connection.recv.side_effect = chunks
                scope = {"raw_request": module.raw_request}
                with patch.object(module.socket, "socket", return_value=connection) as opened:
                    if error is None:
                        exec(probe, scope)
                        self.assertEqual(scope["peer_denied"], json.loads(denial))
                    else:
                        with self.assertRaises(error):
                            exec(probe, scope)
                opened.assert_called_once_with(module.socket.AF_UNIX, module.socket.SOCK_STREAM)
                connection.settimeout.assert_called_once_with(15)
                connection.connect.assert_called_once_with(module.SOCKET)
                connection.sendall.assert_called_once_with(b"")
                connection.shutdown.assert_called_once_with(module.socket.SHUT_WR)
                self.assertEqual(connection.recv.call_count, len(chunks))
        # Narrow command/file boundary regressions, not an Engine integration claim.
        with tempfile.TemporaryDirectory() as directory:
            instance = module.NativeQA(SimpleNamespace(evidence_dir=Path(directory)))
            with self.subTest("known guest default-server trust external contract"):
                self.assertEqual(
                    module.digest(GUEST_HOSTS),
                    "5b44770a4caca465e8991cbbaaa6a50eae52bc5d349700f4ca2c240ca0458629",
                )
                fixture_ca = "/etc/docker/certs.d/ghcr.io/native-fleet-qa-" + "a" * 32 + ".crt"
                changed = module.fixture_hosts_bytes(GUEST_HOSTS, fixture_ca)
                before = tomllib.loads(GUEST_HOSTS.decode())
                after = tomllib.loads(changed.decode())
                self.assertEqual(after.pop("ca"), [fixture_ca])
                self.assertEqual(after, before)
                self.assertTrue(changed.endswith(GUEST_HOSTS[GUEST_HOSTS.index(b"[host.") :]))
            with self.subTest("missing Docker Health requires the real fixed application probe"):
                container = {"State": {"Running": True}}

                def once(predicate, **kwargs):
                    self.assertTrue(predicate())

                with (
                    patch.object(module, "inspect", return_value=container),
                    patch.object(module, "wait", side_effect=once),
                    patch.object(
                        module, "docker", return_value=SimpleNamespace(returncode=0, stdout=b"200")
                    ) as command,
                ):
                    instance.wait_healthy("ipmi-monitor")
                    self.assertIn("http://127.0.0.1:5000/health", command.call_args.args)
                    self.assertIn("--max-time", command.call_args.args)
                    self.assertLessEqual(command.call_args.kwargs["timeout"], 5)
                with (
                    patch.object(module, "inspect", return_value=container),
                    patch.object(
                        module,
                        "wait",
                        side_effect=lambda predicate, **kwargs: self.assertFalse(predicate()),
                    ),
                    patch.object(
                        module, "docker", return_value=SimpleNamespace(returncode=0, stdout=b"503")
                    ),
                ):
                    instance.wait_healthy("ipmi-monitor")
                container["State"]["Health"] = {"Status": "unhealthy"}
                with (
                    patch.object(module, "inspect", return_value=container),
                    patch.object(module, "wait", side_effect=once),
                    patch.object(module, "docker") as command,
                ):
                    with self.assertRaisesRegex(RuntimeError, "unhealthy"):
                        instance.wait_healthy("ipmi-monitor")
                    command.assert_not_called()
            with self.subTest("continuation waits through the prelaunch mapping window"):
                instance.jobs = Path(directory) / "jobs"
                instance.jobs.mkdir()
                mapped = {"job_id": "a" * 32, "operation_id": "fixture-operation"}
                helper = "cryptolabs-update-" + mapped["job_id"]
                job = {
                    "id": mapped["job_id"],
                    "operation_id": mapped["operation_id"],
                    "helper": helper,
                    "state": "queued",
                }

                def launch_window(predicate, **kwargs):
                    self.assertFalse(predicate())  # mapping exists, job does not
                    module.write(instance.jobs / (mapped["job_id"] + ".json"), job)
                    self.assertFalse(predicate())  # job exists, helper not running
                    running = {
                        "State": {"Running": True},
                        "Config": {"Labels": {"io.cryptolabs.update.worker": mapped["job_id"]}},
                    }
                    with patch.object(
                        module,
                        "docker",
                        return_value=SimpleNamespace(
                            returncode=0, stdout=module.encoded([running])
                        ),
                    ) as command:
                        self.assertEqual(predicate(), "helper-running")
                        self.assertEqual(command.call_args.args, ("inspect", helper))
                    job["state"] = "completed"
                    module.write(instance.jobs / (mapped["job_id"] + ".json"), job)
                    with patch.object(module, "docker") as command:
                        self.assertEqual(predicate(), "job-completed")
                        command.assert_not_called()

                with (
                    patch.object(module, "wait", side_effect=launch_window),
                    patch.object(
                        module, "docker", return_value=SimpleNamespace(returncode=1, stdout=b"")
                    ),
                ):
                    instance.wait_mapped_worker(mapped)
            with self.subTest("timeout keeps failure and cleanup without public private data"):
                marker = "SYNTHETIC_FIXTURE_KEY_MUST_NOT_APPEAR"
                instance.preflight = lambda: None
                instance.images = lambda: module.docker("run", "AUTH_SECRET_KEY=" + marker)
                instance.cleanup = unittest.mock.Mock()
                with patch.object(
                    module.subprocess,
                    "run",
                    side_effect=lambda argv, **kwargs: (_ for _ in ()).throw(
                        subprocess.TimeoutExpired(argv, 180, output=marker)
                    ),
                ):
                    try:
                        instance.execute()
                    except RuntimeError:
                        visible = traceback.format_exc()
                    except Exception:
                        self.fail("timeout escaped without sanitized RuntimeError")
                    else:
                        self.fail("timeout must fail the native gate")
                self.assertNotIn(marker, visible)
                self.assertNotIn("TimeoutExpired", visible)
                self.assertIn("timed out", visible)
                instance.cleanup.assert_called_once()
                self.assertEqual(instance.events[-1].get("phase"), "images")
                self.assertIn('"result":"failed"', (Path(directory) / "results.json").read_text())
            # A failed fixture push must retain useful fixed signals without captured data.
            private = (
                b"SYNTHETIC_PRIVATE_ARG https://private.invalid/path Authorization: Bearer token "
                b"Cookie: session=private -----BEGIN PRIVATE KEY----- ENV_SECRET=value"
            )
            cases = (
                (b"x509: certificate signed by unknown authority", ["certificate-untrusted"]),
                (
                    b"x509: certificate has expired or is not yet valid",
                    ["certificate-name-or-time"],
                ),
                (
                    b"CA certificates should use the extension .crt.",
                    ["client-certificate-configuration"],
                ),
                (b"server gave HTTP response to HTTPS client", ["tls-protocol"]),
                (b"no such host", ["name-resolution"]),
                (b"connect: connection refused", ["connection-refused"]),
                (b"context deadline exceeded", ["timeout"]),
                (b"unauthorized: authentication required", ["registry-denied-or-auth"]),
                (b"received unexpected HTTP status:", ["registry-http-error"]),
                (b"manifest invalid", ["manifest-or-blob-invalid"]),
                (b"no space left on device", ["storage-error"]),
                (
                    b"x509: certificate signed by unknown authority\nconnect: connection refused",
                    ["certificate-untrusted", "connection-refused"],
                ),
                (b"unrecognized failure", ["unknown"]),
                (None, ["timeout"]),
            )
            keys = ("proxy-a", "proxy-b", "ipmi-old", "ipmi-new", "ipmi-bad")
            for number, (output, signals) in enumerate(cases):
                with self.subTest("fixture push diagnostics", signals=signals, number=number):
                    failed = module.NativeQA(
                        SimpleNamespace(evidence_dir=Path(directory) / str(number))
                    )
                    key = keys[number % len(keys)]
                    failed.preflight = lambda: None
                    failed.images = lambda failed=failed, key=key: failed.push_fixture(
                        key, private.decode()
                    )
                    failed.cleanup = unittest.mock.Mock()
                    exit_code = 99999 if signals == ["unknown"] else 1
                    command_result = subprocess.CompletedProcess(
                        [],
                        exit_code,
                        stdout=private + (output or b"" if number % 2 else b""),
                        stderr=output or b"" if not number % 2 else b"",
                    )
                    error = subprocess.TimeoutExpired(
                        [private], 900, output=private, stderr=private
                    )
                    with patch.object(
                        module.subprocess,
                        "run",
                        side_effect=error if output is None else None,
                        return_value=command_result,
                    ):
                        try:
                            failed.execute()
                        except Exception as caught:
                            failure = caught
                            visible = traceback.format_exc()
                        else:
                            self.fail("failed fixture push must fail the native gate")
                    events = [e for e in failed.events if e["case"] == "fixture-registry-push"]
                    self.assertEqual(
                        events,
                        [
                            {
                                "case": "fixture-registry-push",
                                "fixture_key": key,
                                "result": "failed",
                                "exit_code": None if output is None else min(exit_code, 255),
                                "diagnostic_signals": signals,
                                "diagnostic_version": 1,
                            }
                        ],
                    )
                    self.assertIsInstance(failure, RuntimeError)
                    failed.cleanup.assert_called_once()
                    evidence = (failed.evidence / "results.json").read_text()
                    self.assertEqual(failed.events[-1]["result"], "failed")
                    for forbidden in (
                        "SYNTHETIC_PRIVATE_ARG",
                        "private.invalid",
                        "Authorization:",
                        "Cookie:",
                        "BEGIN PRIVATE KEY",
                        "ENV_SECRET",
                        "TimeoutExpired",
                        "99999",
                    ):
                        self.assertNotIn(forbidden, visible + evidence)
            with self.subTest("successful push preserves digest output without diagnostic failure"):
                completed = subprocess.CompletedProcess(
                    [], 0, stdout=b"digest: sha256:" + b"a" * 64, stderr=b""
                )
                before = list(instance.events)
                with patch.object(module.subprocess, "run", return_value=completed) as command:
                    self.assertIs(instance.push_fixture("proxy-a", "fixture-tag"), completed)
                    self.assertEqual(command.call_args.args[0], ["docker", "push", "fixture-tag"])
                self.assertEqual(instance.events, before)
                with patch.object(module.subprocess, "run") as command:
                    with self.assertRaisesRegex(RuntimeError, "unknown registry fixture key"):
                        instance.push_fixture(private.decode(), "fixture-tag")
                    command.assert_not_called()
                self.assertEqual(module.registry_push_signals(b"no such ", b"host"), ["unknown"])
            with self.subTest("baseline registry CA survives exclusive fixture add and remove"):
                ca = Path(directory) / "registry-ca"
                ca.mkdir(mode=0o755)
                baseline = ca / "ca.crt"
                baseline.write_bytes(b"baseline trusted public CA")
                before = baseline.stat()
                directory_before = ca.stat()
                source = Path(directory) / "fixture.crt"
                source.write_bytes(b"synthetic fixture public CA")
                original_lstat = module.Path.lstat

                def root_owned(path, *args, **kwargs):
                    # Ownership boundary only; all add/remove operations use real temporary files.
                    observed = original_lstat(path, *args, **kwargs)
                    fields = list(observed)
                    fields[4] = 0
                    return module.os.stat_result(fields)

                with (
                    patch.object(module, "REGISTRY_CA_DIR", ca),
                    patch.object(module.Path, "lstat", root_owned),
                ):
                    instance.install_registry_ca(source)
                    owned = instance.registry_ca_file
                    self.assertNotEqual(owned.name, "ca.crt")
                    self.assertEqual(owned.suffix, ".crt")
                    self.assertEqual(owned.read_bytes(), source.read_bytes())
                    instance.remove_registry_ca()
                self.assertEqual(set(ca.iterdir()), {baseline})
                self.assertEqual(baseline.read_bytes(), b"baseline trusted public CA")
                after = baseline.stat()
                self.assertEqual(
                    (after.st_mode, after.st_uid, after.st_gid, after.st_mtime_ns),
                    (before.st_mode, before.st_uid, before.st_gid, before.st_mtime_ns),
                )
                self.assertEqual(
                    (ca.stat().st_mode, ca.stat().st_uid, ca.stat().st_gid),
                    (directory_before.st_mode, directory_before.st_uid, directory_before.st_gid),
                )
            engine = {
                "ServerVersion": "29.1.3",
                "DriverStatus": [["driver-type", "io.containerd.snapshotter.v1"]],
                "SecurityOptions": ["name=seccomp,profile=builtin"],
            }

            @contextmanager
            def trust_fixture(name):
                base = Path(directory) / name
                base.mkdir(mode=0o700)
                ca = base / "certs"
                ca.mkdir(mode=0o755)
                hosts = ca / "hosts.toml"
                hosts.write_bytes(GUEST_HOSTS)
                hosts.chmod(0o640)
                os.utime(hosts, ns=(1700000000000000000, 1700000001000000000))
                root = base / "fixture"
                root.mkdir(mode=0o700)
                source = base / "public.crt"
                source.write_bytes(b"synthetic public fixture CA")
                original_lstat, original_fstat = module.Path.lstat, module.os.fstat

                def as_root(info, *, ancestor=False):
                    # Simulate only the privileged ownership boundary on macOS. All
                    # file reads, writes, inode changes and restoration remain real.
                    values = {key: getattr(info, key) for key in dir(info) if key.startswith("st_")}
                    values["st_uid"] = 0
                    if ancestor:
                        values["st_mode"] = module.stat.S_IFDIR | 0o755
                    return SimpleNamespace(**values)

                def root_lstat(path, *args, **kwargs):
                    return as_root(
                        original_lstat(path, *args, **kwargs),
                        ancestor=path in base.parents,
                    )

                guest = module.NativeQA(SimpleNamespace(evidence_dir=base / "evidence"))
                with (
                    patch.object(module, "ROOT", root),
                    patch.object(module, "REGISTRY_CA_DIR", ca),
                    patch.object(module.Path, "lstat", root_lstat),
                    patch.object(
                        module.os, "fstat", side_effect=lambda fd: as_root(original_fstat(fd))
                    ),
                    patch.object(module.os, "listxattr", return_value=[], create=True),
                ):
                    yield guest, hosts, source, root

            unsupported = (
                {**engine, "ServerVersion": "99.0 SYNTHETIC_PRIVATE_VERSION"},
                {**engine, "DriverStatus": None},
                {**engine, "DriverStatus": [["driver-type", "overlay2"]]},
                {**engine, "SecurityOptions": ["name=rootless"]},
                {**engine, "SecurityOptions": None},
            )
            for number, context in enumerate(unsupported):
                with self.subTest("unsupported context before any fixture mutation", number=number):
                    with trust_fixture("context-" + str(number)) as (guest, hosts, source, root):
                        guest.preflight = lambda context=context: guest.attest_registry_trust(
                            context
                        )
                        guest.images = unittest.mock.Mock()
                        guest.cleanup = unittest.mock.Mock()
                        with self.assertRaisesRegex(RuntimeError, "native gate held"):
                            guest.execute()
                        guest.images.assert_not_called()
                        guest.cleanup.assert_not_called()
                        self.assertEqual(set(hosts.parent.iterdir()), {hosts})
                        self.assertEqual(guest.events[0]["result"], "failed")
                        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(guest.events))
            for unsafe in (
                "hash",
                "symlink",
                "parent-symlink",
                "mode",
                "directory",
                "hardlink",
                "xattr",
            ):
                with self.subTest("unsafe baseline refused before mutation", unsafe=unsafe):
                    with trust_fixture("unsafe-" + unsafe) as (guest, hosts, source, root):
                        if unsafe == "hash":
                            hosts.write_bytes(b"SYNTHETIC_PRIVATE_CONFIG")
                        elif unsafe == "symlink":
                            hosts.unlink()
                            hosts.symlink_to(source)
                        elif unsafe == "mode":
                            hosts.chmod(0o666)
                        elif unsafe == "parent-symlink":
                            moved = hosts.parent.with_name("moved-certs")
                            hosts.parent.rename(moved)
                            hosts.parent.symlink_to(moved, target_is_directory=True)
                        elif unsafe == "directory":
                            hosts.parent.chmod(0o777)
                        elif unsafe == "hardlink":
                            os.link(hosts, hosts.with_name("other"))
                        with patch.object(
                            module.os,
                            "listxattr",
                            return_value=["unsupported"] if unsafe == "xattr" else [],
                        ):
                            with self.assertRaisesRegex(
                                RuntimeError, "unsupported guest registry trust"
                            ):
                                guest.attest_registry_trust(engine)
                        self.assertIsNone(guest.registry_ca_file)
                        self.assertIsNone(guest.registry_trust)
                        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(guest.events))
            with self.subTest(
                "original inode bytes metadata and baseline CA survive trust round trip"
            ):
                with trust_fixture("roundtrip") as (guest, hosts, source, root):
                    original_info = hosts.stat()
                    baseline_ca = hosts.with_name("ca.crt")
                    baseline_ca.write_bytes(b"existing mirror CA bytes")
                    baseline_info = baseline_ca.stat()
                    guest.attest_registry_trust(engine)
                    guest.install_registry_ca(source)
                    fixture_ca = guest.registry_ca_file
                    guest.install_registry_trust()
                    changed = tomllib.loads(hosts.read_text())
                    self.assertEqual(changed.pop("ca"), [str(fixture_ca)])
                    self.assertEqual(changed, tomllib.loads(GUEST_HOSTS.decode()))
                    self.assertEqual(
                        guest.registry_trust["backup"].stat().st_ino, original_info.st_ino
                    )
                    guest.restore_registry_trust()
                    restored_info = hosts.stat()
                    self.assertEqual(
                        (
                            restored_info.st_ino,
                            restored_info.st_uid,
                            restored_info.st_gid,
                            restored_info.st_mode,
                            restored_info.st_atime_ns,
                            restored_info.st_mtime_ns,
                        ),
                        (
                            original_info.st_ino,
                            original_info.st_uid,
                            original_info.st_gid,
                            original_info.st_mode,
                            original_info.st_atime_ns,
                            original_info.st_mtime_ns,
                        ),
                    )
                    self.assertEqual(hosts.read_bytes(), GUEST_HOSTS)
                    self.assertTrue(fixture_ca.exists())  # Config restored before CA removal.
                    guest.remove_registry_ca()
                    self.assertEqual(baseline_ca.stat(), baseline_info)
                    self.assertEqual(baseline_ca.read_bytes(), b"existing mirror CA bytes")
                    self.assertEqual(guest.events[-1]["result"], "restored")
                    self.assertFalse(guest.events[-1]["ctime_restored"])
            for partial in ("write", "rename"):
                with self.subTest("partial preparation reaches restoration", partial=partial):
                    with trust_fixture("partial-" + partial) as (guest, hosts, source, root):
                        guest.attest_registry_trust(engine)
                        original_replace = module.os.replace

                        def replace(source_path, destination, original_replace=original_replace):
                            if Path(source_path).name.startswith(".native-fleet-qa-"):
                                raise OSError("SYNTHETIC_PRIVATE_RENAME")
                            return original_replace(source_path, destination)

                        def prepare(
                            partial=partial, original_replace=original_replace, replace=replace
                        ):
                            guest.install_registry_ca(source)
                            with (
                                patch.object(
                                    module.os,
                                    "replace",
                                    side_effect=(
                                        replace if partial == "rename" else original_replace
                                    ),
                                ),
                                patch.object(
                                    module.os,
                                    "fsync",
                                    side_effect=(
                                        OSError("SYNTHETIC_PRIVATE_WRITE")
                                        if partial == "write"
                                        else None
                                    ),
                                ),
                            ):
                                guest.install_registry_trust()

                        guest.preflight = lambda: None
                        guest.images = prepare
                        guest.reset_fixture = lambda: None
                        with (
                            patch.object(
                                module, "docker", return_value=SimpleNamespace(stdout=b"")
                            ),
                            patch.object(module, "run"),
                        ):
                            with self.assertRaisesRegex(RuntimeError, "native verification failed"):
                                guest.execute()
                        self.assertEqual(hosts.read_bytes(), GUEST_HOSTS)
                        self.assertIsNone(guest.registry_trust)
                        self.assertIsNone(guest.registry_ca_file)
                        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(guest.events))
            for drift in ("replacement", "content", "restore-failure", "consumer-active"):
                with self.subTest("cleanup custody failure is terminal and private", drift=drift):
                    with trust_fixture("drift-" + drift) as (guest, hosts, source, root):
                        guest.attest_registry_trust(engine)
                        guest.install_registry_ca(source)
                        guest.install_registry_trust()
                        fixture_ca = guest.registry_ca_file
                        private = "SYNTHETIC_PRIVATE_CONFIG_HEADER_KEY_PATH"
                        if drift == "replacement":
                            replacement = hosts.with_name("foreign")
                            replacement.write_bytes(hosts.read_bytes())
                            os.replace(replacement, hosts)
                        elif drift == "content":
                            hosts.write_text(private)
                        untouched = hosts.read_bytes()
                        original_replace = module.os.replace

                        def restore_failure(
                            source_path,
                            destination,
                            private=private,
                            original_replace=original_replace,
                        ):
                            if Path(source_path).name == "original":
                                raise OSError(private)
                            return original_replace(source_path, destination)

                        for method in (
                            "preflight",
                            "images",
                            "units_install",
                            "fixture",
                            "service_update",
                            "proxy_adopt",
                            "rollback",
                            "interrupted_adoption",
                            "reset_fixture",
                        ):
                            setattr(guest, method, lambda *args: None)

                        def consumers(*args, drift=drift):
                            return SimpleNamespace(
                                stdout=(
                                    b"owned-consumer"
                                    if drift == "consumer-active"
                                    and args[-1] == "label=" + guest.label
                                    else b""
                                )
                            )

                        with (
                            patch.object(module, "docker", side_effect=consumers),
                            patch.object(module, "run"),
                            patch.object(
                                module.os,
                                "replace",
                                side_effect=(
                                    restore_failure
                                    if drift == "restore-failure"
                                    else original_replace
                                ),
                            ),
                        ):
                            try:
                                guest.execute()
                            except RuntimeError:
                                visible = traceback.format_exc()
                            else:
                                self.fail("cleanup failure must fail after a passed native flow")
                        self.assertEqual(hosts.read_bytes(), untouched)
                        self.assertTrue(fixture_ca.exists())
                        self.assertTrue(guest.registry_trust["backup"].exists())
                        self.assertTrue(root.exists())
                        flow = [event for event in guest.events if event["case"] == "native-flow"]
                        self.assertEqual([event["result"] for event in flow], ["passed", "failed"])
                        self.assertEqual(flow[-1].get("phase"), "cleanup")
                        self.assertIs(type(flow[-1].get("source_line")), int)
                        self.assertIn(
                            flow[-1].get("source_line"),
                            {line for _, _, line in module.NativeQA.cleanup.__code__.co_lines()},
                        )
                        self.assertEqual(flow[-1].get("error_kind"), "runtime-error")
                        retained = (guest.evidence / "results.json").read_text()
                        self.assertNotIn(private, visible + retained)
                        self.assertNotIn(str(root), visible + retained)
            with self.subTest("early preflight failure emits red evidence without fixture cleanup"):
                early = module.NativeQA(SimpleNamespace(evidence_dir=Path(directory) / "early"))
                early.preflight = unittest.mock.Mock(
                    side_effect=RuntimeError("occupied fixture path")
                )
                early.cleanup = unittest.mock.Mock()
                early.images = unittest.mock.Mock()
                with self.assertRaisesRegex(RuntimeError, "native verification failed"):
                    early.execute()
                early.images.assert_not_called()
                early.cleanup.assert_not_called()
                result = (early.evidence / "results.json").read_text()
                self.assertIn('"result":"failed"', result)
                self.assertNotIn("occupied fixture path", result)
                self.assertEqual(early.events[-1].get("phase"), "preflight")
                early.fixture_owned = True  # Fresh ROOT acquired before the prepared flag.
                with self.assertRaisesRegex(RuntimeError, "native verification failed"):
                    early.execute()
                early.cleanup.assert_called_once()

            original_service_update = module.NativeQA.service_update
            private = "SYNTHETIC_PRIVATE_SERVICE_UPDATE_KEY_PATH"
            for foreign, collector_fails in ((False, False), (True, False), (False, True)):
                with self.subTest(
                    "service update diagnostics", foreign=foreign, collector_fails=collector_fails
                ):
                    guest = module.NativeQA(
                        SimpleNamespace(
                            evidence_dir=Path(directory) / f"service-{foreign}-{collector_fails}"
                        )
                    )
                    guest.preflight = lambda: None
                    guest.images = lambda: None
                    guest.units_install = lambda: None
                    guest.fixture = lambda layout: None
                    guest.cleanup = unittest.mock.Mock()
                    cause = RuntimeError(private)

                    # A same-name, same-filename replacement still has foreign code identity.
                    def service_update(self, cause=cause):
                        self.issuer = private
                        raise cause

                    service_update.__code__ = service_update.__code__.replace(
                        co_filename=str(SCRIPT)
                    )
                    with (
                        patch.object(
                            module.NativeQA,
                            "service_update",
                            service_update if foreign else original_service_update,
                        ),
                        patch.object(module, "inspect", side_effect=cause) as boundary,
                        patch.object(
                            module,
                            "native_phase_failure_metadata",
                            side_effect=RuntimeError(private),
                            create=True,
                        ) if collector_fails else nullcontext(),
                    ):
                        try:
                            guest.execute()
                        except RuntimeError:
                            visible = traceback.format_exc()
                        else:
                            self.fail("phase diagnostics must preserve the original failure")
                    guest.cleanup.assert_called_once()
                    if foreign:
                        boundary.assert_not_called()
                    else:
                        boundary.assert_called_once_with("cryptolabs-proxy")
                    retained = (guest.evidence / "results.json").read_text()
                    self.assertNotIn(private, visible + retained)
                    self.assertNotIn(str(guest.evidence), visible + retained)
                    flow = guest.events[-1]
                    self.assertEqual((flow["result"], flow["phase"]), ("failed", "service_update"))
                    lines = []
                    frame = cause.__traceback__
                    while frame is not None:
                        if frame.tb_frame.f_code is original_service_update.__code__:
                            lines.append(frame.tb_lineno)
                        frame = frame.tb_next
                    expected = None if foreign or collector_fails else lines[-1]
                    self.assertIn("source_line", flow)
                    self.assertEqual(flow["source_line"], expected)
                    self.assertEqual(
                        flow.get("error_kind"), "runtime-error" if expected is not None else "unknown"
                    )
                    if expected is not None:
                        for phase in ("proxy_adopt", "foreign-phase"):
                            self.assertEqual(
                                module.native_phase_failure_metadata(cause, phase),
                                {"source_line": None, "error_kind": "unknown"},
                            )

            original_fixture = module.NativeQA.fixture
            private = "SYNTHETIC_PRIVATE_FIXTURE_KEY_PATH"
            foreign_error = type(private, (Exception,), {})
            errors = (
                (AssertionError, "assertion-error"),
                (FileNotFoundError, "file-not-found"),
                (PermissionError, "permission-error"),
                (OSError, "os-error"),
                (RuntimeError, "runtime-error"),
                (foreign_error, "unknown"),
            )
            cases = [(error_type, kind, False) for error_type, kind in errors]
            cases.append((RuntimeError, "unknown", True))
            for number, (error_type, kind, foreign) in enumerate(cases):
                with self.subTest("fixture diagnostics", kind=kind, foreign=foreign):
                    root = Path(directory) / f"fixture-{number}-{foreign}"
                    root.mkdir()
                    guest = module.NativeQA(SimpleNamespace(evidence_dir=root / "evidence"))
                    guest.preflight = lambda: None
                    guest.images = lambda: None
                    guest.units_install = lambda: None
                    guest.cleanup = unittest.mock.Mock()
                    cause = error_type(private)

                    def fail_command(*args, cause=cause, **kwargs):
                        self.assertEqual(kwargs["env"]["QA_USER_PASS"], private)
                        self.assertEqual(kwargs["env"]["AUTH_SECRET_KEY"], private)
                        raise cause

                    # Same name and even filename must not confer trusted code identity.
                    def fixture(self, layout, cause=cause):
                        signing_key = private
                        self.issuer = signing_key
                        raise cause

                    fixture.__code__ = fixture.__code__.replace(co_filename=str(SCRIPT))
                    with (
                        patch.object(
                            module.NativeQA, "fixture", fixture if foreign else original_fixture
                        ),
                        patch.dict(
                            module.sys.modules,
                            {
                                # Imported by the real fixture, unused before the failed command.
                                "cryptography.hazmat.primitives.asymmetric.ed25519": SimpleNamespace(
                                    Ed25519PrivateKey=None
                                ),
                                "cryptography.hazmat.primitives.serialization": SimpleNamespace(
                                    Encoding=None, PublicFormat=None
                                ),
                                "cryptolabs_proxy.standard_adoption": SimpleNamespace(
                                    _declaration=None, render_standard=None
                                ),
                                "dc_overview.fleet_config": SimpleNamespace(FleetConfig=None),
                                "dc_overview.release_catalog": SimpleNamespace(ReleaseStore=None),
                            },
                        ),
                        patch.dict(os.environ, {"FLEET_NATIVE_RUN_ID": "fixture-test"}),
                        patch.object(module, "ROOT", root),
                        patch.object(module, "CONFIG", root / "config"),
                        patch.object(module, "PROXY_CONFIG", root / "proxy"),
                        patch.object(module, "docker"),
                        patch.object(module.secrets, "token_urlsafe", return_value=private),
                        patch.object(module, "run", side_effect=fail_command) as command,
                    ):
                        # execute chooses named-volume first; bind avoids any fake Docker mount.
                        if not foreign:
                            guest.fixture = lambda layout, guest=guest: original_fixture(
                                guest, "bind"
                            )
                        try:
                            guest.execute()
                        except RuntimeError:
                            visible = traceback.format_exc()
                        else:
                            self.fail("fixture diagnostics must not green the original failure")
                    guest.cleanup.assert_called_once()
                    if foreign:
                        command.assert_not_called()
                    else:
                        command.assert_called_once()
                    retained = (guest.evidence / "results.json").read_text()
                    self.assertNotIn(private, visible + retained)
                    self.assertNotIn(str(root), visible + retained)
                    flow = guest.events[-1]
                    self.assertEqual((flow["result"], flow["phase"]), ("failed", "fixture"))
                    lines = []
                    frame = cause.__traceback__
                    while frame is not None:
                        if frame.tb_frame.f_code is original_fixture.__code__:
                            lines.append(frame.tb_lineno)
                        frame = frame.tb_next
                    expected = None if foreign else lines[-1]
                    self.assertEqual(flow.get("fixture_line"), expected)
                    self.assertIn("fixture_line", flow)
                    self.assertEqual(flow.get("fixture_error_kind"), kind)
                    self.assertEqual(flow.get("source_line"), expected)
                    self.assertIn("source_line", flow)
                    self.assertEqual(flow.get("error_kind"), kind)
                    if expected is not None:
                        self.assertIn(
                            expected, {line for _, _, line in original_fixture.__code__.co_lines()}
                        )


    # TRACEWEAVER: verifies=VER-AUTOADVANCE-008; req=REQ-AUTOADVANCE-008; trace=TRACE-AUTOADVANCE-008
    def test_native_policy_versions_are_bound_to_existing_immutable_images(self):
        module = self.native_module()
        self.assertTrue(hasattr(module, 'IPMI_POLICY_PROOFS'),
                        'native policy proof needs actual source-qualified versions')
        expected = {
            'ipmi-old': ('1.3.1', module.IPMI_OLD, 'a5cfd4ea0d6e43c6346f641693fcb6eef449433b'),
            'ipmi-new': ('1.3.3', module.IPMI_NEW, 'cf79b1258e9b6c0daed8c9c998218e4fb48cc0db'),
        }
        self.assertEqual(set(module.IPMI_POLICY_PROOFS), set(expected))
        qa = module.NativeQA.__new__(module.NativeQA)
        qa.refs = {name: value[1] for name, value in expected.items()}
        for name, (version, reference, revision) in expected.items():
            proof = module.IPMI_POLICY_PROOFS[name]
            self.assertEqual((proof['version'], proof['reference'], proof['source_revision']),
                             (version, reference, revision))
            self.assertEqual(qa.component(name)['release'], version)
            self.assertEqual(qa.component(name)['artifacts']['linux/amd64']['reference'], reference)
        self.assertEqual(module.IPMI_OLD,
            'ghcr.io/cryptolabsza/ipmi-monitor@sha256:738f11f7b432c4d9d8409154c9ca3f531a1e069999eb639a9d86433e84ac279d')
        self.assertEqual(module.IPMI_NEW,
            'ghcr.io/cryptolabsza/ipmi-monitor@sha256:1d616479a3842f5101615b6d97552f732de73fd424fcb844a9c643e92abc8bb1')

    def test_native_policy_checks_real_package_version_and_rechecks_container_identity(self):
        module = self.native_module()
        self.assertTrue(hasattr(module.NativeQA, 'policy_installed_version'),
                        'manifest version alone cannot prove the installed package version')
        import copy
        for fault in (None, 'package-version', 'image-reference', 'source-revision', 'container-race'):
            with self.subTest(fault=fault):
                qa = module.NativeQA.__new__(module.NativeQA)
                qa.label = 'io.cryptolabs.native-qa=fixture'
                qa.refs = {'ipmi-old': module.IPMI_OLD}
                before = {'Id': 'c' * 64, 'Image': 'sha256:' + 'd' * 64,
                          'State': {'Running': True},
                          'Config': {'Labels': {'io.cryptolabs.native-qa': 'fixture'}}}
                image = {'Id': before['Image'], 'Os': 'linux', 'Architecture': 'amd64',
                         'RepoDigests': [] if fault == 'image-reference' else [module.IPMI_OLD],
                         'Config': {'Labels': {'org.opencontainers.image.revision':
                             'e' * 40 if fault == 'source-revision' else
                             'a5cfd4ea0d6e43c6346f641693fcb6eef449433b'}}}
                reads = []
                def inspecting(name, *, image=False):
                    if image:
                        self.assertEqual(name, before['Image'])
                        return copy.deepcopy(image_value)
                    self.assertEqual(name, 'ipmi-monitor')
                    value = copy.deepcopy(before)
                    if reads and fault == 'container-race':
                        value['Id'] = 'f' * 64
                    reads.append(value)
                    return value
                image_value = image
                engine_calls = []
                def engine(*args, **kwargs):
                    engine_calls.append((args, kwargs))
                    self.assertEqual(args[:2], ('exec', before['Id']))
                    self.assertIn('-I', args); self.assertIn('-B', args)
                    self.assertIn('importlib.metadata', args[-1])
                    self.assertNotIn('ipmi_monitor.app', args[-1])
                    self.assertNotIn('subprocess', args[-1])
                    self.assertLessEqual(kwargs.get('timeout', 30), 30)
                    return SimpleNamespace(returncode=0,
                        stdout=b'9.9.9\n' if fault == 'package-version' else b'1.3.1\n', stderr=b'')
                with patch.object(module, 'inspect', side_effect=inspecting), patch.object(module, 'docker', side_effect=engine):
                    if fault:
                        with self.assertRaises((AssertionError, RuntimeError, ValueError)):
                            qa.policy_installed_version('ipmi-old')
                    else:
                        self.assertEqual(qa.policy_installed_version('ipmi-old'), '1.3.1')
                        self.assertGreaterEqual(len(reads), 2)
                        self.assertEqual(len(engine_calls), 1)

    def test_native_policy_discovery_failures_restore_exact_signed_assets(self):
        module = self.native_module()
        self.assertTrue(hasattr(module.NativeQA, 'policy_discovery_refusals'),
                        'native proof must exercise invalid and unavailable signed discovery')
        for failure in (None, 'transport', 'unexpected-success'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                assets = root / 'admission'; assets.mkdir()
                originals = {'admission-index.sig': b'PRIVATE-SIGNATURE-BYTES',
                             'admission-index.json': b'PRIVATE-INDEX-BYTES'}
                for name, value in originals.items():
                    (assets / name).write_bytes(value)
                qa = module.NativeQA.__new__(module.NativeQA)
                current = {'selection_id': 'selected', 'selection_sha256': 'a' * 64,
                           'components': {'ipmi-monitor': {'mode': 'follow-stable'}}}
                qa.policy_listing = lambda: current
                qa.policy_state_snapshot = lambda: {'policy': 'p', 'selection': 's', 'runtime': 'r'}
                qa.record = unittest.mock.Mock()
                seen = []
                def http(method, path, *, body=None, **kwargs):
                    self.assertEqual((method, path), ('POST', '/api/releases/policy-refresh'))
                    self.assertEqual(body, {'expected_selection_id': 'selected',
                                            'expected_selection_sha256': 'a' * 64})
                    if not (assets / 'admission-index.json').exists():
                        self.assertEqual((assets / 'admission-index.sig').read_bytes(), originals['admission-index.sig'])
                        seen.append('unavailable')
                    else:
                        self.assertNotEqual((assets / 'admission-index.sig').read_bytes(), originals['admission-index.sig'])
                        seen.append('invalid-signature')
                    if failure == 'transport':
                        raise RuntimeError('PRIVATE-TRANSPORT-DETAIL')
                    return SimpleNamespace(status_code=200 if failure == 'unexpected-success' else 503,
                                           json=lambda: {'error': {'code': 'unavailable'}})
                qa.http = http
                with patch.object(module, 'ROOT', root):
                    if failure:
                        with self.assertRaises((AssertionError, RuntimeError, ValueError)):
                            qa.policy_discovery_refusals()
                    else:
                        qa.policy_discovery_refusals()
                        self.assertCountEqual(seen, ['invalid-signature', 'unavailable'])
                for name, value in originals.items():
                    self.assertEqual((assets / name).read_bytes(), value)
                self.assertEqual(set(p.name for p in assets.iterdir()), set(originals))
                self.assertNotIn('PRIVATE', repr(qa.record.call_args_list))

    def test_native_policy_race_uses_separate_sessions_and_one_selection_cas(self):
        module = self.native_module()
        self.assertTrue(hasattr(module.NativeQA, 'policy_cas_race'),
                        'native proof needs an actual two-client CAS race')
        import threading
        for winner in ('pin', 'refresh'):
            with self.subTest(winner=winner):
                current = {'selection_id': 'before', 'selection_sha256': 'a' * 64,
                           'components': {'ipmi-monitor': {'mode': 'follow-stable', 'major': 1,
                               'installed_release': '1.3.1', 'selected_release': '1.3.1'}}}
                sessions, posts, closed = [], [], []
                won = threading.Event(); lock = threading.Lock()
                class Client:
                    def __init__(client):
                        client.cookies = {}; client.verify = None
                        with lock:
                            client.number = len(sessions); sessions.append(client)
                    def get(client, url, **kwargs):
                        self.assertEqual(url, module.ORIGIN + '/api/releases/session')
                        return SimpleNamespace(status_code=200,
                            json=lambda: {'csrf_token': 'PRIVATE-' + str(client.number)})
                    def post(client, url, **kwargs):
                        return client.request('POST', url, **kwargs)
                    def request(client, method, url, *, json=None, headers=None, timeout=None, **kwargs):
                        self.assertEqual(method, 'POST')
                        self.assertEqual(len(sessions), 2)
                        self.assertEqual(headers['X-CSRF-Token'], 'PRIVATE-' + str(client.number))
                        self.assertEqual(headers['Origin'], module.ORIGIN)
                        self.assertIsNotNone(timeout); self.assertLessEqual(timeout, 15)
                        role = 'pin' if url.endswith('/policy-set') else 'refresh'
                        expected = {'expected_selection_id': 'before', 'expected_selection_sha256': 'a' * 64}
                        if role == 'pin': expected.update(component='ipmi-monitor', mode='pinned')
                        self.assertEqual(json, expected)
                        if role != winner:
                            self.assertTrue(won.wait(2), 'other client never completed')
                        with lock:
                            posts.append((role, client.number))
                            status = 200 if role == winner else 409
                            if status == 200:
                                won.set()
                        return SimpleNamespace(status_code=status,
                            json=lambda: {'error': {'code': 'selection-conflict'}} if status == 409 else current)
                    def close(client): closed.append(client.number)
                qa = module.NativeQA.__new__(module.NativeQA)
                qa.session = SimpleNamespace(cookies={'session': 'PRIVATE-AUTH'}, verify='/fixed/fixture-ca.crt')
                qa.record = unittest.mock.Mock()
                with patch.dict(sys.modules, {'requests': SimpleNamespace(Session=Client)}):
                    result = qa.policy_cas_race(current)
                self.assertEqual(result, winner)
                self.assertEqual(len(sessions), 2)
                self.assertEqual(len(posts), 2)
                self.assertEqual(len({number for _, number in posts}), 2)
                self.assertCountEqual(closed, [0, 1])
                self.assertTrue(all(client.cookies == qa.session.cookies and
                                    client.verify == qa.session.verify for client in sessions))
                self.assertNotIn('PRIVATE', repr(qa.record.call_args_list))

    def test_native_policy_timer_requires_pin_before_persistent_enable(self):
        module = self.native_module()
        self.assertTrue(hasattr(module.NativeQA, 'policy_timer_prepare'),
                        'packaged timer must be tested with catch-up control')
        qa = module.NativeQA.__new__(module.NativeQA)
        qa.policy_listing = lambda: {'components': {'ipmi-monitor': {'mode': 'follow-stable'}}}
        with patch.object(module, 'run', side_effect=AssertionError('timer effect before pin')) as command:
            with self.assertRaises((AssertionError, RuntimeError, ValueError)):
                qa.policy_timer_prepare()
        command.assert_not_called()

    def test_native_policy_timer_uncertain_creation_cannot_authorize_cleanup(self):
        module = self.native_module()
        self.assertTrue(hasattr(module.NativeQA, 'policy_timer_quiesce'),
                        'new fixture units need positive cleanup ownership')
        qa = module.NativeQA.__new__(module.NativeQA)
        qa.policy_timer_attempted = True
        qa.policy_timer_record = None
        with patch.object(module, 'run', side_effect=AssertionError('unowned unit mutation')) as command:
            with self.assertRaises((AssertionError, RuntimeError, ValueError)):
                qa.policy_timer_quiesce()
        command.assert_not_called()

    def test_native_policy_proof_surrounds_original_manual_upgrade_and_cleanup(self):
        tree = ast.parse(SCRIPT.read_text())
        klass = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'NativeQA')
        methods = {n.name: n for n in klass.body if isinstance(n, ast.FunctionDef)}
        self.assertTrue({'policy_before_update', 'policy_after_update', 'policy_timer_quiesce'} <= methods.keys(),
                        'source guard/unit tests alone cannot prove native policy controls')
        calls = [(n.lineno, n.func.attr) for n in ast.walk(methods['service_update'])
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and isinstance(n.func.value, ast.Name) and n.func.value.id == 'self']
        lines = {name: [line for line, call in calls if call == name]
                 for name in ('policy_before_update', 'apply', 'finish', 'policy_after_update')}
        self.assertTrue(all(len(value) == 1 for value in lines.values()))
        self.assertLess(lines['policy_before_update'][0], lines['apply'][0])
        self.assertLess(lines['finish'][0], lines['policy_after_update'][0])
        for name in ('wait_mapped_worker', 'kill_broker', 'wait_fresh_broker'):
            self.assertIn(name, [call for _, call in calls])
        reset_calls = [n.func.attr for n in ast.walk(methods['reset_fixture'])
                       if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                       and isinstance(n.func.value, ast.Name) and n.func.value.id == 'self']
        self.assertIn('policy_timer_quiesce', reset_calls)
        reset_lines = {n.func.attr: n.lineno for n in ast.walk(methods['reset_fixture'])
                       if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                       and isinstance(n.func.value, ast.Name) and n.func.value.id == 'self'}
        self.assertLess(reset_lines['policy_timer_quiesce'], reset_lines['consume_child_failure'])

    def test_native_policy_retains_actual_old_manifest_without_editing_desired_input(self):
        module = self.native_module()
        self.assertTrue(hasattr(module.NativeQA, 'policy_retain_installed_manifest'),
                        'pending legacy desired selection must not masquerade as installed provenance')
        import copy
        with tempfile.TemporaryDirectory() as directory:
            qa = module.NativeQA.__new__(module.NativeQA)
            qa.data = Path(directory)
            qa.refs = {'ipmi-old': module.IPMI_OLD}
            desired = {'schema_version': 1, 'selection_contract': 1, 'baseline_id': 'legacy-desired',
                       'components': {'ipmi-monitor': {'owner': 'proxy-updater', 'release': '1.3.2',
                           'artifacts': {'linux/amd64': {'kind': 'oci', 'reference': module.LEGACY_DESIRED}}},
                           'cryptolabs-proxy': {'preserve': 'proxy'}, 'grafana': {'preserve': 'pin'}}}
            original = copy.deepcopy(desired)
            policies = {'ipmi-monitor': {'origin': 'baseline', 'enabled': True},
                        'grafana': {'origin': 'customer-pin', 'enabled': False}}
            prepared = object(); captured = []
            def prepare(path, **kwargs):
                captured.append((json.loads(Path(path).read_bytes()), kwargs))
                return prepared
            qa.store = SimpleNamespace(prepare=unittest.mock.Mock(side_effect=prepare),
                                       commit=unittest.mock.Mock())
            qa.policy_retain_installed_manifest(desired, policies)
            self.assertEqual(desired, original)
            qa.store.commit.assert_called_once_with(prepared)
            self.assertEqual(len(captured), 1)
            data, options = captured[0]
            self.assertEqual(data['components']['ipmi-monitor'], qa.component('ipmi-old'))
            for name in ('cryptolabs-proxy', 'grafana'):
                self.assertEqual(data['components'][name], desired['components'][name])
            self.assertEqual(options, {'platform': 'linux/amd64', 'policies': policies})
            tree = ast.parse(SCRIPT.read_text())
            fixture = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'fixture')
            retained = [n.lineno for n in ast.walk(fixture) if isinstance(n, ast.Call)
                        and isinstance(n.func, ast.Attribute) and n.func.attr == 'policy_retain_installed_manifest']
            selected = [n.lineno for n in ast.walk(fixture) if isinstance(n, ast.Call)
                        and isinstance(n.func, ast.Attribute) and n.func.attr == 'commit']
            self.assertEqual(len(retained), 1); self.assertEqual(len(selected), 1)
            self.assertLess(retained[0], selected[0], 'original desired selection must remain the final fixture commit')

    def test_native_policy_kernel_lock_refusal_releases_real_flock_on_every_exit(self):
        module = self.native_module()
        self.assertTrue(hasattr(module.NativeQA, 'policy_lock_refusal'),
                        'native proof must exercise the real lifecycle lock')
        import fcntl
        for transport_failure in (False, True):
            with self.subTest(transport_failure=transport_failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); lock_path = root / '.lifecycle-config.lock'
                lock_path.write_bytes(b''); lock_path.chmod(0o600)
                qa = module.NativeQA.__new__(module.NativeQA)
                qa.policy_listing = lambda: {'selection_id': 'before', 'selection_sha256': 'a' * 64,
                    'components': {'ipmi-monitor': {'mode': 'follow-stable', 'major': 1}}}
                qa.policy_state_snapshot = lambda: {'policy': 'p', 'selection': 's', 'runtime': 'r'}
                qa.record = unittest.mock.Mock(); called = []
                def http(method, path, *, body=None, **kwargs):
                    self.assertEqual((method, path), ('POST', '/api/releases/policy-set'))
                    self.assertEqual(body, {'component': 'ipmi-monitor', 'mode': 'pinned',
                        'expected_selection_id': 'before', 'expected_selection_sha256': 'a' * 64})
                    descriptor = os.open(lock_path, os.O_RDONLY)
                    try:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    finally:
                        os.close(descriptor)
                    called.append(True)
                    if transport_failure:
                        raise RuntimeError('PRIVATE-TRANSPORT')
                    return SimpleNamespace(status_code=409, json=lambda: {'error': {'code': 'busy'}})
                qa.http = http
                actual_fstat, actual_lstat = os.fstat, os.lstat
                def root_metadata(info):
                    # Model root file custody; real descriptors and kernel flock
                    # acquisition/refusal/release remain unchanged.
                    values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
                    values.update(st_uid=0, st_gid=0)
                    return SimpleNamespace(**values)
                with patch.object(module, 'CONFIG', root), \
                     patch.object(module.os, 'fstat', side_effect=lambda *a, **kw: root_metadata(actual_fstat(*a, **kw))), \
                     patch.object(module.os, 'lstat', side_effect=lambda *a, **kw: root_metadata(actual_lstat(*a, **kw))):
                    if transport_failure:
                        with self.assertRaises(RuntimeError): qa.policy_lock_refusal()
                    else:
                        qa.policy_lock_refusal()
                self.assertEqual(called, [True])
                descriptor = os.open(lock_path, os.O_RDONLY)
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)
                self.assertNotIn('PRIVATE', repr(qa.record.call_args_list))

    def test_native_policy_timer_cleanup_validates_both_owned_files_before_effects(self):
        module = self.native_module()
        self.assertTrue(hasattr(module.NativeQA, 'policy_timer_quiesce') and
                        hasattr(module, 'POLICY_REFRESH_SYSTEMD'),
                        'timer cleanup needs a fixed two-file ownership boundary')
        import stat
        for fault in (None, 'changed-bytes', 'changed-inode', 'extra-unit', 'still-active'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); files = {}
                for suffix in ('service', 'timer'):
                    path = root / ('dc-overview-release-refresh.' + suffix)
                    path.write_bytes(('[Unit]\nDescription=owned-' + suffix + '\n').encode())
                    path.chmod(0o600); info = path.lstat()
                    files[str(path)] = {'sha256': module.digest(path.read_bytes()),
                                       'device': info.st_dev, 'inode': info.st_ino}
                if fault == 'changed-bytes':
                    next(root.iterdir()).write_bytes(b'foreign unit bytes')
                if fault == 'changed-inode':
                    files[str(root / 'dc-overview-release-refresh.service')]['inode'] += 1
                if fault == 'extra-unit': files[str(root / 'unrelated.service')] = dict(next(iter(files.values())))
                qa = module.NativeQA.__new__(module.NativeQA)
                qa.policy_timer_attempted = True
                qa.policy_timer_record = {'files': files}
                actual_lstat, actual_fstat = os.lstat, os.fstat
                def native_root_info(info):
                    # OS ownership and ancestor directory modes are synthetic;
                    # file bytes, inode/device, type, link count and faults are real.
                    values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
                    values.update(st_uid=0, st_gid=0)
                    if stat.S_ISDIR(info.st_mode): values['st_mode'] = stat.S_IFDIR | 0o755
                    return SimpleNamespace(**values)
                calls = []
                def command(*args, **kwargs):
                    self.assertEqual(args[0], 'systemctl')
                    self.assertTrue(all(name in ('dc-overview-release-refresh.service',
                        'dc-overview-release-refresh.timer') for name in args[2:] if not name.startswith('-')))
                    calls.append(args)
                    if args[1] == 'is-active':
                        return SimpleNamespace(returncode=0 if fault == 'still-active' else 3,
                            stdout=b'active\n' if fault == 'still-active' else b'inactive\n', stderr=b'')
                    if args[1] == 'is-enabled': return SimpleNamespace(returncode=1, stdout=b'disabled\n', stderr=b'')
                    self.assertIn(args[1], ('disable', 'stop'))
                    return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
                with patch.object(module, 'POLICY_REFRESH_SYSTEMD', root), \
                     patch.object(module.os, 'lstat', side_effect=lambda *a, **kw: native_root_info(actual_lstat(*a, **kw))), \
                     patch.object(module.os, 'fstat', side_effect=lambda *a, **kw: native_root_info(actual_fstat(*a, **kw))), \
                     patch.object(module, 'run', side_effect=command):
                    if fault:
                        with self.assertRaises((AssertionError, RuntimeError, ValueError)):
                            qa.policy_timer_quiesce()
                        if fault != 'still-active':
                            self.assertEqual(calls, [], 'unproven files cannot authorize even a fixed unit effect')
                        else:
                            self.assertIn(('systemctl', 'disable', '--now', 'dc-overview-release-refresh.timer'), calls)
                    else:
                        qa.policy_timer_quiesce()
                        self.assertIn(('systemctl', 'disable', '--now', 'dc-overview-release-refresh.timer'), calls)
                        self.assertIn(('systemctl', 'stop', 'dc-overview-release-refresh.service'), calls)

    def test_native_policy_race_refuses_uncertain_or_non_cas_results_without_retry(self):
        module = self.native_module()
        self.assertTrue(hasattr(module.NativeQA, 'policy_cas_race'))
        import threading
        for outcome in ('both-success', 'both-conflict', 'transport'):
            with self.subTest(outcome=outcome):
                clients = []; lock = threading.Lock()
                class Client:
                    def __init__(client):
                        client.cookies = {}; client.verify = None; client.calls = 0; client.closed = False
                        with lock: clients.append(client)
                    def get(client, *args, **kwargs):
                        return SimpleNamespace(status_code=200, json=lambda: {'csrf_token': 'PRIVATE'})
                    def post(client, url, **kwargs): return client.request('POST', url, **kwargs)
                    def request(client, *args, **kwargs):
                        client.calls += 1
                        if outcome == 'transport': raise RuntimeError('PRIVATE-TRANSPORT')
                        return SimpleNamespace(status_code=200 if outcome == 'both-success' else 409,
                                               json=lambda: {})
                    def close(client): client.closed = True
                qa = module.NativeQA.__new__(module.NativeQA)
                qa.session = SimpleNamespace(cookies={'session': 'PRIVATE'}, verify='/fixture-ca')
                qa.record = unittest.mock.Mock()
                with patch.dict(sys.modules, {'requests': SimpleNamespace(Session=Client)}):
                    with self.assertRaises((AssertionError, RuntimeError, ValueError)):
                        qa.policy_cas_race({'selection_id': 'before', 'selection_sha256': 'a' * 64})
                self.assertEqual(len(clients), 2)
                self.assertTrue(all(client.calls <= 1 and client.closed for client in clients))
                self.assertNotIn('PRIVATE', repr(qa.record.call_args_list))

    def test_native_policy_full_procedure_requires_real_actions_and_preserves_runtime_scope(self):
        module = self.native_module()
        self.assertTrue(hasattr(module.NativeQA, 'policy_before_update') and
                        hasattr(module.NativeQA, 'policy_after_update'),
                        'native control procedures must be executable, not empty proof labels')
        import copy
        for winner, fault in (('pin', None), ('refresh', None),
                              ('refresh', 'runtime-change'), ('pin', 'unrelated-change')):
            with self.subTest(winner=winner, fault=fault):
                qa = module.NativeQA.__new__(module.NativeQA)
                qa.layout = 'named-volume'
                qa.refs = {'ipmi-old': module.IPMI_OLD, 'ipmi-new': module.IPMI_NEW}
                state = {'serial': 0, 'mode': 'pinned', 'installed': '1.3.1', 'selected': '1.3.2',
                         'runtime': {'ipmi-monitor': 'original-ipmi', 'cryptolabs-proxy': 'original-proxy'},
                         'unrelated': {'grafana': 'original-pin', 'vast-price-manager': 'external-owner'}}
                events = []
                def listing():
                    return {'selection_id': 's-' + str(state['serial']),
                            'selection_sha256': hashlib.sha256(str(state['serial']).encode()).hexdigest(),
                            'components': {'ipmi-monitor': {'supported': True, 'mode': state['mode'],
                                'major': 1 if state['mode'] == 'follow-stable' else None,
                                'installed_release': state['installed'], 'selected_release': state['selected']}}}
                def snapshot():
                    return copy.deepcopy({'selection': listing()['selection_sha256'], 'policy': state['mode'],
                                          'runtime': state['runtime'], 'unrelated': state['unrelated']})
                def http(method, path, *, body=None, **kwargs):
                    if method == 'GET':
                        self.assertEqual(path, '/api/releases/policies')
                        return SimpleNamespace(status_code=200, json=listing)
                    self.assertEqual((method, path), ('POST', '/api/releases/policy-set'))
                    current = listing()
                    self.assertEqual(body['expected_selection_id'], current['selection_id'])
                    self.assertEqual(body['expected_selection_sha256'], current['selection_sha256'])
                    self.assertEqual(set(body), {'component', 'mode', 'expected_selection_id', 'expected_selection_sha256'})
                    self.assertEqual(body['component'], 'ipmi-monitor')
                    state['mode'] = body['mode']; state['serial'] += 1
                    if body['mode'] == 'pinned': state['selected'] = state['installed']
                    if fault == 'unrelated-change': state['unrelated']['grafana'] = 'changed-pin'
                    events.append(('mode', body['mode']))
                    value = listing()
                    return SimpleNamespace(status_code=200, json=lambda: value)
                def race(current):
                    self.assertEqual(current['selection_id'], listing()['selection_id'])
                    self.assertEqual((state['mode'], state['selected']), ('follow-stable', '1.3.1'))
                    state['serial'] += 1
                    if winner == 'refresh': state['selected'] = '1.3.3'
                    else: state.update(mode='pinned', selected='1.3.1')
                    events.append(('race', winner)); return winner
                def timer_prepare():
                    self.assertEqual(state['mode'], 'pinned', 'Persistent catch-up must run while pinned')
                    unchanged = snapshot()
                    # A catch-up refresh while pinned cannot advance selection.
                    self.assertEqual(snapshot(), unchanged)
                    events.append(('timer', 'prepared-and-quiesced'))
                def timer_refresh():
                    if state['mode'] == 'follow-stable':
                        state.update(selected='1.3.3', serial=state['serial'] + 1)
                    if fault == 'runtime-change': state['runtime']['ipmi-monitor'] = 'unexpected-restart'
                    events.append(('timer', 'refresh'))
                qa.http = http; qa.policy_listing = listing; qa.policy_state_snapshot = snapshot
                qa.policy_installed_version = unittest.mock.Mock(side_effect=lambda key: state['installed'])
                qa.policy_discovery_refusals = unittest.mock.Mock()
                qa.policy_lock_refusal = unittest.mock.Mock()
                qa.policy_cas_race = unittest.mock.Mock(side_effect=race)
                qa.policy_timer_prepare = unittest.mock.Mock(side_effect=timer_prepare)
                qa.policy_timer_refresh = unittest.mock.Mock(side_effect=timer_refresh)
                qa.record = unittest.mock.Mock()
                def command(*args, **kwargs):
                    self.assertEqual(args, ('systemctl', 'restart', module.SERVICE))
                    events.append(('broker', 'restart'))
                    return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
                with patch.object(module, 'run', side_effect=command):
                    if fault:
                        with self.assertRaises((AssertionError, RuntimeError, ValueError)):
                            qa.policy_before_update()
                    else:
                        qa.policy_before_update()
                        self.assertEqual((state['mode'], state['selected'], state['installed']),
                                         ('follow-stable', '1.3.3', '1.3.1'))
                        qa.policy_discovery_refusals.assert_called_once()
                        qa.policy_lock_refusal.assert_called_once()
                        qa.policy_cas_race.assert_called_once()
                        qa.policy_timer_prepare.assert_called_once()
                        self.assertIn(('broker', 'restart'), events)
                        self.assertEqual(state['runtime']['ipmi-monitor'], 'original-ipmi')
                        self.assertEqual(state['unrelated']['grafana'], 'original-pin')
                        # The original native manual flow, outside these policy
                        # procedures, is the sole operation that changes runtime.
                        state['installed'] = '1.3.3'
                        state['runtime']['ipmi-monitor'] = 'manually-updated-ipmi'
                        qa.policy_after_update()
                        self.assertEqual((state['mode'], state['selected']), ('pinned', '1.3.3'))
                        self.assertEqual(state['runtime']['ipmi-monitor'], 'manually-updated-ipmi')
                        self.assertEqual(state['runtime']['cryptolabs-proxy'], 'original-proxy')
                        self.assertEqual(state['unrelated']['grafana'], 'original-pin')
                        self.assertEqual(qa.policy_timer_refresh.call_count, 2)
                        self.assertEqual(qa.policy_installed_version.call_args_list,
                                         [unittest.mock.call('ipmi-old'), unittest.mock.call('ipmi-new')])

    def test_native_policy_timer_prepare_runs_packaged_cli_pinned_then_quiesces_owned_units(self):
        module = self.native_module()
        self.assertTrue(hasattr(module.NativeQA, 'policy_timer_prepare') and
                        hasattr(module, 'POLICY_REFRESH_SYSTEMD'))
        import stat
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); names = ('dc-overview-release-refresh.service', 'dc-overview-release-refresh.timer')
            qa = module.NativeQA.__new__(module.NativeQA)
            qa.args = SimpleNamespace(dc_source=ROOT)
            qa.units = []; qa.record = unittest.mock.Mock()
            qa.policy_listing = lambda: {'components': {'ipmi-monitor': {'mode': 'pinned'}}}
            qa.policy_state_snapshot = lambda: {'policy': 'pinned', 'selection': 'old', 'runtime': 'unchanged'}
            live = {'timer': False, 'service': False, 'installer_calls': 0}
            calls = []; cli = str(Path(module.sys.executable).parent / 'dc-overview')
            actual_lstat, actual_fstat = os.lstat, os.fstat
            def root_metadata(info):
                values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
                values.update(st_uid=0, st_gid=0)
                if stat.S_ISDIR(info.st_mode): values['st_mode'] = stat.S_IFDIR | 0o755
                return SimpleNamespace(**values)
            def command(*args, **kwargs):
                arguments = tuple(map(str, args)); calls.append(arguments)
                if arguments == (cli, 'release', 'policy-install-timer'):
                    self.assertEqual(qa.policy_listing()['components']['ipmi-monitor']['mode'], 'pinned')
                    live['installer_calls'] += 1
                    for name in names:
                        raw = (ROOT / 'src/dc_overview/templates/systemd' / name).read_text()
                        path = root / name; path.write_text(raw.replace('@RELEASE_CLI@', cli)); path.chmod(0o600)
                    # Model systemd's Persistent catch-up on enable. It happens
                    # before FOLLOW, so the pinned selection remains untouched.
                    live['timer'] = True
                elif arguments[:2] == ('systemctl', 'show'):
                    return SimpleNamespace(returncode=0, stderr=b'', stdout=(
                        b'ActiveState=active\nUnitFileState=enabled\nPersistent=yes\n'
                        b'NextElapseUSecRealtime=Sat 2026-11-07 00:05:00 UTC\n'))
                elif arguments == ('systemctl', 'disable', '--now', names[1]): live['timer'] = False
                elif arguments == ('systemctl', 'stop', names[0]): live['service'] = False
                elif arguments[:2] == ('systemctl', 'is-active'):
                    active = live['timer'] if arguments[2] == names[1] else live['service']
                    return SimpleNamespace(returncode=0 if active else 3,
                                           stdout=b'active\n' if active else b'inactive\n', stderr=b'')
                elif arguments[:2] == ('systemctl', 'is-enabled'):
                    return SimpleNamespace(returncode=0 if live['timer'] else 1,
                        stdout=b'enabled\n' if live['timer'] else b'disabled\n', stderr=b'')
                elif arguments[:2] == ('systemd-analyze', 'verify'):
                    self.assertEqual(set(arguments[2:]), {str(root / name) for name in names})
                else: self.fail('unreviewed timer command: ' + repr(arguments))
                return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
            with patch.object(module, 'POLICY_REFRESH_SYSTEMD', root), \
                 patch.object(module.os, 'lstat', side_effect=lambda *a, **kw: root_metadata(actual_lstat(*a, **kw))), \
                 patch.object(module.os, 'fstat', side_effect=lambda *a, **kw: root_metadata(actual_fstat(*a, **kw))), \
                 patch.object(module, 'run', side_effect=command):
                qa.policy_timer_prepare()
            self.assertEqual(live['installer_calls'], 1)
            self.assertFalse(live['timer']); self.assertFalse(live['service'])
            self.assertTrue(qa.policy_timer_attempted)
            self.assertEqual(set(qa.policy_timer_record['files']), {str(root / name) for name in names})
            self.assertTrue({root / name for name in names} <= set(qa.units))
            for name in names:
                path = root / name; info = path.lstat(); recorded = qa.policy_timer_record['files'][str(path)]
                self.assertEqual(recorded, {'sha256': module.digest(path.read_bytes()),
                                           'device': info.st_dev, 'inode': info.st_ino})
            self.assertIn(('systemctl', 'disable', '--now', names[1]), calls)

    def test_native_policy_timer_refresh_executes_fixed_oneshot_without_http_or_retry(self):
        module = self.native_module()
        self.assertTrue(hasattr(module.NativeQA, 'policy_timer_refresh'),
                        'headless proof must execute the real packaged service')
        unit = 'dc-overview-release-refresh.service'
        for fault in (None, 'enabled', 'active', 'unknown', 'start-failure',
                      'result-failure', 'missing-status', 'still-active'):
            with self.subTest(fault=fault):
                qa = module.NativeQA.__new__(module.NativeQA)
                qa.record = unittest.mock.Mock()
                qa.http = unittest.mock.Mock(side_effect=AssertionError('HTTP substitution forbidden'))
                qa.policy_listing = unittest.mock.Mock(side_effect=AssertionError('HTTP listing forbidden here'))
                calls = []
                def quiesce():
                    calls.append(('quiesce',))
                    if fault in ('enabled', 'active', 'unknown'):
                        raise RuntimeError('PRIVATE-UNCERTAIN-UNIT')
                qa.policy_timer_quiesce = unittest.mock.Mock(side_effect=quiesce)
                def command(*args, **kwargs):
                    calls.append(args)
                    if args == ('systemctl', 'start', unit):
                        if fault == 'start-failure': raise RuntimeError('PRIVATE-START-FAILURE')
                        return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
                    self.assertEqual(args[:3], ('systemctl', 'show', unit))
                    fields = {'Id': unit, 'ActiveState': 'inactive', 'SubState': 'dead',
                              'MainPID': '0', 'Result': 'success', 'ExecMainStatus': '0'}
                    if fault == 'result-failure': fields.update(Result='exit-code', ExecMainStatus='1')
                    if fault == 'missing-status': del fields['ExecMainStatus']
                    if fault == 'still-active': fields.update(ActiveState='active', SubState='running', MainPID='123')
                    return SimpleNamespace(returncode=0, stderr=b'',
                        stdout=('\n'.join(name + '=' + value for name, value in fields.items()) + '\n').encode())
                with patch.object(module, 'run', side_effect=command):
                    if fault:
                        with self.assertRaises((AssertionError, RuntimeError, ValueError)):
                            qa.policy_timer_refresh()
                    else:
                        qa.policy_timer_refresh()
                self.assertEqual(calls[0], ('quiesce',))
                qa.policy_timer_quiesce.assert_called_once()
                starts = [call for call in calls if call[:2] == ('systemctl', 'start')]
                self.assertEqual(len(starts), 0 if fault in ('enabled', 'active', 'unknown') else 1)
                qa.http.assert_not_called(); qa.policy_listing.assert_not_called()
                self.assertNotIn('PRIVATE', repr(qa.record.call_args_list))

    def test_native_policy_snapshot_is_sensitive_to_real_identity_and_pin_changes(self):
        module = self.native_module()
        self.assertTrue(hasattr(module.NativeQA, 'policy_state_snapshot'),
                        'a constant projection cannot prove no restart or pin preservation')
        import copy
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); store_root = root / 'releases'
            policy = store_root / 'broker/policy-state.json'; policy.parent.mkdir(parents=True)
            policy.write_bytes(b'{"schema_version":1,"components":{}}\n'); policy.chmod(0o600)
            current = SimpleNamespace(selection_sha256='a' * 64,
                manifest=SimpleNamespace(data={'components': {'ipmi-monitor': {'release': '1.3.1'},
                    'grafana': {'release': 'pinned'}, 'vast-price-manager': {'release': 'external'}}}),
                selection={'components': {'ipmi-monitor': {'origin': 'baseline'},
                    'grafana': {'origin': 'customer-pin', 'pin': 'g' * 64},
                    'vast-price-manager': {'origin': 'unmanaged'}}})
            records = {}
            for number, name, running in ((1, 'ipmi-monitor', True), (2, 'cryptolabs-proxy', True),
                                          (3, 'native-fleet-registry', True), (4, 'owned-initializer', False)):
                identity = str(number) * 64
                records[identity] = {'Id': identity, 'Name': '/' + name,
                    'Image': 'sha256:' + str(number + 4) * 64,
                    'State': {'Running': running, 'StartedAt': '2026-11-06T00:00:00Z'},
                    'Config': {'Env': ['PRIVATE=must-not-be-projected']}}
            qa = module.NativeQA.__new__(module.NativeQA)
            qa.store = SimpleNamespace(root=store_root)
            qa.selection = lambda: current
            inventory = list(records)
            def engine(*args, **kwargs):
                self.assertEqual(args, ('ps', '-aq', '--no-trunc'))
                return SimpleNamespace(returncode=0, stdout=('\n'.join(inventory) + '\n').encode(), stderr=b'')
            def inspecting(identity, **kwargs):
                self.assertIn(identity, records)
                return copy.deepcopy(records[identity])
            with patch.object(module, 'CONFIG', root), patch.object(module, 'docker', side_effect=engine), \
                 patch.object(module, 'inspect', side_effect=inspecting) as read:
                baseline = qa.policy_state_snapshot()
                self.assertEqual(set(baseline), {'selection', 'policy', 'runtime', 'unrelated'})
                self.assertEqual(baseline, qa.policy_state_snapshot())
                self.assertEqual(len(baseline['runtime']), 4, 'include registry and stopped fixture objects')
                self.assertNotIn('PRIVATE', json.dumps(baseline))
                for number, field, changed in ((1, 'Id', '9' * 64), (1, 'Image', 'sha256:' + 'f' * 64),
                                               (1, 'StartedAt', '2026-11-06T00:01:00Z'), (1, 'Running', False),
                                               (2, 'Id', '8' * 64), (3, 'Id', '7' * 64)):
                    identity = str(number) * 64; original = copy.deepcopy(records[identity])
                    if field in ('StartedAt', 'Running'): records[identity]['State'][field] = changed
                    else: records[identity][field] = changed
                    try:
                        # A mismatched inspected ID may be refused instead of
                        # yielding a snapshot; it must never equal the baseline.
                        try: observed = qa.policy_state_snapshot()
                        except (AssertionError, RuntimeError, ValueError): observed = None
                        self.assertNotEqual(observed, baseline)
                    finally: records[identity] = original
                for mapping, name, value in ((current.manifest.data['components']['grafana'], 'release', 'changed'),
                    (current.selection['components']['grafana'], 'pin', 'changed')):
                    old = mapping[name]; mapping[name] = value
                    self.assertNotEqual(qa.policy_state_snapshot(), baseline); mapping[name] = old
                current.selection_sha256 = 'b' * 64
                self.assertNotEqual(qa.policy_state_snapshot(), baseline)
                current.selection_sha256 = 'a' * 64
                original_component = copy.deepcopy(current.manifest.data['components']['ipmi-monitor'])
                current.manifest.data['components']['ipmi-monitor']['release'] = '1.3.3'
                self.assertEqual(qa.policy_state_snapshot()['unrelated'], baseline['unrelated'])
                current.manifest.data['components']['ipmi-monitor'] = original_component
                policy.write_bytes(b'{"schema_version":1,"components":{"ipmi-monitor":{"mode":"follow-stable","major":1}}}\n')
                self.assertNotEqual(qa.policy_state_snapshot(), baseline)
                policy.unlink()
                self.assertNotEqual(qa.policy_state_snapshot(), baseline)
                self.assertNotIn('PRIVATE', json.dumps(baseline), 'retained snapshots must be detached from later state')
                read.reset_mock(); inventory[:] = ['f' * 64] * 65
                with self.assertRaises((AssertionError, RuntimeError, ValueError)):
                    qa.policy_state_snapshot()
                read.assert_not_called()
                for invalid in (['not-an-id'], ['1' * 64, '1' * 64]):
                    inventory[:] = invalid; read.reset_mock()
                    with self.assertRaises((AssertionError, RuntimeError, ValueError)):
                        qa.policy_state_snapshot()
                    read.assert_not_called()


    def test_native_policy_cleanup_preserves_unproven_timer_files_and_continues_independent_cleanup(self):
        module = self.native_module()
        import stat
        for fault in (None, 'changed-bytes', 'changed-inode', 'unknown-record'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); systemd = root / 'systemd'; systemd.mkdir()
                work = root / 'work'; work.mkdir()
                paths = [systemd / ('dc-overview-release-refresh.' + suffix) for suffix in ('service', 'timer')]
                files = {}
                for path in paths:
                    path.write_bytes(('owned ' + path.name).encode()); path.chmod(0o600)
                    info = path.lstat()
                    files[str(path)] = {'sha256': module.digest(path.read_bytes()),
                                       'device': info.st_dev, 'inode': info.st_ino}
                if fault == 'changed-bytes': paths[0].write_bytes(b'replaced unproven service')
                if fault == 'changed-inode': files[str(paths[0])]['inode'] += 1
                retained = {path: path.read_bytes() for path in paths}
                broker = systemd / module.SERVICE; broker.write_bytes(b'independently owned broker')
                qa = module.NativeQA.__new__(module.NativeQA)
                qa.units = [broker, *paths]
                qa.label = 'io.cryptolabs.native-qa=fixture'
                qa.hosts = None; qa.registry_ca_file = None
                qa.policy_timer_attempted = True; qa.policy_timer_quiesced = False
                qa.policy_timer_record = None if fault == 'unknown-record' else {'files': files}
                qa.reset_fixture = lambda: qa.policy_timer_quiesce()
                qa.restore_registry_trust = unittest.mock.Mock()
                qa.remove_registry_ca = unittest.mock.Mock()
                qa.record = unittest.mock.Mock()
                actual_lstat, actual_fstat = os.lstat, os.fstat
                def root_metadata(info):
                    # Offline owner/directory-mode projection; real file bytes,
                    # device/inode and replacement/refusal observations remain.
                    values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
                    values.update(st_uid=0, st_gid=0)
                    if stat.S_ISDIR(info.st_mode): values['st_mode'] = stat.S_IFDIR | 0o755
                    return SimpleNamespace(**values)
                commands = []
                def command(*args, **kwargs):
                    commands.append(args)
                    self.assertEqual(args[0], 'systemctl')
                    if args[1] == 'is-active': return SimpleNamespace(returncode=3, stdout=b'inactive\n', stderr=b'')
                    if args[1] == 'is-enabled': return SimpleNamespace(returncode=1, stdout=b'disabled\n', stderr=b'')
                    self.assertIn(args[1], ('disable', 'stop', 'daemon-reload'))
                    return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
                def engine(*args, **kwargs):
                    self.assertIn(args, (('ps', '-aq', '--filter', 'name=^/native-fleet-registry$'),
                        ('ps', '-aq', '--filter', 'label=' + qa.label)))
                    return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
                def fixture_path(*args):
                    value = Path(*args)
                    return root / 'absent-cli-link' if str(value) == '/usr/local/bin/dc-overview' else value
                with patch.object(module, 'ROOT', work), patch.object(module, 'POLICY_REFRESH_SYSTEMD', systemd), \
                     patch.object(module, 'Path', side_effect=fixture_path), \
                     patch.object(module.os, 'lstat', side_effect=lambda *a, **kw: root_metadata(actual_lstat(*a, **kw))), \
                     patch.object(module.os, 'fstat', side_effect=lambda *a, **kw: root_metadata(actual_fstat(*a, **kw))), \
                     patch.object(module, 'run', side_effect=command), patch.object(module, 'docker', side_effect=engine):
                    if fault:
                        with self.assertRaises(RuntimeError): qa.cleanup()
                    else:
                        qa.cleanup()
                self.assertFalse(broker.exists(), 'independent original cleanup must continue')
                if fault:
                    for path, content in retained.items():
                        self.assertTrue(path.exists(), 'custody refusal must retain the unproven unit')
                        self.assertEqual(path.read_bytes(), content)
                    self.assertFalse(qa.policy_timer_quiesced)
                    qa.restore_registry_trust.assert_not_called()
                    self.assertFalse(any(call[1] in ('disable', 'stop') for call in commands))
                else:
                    self.assertTrue(all(not path.exists() for path in paths))
                    qa.restore_registry_trust.assert_called_once()


if __name__ == "__main__":
    unittest.main()
