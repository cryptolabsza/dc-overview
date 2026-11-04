# TRACEWEAVER: file-role=native-route-verification; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
# TRACEWEAVER: verifies=VER-FLEETUPDATE-001; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001
"""Bounded security contract for the explicit native QA route; no guest execution."""

import ast
import importlib.util
import hashlib
import json
import os
import runpy
import selectors
import subprocess
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
                    "CREATE TABLE cloud_sync(id INTEGER PRIMARY KEY,license_key TEXT,sync_enabled INTEGER,subscription_valid INTEGER)",
                    "CREATE TABLE server(id INTEGER PRIMARY KEY,bmc_ip TEXT,server_name TEXT,status TEXT,updated_at TEXT)",
                    "CREATE TABLE server_status(bmc_ip TEXT PRIMARY KEY,server_name TEXT,last_check TEXT)",
                ):
                    db.execute(sql)
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
        with tempfile.TemporaryDirectory() as directory:
            qa = module.NativeQA(SimpleNamespace(evidence_dir=Path(directory)))
            cleaned = []
            def failed_fixture(layout):
                raise RuntimeError("PRIVATE_BOOTSTRAP_FAILURE")
            with patch.object(qa, "preflight"), patch.object(qa, "images"), patch.object(qa, "units_install"), patch.object(qa, "fixture", side_effect=failed_fixture), patch.object(qa, "cleanup", side_effect=lambda: cleaned.append(True)), patch.object(module, "native_phase_failure_metadata", side_effect=RuntimeError("PRIVATE_COLLECTOR_FAILURE")):
                with self.assertRaisesRegex(RuntimeError, "^native verification failed; native gate held$"):
                    qa.execute()
            self.assertEqual(cleaned, [True])
            event = next(event for event in qa.events if event["case"] == "native-flow")
            self.assertEqual(event["result"], "failed")
            self.assertEqual(event["phase"], "fixture")
            self.assertNotIn("PRIVATE", json.dumps(qa.events))

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
            root = Path(d)
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
            operation = {"schema_version": 1, "operation_id": identity, "state": "recovery-required", "phase": "owner",
                         "reason": "Owner operation interrupted; reconcile retained operation before retry",
                         "manifest": "PRIVATE_MANIFEST", "request": {"private": "PRIVATE_REQUEST"}}
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
                if release_broker is not None:
                    guards.enter_context(patch.multiple(release_broker.InstalledOwner, **{name: unittest.mock.Mock(side_effect=forbidden) for name in ("capabilities", "identity", "submit", "status", "recover", "adopt")}))
                    guards.enter_context(patch.object(release_broker.ReleaseBroker, "dispatch", side_effect=forbidden))
                    guards.enter_context(patch.object(release_broker.ReleaseBroker, "run_operation", side_effect=forbidden))
                before = {p: p.read_bytes() for p in (path, mapped)}
                value = qa.owner_mapping_observation(identity)
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
                for content in (b"{", b"x" * 1048577, module.encoded({**operation, "operation_id": "00000000-0000-4000-8000-000000000002"})):
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
        if pin != "ROOT_MUST_SET_REVIEWED_RECOVERY_PROXY_SHA":
            self.assertRegex(pin, r"^[a-f0-9]{40}$")
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


if __name__ == "__main__":
    unittest.main()
