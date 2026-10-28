# TRACEWEAVER: file-role=native-route-verification; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
# TRACEWEAVER: verifies=VER-FLEETUPDATE-001; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001
"""Bounded security contract for the explicit native QA route; no guest execution."""

import ast
import importlib.util
import json
import os
import subprocess
import tempfile
import tomllib
import traceback
import unittest
from contextlib import contextmanager, nullcontext
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


class FleetNativeRouteTest(unittest.TestCase):
    def native_module(self):
        spec = importlib.util.spec_from_file_location("fleet_native_diagnostics", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

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
        self.assertEqual(pin, "5db15086c26095179f2af56bfa434c85426a6699")
        preflight = next(
            i for i, s in enumerate(job["steps"]) if s.get("name") == "Reject unresolved source pin"
        )
        self.assertLess(preflight, job["steps"].index(checkouts[1]))
        self.assertIn("--check-inputs-only", job["steps"][preflight]["run"])
        self.assertEqual(checkouts[1]["with"]["ref"], "${{ env.PROXY_SOURCE_SHA }}")

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
