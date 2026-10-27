# TRACEWEAVER: file-role=native-route-verification; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
# TRACEWEAVER: verifies=VER-FLEETUPDATE-001; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001
"""Bounded security contract for the explicit native QA route; no guest execution."""

import importlib.util
import subprocess
import tempfile
import traceback
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/fleet-release-native-qa.yml"
SCRIPT = ROOT / "scripts/verify_fleet_release_native.py"


class FleetNativeRouteTest(unittest.TestCase):
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
        self.assertEqual(pin, "3b1ff8e4a71da0b0392c976c1fe8c5aa5bfbc002")
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
        # Narrow command/file boundary regressions, not an Engine integration claim.
        with tempfile.TemporaryDirectory() as directory:
            instance = module.NativeQA(SimpleNamespace(evidence_dir=Path(directory)))
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
                self.assertIn('"result":"failed"', (Path(directory) / "results.json").read_text())
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
            with self.subTest("early preflight failure emits red evidence without fixture cleanup"):
                early = module.NativeQA(SimpleNamespace(evidence_dir=Path(directory) / "early"))
                early.preflight = unittest.mock.Mock(
                    side_effect=RuntimeError("occupied fixture path")
                )
                early.cleanup = unittest.mock.Mock()
                early.images = unittest.mock.Mock()
                with self.assertRaisesRegex(RuntimeError, "occupied fixture"):
                    early.execute()
                early.images.assert_not_called()
                early.cleanup.assert_not_called()
                result = (early.evidence / "results.json").read_text()
                self.assertIn('"result":"failed"', result)
                self.assertIn("occupied fixture path", result)


if __name__ == "__main__":
    unittest.main()
