"""Tests for reusable Grafana fleet alert provisioning."""

import shutil
import stat
import subprocess
from unittest.mock import MagicMock, patch

import pytest
import requests
import yaml
from click.testing import CliRunner

from dc_overview.cli import _sync_alerts_for_upgrade, main
from dc_overview.fleet_config import FleetConfig
from dc_overview.fleet_manager import FleetManager
from dc_overview.grafana_alerts import (
    ALERT_RULES_FILENAME,
    MANAGED_ALERT_UIDS,
    NOTIFICATION_TEMPLATE_FILENAME,
    NOTIFICATION_TEMPLATE_NAME,
    DuplicateManagedAlertError,
    GrafanaReceiverError,
    configure_grafana_telegram_receiver,
    install_grafana_alerts,
    reload_grafana_alerts,
    render_grafana_alerts,
    sync_grafana_alerts,
)
from dc_overview.templates import generate_docker_compose, setup_grafana_provisioning


def _rule(rendered: str, uid: str) -> dict:
    document = yaml.safe_load(rendered)
    rules = [
        rule
        for group in document["groups"]
        for rule in group["rules"]
    ]
    return next(rule for rule in rules if rule["uid"] == uid)


def _query_expression(rule: dict, ref_id: str = "A") -> str:
    query = next(query for query in rule["data"] if query["refId"] == ref_id)
    return query["model"]["expr"]


def _write_alert_rules(path, *uids: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": 1,
                "groups": [
                    {
                        "orgId": 1,
                        "name": "Existing alerts",
                        "folder": "Infrastructure Alerts",
                        "interval": "1m",
                        "rules": [{"uid": uid, "title": uid} for uid in uids],
                    }
                ],
            },
            sort_keys=False,
        )
    )


def _set_rule_receiver(path, receiver: str) -> None:
    document = yaml.safe_load(path.read_text())
    for group in document.get("groups", []):
        for rule in group.get("rules", []):
            rule["notification_settings"] = {
                "receiver": receiver,
                "group_wait": "0s",
            }
    path.write_text(yaml.safe_dump(document, sort_keys=False))


def _uids(path) -> set[str]:
    document = yaml.safe_load(path.read_text())
    return {
        rule["uid"]
        for group in document.get("groups", [])
        for rule in group.get("rules", [])
    }


class TestGrafanaAlertRendering:
    def test_thermal_alert_is_gated_by_healthy_telemetry_and_hardware_state(self):
        rendered = render_grafana_alerts(instance_matcher=r"gpu-node-.+")
        rule = _rule(rendered, "fleet-gpu-thermal-slowdown")
        expression = _query_expression(rule)

        assert 'instance=~"gpu-node-.+"' in expression
        assert "DCGM_FI_DEV_CLOCKS_THROTTLE_REASON" in expression
        assert "DCGM_FI_DEV_GPU_TEMP" in expression
        assert "group_left()" in expression
        assert "DCXP_GPU_STATE" in expression
        assert "DCXP_GPU_HW_FAILURE" in expression
        assert "DCXP_GPU_FALLEN_OFF_BUS" not in expression
        assert "unless on(instance, gpu, UUID, pci_bus_id)" not in expression
        assert "RunpodCCC" not in rendered

    def test_thermal_alert_reports_the_current_joined_core_temperature(self):
        rule = _rule(render_grafana_alerts(), "fleet-gpu-thermal-slowdown")
        annotations = " ".join(rule["annotations"].values())

        assert "$values.A.Value" in annotations
        assert "°C" in annotations
        assert "core temperature" in annotations.lower()

    def test_hardware_alert_is_immediate_and_explains_telemetry_is_invalid(self):
        rule = _rule(render_grafana_alerts(), "fleet-gpu-hardware-failure")
        usable_expression = _query_expression(rule, "A")
        total_expression = _query_expression(rule, "B")
        annotations = " ".join(rule["annotations"].values())

        assert rule["for"] == "0s"
        assert "DCXP_GPU_HW_FAILURE" in usable_expression
        assert 'DCXP_GPU_COUNT{type="usable"}' in usable_expression
        assert 'DCXP_GPU_COUNT{type="pcie"}' in total_expression
        assert usable_expression.partition("*")[0] == total_expression.partition("*")[0]
        assert "usable" in annotations.lower()
        assert "temperature unavailable" in annotations.lower()
        assert "$values.A.Value" in annotations
        assert "$values.B.Value" in annotations

    def test_partial_nvml_inventory_mismatch_is_immediate_but_full_timeout_is_not(self):
        rule = _rule(render_grafana_alerts(), "fleet-gpu-inventory-mismatch")
        usable_expression = _query_expression(rule, "A")
        total_expression = _query_expression(rule, "B")
        annotations = " ".join(rule["annotations"].values()).lower()

        assert rule["for"] == "0s"
        assert "DCXP_GPU_STATE" in usable_expression
        assert 'UUID="DRIVER-ERROR"' in usable_expression
        assert "== 2" in usable_expression
        assert 'DCXP_GPU_COUNT{type="nvml"} > 0' in usable_expression
        assert (
            'DCXP_GPU_COUNT{type="nvml"}\n'
            '      < on(instance, Hostname)\n'
            '      DCXP_GPU_COUNT{type="pcie"}'
        ) in usable_expression
        assert 'DCXP_GPU_COUNT{type="usable"}' in usable_expression
        assert 'DCXP_GPU_COUNT{type="pcie"}' in total_expression
        assert "DCXP_GPU_HW_FAILURE" not in usable_expression
        assert "inventory" in annotations
        assert "usable" in annotations
        assert "temperature unavailable" in annotations
        assert "hardware failure" not in annotations
        assert "fleet-gpu-inventory-mismatch" in MANAGED_ALERT_UIDS

    @pytest.mark.skipif(shutil.which("promtool") is None, reason="promtool unavailable")
    def test_promtool_inventory_mismatch_selects_only_missing_gpu_placeholder(
        self, tmp_path
    ):
        expression = _query_expression(
            _rule(render_grafana_alerts(), "fleet-gpu-inventory-mismatch"),
            "A",
        )
        fixture = {
            "evaluation_interval": "1m",
            "tests": [
                {
                    "interval": "1m",
                    "input_series": [
                        {
                            "series": (
                                'DCXP_GPU_STATE{Hostname="runpodccc95",'
                                'UUID="DRIVER-ERROR",gpu="7",instance="RunpodCCC95",'
                                'pci_bus_id="0000:e1:00.0"}'
                            ),
                            "values": "2",
                        },
                        {
                            "series": (
                                'DCXP_GPU_STATE{Hostname="runpodccc95",UUID="GPU-PRESENT",'
                                'gpu="3",instance="RunpodCCC95",'
                                'pci_bus_id="0000:41:00.0"}'
                            ),
                            "values": "2",
                        },
                        {
                            "series": (
                                'DCXP_GPU_COUNT{Hostname="runpodccc95",'
                                'instance="RunpodCCC95",type="nvml"}'
                            ),
                            "values": "7",
                        },
                        {
                            "series": (
                                'DCXP_GPU_COUNT{Hostname="runpodccc95",'
                                'instance="RunpodCCC95",type="pcie"}'
                            ),
                            "values": "8",
                        },
                        {
                            "series": (
                                'DCXP_GPU_COUNT{Hostname="runpodccc95",'
                                'instance="RunpodCCC95",type="usable"}'
                            ),
                            "values": "6",
                        },
                    ],
                    "promql_expr_test": [
                        {
                            "expr": expression,
                            "eval_time": "0m",
                            "exp_samples": [
                                {
                                    "labels": (
                                        '{Hostname="runpodccc95",UUID="DRIVER-ERROR",'
                                        'gpu="7",instance="RunpodCCC95",'
                                        'pci_bus_id="0000:e1:00.0"}'
                                    ),
                                    "value": 6,
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        fixture_path = tmp_path / "inventory-promql.test.yml"
        fixture_path.write_text(yaml.safe_dump(fixture, sort_keys=False))

        result = subprocess.run(
            ["promtool", "test", "rules", str(fixture_path)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, result.stdout + result.stderr

    def test_receiver_is_optional_and_configurable(self):
        without_receiver = _rule(render_grafana_alerts(), "fleet-gpu-hardware-failure")
        with_receiver = _rule(
            render_grafana_alerts(receiver="Site Telegram"),
            "fleet-gpu-hardware-failure",
        )

        assert "notification_settings" not in without_receiver
        assert with_receiver["notification_settings"]["receiver"] == "Site Telegram"

    @pytest.mark.skipif(shutil.which("promtool") is None, reason="promtool unavailable")
    def test_promtool_evaluates_thermal_join_to_live_temperature(self, tmp_path):
        expression = _query_expression(
            _rule(render_grafana_alerts(), "fleet-gpu-thermal-slowdown")
        )
        identity = (
            'Hostname="runpodccc95",UUID="GPU-1",gpu="1",'
            'instance="RunpodCCC95",pci_bus_id="0000:23:00.0"'
        )
        fixture = {
            "evaluation_interval": "1m",
            "tests": [
                {
                    "interval": "1m",
                    "input_series": [
                        {
                            "series": (
                                "DCGM_FI_DEV_CLOCKS_THROTTLE_REASON{"
                                f'{identity},reason="HwThermalSlowdown"'
                                "}"
                            ),
                            "values": "1 1 1",
                        },
                        {
                            "series": f"DCGM_FI_DEV_GPU_TEMP{{{identity}}}",
                            "values": "78 79 80",
                        },
                        {
                            "series": f"DCXP_GPU_STATE{{{identity}}}",
                            "values": "1 2 1",
                        },
                        {
                            "series": (
                                "DCXP_GPU_HW_FAILURE{"
                                f'{identity},failure_reason="none"'
                                "}"
                            ),
                            "values": "0 0 1",
                        },
                    ],
                    "promql_expr_test": [
                        {
                            "expr": expression,
                            "eval_time": "0m",
                            "exp_samples": [
                                {
                                    "labels": (
                                        "{"
                                        f'{identity},reason="HwThermalSlowdown"'
                                        "}"
                                    ),
                                    "value": 78,
                                }
                            ],
                        },
                        {
                            "expr": expression,
                            "eval_time": "1m",
                            "exp_samples": [],
                        },
                        {
                            "expr": expression,
                            "eval_time": "2m",
                            "exp_samples": [],
                        },
                    ],
                }
            ],
        }
        fixture_path = tmp_path / "thermal-promql.test.yml"
        fixture_path.write_text(yaml.safe_dump(fixture, sort_keys=False))

        result = subprocess.run(
            ["promtool", "test", "rules", str(fixture_path)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, result.stdout + result.stderr


class TestGrafanaAlertInstallation:
    def test_installer_creates_canonical_alerting_file(self, tmp_path):
        path = install_grafana_alerts(
            tmp_path,
            instance_matcher="client-gpu-.+",
            receiver="Client Notifications",
        )

        assert path == (
            tmp_path / "grafana" / "provisioning" / "alerting" / ALERT_RULES_FILENAME
        )
        assert path.exists()
        rendered = path.read_text()
        assert 'instance=~"client-gpu-.+"' in _query_expression(
            _rule(rendered, "fleet-gpu-thermal-slowdown")
        )

    def test_installed_alert_file_is_readable_by_non_root_grafana(self, tmp_path):
        path = install_grafana_alerts(tmp_path)

        assert stat.S_IMODE(path.stat().st_mode) == 0o644

    def test_installer_provisions_a_concise_reusable_notification_template(self, tmp_path):
        install_grafana_alerts(tmp_path)

        template_path = (
            tmp_path
            / "grafana"
            / "provisioning"
            / "alerting"
            / NOTIFICATION_TEMPLATE_FILENAME
        )
        document = yaml.safe_load(template_path.read_text())
        content = document["templates"][0]["template"]

        assert document["templates"][0]["name"] == "dc-overview-notifications"
        assert f'{{{{ define "{NOTIFICATION_TEMPLATE_NAME}" }}}}' in content
        assert "🔴" in content
        assert "🟢" in content
        assert ".Annotations.summary" in content
        assert ".Annotations.description" in content
        assert ".Alerts.Firing" in content
        assert ".Alerts.Resolved" in content
        assert '.Status "firing"' not in content
        for noisy_default in (".Values", ".Labels", ".GeneratorURL", ".SilenceURL"):
            assert noisy_default not in content
        assert stat.S_IMODE(template_path.stat().st_mode) == 0o644

    @patch("dc_overview.grafana_alerts.os.chown")
    def test_reinstall_preserves_existing_file_ownership_where_permitted(
        self, mock_chown, tmp_path
    ):
        target = install_grafana_alerts(tmp_path)
        original = target.stat()
        mock_chown.reset_mock()

        install_grafana_alerts(tmp_path)

        assert any(
            call.args[1:] == (original.st_uid, original.st_gid)
            for call in mock_chown.call_args_list
        )

    def test_installer_refuses_managed_uid_in_another_provisioning_file(self, tmp_path):
        legacy = (
            tmp_path / "grafana" / "provisioning" / "alerting" / "fleet-alerts.yml"
        )
        _write_alert_rules(legacy, "fleet-gpu-thermal-slowdown", "unrelated-alert")

        with pytest.raises(DuplicateManagedAlertError, match="fleet-alerts.yml"):
            install_grafana_alerts(tmp_path)

        assert not legacy.with_name(ALERT_RULES_FILENAME).exists()

    def test_reinstalling_the_canonical_file_is_idempotent(self, tmp_path):
        first = install_grafana_alerts(tmp_path, receiver="Site Telegram")
        first_content = first.read_text()

        second = install_grafana_alerts(tmp_path, receiver="Site Telegram")

        assert second == first
        assert second.read_text() == first_content

    def test_general_grafana_setup_installs_alert_rules(self, tmp_path):
        setup_grafana_provisioning(tmp_path, receiver="Site Telegram")

        alert_path = (
            tmp_path / "grafana" / "provisioning" / "alerting" / ALERT_RULES_FILENAME
        )
        assert alert_path.exists()
        assert (
            _rule(alert_path.read_text(), "fleet-gpu-hardware-failure")
            ["notification_settings"]["receiver"]
            == "Site Telegram"
        )

    def test_legacy_compose_mounts_installed_alert_provisioning(self, tmp_path):
        compose = generate_docker_compose(tmp_path)

        assert (
            "./grafana/provisioning/alerting:"
            "/etc/grafana/provisioning/alerting:ro"
        ) in compose

    def test_generate_compose_cli_populates_its_mounted_alert_directory(self, tmp_path):
        config_dir = tmp_path / "config"
        output = tmp_path / "deployment" / "docker-compose.yml"
        output.parent.mkdir()

        result = CliRunner().invoke(
            main,
            ["generate-compose", "--output", str(output)],
            env={"DC_OVERVIEW_CONFIG": str(config_dir)},
        )

        assert result.exit_code == 0, result.output
        alert_file = (
            output.parent
            / "grafana"
            / "provisioning"
            / "alerting"
            / ALERT_RULES_FILENAME
        )
        assert alert_file.exists()
        assert "./grafana/provisioning/alerting:" in output.read_text()


class TestGrafanaAlertReload:
    @patch("dc_overview.grafana_alerts.requests.post")
    def test_uses_grafana_provisioning_api_without_container_restart(self, mock_post):
        mock_post.return_value = MagicMock(status_code=204)

        reloaded = reload_grafana_alerts(
            "http://grafana:3000/",
            admin_password="secret",
            timeout=7,
        )

        assert reloaded is True
        mock_post.assert_called_once_with(
            "http://grafana:3000/api/admin/provisioning/alerting/reload",
            auth=("admin", "secret"),
            timeout=7,
        )

    @patch("dc_overview.grafana_alerts.requests.post")
    def test_reload_failure_is_reported_without_restart_fallback(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("refused")

        assert reload_grafana_alerts("http://grafana:3000", "secret") is False
        mock_post.assert_called_once()


class TestGrafanaAlertSync:
    @patch("dc_overview.grafana_alerts.reload_grafana_alerts")
    def test_sync_refuses_duplicates_without_explicit_migration(self, mock_reload, tmp_path):
        legacy = (
            tmp_path / "grafana" / "provisioning" / "alerting" / "fleet-alerts.yml"
        )
        _write_alert_rules(legacy, "fleet-gpu-thermal-slowdown", "unrelated-alert")

        with pytest.raises(DuplicateManagedAlertError):
            sync_grafana_alerts(
                tmp_path,
                grafana_url="http://grafana:3000",
                admin_password="secret",
            )

        mock_reload.assert_not_called()
        assert _uids(legacy) == {"fleet-gpu-thermal-slowdown", "unrelated-alert"}

    @patch("dc_overview.grafana_alerts.configure_grafana_telegram_receiver")
    @patch("dc_overview.grafana_alerts.reload_grafana_alerts")
    def test_sync_activates_receiver_before_immediate_rules(
        self, mock_reload, mock_configure_receiver, tmp_path
    ):
        legacy = (
            tmp_path / "grafana" / "provisioning" / "alerting" / "fleet-alerts.yml"
        )
        canonical = legacy.with_name(ALERT_RULES_FILENAME)
        template = legacy.with_name(NOTIFICATION_TEMPLATE_FILENAME)
        _write_alert_rules(legacy, "fleet-gpu-thermal-slowdown", "unrelated-alert")
        _set_rule_receiver(legacy, "Charlotte Telegram")
        events = []

        def observe_reload(*args, **kwargs):
            if canonical.exists():
                events.append("rules-active")
            elif template.exists():
                events.append("template-loaded")
            return True

        def observe_receiver(*args, **kwargs):
            events.append("receiver-active")
            return MagicMock(configured=True, previous_messages=())

        mock_reload.side_effect = observe_reload
        mock_configure_receiver.side_effect = observe_receiver

        result = sync_grafana_alerts(
            tmp_path,
            grafana_url="http://grafana:3000",
            admin_password="secret",
            migrate_duplicates=True,
        )

        assert result.success is True
        assert events == ["template-loaded", "receiver-active", "rules-active"]

    @patch("dc_overview.grafana_alerts.configure_grafana_telegram_receiver")
    @patch("dc_overview.grafana_alerts.reload_grafana_alerts")
    def test_upgrade_keeps_existing_canonical_rules_unchanged_until_receiver_ready(
        self, mock_reload, mock_configure_receiver, tmp_path
    ):
        canonical = install_grafana_alerts(
            tmp_path,
            receiver="Charlotte Telegram",
        )
        original = canonical.read_bytes()
        events = []

        def observe_reload(*args, **kwargs):
            if mock_reload.call_count == 1:
                assert canonical.read_bytes() == original
            else:
                assert canonical.read_bytes() != original
            events.append("reload")
            return True

        def observe_receiver(*args, **kwargs):
            assert canonical.read_bytes() == original
            events.append("receiver-ready")
            return MagicMock(configured=True, previous_messages=())

        mock_reload.side_effect = observe_reload
        mock_configure_receiver.side_effect = observe_receiver

        result = sync_grafana_alerts(
            tmp_path,
            grafana_url="http://grafana:3000",
            admin_password="secret",
            instance_matcher=r"runpodccc.+",
        )

        assert result.success is True
        assert events == ["reload", "receiver-ready", "reload"]

    @patch(
        "dc_overview.grafana_alerts._restore_grafana_telegram_receiver_messages",
        create=True,
    )
    @patch("dc_overview.grafana_alerts.configure_grafana_telegram_receiver")
    @patch("dc_overview.grafana_alerts.reload_grafana_alerts")
    def test_final_rule_activation_failure_restores_files_and_receiver_message(
        self,
        mock_reload,
        mock_configure_receiver,
        mock_restore_receiver,
        tmp_path,
    ):
        legacy = (
            tmp_path / "grafana" / "provisioning" / "alerting" / "fleet-alerts.yml"
        )
        _write_alert_rules(legacy, "fleet-gpu-thermal-slowdown", "unrelated-alert")
        _set_rule_receiver(legacy, "Charlotte Telegram")
        original = legacy.read_bytes()
        mock_configure_receiver.return_value = MagicMock(
            configured=True,
            previous_messages=(("telegram-1", "old message"),),
        )
        rollback_events = []
        reload_results = iter((True, False, True))

        def observe_reload(*args, **kwargs):
            result = next(reload_results)
            if result is True and mock_reload.call_count == 3:
                rollback_events.append("old-rules-active")
            return result

        def observe_receiver_restore(*args, **kwargs):
            rollback_events.append("receiver-restored")
            return True

        mock_reload.side_effect = observe_reload
        mock_restore_receiver.side_effect = observe_receiver_restore

        result = sync_grafana_alerts(
            tmp_path,
            grafana_url="http://grafana:3000",
            admin_password="secret",
            migrate_duplicates=True,
        )

        assert result.success is False
        assert result.rollback_complete is True
        assert legacy.read_bytes() == original
        assert not legacy.with_name(ALERT_RULES_FILENAME).exists()
        mock_restore_receiver.assert_called_once_with(
            "http://grafana:3000",
            "secret",
            receiver="Charlotte Telegram",
            previous_messages=(("telegram-1", "old message"),),
            admin_user="admin",
            timeout=10,
        )
        assert mock_reload.call_count == 3
        assert rollback_events == ["old-rules-active", "receiver-restored"]

    @patch("dc_overview.grafana_alerts.configure_grafana_telegram_receiver")
    @patch("dc_overview.grafana_alerts.reload_grafana_alerts", return_value=True)
    def test_sync_migrates_only_managed_uids_and_backs_up_touched_files(
        self, mock_reload, mock_configure_receiver, tmp_path
    ):
        legacy = (
            tmp_path / "grafana" / "provisioning" / "alerting" / "fleet-alerts.yml"
        )
        _write_alert_rules(
            legacy,
            "fleet-gpu-hardware-failure",
            "fleet-gpu-thermal-slowdown",
            "unrelated-alert",
        )
        original = legacy.read_bytes()

        result = sync_grafana_alerts(
            tmp_path,
            grafana_url="http://grafana:3000",
            admin_password="secret",
            receiver="Charlotte Telegram",
            migrate_duplicates=True,
        )

        assert result.success is True
        assert result.restored is False
        assert result.canonical_path.exists()
        assert _uids(legacy) == {"unrelated-alert"}
        assert (result.backup_dir / "fleet-alerts.yml").read_bytes() == original
        hardware = _rule(result.canonical_path.read_text(), "fleet-gpu-hardware-failure")
        assert hardware["notification_settings"]["receiver"] == "Charlotte Telegram"
        assert stat.S_IMODE(result.canonical_path.stat().st_mode) == 0o644
        assert mock_reload.call_count == 2
        for call in mock_reload.call_args_list:
            assert call.args == ("http://grafana:3000", "secret")
            assert call.kwargs == {"admin_user": "admin", "timeout": 10}

    @patch("dc_overview.grafana_alerts.reload_grafana_alerts")
    def test_sync_restores_prior_files_when_grafana_reload_fails(
        self, mock_reload, tmp_path
    ):
        mock_reload.side_effect = [False, True]
        legacy = (
            tmp_path / "grafana" / "provisioning" / "alerting" / "fleet-alerts.yml"
        )
        _write_alert_rules(legacy, "fleet-gpu-thermal-slowdown", "unrelated-alert")
        original = legacy.read_bytes()
        canonical = legacy.with_name(ALERT_RULES_FILENAME)

        result = sync_grafana_alerts(
            tmp_path,
            grafana_url="http://grafana:3000",
            admin_password="secret",
            migrate_duplicates=True,
        )

        assert result.success is False
        assert result.restored is True
        assert legacy.read_bytes() == original
        assert not canonical.exists()
        assert not canonical.with_name(NOTIFICATION_TEMPLATE_FILENAME).exists()
        assert mock_reload.call_count == 2

    @patch("dc_overview.grafana_alerts.reload_grafana_alerts", return_value=True)
    @patch("dc_overview.grafana_alerts.install_grafana_alerts")
    def test_sync_rolls_back_every_exception_after_snapshot(
        self, mock_install, mock_reload, tmp_path
    ):
        legacy = (
            tmp_path / "grafana" / "provisioning" / "alerting" / "fleet-alerts.yml"
        )
        _write_alert_rules(legacy, "fleet-gpu-thermal-slowdown", "unrelated-alert")
        original = legacy.read_bytes()
        mock_install.side_effect = RuntimeError("render failed")

        result = sync_grafana_alerts(
            tmp_path,
            grafana_url="http://grafana:3000",
            admin_password="secret",
            migrate_duplicates=True,
        )

        assert result.success is False
        assert result.restored is True
        assert result.rollback_complete is True
        assert "render failed" in result.failure_reason
        assert legacy.read_bytes() == original
        mock_reload.assert_called_once()

    @patch("dc_overview.grafana_alerts.reload_grafana_alerts")
    def test_sync_bounds_rollback_reload_retries_and_surfaces_incomplete_rollback(
        self, mock_reload, tmp_path
    ):
        mock_reload.side_effect = [False, False, False, True]

        result = sync_grafana_alerts(
            tmp_path,
            grafana_url="http://grafana:3000",
            admin_password="secret",
        )

        assert result.success is False
        assert result.restored is True
        assert result.rollback_complete is False
        assert result.status == "rollback_incomplete"
        assert mock_reload.call_count == 3

    @patch("dc_overview.grafana_alerts.reload_grafana_alerts", side_effect=[False, True])
    def test_sync_surfaces_restore_failure_as_rollback_incomplete(
        self, mock_reload, tmp_path
    ):
        legacy = (
            tmp_path / "grafana" / "provisioning" / "alerting" / "fleet-alerts.yml"
        )
        _write_alert_rules(legacy, "fleet-gpu-thermal-slowdown", "unrelated-alert")
        original = legacy.read_bytes()

        from dc_overview import grafana_alerts

        real_atomic_write = grafana_alerts._atomic_write

        def fail_only_while_restoring(path, content, *args, **kwargs):
            if path == legacy and content == original:
                raise PermissionError("restore denied")
            return real_atomic_write(path, content, *args, **kwargs)

        with patch(
            "dc_overview.grafana_alerts._atomic_write",
            side_effect=fail_only_while_restoring,
        ):
            result = sync_grafana_alerts(
                tmp_path,
                grafana_url="http://grafana:3000",
                admin_password="secret",
                migrate_duplicates=True,
            )

        assert result.success is False
        assert result.rollback_complete is False
        assert result.status == "rollback_incomplete"
        assert "restore denied" in result.failure_reason

    @patch("dc_overview.grafana_alerts.os.chown")
    @patch("dc_overview.grafana_alerts.reload_grafana_alerts", side_effect=[False, True])
    def test_rollback_restores_original_mode_and_ownership(
        self, mock_reload, mock_chown, tmp_path
    ):
        canonical = (
            tmp_path
            / "grafana"
            / "provisioning"
            / "alerting"
            / ALERT_RULES_FILENAME
        )
        _write_alert_rules(canonical, "fleet-gpu-hardware-failure")
        canonical.chmod(0o640)
        original = canonical.read_bytes()
        original_stat = canonical.stat()

        result = sync_grafana_alerts(
            tmp_path,
            grafana_url="http://grafana:3000",
            admin_password="secret",
        )

        assert result.restored is True
        assert canonical.read_bytes() == original
        assert stat.S_IMODE(canonical.stat().st_mode) == 0o640
        assert any(
            call.args[1:] == (original_stat.st_uid, original_stat.st_gid)
            for call in mock_chown.call_args_list
        )

    @patch("dc_overview.grafana_alerts.configure_grafana_telegram_receiver")
    @patch("dc_overview.grafana_alerts.reload_grafana_alerts", return_value=True)
    def test_omitted_receiver_preserves_existing_notification_settings(
        self, mock_reload, mock_configure_receiver, tmp_path
    ):
        canonical = install_grafana_alerts(tmp_path, receiver="Existing Telegram")
        before = {
            uid: _rule(canonical.read_text(), uid)["notification_settings"]
            for uid in (
                "fleet-gpu-hardware-failure",
                "fleet-gpu-thermal-slowdown",
            )
        }

        result = sync_grafana_alerts(
            tmp_path,
            grafana_url="http://grafana:3000",
            admin_password="secret",
        )

        assert result.success is True
        for uid, settings in before.items():
            assert _rule(canonical.read_text(), uid)["notification_settings"] == settings
        mock_configure_receiver.assert_called_once_with(
            "http://grafana:3000",
            "secret",
            receiver="Existing Telegram",
            admin_user="admin",
            timeout=10,
        )

    @patch("dc_overview.grafana_alerts.configure_grafana_telegram_receiver")
    @patch("dc_overview.grafana_alerts.reload_grafana_alerts", return_value=True)
    def test_omitted_receiver_routes_new_managed_rules_to_existing_receiver(
        self, mock_reload, mock_configure_receiver, tmp_path
    ):
        canonical = install_grafana_alerts(tmp_path, receiver="Existing Telegram")
        document = yaml.safe_load(canonical.read_text())
        for group in document["groups"]:
            group["rules"] = [
                rule
                for rule in group["rules"]
                if rule["uid"] != "fleet-gpu-inventory-mismatch"
            ]
        canonical.write_text(yaml.safe_dump(document, sort_keys=False))

        result = sync_grafana_alerts(
            tmp_path,
            grafana_url="http://grafana:3000",
            admin_password="secret",
        )

        assert result.success is True
        new_rule = _rule(canonical.read_text(), "fleet-gpu-inventory-mismatch")
        assert new_rule["notification_settings"]["receiver"] == "Existing Telegram"

    @patch("dc_overview.grafana_alerts.configure_grafana_telegram_receiver")
    @patch("dc_overview.grafana_alerts.reload_grafana_alerts", return_value=True)
    def test_receiver_configuration_exception_restores_provisioned_files(
        self, mock_reload, mock_configure_receiver, tmp_path
    ):
        canonical = install_grafana_alerts(tmp_path, receiver="Existing Telegram")
        original = canonical.read_bytes()
        mock_configure_receiver.side_effect = RuntimeError("unexpected API codec failure")

        result = sync_grafana_alerts(
            tmp_path,
            grafana_url="http://grafana:3000",
            admin_password="secret",
        )

        assert result.success is False
        assert result.rollback_complete is True
        assert canonical.read_bytes() == original
        assert mock_reload.call_count == 2

    @patch("dc_overview.grafana_alerts.reload_grafana_alerts", return_value=True)
    def test_sync_can_explicitly_clear_existing_receiver(self, mock_reload, tmp_path):
        canonical = install_grafana_alerts(tmp_path, receiver="Old Telegram")

        result = sync_grafana_alerts(
            tmp_path,
            grafana_url="http://grafana:3000",
            admin_password="secret",
            clear_receiver=True,
        )

        assert result.success is True
        for uid in ("fleet-gpu-hardware-failure", "fleet-gpu-thermal-slowdown"):
            assert "notification_settings" not in _rule(canonical.read_text(), uid)

    @patch("dc_overview.grafana_alerts.configure_grafana_telegram_receiver")
    @patch("dc_overview.grafana_alerts.reload_grafana_alerts", return_value=True)
    def test_repeated_sync_is_idempotent_and_backs_up_the_canonical_file(
        self, mock_reload, mock_configure_receiver, tmp_path
    ):
        first = sync_grafana_alerts(
            tmp_path,
            grafana_url="http://grafana:3000",
            admin_password="secret",
            receiver="Site Telegram",
        )
        first_content = first.canonical_path.read_bytes()

        second = sync_grafana_alerts(
            tmp_path,
            grafana_url="http://grafana:3000",
            admin_password="secret",
            receiver="Site Telegram",
        )

        assert second.canonical_path.read_bytes() == first_content
        assert (second.backup_dir / ALERT_RULES_FILENAME).read_bytes() == first_content
        assert mock_reload.call_count == 4

    @patch("dc_overview.cli.subprocess.run")
    @patch("dc_overview.grafana_alerts.requests.post")
    @patch("dc_overview.grafana_alerts.configure_grafana_telegram_receiver")
    def test_sync_cli_migrates_and_preserves_configured_receiver(
        self, mock_configure_receiver, mock_post, mock_subprocess, tmp_path
    ):
        mock_post.return_value = MagicMock(status_code=200)
        legacy = (
            tmp_path / "grafana" / "provisioning" / "alerting" / "fleet-alerts.yml"
        )
        _write_alert_rules(legacy, "fleet-gpu-thermal-slowdown", "unrelated-alert")

        result = CliRunner().invoke(
            main,
            [
                "sync-alerts",
                "--config-dir",
                str(tmp_path),
                "--grafana-url",
                "http://grafana:3000",
                "--receiver",
                "Charlotte Telegram",
                "--migrate-duplicates",
            ],
            env={"GRAFANA_PASSWORD": "secret"},
        )

        assert result.exit_code == 0, result.output
        canonical = legacy.with_name(ALERT_RULES_FILENAME)
        hardware = _rule(canonical.read_text(), "fleet-gpu-hardware-failure")
        assert hardware["notification_settings"]["receiver"] == "Charlotte Telegram"
        assert "backup" in result.output.lower()
        assert FleetConfig.load(tmp_path).grafana.alert_receiver == "Charlotte Telegram"
        mock_subprocess.assert_not_called()

    @patch("dc_overview.grafana_alerts.requests.post")
    def test_sync_cli_explicit_clear_is_persisted(self, mock_post, tmp_path):
        mock_post.return_value = MagicMock(status_code=200)
        config = FleetConfig(config_dir=tmp_path)
        config.grafana.alert_receiver = "Old Telegram"
        config.save()
        canonical = install_grafana_alerts(tmp_path, receiver="Old Telegram")

        result = CliRunner().invoke(
            main,
            ["sync-alerts", "--config-dir", str(tmp_path), "--clear-receiver"],
            env={"GRAFANA_PASSWORD": "secret"},
        )

        assert result.exit_code == 0, result.output
        assert FleetConfig.load(tmp_path).grafana.alert_receiver is None
        for uid in ("fleet-gpu-hardware-failure", "fleet-gpu-thermal-slowdown"):
            assert "notification_settings" not in _rule(canonical.read_text(), uid)

    @patch("dc_overview.cli.sync_grafana_alerts")
    def test_sync_cli_persists_receiver_without_rewriting_secrets(
        self, mock_sync, tmp_path
    ):
        config = FleetConfig(config_dir=tmp_path)
        config.save()
        secrets_path = tmp_path / ".secrets.yaml"
        secrets_path.write_text("preserved_secret: do-not-rewrite\n")
        before = secrets_path.read_bytes()
        mock_sync.return_value = MagicMock(
            success=True,
            backup_dir=tmp_path / "backup",
            migrated_files=(),
            notification_template_configured=True,
        )

        result = CliRunner().invoke(
            main,
            [
                "sync-alerts",
                "--config-dir",
                str(tmp_path),
                "--receiver",
                "Site Telegram",
            ],
            env={"GRAFANA_PASSWORD": "live-secret"},
        )

        assert result.exit_code == 0, result.output
        assert secrets_path.read_bytes() == before
        assert FleetConfig.load(tmp_path).grafana.alert_receiver == "Site Telegram"

    @patch("dc_overview.cli.sync_grafana_alerts")
    @patch("dc_overview.fleet_config.FleetConfig.persist_alert_receiver")
    def test_sync_cli_does_not_change_live_grafana_when_config_persistence_fails(
        self, mock_persist, mock_sync, tmp_path
    ):
        mock_persist.side_effect = PermissionError("config is read-only")

        result = CliRunner().invoke(
            main,
            [
                "sync-alerts",
                "--config-dir",
                str(tmp_path),
                "--receiver",
                "Site Telegram",
            ],
            env={"GRAFANA_PASSWORD": "live-secret"},
        )

        assert result.exit_code != 0
        assert "live Grafana was not changed" in result.output
        mock_sync.assert_not_called()

    @patch("dc_overview.cli.sync_grafana_alerts")
    @patch("dc_overview.fleet_config.FleetConfig.snapshot_public_config")
    def test_sync_cli_reports_config_snapshot_failure_before_live_change(
        self, mock_snapshot, mock_sync, tmp_path
    ):
        mock_snapshot.side_effect = PermissionError("config cannot be read")

        result = CliRunner().invoke(
            main,
            [
                "sync-alerts",
                "--config-dir",
                str(tmp_path),
                "--receiver",
                "Site Telegram",
            ],
            env={"GRAFANA_PASSWORD": "live-secret"},
        )

        assert result.exit_code != 0
        assert "live Grafana was not changed" in result.output
        mock_sync.assert_not_called()

    @patch("dc_overview.cli.sync_grafana_alerts")
    def test_sync_cli_restores_exact_public_config_when_live_sync_fails(
        self, mock_sync, tmp_path
    ):
        config = FleetConfig(config_dir=tmp_path)
        config.grafana.alert_receiver = "Old Telegram"
        config.save()
        config_path = tmp_path / "fleet-config.yaml"
        secrets_path = tmp_path / ".secrets.yaml"
        original_config = config_path.read_bytes()
        original_secrets = secrets_path.read_bytes()
        mock_sync.return_value = MagicMock(
            success=False,
            rollback_complete=True,
            backup_dir=tmp_path / "backup",
            failure_reason="Grafana rejected reload",
        )

        result = CliRunner().invoke(
            main,
            [
                "sync-alerts",
                "--config-dir",
                str(tmp_path),
                "--receiver",
                "New Telegram",
            ],
            env={"GRAFANA_PASSWORD": "live-secret"},
        )

        assert result.exit_code != 0
        assert config_path.read_bytes() == original_config
        assert secrets_path.read_bytes() == original_secrets

    @patch("dc_overview.cli.sync_grafana_alerts")
    def test_sync_cli_removes_new_public_config_when_first_live_sync_fails(
        self, mock_sync, tmp_path
    ):
        mock_sync.return_value = MagicMock(
            success=False,
            rollback_complete=True,
            backup_dir=tmp_path / "backup",
            failure_reason="Grafana rejected reload",
        )

        result = CliRunner().invoke(
            main,
            [
                "sync-alerts",
                "--config-dir",
                str(tmp_path),
                "--receiver",
                "New Telegram",
            ],
            env={"GRAFANA_PASSWORD": "live-secret"},
        )

        assert result.exit_code != 0
        assert not (tmp_path / "fleet-config.yaml").exists()
        assert not (tmp_path / ".secrets.yaml").exists()

    def test_sync_cli_rejects_receiver_and_clear_together(self, tmp_path):
        result = CliRunner().invoke(
            main,
            [
                "sync-alerts",
                "--config-dir",
                str(tmp_path),
                "--receiver",
                "Site Telegram",
                "--clear-receiver",
            ],
            env={"GRAFANA_PASSWORD": "secret"},
        )

        assert result.exit_code != 0
        assert "cannot be used together" in result.output.lower()

    @patch("dc_overview.cli.sync_grafana_alerts")
    def test_sync_cli_reports_receiver_validation_errors_cleanly(
        self, mock_sync, tmp_path
    ):
        mock_sync.side_effect = GrafanaReceiverError(
            "Grafana receiver 'Missing Telegram' was not found"
        )

        result = CliRunner().invoke(
            main,
            ["sync-alerts", "--config-dir", str(tmp_path)],
            env={"GRAFANA_PASSWORD": "live-secret"},
        )

        assert result.exit_code != 0
        assert "Missing Telegram" in result.output
        assert result.exception is not None


class TestGrafanaReceiverWiring:
    @patch("dc_overview.grafana_alerts.time.sleep", create=True)
    @patch("dc_overview.grafana_alerts.requests.get")
    def test_waits_for_concise_message_in_live_alertmanager_config(
        self, mock_get, mock_sleep
    ):
        stale = MagicMock(
            status_code=200,
            json=MagicMock(
                return_value={
                    "config": {
                        "receivers": [
                            {
                                "name": "Site Telegram",
                                "grafana_managed_receiver_configs": [
                                    {
                                        "uid": "telegram-1",
                                        "type": "telegram",
                                        "settings": {"message": "old message"},
                                    }
                                ],
                            }
                        ]
                    }
                }
            ),
        )
        active = MagicMock(
            status_code=200,
            json=MagicMock(
                return_value={
                    "config": {
                        "receivers": [
                            {
                                "name": "Site Telegram",
                                "grafana_managed_receiver_configs": [
                                    {
                                        "uid": "telegram-1",
                                        "type": "telegram",
                                        "settings": {
                                            "message": (
                                                '{{ template "cryptolabs.telegram.message" . }}'
                                            )
                                        },
                                    }
                                ],
                            }
                        ]
                    }
                }
            ),
        )
        mock_get.side_effect = [stale, active]

        from dc_overview import grafana_alerts

        ready = grafana_alerts.wait_for_grafana_telegram_receiver(
            "http://grafana:3000",
            "secret",
            receiver="Site Telegram",
            expected_messages=(
                ("telegram-1", '{{ template "cryptolabs.telegram.message" . }}'),
            ),
            attempts=2,
            poll_interval=0.25,
        )

        assert ready is True
        assert mock_get.call_count == 2
        mock_get.assert_called_with(
            "http://grafana:3000/api/alertmanager/grafana/api/v2/status",
            auth=("admin", "secret"),
            timeout=10,
        )
        mock_sleep.assert_called_once_with(0.25)

    @patch("dc_overview.grafana_alerts.time.sleep", create=True)
    @patch("dc_overview.grafana_alerts.requests.get")
    def test_live_receiver_readiness_is_bounded_and_fails_closed(
        self, mock_get, mock_sleep
    ):
        mock_get.side_effect = requests.ConnectionError("not ready")

        from dc_overview import grafana_alerts

        ready = grafana_alerts.wait_for_grafana_telegram_receiver(
            "http://grafana:3000",
            "secret",
            receiver="Site Telegram",
            expected_messages=(("telegram-1", "expected message"),),
            attempts=3,
            poll_interval=0.25,
        )

        assert ready is False
        assert mock_get.call_count == 3
        assert mock_sleep.call_count == 2

    @patch("dc_overview.grafana_alerts.requests.get")
    def test_missing_receiver_uid_is_not_ready_when_expected_message_is_unset(
        self, mock_get
    ):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"config": {"receivers": []}}),
        )

        from dc_overview import grafana_alerts

        ready = grafana_alerts.wait_for_grafana_telegram_receiver(
            "http://grafana:3000",
            "secret",
            receiver="Site Telegram",
            expected_messages=(("telegram-1", None),),
            attempts=1,
        )

        assert ready is False

    @patch("dc_overview.grafana_alerts.time.sleep", create=True)
    @patch("dc_overview.grafana_alerts.requests.get")
    def test_live_receiver_readiness_surfaces_permanent_http_error(
        self, mock_get, mock_sleep
    ):
        response = MagicMock(status_code=401)
        response.raise_for_status.side_effect = requests.HTTPError(
            "unauthorized",
            response=response,
        )
        mock_get.return_value = response

        from dc_overview import grafana_alerts

        with pytest.raises(GrafanaReceiverError, match="HTTP 401"):
            grafana_alerts.wait_for_grafana_telegram_receiver(
                "http://grafana:3000",
                "secret",
                receiver="Site Telegram",
                expected_messages=(("telegram-1", "expected message"),),
                attempts=30,
            )

        mock_get.assert_called_once()
        mock_sleep.assert_not_called()

    @patch("dc_overview.grafana_alerts.requests.get")
    def test_live_receiver_readiness_rejects_malformed_status(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=["not-alertmanager-status"]),
        )

        from dc_overview import grafana_alerts

        with pytest.raises(GrafanaReceiverError, match="unexpected structure"):
            grafana_alerts.wait_for_grafana_telegram_receiver(
                "http://grafana:3000",
                "secret",
                receiver="Site Telegram",
                expected_messages=(("telegram-1", "expected message"),),
                attempts=30,
            )

        mock_get.assert_called_once()

    @patch(
        "dc_overview.grafana_alerts.wait_for_grafana_telegram_receiver",
        create=True,
        return_value=True,
    )
    @patch("dc_overview.grafana_alerts.requests.put")
    @patch("dc_overview.grafana_alerts.requests.get")
    def test_wires_concise_template_without_replacing_redacted_secrets(
        self, mock_get, mock_put, mock_wait, caplog
    ):
        contact_point = {
            "uid": "telegram-1",
            "name": "Site Telegram",
            "type": "telegram",
            "settings": {
                "bottoken": "[REDACTED]",
                "chatid": "-100123",
                "message": "old message",
            },
            "disableResolveMessage": False,
        }
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[contact_point]),
        )
        mock_put.return_value = MagicMock(status_code=202)

        result = configure_grafana_telegram_receiver(
            "http://grafana:3000",
            "secret",
            receiver="Site Telegram",
        )

        assert result.configured is True
        assert result.previous_messages == (("telegram-1", "old message"),)
        mock_get.assert_called_once_with(
            "http://grafana:3000/api/v1/provisioning/contact-points",
            params={"name": "Site Telegram"},
            auth=("admin", "secret"),
            timeout=10,
        )
        payload = mock_put.call_args.kwargs["json"]
        assert payload["settings"]["bottoken"] == "[REDACTED]"
        assert payload["settings"]["chatid"] == "-100123"
        assert payload["settings"]["message"] == (
            f'{{{{ template "{NOTIFICATION_TEMPLATE_NAME}" . }}}}'
        )
        mock_wait.assert_called_once_with(
            "http://grafana:3000",
            "secret",
            receiver="Site Telegram",
            expected_messages=(
                ("telegram-1", '{{ template "cryptolabs.telegram.message" . }}'),
            ),
            admin_user="admin",
            timeout=10,
        )
        assert "[REDACTED]" not in caplog.text

    @patch(
        "dc_overview.grafana_alerts.wait_for_grafana_telegram_receiver",
        create=True,
        side_effect=[False, True],
    )
    @patch("dc_overview.grafana_alerts.requests.put")
    @patch("dc_overview.grafana_alerts.requests.get")
    def test_readiness_timeout_restores_original_message(
        self, mock_get, mock_put, mock_wait
    ):
        contact_point = {
            "uid": "telegram-1",
            "name": "Site Telegram",
            "type": "telegram",
            "settings": {
                "bottoken": "[REDACTED]",
                "message": "old message",
            },
        }
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[contact_point]),
        )
        mock_put.return_value = MagicMock(status_code=202)

        with pytest.raises(GrafanaReceiverError, match="did not become active") as raised:
            configure_grafana_telegram_receiver(
                "http://grafana:3000",
                "secret",
                receiver="Site Telegram",
            )

        assert raised.value.rollback_complete is True
        assert mock_put.call_count == 2
        assert mock_put.call_args_list[-1].kwargs["json"]["settings"]["message"] == (
            "old message"
        )
        assert mock_wait.call_count == 2

    @patch(
        "dc_overview.grafana_alerts.wait_for_grafana_telegram_receiver",
        create=True,
        side_effect=(
            GrafanaReceiverError("Grafana live receiver check returned HTTP 401"),
            GrafanaReceiverError("Grafana live receiver check returned HTTP 401"),
        ),
    )
    @patch("dc_overview.grafana_alerts.requests.put")
    @patch("dc_overview.grafana_alerts.requests.get")
    def test_rollback_verification_error_marks_receiver_rollback_incomplete(
        self, mock_get, mock_put, mock_wait
    ):
        contact_point = {
            "uid": "telegram-1",
            "name": "Site Telegram",
            "type": "telegram",
            "settings": {
                "bottoken": "[REDACTED]",
                "message": "old message",
            },
        }
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[contact_point]),
        )
        mock_put.return_value = MagicMock(status_code=202)

        with pytest.raises(GrafanaReceiverError) as raised:
            configure_grafana_telegram_receiver(
                "http://grafana:3000",
                "secret",
                receiver="Site Telegram",
            )

        assert raised.value.rollback_complete is False
        assert "rollback verification failed" in str(raised.value)
        assert "HTTP 401" in str(raised.value)
        assert mock_put.call_count == 2
        assert mock_wait.call_count == 2

    @patch(
        "dc_overview.grafana_alerts.wait_for_grafana_telegram_receiver",
        create=True,
        return_value=True,
    )
    @patch("dc_overview.grafana_alerts.requests.put")
    @patch("dc_overview.grafana_alerts.requests.get")
    def test_unexpected_contact_update_error_restores_every_attempted_receiver(
        self, mock_get, mock_put, mock_wait
    ):
        contact_points = [
            {
                "uid": uid,
                "name": "Site Telegram",
                "type": "telegram",
                "settings": {"bottoken": "[REDACTED]", "message": old_message},
            }
            for uid, old_message in (("telegram-1", "old one"), ("telegram-2", "old two"))
        ]
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=contact_points),
        )
        mock_put.side_effect = [
            MagicMock(status_code=202),
            RuntimeError("response decoder failed"),
            MagicMock(status_code=202),
            MagicMock(status_code=202),
        ]

        with pytest.raises(GrafanaReceiverError) as raised:
            configure_grafana_telegram_receiver(
                "http://grafana:3000",
                "secret",
                receiver="Site Telegram",
            )

        assert raised.value.rollback_complete is True
        assert mock_put.call_count == 4
        restored_messages = [
            call.kwargs["json"]["settings"]["message"]
            for call in mock_put.call_args_list[-2:]
        ]
        assert restored_messages == ["old two", "old one"]
        mock_wait.assert_called_once()

    @patch(
        "dc_overview.grafana_alerts.wait_for_grafana_telegram_receiver",
        create=True,
        return_value=True,
    )
    @patch("dc_overview.grafana_alerts.requests.put")
    @patch("dc_overview.grafana_alerts.requests.get")
    def test_restore_receiver_message_preserves_redacted_settings(
        self, mock_get, mock_put, mock_wait
    ):
        contact_point = {
            "uid": "telegram-1",
            "name": "Site Telegram",
            "type": "telegram",
            "settings": {
                "bottoken": "[REDACTED]",
                "chatid": "-100123",
                "message": '{{ template "cryptolabs.telegram.message" . }}',
            },
        }
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[contact_point]),
        )
        mock_put.return_value = MagicMock(status_code=202)

        from dc_overview import grafana_alerts

        restored = grafana_alerts._restore_grafana_telegram_receiver_messages(
            "http://grafana:3000",
            "secret",
            receiver="Site Telegram",
            previous_messages=(("telegram-1", None),),
            admin_user="admin",
            timeout=10,
        )

        assert restored is True
        payload = mock_put.call_args.kwargs["json"]
        assert payload["settings"]["bottoken"] == "[REDACTED]"
        assert payload["settings"]["chatid"] == "-100123"
        assert "message" not in payload["settings"]
        mock_wait.assert_called_once_with(
            "http://grafana:3000",
            "secret",
            receiver="Site Telegram",
            expected_messages=(("telegram-1", None),),
            admin_user="admin",
            timeout=10,
        )

    @patch(
        "dc_overview.grafana_alerts.wait_for_grafana_telegram_receiver",
        create=True,
        return_value=True,
    )
    @patch("dc_overview.grafana_alerts.requests.put")
    @patch("dc_overview.grafana_alerts.requests.get")
    def test_restore_attempts_every_receiver_after_one_put_fails(
        self, mock_get, mock_put, mock_wait
    ):
        contact_points = [
            {
                "uid": uid,
                "name": "Site Telegram",
                "type": "telegram",
                "settings": {
                    "bottoken": "[REDACTED]",
                    "message": "concise",
                },
            }
            for uid in ("telegram-1", "telegram-2")
        ]
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=contact_points),
        )
        mock_put.side_effect = [
            requests.ConnectionError("first restore failed"),
            requests.ConnectionError("first restore retry failed"),
            MagicMock(status_code=202),
        ]

        from dc_overview import grafana_alerts

        restored = grafana_alerts._restore_grafana_telegram_receiver_messages(
            "http://grafana:3000",
            "secret",
            receiver="Site Telegram",
            previous_messages=(
                ("telegram-1", "old one"),
                ("telegram-2", "old two"),
            ),
            admin_user="admin",
            timeout=10,
        )

        assert restored is False
        assert mock_put.call_count == 3
        assert [
            call.kwargs["json"]["settings"]["message"]
            for call in mock_put.call_args_list
        ] == ["old one", "old one", "old two"]
        mock_wait.assert_not_called()

    @patch("dc_overview.grafana_alerts.requests.put")
    @patch("dc_overview.grafana_alerts.requests.get")
    def test_named_receiver_must_exist_and_be_telegram(self, mock_get, mock_put):
        mock_get.return_value = MagicMock(status_code=200, json=MagicMock(return_value=[]))

        with pytest.raises(GrafanaReceiverError, match="not found"):
            configure_grafana_telegram_receiver(
                "http://grafana:3000",
                "secret",
                receiver="Missing Telegram",
            )

        mock_put.assert_not_called()

    @patch("dc_overview.grafana_alerts.requests.put")
    @patch("dc_overview.grafana_alerts.requests.get")
    def test_invalid_contact_point_response_is_an_actionable_error(
        self, mock_get, mock_put
    ):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=["not-an-object"]),
        )

        with pytest.raises(GrafanaReceiverError, match="invalid contact point"):
            configure_grafana_telegram_receiver(
                "http://grafana:3000",
                "secret",
                receiver="Site Telegram",
            )

        mock_put.assert_not_called()


class TestGrafanaAlertConfigurationPaths:
    def test_fleet_config_round_trips_alert_receiver(self, tmp_path):
        config = FleetConfig(config_dir=tmp_path)
        config.grafana.alert_receiver = "Site Telegram"
        config.save()

        loaded = FleetConfig.load(tmp_path)

        assert loaded.grafana.alert_receiver == "Site Telegram"
        persisted = yaml.safe_load((tmp_path / "fleet-config.yaml").read_text())
        assert persisted["grafana"]["alert_receiver"] == "Site Telegram"

    def test_quickstart_environment_persists_the_alert_receiver(self):
        from dc_overview.quickstart import _render_quickstart_environment

        rendered = _render_quickstart_environment(
            "app-secret",
            "grafana-secret",
            "Site Telegram",
        )

        assert "SECRET_KEY=app-secret\n" in rendered
        assert "GRAFANA_PASSWORD=grafana-secret\n" in rendered
        assert (
            'DC_OVERVIEW_GRAFANA_ALERT_RECEIVER="Site Telegram"\n' in rendered
        )

    @patch("dc_overview.fleet_manager.subprocess.run")
    @patch("dc_overview.fleet_manager.install_grafana_alerts")
    def test_fleet_deploy_passes_receiver_and_stops_before_docker_if_alerts_fail(
        self, mock_install, mock_subprocess, tmp_path
    ):
        config = FleetConfig(config_dir=tmp_path)
        config.grafana.alert_receiver = "Site Telegram"
        manager = FleetManager(config)
        manager._generate_docker_compose = MagicMock(return_value="services: {}\n")
        manager._generate_prometheus_config = MagicMock(return_value="global: {}\n")
        manager._generate_recording_rules = MagicMock(return_value="groups: []\n")
        mock_install.side_effect = PermissionError("alert directory denied")

        with pytest.raises(PermissionError, match="denied"):
            manager._deploy_prometheus_grafana()

        mock_install.assert_called_once_with(
            tmp_path,
            receiver="Site Telegram",
        )
        mock_subprocess.assert_not_called()

    @patch("dc_overview.cli.sync_grafana_alerts")
    @patch("dc_overview.cli.subprocess.run")
    def test_upgrade_materializes_and_migrates_alerts_without_docker(
        self, mock_subprocess, mock_sync, tmp_path
    ):
        config = FleetConfig(config_dir=tmp_path)
        config.grafana.admin_password = "secret"
        config.grafana.alert_receiver = "Site Telegram"
        config.save()
        mock_sync.return_value = MagicMock(success=True)

        result = _sync_alerts_for_upgrade(tmp_path)

        assert result.success is True
        mock_sync.assert_called_once_with(
            tmp_path,
            grafana_url="http://localhost:3000",
            admin_password="secret",
            receiver="Site Telegram",
            migrate_duplicates=True,
        )
        mock_subprocess.assert_not_called()

    @patch("dc_overview.cli.sync_grafana_alerts")
    def test_legacy_upgrade_uses_persisted_dotenv_credentials_and_receiver(
        self, mock_sync, tmp_path
    ):
        (tmp_path / ".env").write_text(
            "GRAFANA_PASSWORD=live-secret\n"
            "DC_OVERVIEW_GRAFANA_ALERT_RECEIVER=Legacy Telegram\n"
        )
        mock_sync.return_value = MagicMock(success=True)

        _sync_alerts_for_upgrade(tmp_path)

        mock_sync.assert_called_once_with(
            tmp_path,
            grafana_url="http://localhost:3000",
            admin_password="live-secret",
            receiver="Legacy Telegram",
            migrate_duplicates=True,
        )

    @patch("dc_overview.cli._sync_alerts_for_upgrade")
    @patch("dc_overview.cli.subprocess.run")
    def test_upgrade_aborts_before_docker_when_required_alert_sync_fails(
        self, mock_subprocess, mock_alert_sync
    ):
        mock_alert_sync.return_value = MagicMock(
            success=False,
            rollback_complete=False,
            failure_reason="restore denied",
        )

        result = CliRunner().invoke(main, ["upgrade"])

        assert result.exit_code != 0
        assert "rollback incomplete" in result.output.lower()
        mock_subprocess.assert_not_called()

    @patch("dc_overview.quickstart.install_grafana_alerts")
    @patch("dc_overview.quickstart.console.print")
    def test_quickstart_does_not_report_monitoring_success_when_alerts_fail(
        self, mock_print, mock_install, tmp_path
    ):
        from dc_overview.quickstart import _configure_required_grafana_provisioning

        mock_install.side_effect = PermissionError("read-only alert directory")

        with pytest.raises(PermissionError, match="read-only"):
            _configure_required_grafana_provisioning(tmp_path, "Site Telegram")

        rendered_output = " ".join(
            str(arg)
            for call in mock_print.call_args_list
            for arg in call.args
        )
        assert "provisioning configured" not in rendered_output.lower()
