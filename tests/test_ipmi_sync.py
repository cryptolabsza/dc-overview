"""Regression coverage for removal of the unsafe DC-to-IPMI YAML bridge."""

from dc_overview.app import Server, db
from dc_overview.web_prometheus import sync_ipmi_monitor_targets


def test_legacy_ipmi_yaml_helper_never_mutates_configuration(app, tmp_path):
    """DC no longer fabricates IPMI enrollment from OS inventory rows."""
    config_path = tmp_path / "servers.yaml"
    original = "servers:\n  - name: unmanaged\n    server_ip: 10.0.0.1\n    bmc_ip: 10.0.0.2\n"
    config_path.write_text(original)

    with app.app_context():
        server = Server(name="dc-only", server_ip="10.0.0.99")
        db.session.add(server)
        db.session.commit()
        sync_ipmi_monitor_targets([server], str(config_path))

    assert config_path.read_text() == original
