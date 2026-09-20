"""The discovery endpoint is the committed server inventory, including removals."""
from dc_overview.app import db, Server


def test_discovery_only_enabled_exporters_with_stable_dashboard_labels(app, client):
    server = Server(name='worker', server_ip='10.0.0.2', node_exporter_installed=True,
                    node_exporter_enabled=False, dc_exporter_installed=True,
                    dc_exporter_enabled=True, watchdog_agent_installed=True,
                    watchdog_agent_enabled=True)
    db.session.add(server)
    db.session.commit()
    response = client.get('/api/prometheus/discovery')
    assert response.status_code == 200
    targets = response.json
    assert {x['targets'][0] for x in targets} == {'10.0.0.2:9835', '10.0.0.2:9878'}
    assert all(x['labels']['instance'] == 'worker' and x['labels']['job'] == 'worker' for x in targets)
    assert {x['labels']['exporter'] for x in targets} == {'dc', 'watchdog'}


def test_discovery_tracks_rename_and_delete_without_shared_files(app, client, auth_headers):
    server = Server(name='old', server_ip='10.0.0.2', node_exporter_installed=True,
                    node_exporter_enabled=True)
    db.session.add(server)
    db.session.commit()
    server_id = server.id
    assert client.put(f'/api/servers/{server_id}', headers=auth_headers,
                      json={'name': 'new', 'server_ip': '10.0.0.3'}).status_code == 200
    target = client.get('/api/prometheus/discovery').json[0]
    assert target['targets'] == ['10.0.0.3:9100']
    assert target['labels']['instance'] == 'new'
    assert client.delete(f'/api/servers/{server_id}', headers=auth_headers).status_code == 200
    assert client.get('/api/prometheus/discovery').json == []


def test_discovery_preserves_explicit_legacy_monitoring_label(app, client):
    server = Server(name='BBmaint', server_ip='88.0.33.141', monitoring_name='master',
                    node_exporter_installed=True, node_exporter_enabled=True)
    db.session.add(server)
    db.session.commit()
    assert client.get('/api/prometheus/discovery').json[0]['labels']['instance'] == 'master'


def test_discovery_brackets_ipv6(app, client):
    db.session.add(Server(name='v6', server_ip='2001:db8::1', node_exporter_installed=True,
                          node_exporter_enabled=True))
    db.session.commit()
    assert client.get('/api/prometheus/discovery').json[0]['targets'] == ['[2001:db8::1]:9100']


def test_generated_config_discovers_all_exporters_once():
    from pathlib import Path
    from jinja2 import Environment, FileSystemLoader
    import yaml
    template_dir = Path(__file__).parents[1] / 'src/dc_overview/templates'
    rendered = Environment(loader=FileSystemLoader(template_dir)).get_template('prometheus.yml.j2').render()
    jobs = yaml.safe_load(rendered)['scrape_configs']
    discovered = [j for j in jobs if 'http_sd_configs' in j]
    assert len(discovered) == 1
    assert discovered[0]['http_sd_configs'][0]['url'] == 'http://dc-overview:5001/api/prometheus/discovery'
    assert not any('file_sd_configs' in j for j in jobs)


def test_fleet_installer_uses_live_inventory_instead_of_static_workers(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import yaml
    from dc_overview.fleet_manager import FleetManager
    manager = object.__new__(FleetManager)
    manager.config = SimpleNamespace(config_dir=tmp_path, master_ip='10.0.0.1',
        servers=[SimpleNamespace(name='old', server_ip='10.0.0.2', exporters_installed=True)],
        components=SimpleNamespace(vast_exporter=False, runpod_exporter=False, ipmi_monitor=True))
    monkeypatch.setattr('dc_overview.fleet_manager.subprocess.run', lambda *a, **k: None)
    manager._configure_prometheus_targets()
    config = yaml.safe_load((tmp_path/'prometheus.yml').read_text())
    assert [j['job_name'] for j in config['scrape_configs']] == ['prometheus', 'dc-managed', 'ipmi-monitor']
    assert config['rule_files'] == ['/etc/prometheus/recording_rules.yml']


def test_preserved_monitoring_alias_cannot_collide_with_add_or_rename(app, client, auth_headers):
    db.session.add(Server(name='BBmaint', server_ip='10.0.0.1', monitoring_name='master'))
    other = Server(name='worker', server_ip='10.0.0.2')
    db.session.add(other)
    db.session.commit()
    assert client.post('/api/servers', headers=auth_headers, json={'name':'master','server_ip':'10.0.0.3'}).status_code == 409
    assert client.put(f'/api/servers/{other.id}', headers=auth_headers, json={'name':'master','server_ip':'10.0.0.2'}).status_code == 409
