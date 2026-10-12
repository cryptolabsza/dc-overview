import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from dc_overview import cli
from dc_overview.controller_adoption import AdoptionError, ensure_mutation_allowed, probe_controller_inventory
from dc_overview import fleet_upgrade

@pytest.fixture(autouse=True)
def no_subprocess_escape(monkeypatch):
    def forbidden(*a,**k): raise AssertionError('unit test subprocess forbidden')
    monkeypatch.setattr(subprocess,'run',forbidden)
    import socket
    monkeypatch.setattr(socket.socket,'connect',forbidden)



def test_setup_guard_precedes_config_load_and_legacy_wizard(monkeypatch,tmp_path):
    seen=[]
    def hold(*args,**kwargs): seen.append('guard'); raise AdoptionError('existing controller')
    monkeypatch.setattr('dc_overview.controller_adoption.ensure_mutation_allowed',hold)
    monkeypatch.setattr(cli,'load_config_from_file',lambda *a:seen.append('config-load'))
    monkeypatch.setattr(cli,'run_quickstart',lambda *a:seen.append('legacy'))
    public=tmp_path/'config.yaml'; public.write_text('site_name: fixture\n')
    for arguments in (['setup','--config',str(public),'--yes'],['setup','--legacy']):
        result=CliRunner().invoke(cli.main,arguments)
        assert result.exit_code!=0
    assert seen==['guard','guard']


def test_direct_fleet_deploy_guards_before_release_or_prerequisites(monkeypatch,tmp_path):
    from dc_overview.fleet_manager import FleetManager
    from dc_overview.fleet_config import FleetConfig
    config=FleetConfig(config_dir=tmp_path)
    seen=[]
    def hold(*a,**k): seen.append('guard'); raise AdoptionError('existing controller')
    monkeypatch.setattr('dc_overview.controller_adoption.ensure_mutation_allowed',hold)
    def selection(*a,**k):
        seen.append('selection')
        raise RuntimeError('RED safety boundary')
    monkeypatch.setattr(fleet_upgrade,'preflight_release',selection)
    manager=FleetManager(config)
    monkeypatch.setattr(manager,'_install_prerequisites',lambda:seen.append('prerequisites'))
    assert manager.deploy() is False
    assert seen==['guard']


def test_release_recovery_guard_precedes_selection_reads(monkeypatch,tmp_path):
    from dc_overview.fleet_config import FleetConfig
    def hold(*a,**k): raise AdoptionError('recovery required')
    monkeypatch.setattr('dc_overview.controller_adoption.ensure_mutation_allowed',hold)
    monkeypatch.setattr(fleet_upgrade,'release_store',lambda *a:pytest.fail('selection touched'))
    with pytest.raises(AdoptionError): fleet_upgrade.preflight_release(FleetConfig(config_dir=tmp_path))


@pytest.mark.parametrize('diagnostic',['permission denied','Error response from daemon: bad inspect','timeout'])
def test_unknown_inspect_cannot_authorize_fresh_setup(monkeypatch,tmp_path,diagnostic):
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=1,stdout='',stderr=diagnostic))
    with pytest.raises(AdoptionError,match='unknown'): ensure_mutation_allowed(tmp_path,setup=True)


def test_precise_named_absence_allows_fresh_setup(monkeypatch,tmp_path):
    monkeypatch.setattr(subprocess,'run',lambda args,**k:SimpleNamespace(returncode=1,stdout='',stderr='Error: No such object: '+args[3]))
    assert ensure_mutation_allowed(tmp_path,setup=True)


def test_public_configuration_cli_exists_and_missing_guard_fails_prewrite(tmp_path,monkeypatch):
    result=CliRunner().invoke(cli.main,['configuration','--help'])
    assert result.exit_code==0
    assert all(name in result.output for name in ('inspect','plan','adopt','recover'))


def test_alternate_ownership_reader_and_sanctioned_write_preserve_references(tmp_path,monkeypatch):
    from dc_overview.web_prometheus import update_prometheus_yml_targets
    config=tmp_path/'prometheus.yml'
    config.write_text('scrape_configs:\n- job_name: old-owned\n  static_configs: [{targets: ["old:9100"]}]\n- job_name: customer\n  bearer_token_file: /etc/prometheus/customer/token\n  static_configs: [{targets: ["customer:9100"]}]\nrule_files: [/etc/prometheus/customer/rules.yml]\n')
    ownership=tmp_path/'ownership.json'
    ownership.write_text(json.dumps({'schema_version':1,'managed_jobs':['old-owned'],
        'file_references':['/etc/prometheus/customer/token','/etc/prometheus/customer/rules.yml']}))
    monkeypatch.setenv('PROMETHEUS_CONFIG_PATH',str(config)); monkeypatch.setenv('PROMETHEUS_OWNERSHIP_PATH',str(ownership))
    assert update_prometheus_yml_targets([],reload_callback=lambda:True)
    actual=config.read_text()
    assert 'old-owned' not in actual and 'dc-managed' in actual and 'customer' in actual
    assert '/etc/prometheus/customer/token' in actual and '/etc/prometheus/customer/rules.yml' in actual


def test_pre_adoption_selected_upgrade_defers_alert_writes_without_bypassing_selection(monkeypatch,tmp_path):
    from dc_overview.fleet_config import FleetConfig
    from dc_overview import controller_adoption
    config=FleetConfig(config_dir=tmp_path); selected=SimpleNamespace(selection={'selection_id':'selected'})
    calls=[]
    monkeypatch.setattr(cli,'DOCKER_CONFIG_DIR',tmp_path)
    monkeypatch.setattr(controller_adoption,'upgrade_requires_adoption',lambda:True)
    monkeypatch.setattr(cli.FleetConfig,'load',lambda *a:config)
    def preflight(config,*args,**kwargs):
        assert config._controller_preservation_hold is True
        calls.append('selection-preflight'); return selected
    monkeypatch.setattr(fleet_upgrade,'preflight_release',preflight)
    monkeypatch.setattr(cli,'_sync_alerts_for_upgrade',lambda *a:pytest.fail('unsafe alert write before adoption'))
    monkeypatch.setattr(fleet_upgrade,'run_selected_upgrade',lambda config,plan: calls.append(('selected',plan)) or {'success':True,'results':{}})
    result=CliRunner().invoke(cli.main,['upgrade'])
    assert result.exit_code==0
    assert calls==['selection-preflight',('selected',selected)]


def test_pre_adoption_unselected_upgrade_holds_before_alert_or_dispatch(monkeypatch,tmp_path):
    from dc_overview.fleet_config import FleetConfig
    from dc_overview import controller_adoption
    monkeypatch.setattr(cli,'DOCKER_CONFIG_DIR',tmp_path)
    monkeypatch.setattr(controller_adoption,'upgrade_requires_adoption',lambda:True)
    monkeypatch.setattr(cli.FleetConfig,'load',lambda *a:FleetConfig(config_dir=tmp_path))
    monkeypatch.setattr(fleet_upgrade,'preflight_release',lambda *a,**k:None)
    monkeypatch.setattr(cli,'_sync_alerts_for_upgrade',lambda *a:pytest.fail('unsafe alert write'))
    monkeypatch.setattr(fleet_upgrade,'run_fleet_upgrade',lambda *a,**k:pytest.fail('unselected dispatch'))
    result=CliRunner().invoke(cli.main,['upgrade'])
    assert result.exit_code!=0 and 'explicit selected' in result.output
