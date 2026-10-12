"""Synthetic post-build manifest contract; no real release facts or provider secrets."""
import hashlib
import importlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

DIGEST = 'a' * 64
OTHER = 'b' * 64


def catalog():
    return importlib.import_module('dc_overview.release_catalog')


def manifest_data():
    owners = {
        'dc-overview': ('proxy-updater','ghcr.io/cryptolabsza/dc-overview'),
        'cryptolabs-proxy': ('proxy-updater','ghcr.io/cryptolabsza/cryptolabs-proxy'),
        'prometheus': ('proxy-updater','prom/prometheus'),
        'grafana': ('proxy-updater','grafana/grafana'),
    }
    components = {name:{'release':'synthetic-1','owner':owner,'artifacts':{'linux/amd64':{'kind':'oci','reference':f'{repo}@sha256:{DIGEST}'}}} for name,(owner,repo) in owners.items()}
    return {'schema_version':1,'selection_contract':1,'baseline_id':'synthetic-baseline','components':components}


def encoded(value):
    return json.dumps(value, indent=2).encode()


def selection(data, **policies):
    raw = encoded(data)
    return {'schema_version':1,'selection_id':'synthetic-selection','manifest_sha256':hashlib.sha256(raw).hexdigest(),
            'components':{name:policies.get(name,{'origin':'baseline','enabled':True}) for name in data['components']}}


def test_exact_manifest_bytes_hash_and_roundtrip():
    raw = encoded(manifest_data())
    value = catalog().Manifest.from_bytes(raw)
    assert value.sha256 == hashlib.sha256(raw).hexdigest()
    assert value.raw == raw
    compact = json.dumps(manifest_data()).encode()
    assert catalog().Manifest.from_bytes(compact).sha256 != value.sha256


@pytest.mark.parametrize('bad', ['schema','contract','owner','repository','platform','digest','command','unknown','duplicate','url'])
def test_manifest_rejects_untrusted_or_unknown_contract(bad):
    value = manifest_data()
    item = value['components']['dc-overview']
    if bad == 'schema': value['schema_version'] = True
    if bad == 'contract': value['selection_contract'] = 2
    if bad == 'owner': item['owner'] = 'run-shell'
    if bad == 'repository': item['artifacts']['linux/amd64']['reference'] = f'evil.invalid/dc-overview@sha256:{DIGEST}'
    if bad == 'platform': item['artifacts'] = {'solar/quantum':item['artifacts']['linux/amd64']}
    if bad == 'digest': item['artifacts']['linux/amd64']['reference'] = 'ghcr.io/cryptolabsza/dc-overview:latest'
    if bad == 'command': item['command'] = 'docker rm all'
    if bad == 'unknown': value['components']['unknown'] = item
    if bad == 'url': value['components']['dc-overview-cli'] = {'release':'1.4.0','owner':'host-cli','artifacts':{'any':{'kind':'wheel','url':'https://evil.invalid/release.whl','sha256':DIGEST}}}
    raw = encoded(value)
    if bad == 'duplicate': raw = b'{"schema_version":1,"schema_version":2,"selection_contract":1,"baseline_id":"x","components":{}}'
    with pytest.raises(ValueError): catalog().Manifest.from_bytes(raw)


def test_missing_platform_blocks_instead_of_falling_back():
    data = manifest_data()
    with pytest.raises(ValueError,match='platform'):
        catalog().resolve(catalog().Manifest.from_bytes(encoded(data)), selection(data), 'linux/arm64')


def test_baseline_digest_can_move_but_customer_pin_cannot():
    data = manifest_data()
    old_ref = data['components']['dc-overview']['artifacts']['linux/amd64']['reference']
    data['components']['dc-overview']['artifacts']['linux/amd64']['reference'] = old_ref.replace(DIGEST, OTHER)
    resolved = catalog().resolve(catalog().Manifest.from_bytes(encoded(data)), selection(data), 'linux/amd64')
    assert resolved['dc-overview']['reference'].endswith(OTHER)
    pinned = selection(data, **{'dc-overview':{'origin':'customer-pin','enabled':True,'pin':old_ref}})
    with pytest.raises(ValueError,match='pin_conflict'):
        catalog().resolve(catalog().Manifest.from_bytes(encoded(data)), pinned, 'linux/amd64')


def test_unmanaged_enabled_role_and_missing_required_component_block():
    data = manifest_data()
    with pytest.raises(ValueError,match='unmanaged'):
        catalog().resolve(catalog().Manifest.from_bytes(encoded(data)),selection(data, **{'dc-overview':{'origin':'unmanaged','enabled':True}}),'linux/amd64')
    with pytest.raises(ValueError,match='required'):
        catalog().resolve(catalog().Manifest.from_bytes(encoded(data)),selection(data),'linux/amd64',required_components={'vast-price-manager'})


def test_disabled_optional_role_remains_disabled_and_requires_no_platform():
    data = manifest_data()
    data['components']['runpod-exporter'] = {'release':'test','owner':'proxy-updater','artifacts':{'linux/arm64':{'kind':'oci','reference':f'ghcr.io/cryptolabsza/runpod-exporter@sha256:{DIGEST}'}}}
    result = catalog().resolve(catalog().Manifest.from_bytes(encoded(data)), selection(data, **{'runpod-exporter':{'origin':'baseline','enabled':False}}),'linux/amd64')
    assert 'runpod-exporter' not in result


def test_selection_hash_mismatch_and_policy_injection_fail():
    data = manifest_data()
    policy = selection(data)
    policy['manifest_sha256'] = OTHER
    with pytest.raises(ValueError,match='hash'):
        catalog().resolve(catalog().Manifest.from_bytes(encoded(data)),policy,'linux/amd64')
    policy = selection(data)
    policy['components']['dc-overview']['command'] = 'evil'
    with pytest.raises(ValueError):
        catalog().resolve(catalog().Manifest.from_bytes(encoded(data)),policy,'linux/amd64')


def test_store_is_exact_immutable_and_hashes_selection_bytes(tmp_path, monkeypatch):
    mod = catalog()
    monkeypatch.setattr(mod, '_require_root', lambda:None)
    monkeypatch.setattr(mod, '_check_root_path', lambda *a, **k:None)
    monkeypatch.setattr(mod.os,'chown',lambda *a:None)
    monkeypatch.setattr(mod.os,'fchown',lambda *a:None)
    source = tmp_path/'published.json'
    raw = encoded(manifest_data())
    source.write_bytes(raw)
    store = mod.ReleaseStore(tmp_path/'releases')
    prepared = store.prepare(source, platform='linux/amd64')
    assert not store.root.exists(), 'preflight cannot write selection'
    store.commit(prepared)
    assert (store.root/'manifests'/f'{hashlib.sha256(raw).hexdigest()}.json').read_bytes() == raw
    assert (store.root/'selection.json').read_bytes() == prepared.selection_raw
    assert prepared.selection_sha256 == hashlib.sha256(prepared.selection_raw).hexdigest()
    assert store.load(platform='linux/amd64').targets == prepared.targets
    stored = store.root/'manifests'/f'{hashlib.sha256(raw).hexdigest()}.json'
    stored.write_bytes(raw+b'\n')
    with pytest.raises(ValueError,match='hash'):
        store.load(platform='linux/amd64')


def test_store_rejects_nonroot_and_world_writable_sources(tmp_path, monkeypatch):
    mod = catalog()
    monkeypatch.setattr(mod.os,'geteuid',lambda:1000)
    with pytest.raises(PermissionError): mod.ReleaseStore(tmp_path/'releases').commit(Mock())
    unsafe = tmp_path/'unsafe'
    unsafe.write_text('public nonsecret')
    unsafe.chmod(0o666)
    with pytest.raises(PermissionError): mod._check_root_path(unsafe)


def test_upgrade_preflight_stops_old_proxy_before_any_selection_write(tmp_path, monkeypatch):
    from dc_overview import fleet_upgrade
    from dc_overview.fleet_config import FleetConfig
    mod = catalog()
    monkeypatch.setattr(mod,'_check_root_path',lambda *a,**k:None)
    source = tmp_path/'published.json'; source.write_bytes(encoded(manifest_data()))
    config = FleetConfig(config_dir=tmp_path/'config')
    monkeypatch.setattr(fleet_upgrade,'proxy_capabilities',lambda **k:{'selection_contract':0})
    with pytest.raises(RuntimeError,match='proxy'):
        fleet_upgrade.preflight_release(config, source, platform='linux/amd64')
    assert not (config.config_dir/'releases').exists()


def test_cli_manifest_failure_happens_before_alert_mutation(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from dc_overview import cli
    source=tmp_path/'bad.json';source.write_text('{}')
    mutate=Mock()
    monkeypatch.setattr(cli,'_sync_alerts_for_upgrade',mutate)
    result=CliRunner().invoke(cli.main,['upgrade','--release-manifest',str(source)])
    assert result.exit_code != 0
    assert 'No such option' not in result.output
    mutate.assert_not_called()


def test_config_release_selection_and_vpm_custody_roundtrip(tmp_path, monkeypatch):
    from dc_overview.fleet_config import FleetConfig
    mod = catalog()
    config = FleetConfig(config_dir=tmp_path)
    config.release_selection.selection_id='synthetic-selection'
    config.release_selection.selection_sha256=DIGEST
    config.release_selection.components={'runpod-exporter':{'origin':'baseline','enabled':False}}
    config.vast_price_manager.data_source='/var/lib/customer-vpm'
    config.vast_price_manager.data_kind='bind'
    config.vast_price_manager.credential_mode='systemd-encrypted'
    config.vast_price_manager.credential_reference='/etc/customer/vpm.cred'
    config.vast_price_manager.layout={'project_name':'customer-project'}
    monkeypatch.setattr('dc_overview.fleet_config.os.chown',lambda *a:None)
    config.save()
    restored=FleetConfig.load(tmp_path)
    assert restored.release_selection == config.release_selection
    assert restored.vast_price_manager.data_source == '/var/lib/customer-vpm'
    assert restored.vast_price_manager.credential_mode == 'systemd-encrypted'
    assert restored.vast_price_manager.layout == {'project_name':'customer-project'}
    public=(tmp_path/'fleet-config.yaml').read_text()
    assert 'vpm.cred' in public
    assert 'synthetic-password' not in public


def test_cli_exact_wheel_prerequisite_is_explicit(monkeypatch):
    from dc_overview import fleet_upgrade
    target={'release':'999.0.0','kind':'wheel','url':'https://github.com/cryptolabsza/dc-overview/releases/download/v999.0.0/dc_overview.whl','sha256':DIGEST}
    with pytest.raises(RuntimeError,match='requires_cli_upgrade'):
        fleet_upgrade.verify_running_cli(target)


def test_selection_upgrade_does_not_confuse_proxy_success_with_suite_completion(monkeypatch, tmp_path):
    from dc_overview import fleet_upgrade
    from dc_overview.fleet_config import FleetConfig
    data=manifest_data()
    data['components']['vast-price-manager']={'release':'test','owner':'dc-vpm','artifacts':{'linux/amd64':{'kind':'oci','reference':f'ghcr.io/cryptolabsza/vast-price-manager@sha256:{DIGEST}'}}}
    manifest=catalog().Manifest.from_bytes(encoded(data))
    targets=catalog().resolve(manifest,selection(data),'linux/amd64')
    prepared=SimpleNamespace(selection=selection(data),selection_sha256=DIGEST,manifest=manifest,targets=targets)
    job=Mock(return_value={'success':True,'results':{'dc-overview':{'success':True}}})
    monkeypatch.setattr(fleet_upgrade,'run_fleet_upgrade',job)
    monkeypatch.setattr(fleet_upgrade,'dispatch_vpm',lambda *a:{'success':False,'state':'blocked','reason':'synthetic health failure'})
    config=FleetConfig(config_dir=tmp_path)
    result=fleet_upgrade.run_selected_upgrade(config,prepared)
    assert result['success'] is False
    assert result['suite_complete'] is False
    assert result['external_owners']['vast-price-manager']['success'] is False
    assert job.call_args.kwargs['selection_id'] == 'synthetic-selection'
    assert job.call_args.kwargs['selection_sha256'] == DIGEST


def test_selected_proxy_job_identity_is_carried_through_submit(monkeypatch):
    from dc_overview import fleet_upgrade
    replies=iter([{'selection_contract':1,'proxy_replacement_policy':'host-adoption-required-v1'}, {'id':'synthetic-job'}, {'state':'completed','success':True,'results':{}}])
    calls=[]
    def updater(*args): calls.append(args);return next(replies)
    monkeypatch.setattr(fleet_upgrade,'_updater',updater)
    result=fleet_upgrade.run_fleet_upgrade('main',selection_id='synthetic-selection',selection_sha256=DIGEST)
    assert result['success'] is True
    assert calls[0] == ('capabilities',)
    assert '--selection-id' in calls[1]
    assert '--selection-sha256' in calls[1]
    assert DIGEST in calls[1]


def test_selected_rendering_uses_manifest_digests_and_defers_watchtower(monkeypatch):
    from dc_overview.fleet_config import FleetConfig
    from dc_overview.fleet_manager import FleetManager
    config=FleetConfig()
    config.enable_watchtower_all=True
    config.ssl.use_existing_proxy=True
    manager=FleetManager(config)
    data=manifest_data(); manifest=catalog().Manifest.from_bytes(encoded(data))
    manager.release_plan=SimpleNamespace(targets=catalog().resolve(manifest,selection(data),'linux/amd64'))
    import yaml
    rendered=yaml.safe_load(manager._generate_docker_compose())
    for name in ('dc-overview','prometheus','grafana'):
        assert rendered['services'][name]['image'] == manager.release_plan.targets[name]['reference']
        assert rendered['services'][name]['labels']['com.centurylinklabs.watchtower.enable'] == 'false'


def test_invalid_setup_manifest_stops_before_prerequisites_or_config_write(tmp_path, monkeypatch):
    from dc_overview.fleet_manager import FleetManager
    from dc_overview.fleet_config import FleetConfig
    config=FleetConfig(config_dir=tmp_path/'config')
    config.release_selection.selection_id='required-selection'
    config.release_selection.selection_sha256=DIGEST
    manager=FleetManager(config)
    prerequisites=Mock()
    for method in ('_setup_ssh_keys','_deploy_prometheus_grafana','_configure_prometheus_targets','_import_dashboards','_setup_reverse_proxy','_setup_security_hardening','_show_completion'):
        monkeypatch.setattr(manager,method,Mock())
    monkeypatch.setattr(manager,'_install_prerequisites',prerequisites)
    assert manager.deploy() is False
    prerequisites.assert_not_called()
    assert not config.config_dir.exists()


def test_vpm_dispatch_preserves_declared_data_and_encrypted_custody(tmp_path, monkeypatch):
    from dc_overview import fleet_upgrade, vpm_service
    from dc_overview.fleet_config import FleetConfig
    config=FleetConfig(config_dir=tmp_path)
    config.ssl.domain='synthetic.example'
    config.vast_price_manager.data_source='/var/lib/customer-vpm'
    config.vast_price_manager.data_kind='bind'
    config.vast_price_manager.credential_mode='systemd-encrypted'
    config.vast_price_manager.credential_reference='/etc/customer/vpm.cred'
    config.vast_price_manager.layout={'project_name':'customer-project','container_name':'customer-vpm','compose_file':'/etc/customer/assembly.yml','data_source':'/var/lib/customer-vpm','data_kind':'bind','master_key_file':'/run/credentials/customer-vpm/master-key','credential_mode':'systemd-encrypted','credential_reference':'/etc/customer/vpm.cred'}
    manager=Mock()
    manager.adopt.return_value={'status':'adopted','state_preserved':True}
    manager.is_adopted.return_value=False
    manager.adopted_spec.side_effect=vpm_service.VPMServiceManager.adopted_spec
    manager.current_managed_image.return_value=f'ghcr.io/cryptolabsza/vast-price-manager@sha256:{DIGEST}'
    factory=Mock(return_value=manager);factory._adoption_spec=vpm_service.VPMServiceManager._adoption_spec
    monkeypatch.setattr(vpm_service,'VPMServiceManager',factory)
    result=fleet_upgrade.dispatch_vpm(config,{'reference':f'ghcr.io/cryptolabsza/vast-price-manager@sha256:{DIGEST}','release':'test','owner':'dc-vpm'})
    assert result['success'] is True
    spec,layout=manager.adopt.call_args.args
    assert spec.data_source == '/var/lib/customer-vpm'
    assert spec.credential_mode == 'systemd-encrypted'
    assert layout.project_name == 'customer-project'
    assert manager.operation_lock.call_count == 0, 'adopt owns its lock'


def test_baseline_proxy_setup_reconciles_even_when_credentials_match(monkeypatch):
    from dc_overview import fleet_manager
    from dc_overview.fleet_config import FleetConfig
    config=FleetConfig();config.ssl.domain='synthetic.example';config.fleet_admin_pass='synthetic-password'
    config.release_selection.selection_id='selected';config.release_selection.selection_sha256=DIGEST
    manager=fleet_manager.FleetManager(config)
    monkeypatch.setattr(fleet_manager,'HAS_PROXY_MODULE',True)
    monkeypatch.setattr(fleet_manager,'get_proxy_config',lambda:{'FLEET_ADMIN_USER':'admin','FLEET_ADMIN_PASS':'synthetic-password'},raising=False)
    setup=Mock(return_value=(True,'reconciled'))
    monkeypatch.setattr(fleet_manager,'proxy_setup',setup,raising=False)
    monkeypatch.setattr(fleet_manager,'ProxyConfig',lambda **kw:SimpleNamespace(**kw),raising=False)
    monkeypatch.setattr(fleet_manager.subprocess,'run',Mock(return_value=SimpleNamespace(returncode=0,stdout='',stderr='')))
    manager._integrate_with_proxy()
    assert setup.call_count == 1
    assert setup.call_args.args[0].release_selection_dir == config.config_dir/'releases'


def test_monitoring_declarations_roundtrip_without_credential_values(tmp_path, monkeypatch):
    from dc_overview.fleet_config import FleetConfig
    config=FleetConfig(config_dir=tmp_path)
    config.prometheus.extra_scrape_configs=[{'job_name':'customer','static_configs':[{'targets':['192.0.2.20:9100']}],'bearer_token_file':'/etc/prometheus/customer/token.ref'}]
    config.prometheus.rule_files=['/etc/prometheus/customer/rules.yml']
    config.prometheus.customer_config_dir='/etc/customer/monitoring'
    config.prometheus.legacy_managed_jobs=['retired-product-job']
    config.grafana.customer_dashboard_dir='/etc/customer/dashboards'
    config.grafana.prometheus_datasource_uid='customer-stable-prometheus'
    config.grafana.overwrite_product_dashboards=False
    monkeypatch.setattr('dc_overview.fleet_config.os.chown',lambda *a:None)
    config.save()
    restored=FleetConfig.load(tmp_path)
    assert restored.prometheus.extra_scrape_configs == config.prometheus.extra_scrape_configs
    assert restored.prometheus.rule_files == config.prometheus.rule_files
    assert restored.prometheus.customer_config_dir == config.prometheus.customer_config_dir
    assert restored.prometheus.legacy_managed_jobs == config.prometheus.legacy_managed_jobs
    assert restored.grafana.customer_dashboard_dir == '/etc/customer/dashboards'
    assert restored.grafana.prometheus_datasource_uid == 'customer-stable-prometheus'


def test_baseline_direct_launches_use_selected_references_and_watchtower_false(monkeypatch):
    from dc_overview.fleet_config import FleetConfig
    from dc_overview.fleet_manager import FleetManager
    config=FleetConfig();config.enable_watchtower_all=True
    manager=FleetManager(config)
    manager.release_plan=SimpleNamespace(targets={'ipmi-monitor':{'kind':'oci','reference':f'ghcr.io/cryptolabsza/ipmi-monitor@sha256:{DIGEST}'}})
    assert manager._selected_image('ipmi-monitor','floating:latest').endswith(DIGEST)
    assert manager._watchtower_args() == ['--label','com.centurylinklabs.watchtower.enable=false']
    with pytest.raises(ValueError,match='Missing'):
        manager._selected_image('runpod-exporter','floating:latest')


def test_baseline_dashboard_loading_cannot_fall_back_to_moving_github(monkeypatch):
    from dc_overview.fleet_config import FleetConfig
    from dc_overview.fleet_manager import FleetManager
    manager=FleetManager(FleetConfig())
    manager.release_plan=SimpleNamespace(targets={})
    fetch=Mock()
    monkeypatch.setattr('dc_overview.fleet_manager.urllib.request.urlopen',fetch)
    assert manager._get_dashboard_json({'local_file':'absent-customer-product.json','github_url':'https://example.invalid/moving'}) is None
    fetch.assert_not_called()


def test_binary_and_wheel_customer_pins_are_bare_sha256():
    data=manifest_data()
    data['components']['dc-overview-cli']={'release':'1.4.0','owner':'host-cli','artifacts':{'any':{'kind':'wheel','url':'https://github.com/cryptolabsza/dc-overview/releases/download/v1.4.0/dc_overview-1.4.0-py3-none-any.whl','sha256':DIGEST}}}
    plan=catalog().resolve(catalog().Manifest.from_bytes(encoded(data)),selection(data,**{'dc-overview-cli':{'origin':'customer-pin','enabled':True,'pin':DIGEST}}),'linux/amd64')
    assert catalog().artifact_identity(plan['dc-overview-cli']) == DIGEST


def test_baseline_setup_uses_verified_worker_coordinator_and_fails_partial(tmp_path,monkeypatch):
    from dc_overview.fleet_config import FleetConfig,Server
    from dc_overview.fleet_manager import FleetManager
    from dc_overview import worker_lifecycle
    config=FleetConfig(config_dir=tmp_path);config.servers=[Server(name='synthetic-worker',server_ip='192.0.2.10',exporters_installed=True)]
    manager=FleetManager(config);manager.release_plan=SimpleNamespace(targets={'dc-exporter':{'owner':'dc-worker'},'node-exporter':{'owner':'dc-worker'}})
    coordinator=Mock(return_value={'dc-exporter':{'success':True,'workers':{'synthetic-worker':{'success':True}}},'node-exporter':{'success':False,'workers':{'synthetic-worker':{'success':False}}}})
    monkeypatch.setattr(worker_lifecycle,'upgrade_workers',coordinator)
    monkeypatch.setattr(manager,'_install_exporters_on_server',Mock(side_effect=AssertionError('must use selected coordinator')))
    manager.deployment_errors=[]
    manager._deploy_to_workers()
    assert coordinator.call_args.kwargs['mode'] == 'install'
    assert manager.deployment_errors
    assert config.servers[0].exporters_installed is True, 'failed verification retains previous observation'


def test_adoption_persists_canonical_declared_refs_then_routine_install(tmp_path,monkeypatch):
    from dc_overview import fleet_upgrade,vpm_service
    from dc_overview.fleet_config import FleetConfig
    config=FleetConfig(config_dir=tmp_path);config.ssl.domain='fleet.example.invalid'
    config.vast_price_manager.layout={'project_name':'customer','container_name':'customer-vpm','compose_file':'/etc/customer/compose.yml','data_source':'/var/lib/customer-vpm','data_kind':'bind','master_key_file':'/run/credentials/customer/master-key','credential_mode':'systemd-encrypted','credential_reference':'/etc/customer/master.cred'}
    config.persist_lifecycle=Mock()
    manager=Mock();manager.current_managed_image.return_value=f'ghcr.io/cryptolabsza/vast-price-manager@sha256:{DIGEST}'
    manager.adopt.return_value={'status':'adopted','state_preserved':True}
    manager.is_adopted.return_value=False
    manager.adopted_spec.side_effect=vpm_service.VPMServiceManager.adopted_spec
    manager.operation_lock.return_value.__enter__=Mock();manager.operation_lock.return_value.__exit__=Mock(return_value=False)
    factory=Mock(return_value=manager);factory._adoption_spec=vpm_service.VPMServiceManager._adoption_spec
    monkeypatch.setattr(vpm_service,'VPMServiceManager',factory)
    wanted={'reference':manager.current_managed_image.return_value,'owner':'dc-vpm','release':'test'}
    assert fleet_upgrade.dispatch_vpm(config,wanted)['success']
    assert config.vast_price_manager.layout is None
    assert config.vast_price_manager.data_source == '/var/lib/customer-vpm'
    assert config.vast_price_manager.credential_mode == 'systemd-encrypted'
    assert config.vast_price_manager.master_key_file == '/run/credentials/vast-price-manager-container.service/vpm-master.key'
    config.persist_lifecycle.assert_called_once()
    assert fleet_upgrade.dispatch_vpm(config,wanted)['success']
    assert manager.adopt.call_count == 1
    assert manager.install.call_count == 1


def test_baseline_setup_vpm_uses_selected_owner_and_never_creates_second_plaintext_key(tmp_path,monkeypatch):
    from dc_overview.fleet_config import FleetConfig
    from dc_overview.fleet_manager import FleetManager
    from dc_overview import fleet_upgrade,vpm_service
    config=FleetConfig(config_dir=tmp_path);config.ssl.domain='fleet.example.invalid'
    config.vast_price_manager.credential_mode='systemd-encrypted';config.vast_price_manager.credential_reference='/etc/customer/master.cred'
    manager=FleetManager(config);manager.release_plan=SimpleNamespace(targets={'vast-price-manager':{'reference':f'ghcr.io/cryptolabsza/vast-price-manager@sha256:{DIGEST}'}})
    key=Mock(side_effect=AssertionError('must preserve declared custody'))
    monkeypatch.setattr(vpm_service,'create_master_key_if_missing',key)
    owner=Mock(return_value={'success':True,'state':'verified'})
    monkeypatch.setattr(fleet_upgrade,'dispatch_vpm',owner)
    manager._deploy_vast_price_manager()
    assert owner.call_args.args == (config,manager.release_plan.targets['vast-price-manager'])
    assert owner.call_args.kwargs['setup'] is True
    key.assert_not_called()


def test_observed_identity_reports_exact_artifact_and_unknown_explicitly(monkeypatch):
    from dc_overview import fleet_upgrade
    desired=f'ghcr.io/cryptolabsza/dc-overview@sha256:{DIGEST}'
    monkeypatch.setattr(fleet_upgrade.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=0,stdout=json.dumps({'Config':{'Image':desired},'State':{'Running':True}})))
    assert fleet_upgrade.observe_component('dc-overview',{'owner':'proxy-updater','kind':'oci','reference':desired}) == {'identity':desired,'state':'running','matches':True}
    assert fleet_upgrade.observe_component('dc-exporter',{'owner':'dc-worker','kind':'binary','sha256':DIGEST}) == {'identity':None,'state':'unknown','matches':None}


def test_lifecycle_public_persistence_preserves_secret_authority_and_unrelated_fields(tmp_path):
    from dc_overview.fleet_config import FleetConfig
    public=tmp_path/'fleet-config.yaml';public.write_text('site_name: customer\nunknown_customer: keep\n');public.chmod(0o640)
    secret=tmp_path/'.secrets.yaml';secret.write_text('scrubbed_authority: keep-exact\n');secret.chmod(0o600)
    config=FleetConfig(config_dir=tmp_path);config.release_selection.selection_id='synthetic-selection'
    config.persist_lifecycle(expected_public=public.read_bytes())
    assert secret.read_text() == 'scrubbed_authority: keep-exact\n'
    assert 'unknown_customer: keep' in public.read_text()
    assert public.stat().st_mode & 0o777 == 0o640
    assert list(tmp_path.glob('fleet-config.lifecycle-*.bak'))
    previous=public.read_bytes();public.write_text('concurrent_customer: new\n')
    with pytest.raises(RuntimeError,match='changed'):
        config.persist_lifecycle(expected_public=previous)
    assert public.read_text() == 'concurrent_customer: new\n'


def test_monitoring_collision_blocks_setup_before_any_mutation(tmp_path,monkeypatch):
    from dc_overview.fleet_config import FleetConfig
    from dc_overview.fleet_manager import FleetManager
    from dc_overview import fleet_upgrade
    config=FleetConfig(config_dir=tmp_path);config.prometheus.extra_scrape_configs=[{'job_name':'dc-managed','static_configs':[{'targets':['192.0.2.1:9999']}]}]
    manager=FleetManager(config);plan=SimpleNamespace(targets={})
    monkeypatch.setattr(fleet_upgrade,'preflight_release',lambda *a,**k:plan)
    commit=Mock();monkeypatch.setattr(fleet_upgrade,'commit_release',commit)
    mutation=Mock();monkeypatch.setattr(manager,'_install_prerequisites',mutation)
    for name in ('_setup_ssh_keys','_deploy_prometheus_grafana','_configure_prometheus_targets','_import_dashboards','_setup_reverse_proxy','_setup_security_hardening','_show_completion','_deploy_vast_exporter','_deploy_runpod_exporter','_deploy_ipmi_monitor'):
        monkeypatch.setattr(manager,name,Mock())
    assert manager.deploy() is False
    mutation.assert_not_called();commit.assert_not_called()


def test_baseline_compose_mounts_product_directory_and_customer_refs_readonly(tmp_path):
    from dc_overview.fleet_config import FleetConfig
    from dc_overview.fleet_manager import FleetManager
    import yaml
    config=FleetConfig(config_dir=tmp_path);config.prometheus.customer_config_dir=str(tmp_path/'customer')
    config.ssl.use_existing_proxy=True
    manager=FleetManager(config);data=manifest_data();manager.release_plan=SimpleNamespace(targets=catalog().resolve(catalog().Manifest.from_bytes(encoded(data)),selection(data),'linux/amd64'))
    value=yaml.safe_load(manager._generate_docker_compose())
    assert './prometheus:/etc/prometheus:ro' in value['services']['prometheus']['volumes']
    assert str(tmp_path/'customer')+':/etc/prometheus/customer:ro' in value['services']['prometheus']['volumes']
    assert './prometheus:/etc/dc-overview/prometheus' in value['services']['dc-overview']['volumes']
    assert not any('/prometheus.yml:/etc/prometheus/' in mount for mount in value['services']['prometheus']['volumes'])


def test_selected_prometheus_validation_precedes_every_monitoring_file_write(tmp_path,monkeypatch):
    from dc_overview.fleet_config import FleetConfig
    from dc_overview.fleet_manager import FleetManager
    config=FleetConfig(config_dir=tmp_path);manager=FleetManager(config)
    manager.release_plan=SimpleNamespace(targets={});manager.monitoring_plan={'prometheus':{'scrape_configs':[]},'grafana':{'prometheus_datasource_uid':'existing-uid'}}
    old=tmp_path/'docker-compose.yml';old.write_text('existing compose')
    monkeypatch.setattr(manager,'_generate_docker_compose',lambda:'synthetic proposed compose')
    monkeypatch.setattr(manager,'_validate_baseline_prometheus',lambda *a:False)
    with pytest.raises(RuntimeError,match='validation'):
        manager._deploy_prometheus_grafana()
    assert old.read_text() == 'existing compose'
    assert not (tmp_path/'prometheus').exists()


def test_selected_monitoring_preserves_customer_job_and_datasource_uid(tmp_path,monkeypatch):
    from dc_overview.fleet_config import FleetConfig
    from dc_overview.fleet_manager import FleetManager
    from dc_overview import fleet_upgrade
    config=FleetConfig(config_dir=tmp_path);config.components.vast_exporter=False
    (tmp_path/'prometheus.yml').write_text('global:\n  scrape_interval: 37s\nscrape_configs:\n- job_name: customer\n  static_configs:\n  - targets: [192.0.2.70:9000]\n')
    manager=FleetManager(config);manager.release_plan=SimpleNamespace(targets={})
    monkeypatch.setattr(fleet_upgrade,'observe_component',lambda *a:{'state':'running'})
    source={'type':'prometheus','uid':'customer-stable','isDefault':True,'url':'http://customer-prometheus:9090'}
    monkeypatch.setattr(manager,'_grafana_request',lambda path: [source] if path == '/api/datasources' else [{'uid':'dc-overview-main'}])
    prepared=manager._prepare_baseline_monitoring()
    assert prepared['prometheus']['global']['scrape_interval'] == '37s'
    assert prepared['prometheus']['scrape_configs'][0]['job_name'] == 'customer'
    assert prepared['grafana']['prometheus_datasource_uid'] == 'customer-stable'
    assert prepared['grafana']['existing_datasource'] == source
    assert 'dc-overview-main' in prepared['grafana']['skipped_uids']


def test_unlabeled_existing_immutable_images_default_to_customer_pin(monkeypatch,tmp_path):
    from dc_overview import fleet_upgrade
    from dc_overview.fleet_config import FleetConfig
    desired=manifest_data();manifest=catalog().Manifest.from_bytes(encoded(desired));existing=f'ghcr.io/cryptolabsza/dc-overview@sha256:{OTHER}'
    def inspect(command,**kwargs):
        name=command[3]
        return SimpleNamespace(returncode=0,stdout=json.dumps({'Config':{'Image':existing,'Labels':{}},'State':{'Running':True}})) if name == 'dc-overview' else SimpleNamespace(returncode=1,stdout='',stderr=f'No such object: {name}')
    monkeypatch.setattr(fleet_upgrade.subprocess,'run',inspect)
    policy=fleet_upgrade.adopt_existing_policies(FleetConfig(config_dir=tmp_path),manifest,{})
    assert policy['dc-overview'] == {'origin':'customer-pin','enabled':True,'pin':existing}
    with pytest.raises(ValueError,match='pin_conflict'):
        catalog().resolve(manifest,selection(desired,**policy),'linux/amd64')
    explicit={'dc-overview':{'origin':'baseline','enabled':True}}
    assert fleet_upgrade.adopt_existing_policies(FleetConfig(config_dir=tmp_path),manifest,explicit)['dc-overview'] == explicit['dc-overview']


def test_exact_wheel_provenance_accepts_selected_cli_without_self_replace(monkeypatch):
    from dc_overview import fleet_upgrade,__version__
    import importlib.metadata
    url=f'https://github.com/cryptolabsza/dc-overview/releases/download/v{__version__}/dc_overview.whl'
    distribution=SimpleNamespace(version=__version__,read_text=lambda name:json.dumps({'url':url,'archive_info':{'hashes':{'sha256':DIGEST}}}))
    monkeypatch.setattr(importlib.metadata,'distribution',lambda *a:distribution)
    target={'release':__version__,'url':url,'sha256':DIGEST}
    assert fleet_upgrade.verify_running_cli(target)['success'] is True
    target['sha256']=OTHER
    with pytest.raises(RuntimeError,match='requires_cli_upgrade'):
        fleet_upgrade.verify_running_cli(target)


def test_selected_direct_dc_container_has_product_config_directory_mount(tmp_path,monkeypatch):
    from dc_overview.fleet_config import FleetConfig
    from dc_overview.fleet_manager import FleetManager
    from dc_overview import fleet_manager
    config=FleetConfig(config_dir=tmp_path);config.components.ipmi_monitor=False
    manager=FleetManager(config);manager.release_plan=SimpleNamespace(targets={'dc-overview':{'kind':'oci','reference':f'ghcr.io/cryptolabsza/dc-overview@sha256:{DIGEST}'}})
    run=Mock(return_value=SimpleNamespace(returncode=0,stdout='',stderr=''))
    monkeypatch.setattr(fleet_manager.subprocess,'run',run)
    monkeypatch.setattr(manager,'_wait_for_container',lambda *a,**k:True)
    monkeypatch.setattr(manager,'_populate_dc_overview_servers',lambda:None)
    monkeypatch.setattr(fleet_manager.time,'sleep',lambda *a:None)
    manager._deploy_dc_overview_container()
    command=next(call.args[0] for call in run.call_args_list if call.args[0][:2] == ['docker','run'])
    assert str(tmp_path/'prometheus')+':/etc/dc-overview/prometheus' in command
    assert 'PROMETHEUS_CONFIG_PATH=/etc/dc-overview/prometheus/prometheus.yml' in command
    assert 'com.centurylinklabs.watchtower.enable=false' in command


def test_selected_server_population_does_not_mark_failed_agent_as_installed(tmp_path,monkeypatch):
    from dc_overview.fleet_config import FleetConfig,Server
    from dc_overview.fleet_manager import FleetManager
    from dc_overview import fleet_manager
    config=FleetConfig(config_dir=tmp_path);config.servers=[Server(name='synthetic-worker',server_ip='192.0.2.10')]
    config.watchdog.api_key='synthetic-account-key';config.components.dc_watchdog=True
    manager=FleetManager(config);manager.release_plan=SimpleNamespace(targets={})
    manager.worker_outcomes={'dc-watchdog-agent':{'workers':{'synthetic-worker':{'success':False}}}}
    run=Mock(return_value=SimpleNamespace(returncode=0,stdout='{}',stderr=''))
    monkeypatch.setattr(fleet_manager.subprocess,'run',run)
    monkeypatch.setattr(manager,'_wait_for_container',lambda *a,**k:True)
    monkeypatch.setattr(fleet_manager.time,'sleep',lambda *a:None)
    manager._populate_dc_overview_servers()
    requests=[call.args[0] for call in run.call_args_list if '-d' in call.args[0] and '/api/servers' in ' '.join(call.args[0])]
    posted=json.loads(requests[0][requests[0].index('-d')+1])
    assert posted.get('watchdog_agent_installed') is not True


def test_manifest_wizard_distinguishes_baseline_default_from_customer_vpm_pin(tmp_path,monkeypatch):
    from dc_overview import fleet_wizard
    wizard=fleet_wizard.FleetWizard(config_dir=tmp_path)
    wizard.config._release_manifest_path=tmp_path/'suite-release.json'
    monkeypatch.setattr(fleet_wizard.questionary,'select',lambda *a,**k:SimpleNamespace(ask=lambda:'default'))
    wizard._select_vpm_image()
    assert wizard.config.release_selection.components['vast-price-manager'] == {'origin':'baseline','enabled':True}
    monkeypatch.setattr(fleet_wizard.questionary,'select',lambda *a,**k:SimpleNamespace(ask=lambda:'custom'))
    custom=f'ghcr.io/cryptolabsza/vast-price-manager@sha256:{OTHER}'
    monkeypatch.setattr(fleet_wizard.questionary,'text',lambda *a,**k:SimpleNamespace(ask=lambda:custom))
    assert wizard._select_vpm_image() == custom
    assert wizard.config.release_selection.components['vast-price-manager']['pin'] == custom


def test_unattended_config_honors_declared_release_storage_root(tmp_path,monkeypatch):
    from dc_overview.cli import load_config_from_file
    config_path=tmp_path/'input.yaml';directory=tmp_path/'installed-customer'
    config_path.write_text('config_dir: '+str(directory)+'\nfleet_admin_user: synthetic\nfleet_admin_pass: synthetic-password\ncomponents:\n  vast_exporter: false\n')
    config=load_config_from_file(str(config_path))
    assert config.config_dir == directory
    from dc_overview.fleet_upgrade import release_store
    assert release_store(config).root == directory/'releases'


def test_disabled_customer_pin_conflicts_still_fail_before_consumption():
    data=manifest_data()
    with pytest.raises(ValueError,match='pin_conflict'):
        catalog().resolve(catalog().Manifest.from_bytes(encoded(data)),selection(data,**{'dc-overview':{'origin':'customer-pin','enabled':False,'pin':f'ghcr.io/cryptolabsza/dc-overview@sha256:{OTHER}'}}),'linux/amd64')


def test_missing_host_wheel_has_explicit_cli_upgrade_prerequisite(tmp_path,monkeypatch):
    from dc_overview import fleet_upgrade
    from dc_overview.fleet_config import FleetConfig
    source=tmp_path/'manifest.json';source.write_bytes(encoded(manifest_data()))
    monkeypatch.setattr(fleet_upgrade,'proxy_capabilities',lambda **k:{'selection_contract':1,'proxy_replacement_policy':'host-adoption-required-v1'})
    with pytest.raises(RuntimeError,match='requires_cli_upgrade'):
        fleet_upgrade.preflight_release(FleetConfig(config_dir=tmp_path),source,platform='linux/amd64',fresh_setup=True)


def test_monitoring_preparation_retains_exact_source_snapshot(tmp_path,monkeypatch):
    from dc_overview.fleet_config import FleetConfig
    from dc_overview.fleet_manager import FleetManager
    from dc_overview import fleet_upgrade
    source=tmp_path/'prometheus.yml';raw=b'global: {scrape_interval: 37s}\nscrape_configs: []\n';source.write_bytes(raw)
    manager=FleetManager(FleetConfig(config_dir=tmp_path));manager.release_plan=SimpleNamespace(targets={})
    monkeypatch.setattr(fleet_upgrade,'observe_component',lambda *a:{'state':'unknown'})
    plan=manager._prepare_baseline_monitoring()
    assert plan['source_path'] == source
    assert plan['source_bytes'] == raw


def test_selection_cannot_override_an_intentional_component_disable(tmp_path):
    from dc_overview import fleet_upgrade
    from dc_overview.fleet_config import FleetConfig
    config=FleetConfig(config_dir=tmp_path);config.components.ipmi_monitor=False
    plan=SimpleNamespace(targets={'ipmi-monitor':{'owner':'proxy-updater'}})
    with pytest.raises(ValueError,match='disabled'):
        fleet_upgrade.validate_configured_roles(config,plan)


def test_release_storage_directory_must_be_absolute_without_parent_traversal():
    with pytest.raises(ValueError,match='absolute'):
        catalog().ReleaseStore(Path('relative-releases'))
    with pytest.raises(ValueError,match='parent'):
        catalog().ReleaseStore(Path('/etc/customer/../releases'))


def test_baseline_proxy_integration_cannot_use_legacy_mutation_fallback(tmp_path,monkeypatch):
    from dc_overview.fleet_config import FleetConfig
    from dc_overview.fleet_manager import FleetManager
    from dc_overview import fleet_manager
    manager=FleetManager(FleetConfig(config_dir=tmp_path));manager.release_plan=SimpleNamespace(targets={})
    mutation=Mock();monkeypatch.setattr(fleet_manager.subprocess,'run',mutation)
    with pytest.raises(RuntimeError,match='supported proxy'):
        manager._integrate_with_proxy_legacy('fleet.example.invalid')
    mutation.assert_not_called()
