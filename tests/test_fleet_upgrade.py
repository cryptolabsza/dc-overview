"""Host CLI delegates to the same durable updater as Fleet's web controls."""
import json
from types import SimpleNamespace
import pytest


def test_host_upgrade_polls_across_proxy_restart_without_recreating_containers(monkeypatch):
    from dc_overview.fleet_upgrade import run_fleet_upgrade
    calls=[]
    results=iter([{'id':'abc','state':'queued'}, None,
                  {'id':'abc','state':'completed','success':True,'results':{'dc-overview':{'success':True}}}])
    def run(command, **kwargs):
        calls.append(command)
        value=next(results)
        return SimpleNamespace(returncode=1 if value is None else 0,stdout=json.dumps(value),stderr='')
    monkeypatch.setattr('dc_overview.fleet_upgrade.subprocess.run',run)
    monkeypatch.setattr('dc_overview.fleet_upgrade.time.sleep',lambda _:None)
    assert run_fleet_upgrade('dev')['success'] is True
    assert all(c[:3]==['docker','exec','cryptolabs-proxy'] for c in calls)
    assert '--branch' in calls[0] and 'dev' in calls[0]


def test_host_upgrade_does_not_claim_partial_failure_success(monkeypatch):
    from dc_overview.fleet_upgrade import run_fleet_upgrade
    responses=iter([{'id':'abc','state':'queued'}, {'id':'abc','state':'failed','success':False,'results':{'grafana':{'success':False}}}])
    monkeypatch.setattr('dc_overview.fleet_upgrade.subprocess.run',lambda *a,**k:SimpleNamespace(returncode=0,stdout=json.dumps(next(responses)),stderr=''))
    monkeypatch.setattr('dc_overview.fleet_upgrade.time.sleep',lambda _:None)
    assert run_fleet_upgrade('main')['success'] is False


def test_host_upgrade_returns_final_interrupted_job_from_proxy_json_contract(monkeypatch):
    from dc_overview.fleet_upgrade import run_fleet_upgrade
    responses = iter([
        {'id': 'abc', 'state': 'queued', 'results': {}},
        {'id': 'abc', 'state': 'interrupted', 'success': False,
         'message': 'Update helper stopped before completion.', 'results': {}},
    ])
    monkeypatch.setattr('dc_overview.fleet_upgrade.subprocess.run',
                        lambda *a, **k: SimpleNamespace(returncode=0, stdout=json.dumps(next(responses)), stderr=''))
    monkeypatch.setattr('dc_overview.fleet_upgrade.time.sleep', lambda _: None)
    result = run_fleet_upgrade('main')
    assert result['state'] == 'interrupted'
    assert result['success'] is False


def test_host_upgrade_failure_to_submit_never_uses_lossy_fallback(monkeypatch):
    from dc_overview.fleet_upgrade import run_fleet_upgrade
    calls=[]
    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=1,stdout='',stderr='unavailable')
    monkeypatch.setattr('dc_overview.fleet_upgrade.subprocess.run',run)
    with pytest.raises(RuntimeError,match='updater'):
        run_fleet_upgrade('main')
    assert len(calls)==1
