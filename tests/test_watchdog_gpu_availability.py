from types import SimpleNamespace
from unittest.mock import Mock
from dc_overview import web_watchdog as wd


def response(customer):
    return Mock(ok=True,json=lambda:{'agents':[{'worker_id':'same','online':True,'gpu_availability':{'active':True,'classification':'driver_unresponsive','last_received':100,'observation':{'source_age_bound':30,'status':'busy'},'expected':8}}]})


def test_cache_is_bound_to_credential_even_inside_ttl_and_failure(monkeypatch):
    monkeypatch.setattr(wd,'_watchdog_api_cache',{'ts':0,'data':None})
    key=['customer-A'];monkeypatch.setattr(wd,'get_watchdog_api_key',lambda:key[0])
    monkeypatch.setattr(wd.time,'time',lambda:100)
    get=Mock(return_value=response('A'));monkeypatch.setattr(wd.http_requests,'get',get)
    assert wd.get_watchdog_agents_from_api()['same']['online']
    key[0]='customer-B';get.side_effect=RuntimeError('offline')
    assert wd.get_watchdog_agents_from_api()=={}
    assert get.call_count==2
    key[0]='';assert wd.get_watchdog_agents_from_api()=={}


def test_source_age_grows_through_cache_and_active_incident_is_retained(monkeypatch):
    monkeypatch.setattr(wd,'_watchdog_api_cache',{'ts':0,'data':None})
    monkeypatch.setattr(wd,'get_watchdog_api_key',lambda:'A')
    clock=[100];monkeypatch.setattr(wd.time,'time',lambda:clock[0])
    get=Mock(return_value=response('A'));monkeypatch.setattr(wd.http_requests,'get',get)
    assert wd.get_watchdog_agents_from_api()['same']['gpu_availability']['source_age_seconds']==30
    clock[0]=120
    state=wd.get_watchdog_agents_from_api()['same']['gpu_availability']
    assert state['source_age_seconds']==50 and state['active'] is True
    clock[0]=150;get.side_effect=RuntimeError()
    state=wd.get_watchdog_agents_from_api()['same']['gpu_availability']
    assert state['coverage']=='stale' and state['active'] is True
    clock[0]=200;assert wd.get_watchdog_agents_from_api()=={}


def test_online_agent_is_not_gpu_all_clear(monkeypatch):
    agent={'online':True,'gpu_availability':{'active':True,'classification':'driver_unresponsive'}}
    monkeypatch.setattr(wd,'get_watchdog_agents_from_api',lambda:{'same':agent})
    result=wd.check_watchdog_agent(SimpleNamespace(name='same'))
    assert result['running'] is True
    assert result['gpu_availability']['active'] is True


def test_late_old_credential_response_cannot_overwrite_new_context(monkeypatch):
    monkeypatch.setattr(wd,'_watchdog_api_cache',{'ts':0,'data':None})
    monkeypatch.setattr(wd.time,'time',lambda:100)
    key=['A'];monkeypatch.setattr(wd,'get_watchdog_api_key',lambda:key[0])
    a=Mock(ok=True,json=lambda:{'agents':[{'worker_id':'same','name':'A'}]})
    b=Mock(ok=True,json=lambda:{'agents':[{'worker_id':'same','name':'B'}]})
    def get(*args,**kwargs):
        if kwargs['params']['api_key']=='A':
            key[0]='B';assert wd.get_watchdog_agents_from_api()['same']['name']=='B'
            return a
        return b
    monkeypatch.setattr(wd.http_requests,'get',get)
    assert wd.get_watchdog_agents_from_api()=={}
    assert wd.get_watchdog_agents_from_api()['same']['name']=='B'


def test_update_has_private_rollback_owned_probe_state_without_gpu_discovery(monkeypatch):
    import subprocess
    from test_operational_customer_contract import host
    from test_selected_worker_lifecycle import target
    scripts=[]
    def remote(cmd,**kwargs):
        scripts.append(kwargs['input'])
        return subprocess.CompletedProcess(cmd,0,'WATCHDOG_PREFLIGHT=verified\nINSTALL_SUCCESS','')
    monkeypatch.setattr(wd,'build_ssh_cmd',lambda *a,**k:(['ssh'],{}))
    monkeypatch.setattr(wd.subprocess,'run',remote)
    assert wd.install_watchdog_agent_remote(host(),'synthetic-account',selected_artifact=target('dc-watchdog-agent',version='2.0.8'),mode='update')[0]
    script=scripts[-1]
    assert 'StateDirectory=dc-watchdog' in script and 'StateDirectoryMode=0700' in script
    assert '40-cryptolabs-gpu-probe-state.conf' in script
    assert '"$PROBE_DROPIN"' in script[script.index('files='):script.index('for file in')]
    assert 'timeout 5 nvidia-smi' not in script

def test_server_coverage_unknown_or_disabled_cannot_become_available():
    for coverage in ('unknown','disabled','epoch_history_exhausted'):
        result=wd._gpu_availability_view({'coverage':coverage,'active':True,'last_received':100,'observation':{'source_age_bound':30}},100)
        assert result['coverage']==coverage

def test_critical_hardware_and_recipient_receipts_survive_safe_projection():
    state={'active':True,'hardware_active':True,'classification':'hardware_pcie_loss','severity':'critical',
           'hardware_diagnostic':{'usable':7,'record_count':8},'last_received':100,
           'observation':{'source_age_bound':0},'delivery':[{'channel':'telegram','status':'delivered','receipt':{'message_id':123,'recipient_fingerprint':'fixture'}}],
           'private_token':'must-not-project'}
    result=wd._gpu_availability_view(state,101)
    assert result['severity']=='critical' and result['hardware_active']
    assert result['delivery'][0]['receipt']['message_id']==123
    assert 'private_token' not in result
