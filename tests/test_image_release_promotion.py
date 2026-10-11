"""Offline registry fixtures prove exact bytes and held floating aliases."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

import pytest
import yaml

ROOT=Path(__file__).resolve().parents[1]
PROJECT=re.search(r'^name = "([^"]+)"',(ROOT/'pyproject.toml').read_text(),re.M).group(1)
VERSION=re.search(r'^version = "([^"]+)"',(ROOT/'pyproject.toml').read_text(),re.M).group(1)
SHA='a'*40
IMAGES=['dc-overview','runpod-exporter','vastai-exporter'] if PROJECT=='dc-overview' else ['cryptolabs-proxy']
MANIFEST='application/vnd.oci.image.manifest.v1+json'
INDEX='application/vnd.oci.image.index.v1+json'
CONFIG='application/vnd.oci.image.config.v1+json'


def encoded(value): return json.dumps(value,separators=(',',':')).encode()
def digest(data): return 'sha256:'+hashlib.sha256(data).hexdigest()


@pytest.fixture
def mod():
    if sys.version_info<(3,11): pytest.skip('Actions helper uses Python3.11')
    spec=importlib.util.spec_from_file_location('promotion',ROOT/'scripts/image_promotion.py')
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class Registry:
    def __init__(self, *, indexed=False, attestation=False):
        self.manifests={}; self.blobs={}; self.writes=[]; self.expected={}; self.failure=None
        self.context={'project':PROJECT,'repository':'cryptolabsza/'+PROJECT,'version':VERSION,
                      'tag':'v'+VERSION,'source_sha':SHA}
        for image in IMAGES:
            repo='ghcr.io/cryptolabsza/'+image
            child=self.image(repo)
            data=child
            if indexed:
                descriptor={'mediaType':MANIFEST,'digest':digest(child),'size':len(child),
                            'platform':{'os':'linux','architecture':'amd64'}}
                descriptors=[descriptor]
                if attestation:
                    config=encoded({'os':'unknown','architecture':'unknown','config':{}})
                    self.blobs[(repo,digest(config))]=config
                    attest=encoded({'schemaVersion':2,'mediaType':MANIFEST,
                        'config':{'mediaType':CONFIG,'digest':digest(config),'size':len(config)},'layers':[]})
                    self.manifests[(repo,digest(attest))]=(attest,MANIFEST)
                    descriptors.append({'mediaType':MANIFEST,'digest':digest(attest),'size':len(attest),
                        'platform':{'os':'unknown','architecture':'unknown'},
                        'annotations':{'vnd.docker.reference.type':'attestation-manifest',
                                       'vnd.docker.reference.digest':digest(child)}})
                data=encoded({'schemaVersion':2,'mediaType':INDEX,'manifests':descriptors})
            identity=digest(data); self.expected[image]=identity
            media=INDEX if indexed else MANIFEST
            for ref in (identity,VERSION,'v'+VERSION,'sha-'+SHA):
                self.manifests[(repo,ref)]=(data,media)
    def image(self,repo,arch='amd64'):
        config=encoded({'os':'linux','architecture':arch,'config':{'Labels':{
            'org.opencontainers.image.source':'https://github.com/cryptolabsza/'+PROJECT,
            'org.opencontainers.image.revision':SHA,'org.opencontainers.image.version':VERSION}}})
        self.blobs[(repo,digest(config))]=config
        data=encoded({'schemaVersion':2,'mediaType':MANIFEST,
              'config':{'mediaType':CONFIG,'digest':digest(config),'size':len(config)},'layers':[]})
        self.manifests[(repo,digest(data))]=(data,MANIFEST)
        return data
    def manifest(self,repo,ref,missing=False):
        if self.failure=='read': raise RuntimeError('offline read failure')
        value=self.manifests.get((repo,ref))
        if value is None:
            if missing:return None
            raise RuntimeError('manifest absent')
        return value
    def blob(self,repo,ref):return self.blobs[(repo,ref)]
    def put(self,repo,tag,data,media):
        self.writes.append((repo,tag,data,media))
        if self.failure=='put':raise RuntimeError('uncertain write failure')
        self.manifests[(repo,tag)]=(b'changed' if self.failure=='readback' else data,media)


@pytest.mark.parametrize('image',IMAGES)
@pytest.mark.parametrize('ref,event,expected',[
    ('refs/tags/v'+VERSION,'push',[VERSION,'v'+VERSION,'sha-'+SHA]),
    ('refs/tags/v'+VERSION,'workflow_dispatch',[VERSION,'v'+VERSION,'sha-'+SHA]),
    ('refs/heads/main','push',['main','sha-main-'+SHA]),
    ('refs/heads/master','push',['main','sha-main-'+SHA]),
    ('refs/heads/dev','push',['dev','develop','sha-dev-'+SHA]),
    ('refs/heads/develop','push',['dev','develop','sha-dev-'+SHA]),
    ('refs/pull/42/merge','pull_request',['pr-42','sha-pr-42-'+SHA])])
def test_build_tag_matrix_has_only_explicit_safe_discovery(mod,image,ref,event,expected):
    repo='ghcr.io/cryptolabsza/'+image
    result=mod.build_tags(repo,ref,SHA,event,version=VERSION)
    assert result['tags']==[repo+':'+tag for tag in expected]
    assert not {'latest','stable',VERSION.rsplit('.',1)[0],VERSION.split('.')[0]} & set(expected)


@pytest.mark.parametrize('override',['latest','stable','1','1.2','other','v9.9.9','a\n$(touch /tmp/unsafe)'])
def test_any_tag_override_refuses_before_build(mod,override):
    with pytest.raises(ValueError):mod.build_tags('ghcr.io/cryptolabsza/'+IMAGES[0],'refs/heads/main',SHA,
                                                 'workflow_dispatch',version=VERSION,override=override)


@pytest.mark.parametrize('ref,sha,event',[
    ('refs/tags/v9.9.9',SHA,'push'),('refs/tags/v'+VERSION+'-rc1',SHA,'push'),
    ('refs/heads/latest',SHA,'workflow_dispatch'),('refs/tags/v'+VERSION,'injected','push'),
    ('refs/tags/v'+VERSION,SHA,'pull_request'),('refs/pull/42/merge',SHA,'push')])
def test_invalid_release_or_event_never_computes_promotable_tags(mod,ref,sha,event):
    with pytest.raises(ValueError):mod.build_tags('ghcr.io/cryptolabsza/'+IMAGES[0],ref,sha,event,version=VERSION)


@pytest.mark.parametrize('indexed,attestation',[(False,False),(True,False),(True,True)])
def test_promotion_reuses_exact_single_manifest_or_index_bytes(mod,indexed,attestation):
    client=Registry(indexed=indexed,attestation=attestation)
    receipt=mod.promote(client.context,client.expected,['linux/amd64'],client)
    assert receipt['status']=='verified'
    assert len(client.writes)==4*len(IMAGES)
    for repo,alias,data,media in client.writes:
        assert digest(data)==client.expected[repo.rsplit('/',1)[1]]
        assert client.manifests[(repo,alias)]==(data,media)
    assert all(operation['after_digest']==operation['expected_digest'] for operation in receipt['operations'])
    client.writes.clear()
    assert mod.promote(client.context,client.expected,['linux/amd64'],client)['status']=='verified'
    assert client.writes==[], 'Re-running verified promotion should reuse identical aliases'


@pytest.mark.parametrize('failure',['digest','version-tag','v-tag','sha-tag','revision','version','source',
    'platform','missing-image','extra-image','config-hash','descriptor-size','unknown-index-platform','index-child-platform'])
def test_all_targets_preflight_before_any_alias_write(mod,failure):
    client=Registry(indexed=failure.startswith('index') or failure=='unknown-index-platform')
    image=IMAGES[-1]; repo='ghcr.io/cryptolabsza/'+image
    expected=copy.deepcopy(client.expected)
    if failure=='digest':expected[image]='sha256:'+'f'*64
    if failure in ('version-tag','v-tag','sha-tag'):
        ref=VERSION if failure=='version-tag' else 'v'+VERSION if failure=='v-tag' else 'sha-'+SHA
        client.manifests[(repo,ref)]=(b'wrong bytes',MANIFEST)
    if failure in ('revision','version','source','platform','config-hash'):
        key=next(k for k in client.blobs if k[0]==repo)
        value=json.loads(client.blobs[key]); labels=value['config']['Labels']
        if failure=='revision':labels['org.opencontainers.image.revision']='b'*40
        if failure=='version':labels['org.opencontainers.image.version']='9.9.9'
        if failure=='source':labels['org.opencontainers.image.source']='https://evil.invalid/source'
        if failure=='platform':value['architecture']='arm64'
        # Rebind the parent descriptors for valid changed configs except explicit hash corruption.
        old_digest=key[1]; config=encoded(value); new_digest=digest(config)
        if failure=='config-hash':client.blobs[key]=b'corrupted config'
        else:
            client.blobs[(repo,new_digest)]=config
            body=json.loads(client.manifests[(repo,expected[image])][0])
            body['config'].update(digest=new_digest,size=len(config)); data=encoded(body)
            expected[image]=digest(data)
            for ref in (expected[image],VERSION,'v'+VERSION,'sha-'+SHA):client.manifests[(repo,ref)]=(data,MANIFEST)
    if failure=='missing-image':expected.pop(image)
    if failure=='extra-image':expected['unknown-image']='sha256:'+'f'*64
    if failure in ('descriptor-size','unknown-index-platform','index-child-platform'):
        body=json.loads(client.manifests[(repo,expected[image])][0])
        if failure=='descriptor-size':body['config']['size']+=1
        if failure=='unknown-index-platform':body['manifests'][0]['platform']['os']='unknown'
        if failure=='index-child-platform':body['manifests'][0]['platform']['architecture']='arm64'
        data=encoded(body); expected[image]=digest(data)
        for ref in (expected[image],VERSION,'v'+VERSION,'sha-'+SHA):
            client.manifests[(repo,ref)]=(data,INDEX if 'manifests' in body else MANIFEST)
    receipt=mod.promote(client.context,expected,['linux/amd64'],client)
    assert receipt['status']=='held' and receipt['operations']==[]
    assert client.writes==[]


@pytest.mark.parametrize('failure',['read','put','readback'])
def test_truthful_hold_or_partial_receipt_on_registry_failure(mod,failure):
    client=Registry();client.failure=failure
    receipt=mod.promote(client.context,client.expected,['linux/amd64'],client)
    assert receipt['status']==('held' if failure=='read' else 'partial')
    assert receipt['error_code']
    if failure=='read':assert client.writes==[]
    else:assert len(client.writes)==1 and len(receipt['operations'])==1
    assert not all(o.get('state')=='verified' for o in receipt['operations']) or not receipt['operations']


def test_alias_drift_after_preflight_holds_before_overwriting_unexpected_actor(mod):
    client=Registry();original=client.manifest;seen=[]
    def drifting(repo,ref,missing=False):
        if ref=='latest':
            seen.append((repo,ref))
            if len(seen)>len(IMAGES):return (b'changed by another actor',MANIFEST)
        return original(repo,ref,missing)
    client.manifest=drifting
    receipt=mod.promote(client.context,client.expected,['linux/amd64'],client)
    assert receipt['status']=='held' and client.writes==[]


def test_build_workflows_use_the_same_safe_generator_and_no_automatic_aliases():
    workflow=yaml.safe_load((ROOT/'.github/workflows/docker-build.yml').read_text())
    trigger=workflow.get('on',workflow.get(True))
    assert 'tag_override' not in trigger.get('workflow_dispatch',{}).get('inputs',{})
    for job in workflow['jobs'].values():
        if not any('image_promotion.py tags' in step.get('run','') for step in job['steps']):continue
        assert job['runs-on']==['self-hosted','linux']
        assert any('DOCKER_CONFIG=' in step.get('run','') and '$RUNNER_TEMP' in step['run'] for step in job['steps'])
        steps=job['steps']
        assert any('image_promotion.py tags' in s.get('run','') for s in steps)
        assert any(s.get('if')=='always()' and 'DOCKER_CONFIG' in s.get('run','') for s in steps)
        assert any(s.get('uses','').startswith('docker/login-action@') for s in steps)
        for step in steps:
            if 'metadata-action' in step.get('uses',''):
                assert step['with']['flavor']=='latest=false'
                assert '{{major}}' not in step['with'].get('tags','')
                assert 'value=latest' not in step['with'].get('tags','')
            if step.get('uses','').startswith('docker/build-push-action@'):
                assert step['with']['push']=="${{ github.event_name != 'pull_request' }}"
                assert step['with']['tags']=='${{ steps.tags.outputs.tags }}'
            assert 'sudo' not in step.get('run','')
            assert '${{ secrets.' not in step.get('run','')


def test_manual_promotion_is_explicit_and_never_builds_or_triggers_on_release():
    path=ROOT/'.github/workflows/promote-images.yml'
    workflow=yaml.safe_load(path.read_text());trigger=workflow.get('on',workflow.get(True))
    assert set(trigger)=={'workflow_dispatch'}
    inputs=trigger['workflow_dispatch']['inputs']
    assert inputs['release_tag']['required'] and inputs['source_sha']['required']
    for image in IMAGES:assert inputs[image.replace('-','_')+'_digest']['required']
    assert len(workflow['jobs'])==1
    job=workflow['jobs']['promote'];assert job['runs-on']==['self-hosted','linux']
    assert any('PROMOTION_DIR=' in step.get('run','') and '$GITHUB_RUN_ID' in step['run'] and '$GITHUB_RUN_ATTEMPT' in step['run'] for step in job['steps'])
    assert job['permissions']=={'contents':'read','packages':'write'}
    assert any('image_promotion.py promote' in s.get('run','') for s in job['steps'])
    assert any(s.get('if')=='always()' and 'promotion-receipt.json' in str(s) for s in job['steps'])
    for s in job['steps']:
        assert 'docker build' not in s.get('run','') and 'build-push-action' not in s.get('uses','')
        assert '${{ inputs.' not in s.get('run','') and '${{ secrets.' not in s.get('run','')
        if s.get('uses','').startswith('actions/checkout@'):
            assert s['with']['ref']=='${{ inputs.release_tag }}'
            assert s['with']['persist-credentials'] is False


def modern_attestation(client):
    for image in IMAGES:
        repo='ghcr.io/cryptolabsza/'+image;old=client.expected[image]
        index=json.loads(client.manifests[(repo,old)][0]);subject=index['manifests'][0]
        empty=b'{}';client.blobs[(repo,digest(empty))]=empty
        data=encoded({'schemaVersion':2,'mediaType':MANIFEST,
            'artifactType':'application/vnd.docker.attestation.manifest.v1+json',
            'subject':{k:subject[k] for k in ('mediaType','digest','size')},
            'config':{'mediaType':'application/vnd.oci.empty.v1+json','digest':digest(empty),'size':2,'data':'e30='},
            'layers':[]})
        client.manifests[(repo,digest(data))]=(data,MANIFEST)
        index['manifests'][1].update(digest=digest(data),size=len(data))
        data=encoded(index);client.expected[image]=digest(data)
        for ref in (digest(data),VERSION,'v'+VERSION,'sha-'+SHA):client.manifests[(repo,ref)]=(data,INDEX)


def test_current_oci_artifact_attestation_index_is_copied_exactly(mod):
    client=Registry(indexed=True,attestation=True);modern_attestation(client)
    assert mod.promote(client.context,client.expected,['linux/amd64'],client)['status']=='verified'
    assert all(digest(data)==client.expected[repo.rsplit('/',1)[1]] for repo,_,data,_ in client.writes)


@pytest.mark.parametrize('fault',['subject','empty-config'])
def test_attestation_unsupported_subject_or_config_holds_all_aliases(mod,fault):
    client=Registry(indexed=True,attestation=True);modern_attestation(client)
    repo='ghcr.io/cryptolabsza/'+IMAGES[-1]
    index=json.loads(client.manifests[(repo,client.expected[IMAGES[-1]])][0]);desc=index['manifests'][1]
    attest=json.loads(client.manifests[(repo,desc['digest'])][0])
    if fault=='subject':attest['subject']['digest']='sha256:'+'f'*64
    else:attest['config']['data']='WyJ1bnNhZmUiXQ=='
    data=encoded(attest);client.manifests[(repo,digest(data))]=(data,MANIFEST)
    desc.update(digest=digest(data),size=len(data));data=encoded(index);client.expected[IMAGES[-1]]=digest(data)
    for ref in (digest(data),VERSION,'v'+VERSION,'sha-'+SHA):client.manifests[(repo,ref)]=(data,INDEX)
    assert mod.promote(client.context,client.expected,['linux/amd64'],client)['status']=='held'
    assert not client.writes


@pytest.mark.parametrize('fault',['tag','sha','local-head','remote-head','dirty'])
def test_source_release_identity_holds_before_registry_access(mod,monkeypatch,fault):
    def git(root,*args):
        if args[0]=='rev-parse':return 'b'*40 if fault=='local-head' else SHA
        return ' M modified.py' if fault=='dirty' else ''
    monkeypatch.setattr(mod,'git',git)
    client=type('Source',(),{'release_commit':lambda self,repo,tag:'b'*40 if fault=='remote-head' else SHA})()
    with pytest.raises(ValueError):mod.check_source(ROOT,'v9.9.9' if fault=='tag' else 'v'+VERSION,
                                                   'bad-sha' if fault=='sha' else SHA,client)


@pytest.mark.parametrize('fault',['repository','image','checkout-sha'])
def test_build_cli_binds_checkout_repository_and_product_images(mod,monkeypatch,tmp_path,fault):
    output=tmp_path/'output';image=IMAGES[0]
    if fault=='image':image='cryptolabs-proxy' if PROJECT=='dc-overview' else 'dc-overview'
    monkeypatch.setenv('GITHUB_REPOSITORY','cryptolabsza/wrong' if fault=='repository' else 'cryptolabsza/'+PROJECT)
    monkeypatch.setenv('GITHUB_REF','refs/tags/v'+VERSION);monkeypatch.setenv('GITHUB_SHA',SHA)
    monkeypatch.setenv('GITHUB_EVENT_NAME','push');monkeypatch.setenv('GITHUB_OUTPUT',str(output))
    monkeypatch.setattr(mod,'git',lambda root,*args:'b'*40 if fault=='checkout-sha' else SHA)
    monkeypatch.setattr(mod.sys,'argv',['image_promotion.py','tags','--root',str(ROOT),
                                      '--image','ghcr.io/cryptolabsza/'+image])
    assert mod.main()==1 and not output.exists()


def test_exact_registry_put_preserves_original_bytes_and_content_type(mod,monkeypatch):
    data=b'{\n  "schemaVersion": 2, "uninterpreted_extension": [3, 2, 1]\n}\n'
    client=mod.Client();calls=[];monkeypatch.setattr(client,'token',lambda repo:'synthetic-ephemeral-jwt')
    def request(url,**kwargs):
        calls.append((url,kwargs));return b'',{'Docker-Content-Digest':digest(data)}
    monkeypatch.setattr(client,'request',request)
    client.put('ghcr.io/cryptolabsza/'+IMAGES[0],'latest',data,MANIFEST)
    assert calls[0][1]['data'] is data and calls[0][1]['method']=='PUT'
    assert calls[0][1]['headers']['Content-Type']==MANIFEST


def test_redirect_never_forwards_registry_authorization(mod):
    request=mod.Request('https://ghcr.io/v2/fixture/blobs/'+('sha256:'+'a'*64),
                        headers={'Authorization':'Bearer synthetic-ephemeral-jwt'})
    redirected=mod.SafeRedirect().redirect_request(request,None,302,'found',{},'https://storage.example.test/blob')
    assert redirected.get_header('Authorization') is None
    with pytest.raises(ValueError):
        mod.SafeRedirect().redirect_request(request,None,302,'found',{},'http://insecure.example.test/blob')
    request=mod.Request('https://ghcr.io/v2/fixture/manifests/latest',data=b'{}',method='PUT')
    with pytest.raises(ValueError):
        mod.SafeRedirect().redirect_request(request,None,302,'found',{},'https://storage.example.test/blob')


def test_registry_metadata_digest_header_is_not_trusted(mod,monkeypatch):
    client=mod.Client();monkeypatch.setattr(client,'token',lambda repo:'synthetic-ephemeral-jwt')
    monkeypatch.setattr(client,'request',lambda *a,**k:(b'actual bytes',{'Docker-Content-Digest':'sha256:'+'f'*64,
                                                                    'Content-Type':MANIFEST}))
    with pytest.raises(ValueError):client.manifest('ghcr.io/cryptolabsza/'+IMAGES[0],VERSION)


def test_main_retains_partial_receipt_without_success_summary(mod,monkeypatch,tmp_path):
    client=Registry();client.failure='readback';receipt=tmp_path/'promotion.json';summary=tmp_path/'summary'
    monkeypatch.setattr(mod,'Client',lambda:client)
    monkeypatch.setattr(mod,'check_source',lambda *a:client.context)
    monkeypatch.setenv('GITHUB_ACTIONS','true');monkeypatch.setenv('GITHUB_EVENT_NAME','workflow_dispatch')
    monkeypatch.setenv('GITHUB_REPOSITORY','cryptolabsza/'+PROJECT);monkeypatch.setenv('GITHUB_STEP_SUMMARY',str(summary))
    args=['image_promotion.py','promote','--root',str(ROOT),'--release-tag','v'+VERSION,'--source-sha',SHA,
          '--platform','linux/amd64','--receipt',str(receipt)]
    for image,value in client.expected.items():args.extend(['--expected-digest',image+'='+value])
    monkeypatch.setattr(mod.sys,'argv',args)
    assert mod.main()==1 and not summary.exists()
    assert json.loads(receipt.read_text())['status']=='partial'


@pytest.mark.parametrize('indexed,attestation',[(False,False),(True,False),(True,True)])
def test_release_retry_reuses_original_bytes_without_build_or_write(mod,indexed,attestation):
    client=Registry(indexed=indexed,attestation=attestation)
    original=copy.deepcopy(client.manifests)
    receipt=mod.release_guard(client.context,['linux/amd64'],client)
    assert receipt['status']=='reuse' and receipt['build'] is False
    assert {target['repository'].rsplit('/',1)[1]:target['digest'] for target in receipt['targets']}==client.expected
    assert client.writes==[] and client.manifests==original


def test_only_wholly_absent_release_can_build_once(mod):
    client=Registry()
    for image in IMAGES:
        for tag in (VERSION,'v'+VERSION,'sha-'+SHA):
            client.manifests.pop(('ghcr.io/cryptolabsza/'+image,tag))
    receipt=mod.release_guard(client.context,['linux/amd64'],client)
    assert receipt['status']=='new' and receipt['build'] is True
    assert all(set(target['observed_tags'].values())=={None} for target in receipt['targets'])
    assert client.writes==[]
    held=mod.release_guard(client.context,['linux/amd64'],client,require_existing=True)
    assert held['status']=='held' and held['build'] is False


@pytest.mark.parametrize('history',['one-missing','one-only','conflict','wrong-source','missing-blob','read-failure','wrong-platform'])
def test_existing_partial_or_conflicting_identities_hold_before_build(mod,history):
    client=Registry();repo='ghcr.io/cryptolabsza/'+IMAGES[-1]
    if history=='one-missing':client.manifests.pop((repo,'sha-'+SHA))
    if history=='one-only':
        client.manifests.pop((repo,'sha-'+SHA));client.manifests.pop((repo,'v'+VERSION))
    if history=='conflict':client.manifests[(repo,VERSION)]=(b'other built timestamp',MANIFEST)
    if history=='wrong-source':client.context['source_sha']='b'*40
    if history=='missing-blob':client.blobs.clear()
    if history=='read-failure':client.failure='read'
    platforms=['linux/arm64'] if history=='wrong-platform' else ['linux/amd64']
    receipt=mod.release_guard(client.context,platforms,client)
    assert receipt['status']=='held' and receipt['build'] is False and receipt['error_code']
    assert client.writes==[]


@pytest.mark.skipif(len(IMAGES)==1,reason='DC product owns three images')
def test_cross_image_partial_history_retains_each_observation_without_rebuild(mod):
    client=Registry();repo='ghcr.io/cryptolabsza/'+IMAGES[-1]
    for tag in (VERSION,'v'+VERSION,'sha-'+SHA):client.manifests.pop((repo,tag))
    receipt=mod.release_guard(client.context,['linux/amd64'],client)
    assert receipt['status']=='held' and receipt['error_code']=='incomplete_product_release'
    assert len(receipt['targets'])==len(IMAGES) and receipt['build'] is False
    assert receipt['targets'][0]['digest']==client.expected[IMAGES[0]]
    assert set(receipt['targets'][-1]['observed_tags'].values())=={None}
    assert client.writes==[]


def test_normal_push_and_manual_runs_share_serialized_product_guard():
    workflow=yaml.safe_load((ROOT/'.github/workflows/docker-build.yml').read_text())
    triggers=workflow.get('on',workflow.get(True));assert 'workflow_dispatch' in triggers
    concurrency=workflow['concurrency']
    assert concurrency=={'group':'image-release-publication-${{ github.repository }}','cancel-in-progress':False}
    guard=workflow['jobs']['release-preflight']
    assert guard['permissions']=={'contents':'read','packages':'read'}
    command=next(s for s in guard['steps'] if 'image_promotion.py guard' in s.get('run',''))
    assert '--platform linux/amd64' in command['run'] and '--receipt' in command['run']
    assert command['env']['GHCR_TOKEN']=='${{ secrets.CR_PAT || secrets.GITHUB_TOKEN }}'
    assert 'TAG_OVERRIDE' in command['env']
    assert any(s.get('if')=='always()' and s.get('uses','').startswith('actions/upload-artifact@') for s in guard['steps'])
    image_jobs=[job for job in workflow['jobs'].values() if any('image_promotion.py tags' in s.get('run','') for s in job['steps'])]
    assert len(image_jobs)==len(IMAGES)
    for job in image_jobs:
        assert job['needs']=='release-preflight'
        for step in job['steps']:
            if 'docker build ' in step.get('run','') or step.get('uses','').startswith('docker/build-push-action@'):
                assert step.get('if')=="needs.release-preflight.outputs.build == 'true'"
            if 'docker --config "$DOCKER_CONFIG" push' in step.get('run',''):
                assert step.get('if')=="github.event_name != 'pull_request' && needs.release-preflight.outputs.build == 'true'"
    final=workflow['jobs']['release-readback']
    assert final['if']=="always() && needs.release-preflight.result == 'success'"
    assert len(final['needs'])==len(IMAGES)+1
    assert any('--require-existing' in s.get('run','') for s in final['steps'])


def test_release_guard_cli_executes_registry_preflight_and_emits_reuse(tmp_path,monkeypatch,mod):
    client=Registry();output=tmp_path/'outputs';receipt=tmp_path/'receipt.json'
    monkeypatch.setattr(mod,'Client',lambda:client)
    monkeypatch.setattr(mod,'git',lambda root,*args: '' if args[0]=='status' else SHA)
    monkeypatch.setenv('GITHUB_ACTIONS','true');monkeypatch.setenv('GITHUB_REPOSITORY','cryptolabsza/'+PROJECT)
    monkeypatch.setenv('GITHUB_SHA',SHA);monkeypatch.setenv('GITHUB_REF','refs/tags/v'+VERSION)
    monkeypatch.setenv('GITHUB_EVENT_NAME','workflow_dispatch');monkeypatch.setenv('GITHUB_OUTPUT',str(output))
    monkeypatch.setattr(mod.sys,'argv',['image_promotion.py','guard','--root',str(ROOT),
       '--platform','linux/amd64','--receipt',str(receipt)])
    assert mod.main()==0
    assert 'build=false' in output.read_text()
    assert json.loads(receipt.read_text())['status']=='reuse' and client.writes==[]


@pytest.mark.parametrize('event,ref',[('push','refs/heads/dev'),('pull_request','refs/pull/42/merge')])
def test_discovery_guard_never_reads_or_writes_registry(tmp_path,monkeypatch,mod,event,ref):
    monkeypatch.setattr(mod,'Client',lambda:pytest.fail('branch or PR attempted registry access'))
    monkeypatch.setattr(mod,'git',lambda root,*args: '' if args[0]=='status' else SHA)
    monkeypatch.setenv('GITHUB_ACTIONS','true');monkeypatch.setenv('GITHUB_REPOSITORY','cryptolabsza/'+PROJECT)
    monkeypatch.setenv('GITHUB_SHA',SHA);monkeypatch.setenv('GITHUB_REF',ref)
    monkeypatch.setenv('GITHUB_EVENT_NAME',event);monkeypatch.setenv('GITHUB_OUTPUT',str(tmp_path/'output'))
    monkeypatch.setattr(mod.sys,'argv',['image_promotion.py','guard','--root',str(ROOT),
       '--platform','linux/amd64','--receipt',str(tmp_path/'receipt.json')])
    assert mod.main()==0
    receipt=json.loads((tmp_path/'receipt.json').read_text())
    assert receipt['status']=='discovery' and receipt['build'] is True


def test_actual_workflow_conditions_do_zero_build_or_push_on_reuse():
    workflow=yaml.safe_load((ROOT/'.github/workflows/docker-build.yml').read_text())
    evaluated=[]
    for job in workflow['jobs'].values():
        for step in job['steps']:
            run=step.get('run','');uses=step.get('uses','')
            if 'docker build ' in run or 'docker --config "$DOCKER_CONFIG" push' in run or uses.startswith('docker/build-push-action@'):
                condition=step['if']
                expression=condition.replace('needs.release-preflight.outputs.build',repr('false')).replace(
                    'github.event_name',repr('workflow_dispatch')).replace('&&','and')
                evaluated.append(eval(expression,{'__builtins__':{}}))
    assert len(evaluated)==(6 if PROJECT=='dc-overview' else 1)
    assert not any(evaluated), 'A coherent release retry must execute zero build/push steps'


def test_cli_retains_partial_history_and_no_build_output(tmp_path,monkeypatch,mod):
    client=Registry();repo='ghcr.io/cryptolabsza/'+IMAGES[-1]
    client.manifests.pop((repo,'v'+VERSION))
    output=tmp_path/'output';receipt=tmp_path/'receipt.json'
    monkeypatch.setattr(mod,'Client',lambda:client)
    monkeypatch.setattr(mod,'git',lambda root,*args: '' if args[0]=='status' else SHA)
    monkeypatch.setenv('GITHUB_ACTIONS','true');monkeypatch.setenv('GITHUB_REPOSITORY','cryptolabsza/'+PROJECT)
    monkeypatch.setenv('GITHUB_SHA',SHA);monkeypatch.setenv('GITHUB_REF','refs/tags/v'+VERSION)
    monkeypatch.setenv('GITHUB_EVENT_NAME','push');monkeypatch.setenv('GITHUB_OUTPUT',str(output))
    monkeypatch.setattr(mod.sys,'argv',['image_promotion.py','guard','--root',str(ROOT),
       '--platform','linux/amd64','--receipt',str(receipt),'--require-existing'])
    assert mod.main()==1 and not output.exists()
    retained=json.loads(receipt.read_text())
    assert retained['status']=='held' and retained['build'] is False
    assert len(retained['targets'])==len(IMAGES)
    assert retained['targets'][-1]['observed_tags']['v'+VERSION] is None
    assert client.writes==[]


def test_guard_tokens_request_pull_scope_only(mod,monkeypatch):
    monkeypatch.setenv('GHCR_USER','fixture-user');monkeypatch.setenv('GHCR_TOKEN','fixture-only-token')
    client=mod.Client();client.read_only=True;calls=[]
    def request(url,**kwargs):
        calls.append(url);return encoded({'token':'fixture-scoped-token'}),{}
    monkeypatch.setattr(client,'request',request)
    assert client.token('ghcr.io/cryptolabsza/'+IMAGES[0])=='fixture-scoped-token'
    assert ':pull,push' not in calls[0] and '%3Apull' in calls[0]


def test_runner_paths_are_initialized_in_steps_with_valid_contexts(tmp_path):
    import os
    for filename in ('docker-build.yml','promote-images.yml'):
        workflow=yaml.safe_load((ROOT/'.github/workflows'/filename).read_text())
        for job_name,job in workflow['jobs'].items():
            assert 'runner.' not in str(job.get('env',{}))
            path_steps=[step for step in job['steps'] if step.get('name')=='Initialize isolated runner path']
            assert len(path_steps)==1
            script=path_steps[0]['run'];envfile=tmp_path/(filename+'-'+job_name)
            result=subprocess.run(['bash','-euo','pipefail','-c',script],capture_output=True,text=True,
                env={**os.environ,'RUNNER_TEMP':str(tmp_path),'GITHUB_ENV':str(envfile),
                     'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'2'})
            assert result.returncode==0,result.stderr
            value=envfile.read_text().strip().split('=',1)[1]
            assert value.startswith(str(tmp_path)+'/') and '123-2' in value
            assert '${{' not in value
