#!/usr/bin/env python3
"""Normal release tag policy and exact-byte GHCR alias promotion, without rebuilding."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, HTTPRedirectHandler, build_opener

PRODUCTS={'dc-overview':('dc-overview','runpod-exporter','vastai-exporter'),
          'cryptolabs-proxy':('cryptolabs-proxy',)}
REPOS={'ghcr.io/cryptolabsza/'+image for images in PRODUCTS.values() for image in images}
VERSION=re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)')
SHA=re.compile(r'[0-9a-f]{40}')
DIGEST=re.compile(r'sha256:[0-9a-f]{64}')
PLATFORMS={'linux/amd64','linux/arm64'}
MANIFESTS={'application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json'}
INDEXES={'application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json'}
CONFIGS={'application/vnd.oci.image.config.v1+json','application/vnd.docker.container.image.v1+json'}


class Hold(ValueError):
    """Fixed, non-sensitive reason code."""


def digest(data):return 'sha256:'+hashlib.sha256(data).hexdigest()


def build_tags(image,ref,sha,event,*,version,override=''):
    if image not in REPOS or not SHA.fullmatch(sha) or not VERSION.fullmatch(version):
        raise Hold('invalid_build_identity')
    if override:
        raise Hold('tag_override_refused')
    if event not in ('push','workflow_dispatch','pull_request'):
        raise Hold('unsupported_build_event')
    pr=re.fullmatch(r'refs/pull/([1-9][0-9]*)/merge',ref)
    if event=='pull_request':
        if not pr:raise Hold('invalid_pull_request_ref')
        tags=['pr-'+pr[1]];display='pr-'+pr[1];channel='pull-request'
    elif ref=='refs/tags/v'+version:
        tags=[version,'v'+version];display=version;channel='release-artifact'
    elif ref in ('refs/heads/main','refs/heads/master'):
        tags=['main'];display='main';channel='main'
    elif ref in ('refs/heads/dev','refs/heads/develop'):
        tags=['dev','develop'];display='dev';channel='development'
    else:
        raise Hold('unsupported_build_ref')
    tags.append('sha-'+sha if channel=='release-artifact' else 'sha-'+display+'-'+sha)
    return {'tags':[image+':'+tag for tag in tags],'version':display,'channel':channel}


def aliases(version):
    if not VERSION.fullmatch(version):raise Hold('invalid_release_version')
    major,minor,_=version.split('.')
    # Preserve existing DC policy: major0 releases have no broad major alias.
    return ['latest','stable',major+'.'+minor]+([major] if major!='0' else [])


def project(root):
    data=tomllib.loads((root/'pyproject.toml').read_text())['project']
    name,version=data['name'],data['version']
    if name not in PRODUCTS or not VERSION.fullmatch(version):raise Hold('invalid_source_project')
    return name,version


def git(root,*args):
    result=subprocess.run(['git','-C',str(root),*args],capture_output=True,check=False)
    if result.returncode:raise Hold('source_revision_unavailable')
    return result.stdout.decode().strip()


def check_source(root,tag,sha,client):
    name,version=project(root)
    if tag!='v'+version or not SHA.fullmatch(sha):raise Hold('release_source_mismatch')
    if (git(root,'rev-parse','HEAD')!=sha or git(root,'rev-parse',f'refs/tags/{tag}^{{commit}}')!=sha
            or git(root,'status','--porcelain','--untracked-files=normal')):
        raise Hold('checkout_source_mismatch')
    if client.release_commit('cryptolabsza/'+name,tag)!=sha:raise Hold('published_source_mismatch')
    return {'project':name,'repository':'cryptolabsza/'+name,'version':version,'tag':tag,'source_sha':sha}


def checked_manifest(client,repo,ref):
    data,media=client.manifest(repo,ref)
    if media not in MANIFESTS|INDEXES:raise Hold('unsupported_manifest_media_type')
    if DIGEST.fullmatch(ref) and digest(data)!=ref:raise Hold('manifest_digest_mismatch')
    value=json.loads(data)
    if type(value.get('schemaVersion')) is not int or value['schemaVersion']!=2 or value.get('mediaType')!=media:
        raise Hold('invalid_manifest_schema')
    return data,media,value


def descriptor(item,media_types):
    if (not isinstance(item,dict) or item.get('mediaType') not in media_types
            or not isinstance(item.get('digest'),str) or not DIGEST.fullmatch(item['digest'])
            or type(item.get('size')) is not int or not 0<item['size']<=16*1024*1024):
        raise Hold('invalid_descriptor')
    return item['digest']


def config(client,repo,manifest,media_types=CONFIGS):
    item=manifest['config'];identity=descriptor(item,media_types)
    if item['mediaType']=='application/vnd.oci.empty.v1+json' and 'data' in item:
        data=base64.b64decode(item['data'],validate=True)
    else:
        data=client.blob(repo,identity)
    if digest(data)!=identity or len(data)!=item['size']:raise Hold('config_digest_mismatch')
    return json.loads(data)


def platform_identity(value):
    if value.get('variant') not in (None,'','v8'):raise Hold('unsupported_platform_variant')
    return value.get('os','')+'/'+value.get('architecture','')


def image_config(client,repo,value,context):
    image=config(client,repo,value)
    platform=platform_identity(image)
    labels=image.get('config',{}).get('Labels',{})
    wanted={'org.opencontainers.image.source':'https://github.com/'+context['repository'],
            'org.opencontainers.image.revision':context['source_sha'],
            'org.opencontainers.image.version':context['version']}
    if any(labels.get(key)!=value for key,value in wanted.items()):raise Hold('image_source_labels_mismatch')
    if platform not in PLATFORMS:raise Hold('unsupported_image_platform')
    return platform


def validate_target(client,repo,identity,context,platforms):
    data,media,value=checked_manifest(client,repo,identity)
    for tag in (context['version'],context['tag'],'sha-'+context['source_sha']):
        tagged,_=client.manifest(repo,tag)
        if tagged!=data:raise Hold('release_tag_digest_mismatch')
    actual={};attestations=[];image_sizes={}
    if media in MANIFESTS:
        actual[image_config(client,repo,value,context)]=identity
    else:
        children=value.get('manifests')
        if not isinstance(children,list) or not 1<=len(children)<=8:raise Hold('invalid_image_index')
        pending=[]
        for item in children:
            child_digest=descriptor(item,MANIFESTS)
            child_data,_,child=checked_manifest(client,repo,child_digest)
            if len(child_data)!=item['size']:raise Hold('child_descriptor_size_mismatch')
            declared=platform_identity(item.get('platform',{}))
            if declared=='unknown/unknown':
                pending.append((item,child));continue
            actual_platform=image_config(client,repo,child,context)
            if declared!=actual_platform or declared in actual:raise Hold('index_platform_mismatch')
            actual[declared]=child_digest;image_sizes[child_digest]=len(child_data)
        for item,child in pending:
            annotations=item.get('annotations',{})
            if (annotations.get('vnd.docker.reference.type')!='attestation-manifest'
                    or annotations.get('vnd.docker.reference.digest') not in actual.values()):
                raise Hold('unrecognised_index_metadata')
            if child.get('artifactType')=='application/vnd.docker.attestation.manifest.v1+json':
                subject=child.get('subject',{})
                subject_digest=descriptor(subject,MANIFESTS)
                if (subject_digest!=annotations['vnd.docker.reference.digest']
                        or subject['size']!=image_sizes.get(subject_digest)
                        or config(client,repo,child,{'application/vnd.oci.empty.v1+json'})!={}):
                    raise Hold('invalid_attestation_subject_or_config')
            elif child.get('artifactType') or platform_identity(config(client,repo,child))!='unknown/unknown':
                raise Hold('invalid_attestation_platform')
            attestations.append(item['digest'])
    if set(actual)!=set(platforms):raise Hold('release_platform_set_mismatch')
    return {'repository':repo,'digest':identity,'media_type':media,'platforms':actual,
            'attestations':attestations,'data':data}


def observed(client,repo,tag):
    value=client.manifest(repo,tag,missing=True)
    return digest(value[0]) if value else None


def error_code(error):
    if isinstance(error,Hold):return str(error)
    if isinstance(error,(RuntimeError,OSError)):return 'registry_operation_failed'
    return 'invalid_registry_metadata'


def promote(context,expected,platforms,client):
    receipt={'schema_version':1,'status':'held','recorded_utc':datetime.now(timezone.utc).isoformat(),
             'release':context,'targets':[],'operations':[]}
    try:
        product=context['project']
        if (product not in PRODUCTS or context['repository']!='cryptolabsza/'+product
                or not SHA.fullmatch(context['source_sha']) or not VERSION.fullmatch(context['version'])
                or context['tag']!='v'+context['version']):raise Hold('invalid_release_identity')
        if set(expected)!=set(PRODUCTS[product]):raise Hold('complete_expected_images_required')
        if not platforms or len(set(platforms))!=len(platforms) or not set(platforms)<=PLATFORMS:
            raise Hold('unsupported_requested_platforms')
        planned=[]
        # All source/version/config/platform and current alias reads precede ANY write.
        for image in PRODUCTS[product]:
            identity=expected[image]
            if not isinstance(identity,str) or not DIGEST.fullmatch(identity):raise Hold('invalid_expected_digest')
            target=validate_target(client,'ghcr.io/cryptolabsza/'+image,identity,context,platforms)
            receipt['targets'].append({k:v for k,v in target.items() if k!='data'})
            for alias in aliases(context['version']):
                planned.append((target,alias,observed(client,target['repository'],alias)))
        for target,alias,before in planned:
            repo=target['repository'];identity=target['digest']
            current=observed(client,repo,alias)
            if current!=before:raise Hold('alias_changed_since_preflight')
            operation={'repository':repo,'alias':alias,'before_digest':before,
                       'expected_digest':identity,'state':'verified' if current==identity else 'write-uncertain'}
            receipt['operations'].append(operation)
            if current!=identity:
                try:
                    client.put(repo,alias,target['data'],target['media_type'])
                except Exception:
                    # The write may have reached the registry despite a lost response.
                    try:operation['after_digest']=observed(client,repo,alias)
                    except Exception:operation['after_digest']=None
                    raise
            operation['after_digest']=observed(client,repo,alias)
            if operation['after_digest']!=identity:raise Hold('alias_readback_mismatch')
            operation['state']='verified'
        # A later actor's change must not turn the completed loop into a success claim.
        for operation in receipt['operations']:
            operation['after_digest']=observed(client,operation['repository'],operation['alias'])
            if operation['after_digest']!=operation['expected_digest']:
                operation['state']='changed-after-write';raise Hold('alias_changed_during_promotion')
        receipt['status']='verified'
    except Exception as error:
        receipt['status']='partial' if any(o['state']!='verified' or o['before_digest']!=o['expected_digest']
                                          for o in receipt['operations']) else 'held'
        receipt['error_code']=error_code(error)
    return receipt


def release_guard(context,platforms,client,*,require_existing=False):
    """Read all product identities before any build; never repair or overwrite history."""
    receipt={'schema_version':1,'status':'held','build':False,
             'recorded_utc':datetime.now(timezone.utc).isoformat(),
             'release':context,'targets':[],'operations':[]}
    try:
        product=context['project']
        if (product not in PRODUCTS or context['repository']!='cryptolabsza/'+product
                or not SHA.fullmatch(context['source_sha']) or not VERSION.fullmatch(context['version'])
                or context['tag']!='v'+context['version']):raise Hold('invalid_release_identity')
        if not platforms or len(set(platforms))!=len(platforms) or not set(platforms)<=PLATFORMS:
            raise Hold('unsupported_requested_platforms')
        tags=(context['version'],context['tag'],'sha-'+context['source_sha'])
        # Retain all observed identities, including cross-image partial histories.
        for image in PRODUCTS[product]:
            repo='ghcr.io/cryptolabsza/'+image
            target={'repository':repo,'observed_tags':{}}
            receipt['targets'].append(target)
            for tag in tags:target['observed_tags'][tag]=observed(client,repo,tag)
            values=set(target['observed_tags'].values())
            if values=={None}:target['state']='absent'
            elif None in values:target['state']='partial'
            elif len(values)!=1:target['state']='conflicting'
            else:target.update(state='complete',digest=next(iter(values)))
        states={target['state'] for target in receipt['targets']}
        if states=={'absent'}:
            if require_existing:raise Hold('publication_incomplete')
            receipt.update(status='new',build=True)
        elif states=={'complete'}:
            for target in receipt['targets']:
                validated=validate_target(client,target['repository'],target['digest'],context,platforms)
                target.update({key:value for key,value in validated.items() if key!='data'})
            receipt['status']='reuse'
        else:raise Hold('incomplete_product_release')
    except Exception as error:
        receipt['error_code']=error_code(error)
    return receipt


def build_source(root):
    name,version=project(root)
    sha=os.environ.get('GITHUB_SHA','')
    if (os.environ.get('GITHUB_ACTIONS')!='true'
            or os.environ.get('GITHUB_REPOSITORY')!='cryptolabsza/'+name
            or git(root,'rev-parse','HEAD')!=sha
            or git(root,'status','--porcelain','--untracked-files=normal')):
        raise Hold('invalid_build_source')
    result=build_tags('ghcr.io/cryptolabsza/'+PRODUCTS[name][0],os.environ['GITHUB_REF'],sha,
                     os.environ['GITHUB_EVENT_NAME'],version=version,override=os.environ.get('TAG_OVERRIDE',''))
    context={'project':name,'repository':'cryptolabsza/'+name,'version':version,
             'tag':'v'+version,'source_sha':sha}
    if result['channel']=='release-artifact' and git(root,'rev-parse',f'refs/tags/v{version}^{{commit}}')!=sha:
        raise Hold('release_source_mismatch')
    return context,result


class SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,message,headers,url):
        if request.get_method()!='GET' or urlsplit(url).scheme!='https':raise Hold('unsafe_registry_redirect')
        redirected=super().redirect_request(request,fp,code,message,headers,url)
        redirected.remove_header('Authorization')
        return redirected


class Client:
    def __init__(self):
        self.opener=build_opener(SafeRedirect());self.tokens={}
    def request(self,url,*,headers=None,data=None,method='GET',missing=False):
        try:
            with self.opener.open(Request(url,headers=headers or {},data=data,method=method),timeout=60) as response:
                return response.read(16*1024*1024+1),dict(response.headers)
        except HTTPError as error:
            if missing and error.code==404:return None
            raise RuntimeError('registry_request_failed') from None
        except (URLError,OSError):raise RuntimeError('registry_request_failed') from None
    def token(self,repo):
        if repo not in REPOS:raise Hold('unsupported_registry_repository')
        if repo not in self.tokens:
            credentials=(os.environ['GHCR_USER']+':'+os.environ['GHCR_TOKEN']).encode()
            query=urlencode({'service':'ghcr.io','scope':'repository:'+repo[len('ghcr.io/'):]+(':pull' if getattr(self,'read_only',False) else ':pull,push')})
            data,_=self.request('https://ghcr.io/token?'+query,
                                 headers={'Authorization':'Basic '+base64.b64encode(credentials).decode()})
            token=json.loads(data).get('token')
            if not isinstance(token,str) or not token:raise Hold('registry_token_unavailable')
            self.tokens[repo]=token
        return self.tokens[repo]
    def manifest(self,repo,ref,missing=False):
        if not (DIGEST.fullmatch(ref) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',ref)):
            raise Hold('invalid_registry_reference')
        result=self.request('https://ghcr.io/v2/'+repo[len('ghcr.io/'): ]+'/manifests/'+quote(ref,safe=':'),
            headers={'Authorization':'Bearer '+self.token(repo),'Accept':', '.join(sorted(MANIFESTS|INDEXES))},missing=missing)
        if result is None:return None
        data,headers=result;headers={k.lower():v for k,v in headers.items()}
        if len(data)>16*1024*1024 or headers.get('docker-content-digest')!=digest(data):
            raise Hold('registry_response_digest_mismatch')
        return data,headers['content-type'].split(';',1)[0]
    def blob(self,repo,ref):
        if not DIGEST.fullmatch(ref):raise Hold('invalid_blob_digest')
        data,_=self.request('https://ghcr.io/v2/'+repo[len('ghcr.io/'): ]+'/blobs/'+ref,
                           headers={'Authorization':'Bearer '+self.token(repo)})
        if len(data)>16*1024*1024:raise Hold('config_blob_too_large')
        return data
    def put(self,repo,tag,data,media):
        if not re.fullmatch(r'latest|stable|[0-9]+(?:\.[0-9]+)?',tag):raise Hold('unsupported_promotion_alias')
        body,headers=self.request('https://ghcr.io/v2/'+repo[len('ghcr.io/'): ]+'/manifests/'+tag,
            headers={'Authorization':'Bearer '+self.token(repo),'Content-Type':media},data=data,method='PUT')
        headers={k.lower():v for k,v in headers.items()}
        if headers.get('docker-content-digest')!=digest(data):raise Hold('registry_write_digest_mismatch')
    def github(self,repo,path):
        data,_=self.request('https://api.github.com/repos/'+repo+'/'+path,
            headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/vnd.github+json'})
        return json.loads(data)
    def release_commit(self,repo,tag):
        release=self.github(repo,'releases/tags/'+quote(tag,safe=''))
        if release.get('draft') is not False or release.get('tag_name')!=tag:raise Hold('published_release_required')
        value=self.github(repo,'git/ref/tags/'+quote(tag,safe=''))['object']
        for _ in range(5):
            if value['type']=='commit' and SHA.fullmatch(value['sha']):return value['sha']
            if value['type']!='tag' or not SHA.fullmatch(value['sha']):break
            value=self.github(repo,'git/tags/'+value['sha'])['object']
        raise Hold('published_tag_unresolved')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['tags','guard','promote'])
    parser.add_argument('--image');parser.add_argument('--root',type=Path,default=Path('.'))
    parser.add_argument('--release-tag');parser.add_argument('--source-sha')
    parser.add_argument('--expected-digest',action='append',default=[])
    parser.add_argument('--platform',action='append',default=[])
    parser.add_argument('--receipt',type=Path)
    parser.add_argument('--require-existing',action='store_true')
    args=parser.parse_args();receipt=None
    try:
        root=args.root.resolve();name,version=project(root)
        if args.command=='tags':
            if (os.environ.get('GITHUB_REPOSITORY')!='cryptolabsza/'+name
                    or args.image not in {'ghcr.io/cryptolabsza/'+image for image in PRODUCTS[name]}
                    or git(root,'rev-parse','HEAD')!=os.environ.get('GITHUB_SHA')):
                raise Hold('invalid_build_source')
            result=build_tags(args.image,os.environ['GITHUB_REF'],os.environ['GITHUB_SHA'],
                os.environ['GITHUB_EVENT_NAME'],version=version,override=os.environ.get('TAG_OVERRIDE',''))
            with open(os.environ['GITHUB_OUTPUT'],'a') as out:
                out.write('tags='+','.join(result['tags'])+'\nversion='+result['version']+'\nchannel='+result['channel']+'\n')
            return 0
        if args.command=='guard':
            if not args.receipt or args.receipt.exists():raise Hold('fresh_receipt_path_required')
            context,result=build_source(root)
            if result['channel']=='release-artifact':
                client=Client();client.read_only=True
                receipt=release_guard(context,args.platform,client,require_existing=args.require_existing)
            else:
                receipt={'schema_version':1,'status':'discovery','build':True,'release':context,
                         'channel':result['channel'],'targets':[],'operations':[]}
            args.receipt.write_text(json.dumps(receipt,indent=2)+'\n')
            if receipt['status']!='held':
                with open(os.environ['GITHUB_OUTPUT'],'a') as out:
                    out.write('build='+str(receipt['build']).lower()+'\nstatus='+receipt['status']+'\n')
                summary=os.environ.get('GITHUB_STEP_SUMMARY')
                if summary and receipt['status']=='reuse':
                    with open(summary,'a') as out:
                        out.write('## Verified existing image release identities\n\n')
                        for target in receipt['targets']:
                            out.write(f"- `{target['repository']}@{target['digest']}` retained without rebuilding\n")
                return 0
            raise Hold(receipt['error_code'])
        if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('GITHUB_EVENT_NAME')!='workflow_dispatch':
            raise Hold('manual_actions_only')
        if os.environ.get('GITHUB_REPOSITORY')!='cryptolabsza/'+name:raise Hold('repository_mismatch')
        if not args.receipt or args.receipt.exists():raise Hold('fresh_receipt_path_required')
        expected={}
        for item in args.expected_digest:
            image,identity=item.split('=',1)
            if image in expected:raise Hold('duplicate_expected_image')
            expected[image]=identity
        client=Client();context=check_source(root,args.release_tag,args.source_sha,client)
        receipt=promote(context,expected,args.platform,client)
        if receipt['status']=='verified':
            try:check_source(root,args.release_tag,args.source_sha,client)
            except Exception as error:
                receipt['status']='partial';receipt['error_code']=error_code(error)
    except Exception as error:
        if receipt is None:
            receipt={'schema_version':1,'status':'held','recorded_utc':datetime.now(timezone.utc).isoformat(),
                     'error_code':error_code(error),'build':False,'targets':[],'operations':[]}
    if args.command in ('promote','guard') and args.receipt and not args.receipt.exists():
        args.receipt.write_text(json.dumps(receipt,indent=2)+'\n')
    if receipt and receipt['status']=='verified':
        summary=os.environ.get('GITHUB_STEP_SUMMARY')
        if summary:
            with open(summary,'a') as out:
                out.write('## Verified image alias promotion\n\n')
                for item in receipt['targets']:out.write(f"- `{item['repository']}@{item['digest']}`\n")
        return 0
    print('Image release operation held; inspect the non-sensitive receipt.',file=sys.stderr)
    return 1


if __name__=='__main__':sys.exit(main())
