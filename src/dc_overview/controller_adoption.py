"""Bounded, same-image adoption of the existing customer monitoring topology.

Planning may create isolated source-proof helpers; it makes no customer-service writes. Actual inspect/Env and recovery records are private;
public reports omit environment and secret-derived fingerprints. Only DC and
Prometheus participate in compensation. Persistent stores are never rewound.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import time
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
from urllib.parse import quote

import yaml

from .monitoring import _validate_references, _jobs, PRODUCT_JOB_NAMES

ROLES = ('dc-overview', 'prometheus', 'grafana', 'cryptolabs-proxy')
MUTABLE = ('dc-overview', 'prometheus')
GUARD_CAPABILITY = {'schema_version': 1, 'api': 'AdoptionEngine.controller_guard',
                    'durable_updater_exclusion': True}
# Engine-generated inspect metadata is ignored; behavior-bearing create inputs
# are explicitly bounded. Named unsupported fields fail before staging.
CONFIG_FIELDS = frozenset('Hostname Domainname User AttachStdin AttachStdout AttachStderr ExposedPorts Tty OpenStdin StdinOnce Env Cmd Healthcheck ArgsEscaped Image Volumes WorkingDir Entrypoint NetworkDisabled MacAddress OnBuild Labels StopSignal StopTimeout Shell'.split())
HOST_FIELDS = frozenset('Binds ContainerIDFile LogConfig NetworkMode PortBindings RestartPolicy AutoRemove VolumeDriver VolumesFrom ConsoleSize CapAdd CapDrop CgroupnsMode Dns DnsOptions DnsSearch ExtraHosts GroupAdd IpcMode Cgroup Links OomScoreAdj PidMode Privileged PublishAllPorts ReadonlyRootfs SecurityOpt StorageOpt Tmpfs UTSMode UsernsMode ShmSize Sysctls Runtime Isolation CpuShares Memory NanoCpus CgroupParent BlkioWeight BlkioWeightDevice BlkioDeviceReadBps BlkioDeviceWriteBps BlkioDeviceReadIOps BlkioDeviceWriteIOps CpuPeriod CpuQuota CpuRealtimePeriod CpuRealtimeRuntime CpusetCpus CpusetMems Devices DeviceCgroupRules DeviceRequests MemoryReservation MemorySwap MemorySwappiness OomKillDisable PidsLimit Ulimits CpuCount CpuPercent IOMaximumIOps IOMaximumBandwidth MaskedPaths ReadonlyPaths Init Mounts'.split())
ENDPOINT_FIELDS = frozenset('Aliases Links IPAMConfig MacAddress DriverOpts GwPriority'.split())
ENDPOINT_METADATA = frozenset('NetworkID EndpointID Gateway IPAddress IPPrefixLen IPv6Gateway GlobalIPv6Address GlobalIPv6PrefixLen DNSNames'.split())


# Fixed stdlib-only helper. Read unchanged source from its immutable image;
# cached payloads are data and are never invoked as executable code.
CACHE_PROOF_SCRIPT = r"""
import base64, importlib.util, io, json, marshal, os, pathlib, stat, sys
ok=False
try:
 value=json.loads(base64.b64decode(''.join(sys.argv[1:-1]),validate=True)); rows=value['caches']; total=0; ok=isinstance(rows,list)
 for row in value['directories']:
  path=pathlib.Path(row['path'])
  if path.is_symlink() or '..' in path.parts or not path.is_absolute(): ok=False; break
  if path.exists():
   current=path.stat(); expected={'uid':current.st_uid,'gid':current.st_gid,'mode':stat.S_IMODE(current.st_mode)}
   if not path.is_dir(): ok=False; break
  elif path.name=='__pycache__' and row['kind']==1:
   parent=path.parent.stat(); expected={'uid':parent.st_uid,'gid':parent.st_gid,'mode':0o755}
  else: ok=False; break
  if row['custody']!=expected: ok=False; break
 for row in rows if ok else []:
  cached=base64.b64decode(row['cache'],validate=True); total+=len(cached)
  if len(cached)>256*1024 or total>8*1024*1024 or len(cached)<16 or cached[:4]!=importlib.util.MAGIC_NUMBER: ok=False; break
  if int.from_bytes(cached[4:8],'little') not in (0,1,3) or row['optimize'] not in (0,1,2): ok=False; break
  source=pathlib.Path(row['source'])
  if not source.is_absolute() or '..' in source.parts or source.is_symlink() or source.stat().st_size>1024*1024: ok=False; break
  expected=compile(source.read_bytes(),str(source),'exec',dont_inherit=True,optimize=row['optimize'])
  payload=io.BytesIO(cached[16:]); actual=marshal.load(payload)
  if payload.tell()!=len(cached)-16 or actual!=expected or actual.co_filename!=str(source): ok=False; break
except Exception: ok=False
pathlib.Path(sys.argv[-1]).write_text(json.dumps({'equivalent':bool(ok)}))
os.chmod(sys.argv[-1],0o600)
"""

class AdoptionError(RuntimeError):
    """A bounded precondition or recovery hold; never contains inspected Env."""


RUNNING_FILE_PROOF_SCRIPT = r'''
set -eu
[ "$#" -eq 2 ]
limit="$1"; file="$2"; parent="$file"
while [ "$parent" != / ]; do
  [ ! -L "$parent" ] || exit 1
  parent="${parent%/*}"; [ -n "$parent" ] || parent=/
done
[ -f "$file" ]
snapshot() {
  /bin/busybox stat -c '%u %g %a %s %i %d' "$file"
  parent="$file"
  while :; do
    parent="${parent%/*}"; [ -n "$parent" ] || parent=/
    [ "$parent" != / ] || break
    [ -d "$parent" ]
    /bin/busybox stat -c '%u %g %a %i %d' "$parent"
  done
}
metadata=$(/bin/busybox stat -c '%s' "$file")
[ "$metadata" -le "$limit" ]
before=$(snapshot)
printf '%s\nDATA\n' "$before"
/bin/busybox od -An -v -tx1 "$file"
printf '\nEND\n'
after=$(snapshot)
[ "$before" = "$after" ]
printf '%s\n' "$after"
'''


def _encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

def _cache_proof_command(payload):
    """Bound the whole helper argv, including fixed arguments and NULs."""
    entrypoint=['python3','-I','-B','-S','-c',CACHE_PROOF_SCRIPT]
    command=[payload[i:i+48*1024] for i in range(0,len(payload),48*1024)]+['/tmp/source-proof.json']
    sizes=[len(arg.encode()) for arg in entrypoint+command]
    if max(sizes)>48*1024 or sum(size+1 for size in sizes)>512*1024:
        raise AdoptionError('unsupported cache proof payload argument bound')
    return entrypoint,command

def _safe_path(value):
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts or any(c in str(path) for c in '\0\r\n:'):
        raise AdoptionError('unsupported absolute path')
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise AdoptionError('symlink path is unsupported')
    return path


def _declaration(value):
    required = {'schema_version','product_directory','dc_destination','managed_jobs','session_routes','maintenance_owners','public_inputs'}
    if not isinstance(value,dict) or set(value) != required or value['schema_version'] != 1:
        raise AdoptionError('controller declaration schema_version 1 required')
    value = copy.deepcopy(value)
    product = _safe_path(value['product_directory'])
    # Public product files must not be put underneath the private config root.
    if product == Path('/etc/dc-overview') or Path('/etc/dc-overview') in product.parents:
        raise AdoptionError('product directory requires independently traversable public custody')
    target = PurePosixPath(value['dc_destination'])
    if not target.is_absolute() or '..' in target.parts or str(target).startswith(('/etc/','/app','/data')) or str(target) == '/':
        raise AdoptionError('DC writer destination requires an isolated traversable path')
    for key in ('managed_jobs','session_routes','maintenance_owners','public_inputs'):
        if not isinstance(value[key],list) or any(not isinstance(v,str) or not v for v in value[key]) or len(value[key]) != len(set(value[key])):
            raise AdoptionError('invalid declaration '+key)
    if not value['session_routes'] or set(value['session_routes']) - {'proxy-sso','local-cookie'}:
        raise AdoptionError('session route authority declaration required')
    if not value['maintenance_owners']:
        raise AdoptionError('affected external lifecycle owners require maintenance exclusion')
    for p in value['public_inputs']: _safe_path(p)
    value['product_directory'] = str(product)
    value['dc_destination'] = str(target)
    return value


def _mounts(source):
    rows = source.get('Mounts')
    if not isinstance(rows,list): raise AdoptionError('mount inventory unavailable')
    result=[]; targets=set()
    options={m.get('Target'):m for m in source['HostConfig'].get('Mounts',[]) or []}
    for mount in rows:
        kind=mount.get('Type'); target=mount.get('Destination')
        if kind not in ('bind','volume') or not isinstance(target,str) or target in targets:
            raise AdoptionError('unsupported mount type or duplicate destination')
        mode=mount.get('Mode','')
        if set(mode.split(',')) - {'','ro','rw','private','rprivate','shared','rshared','slave','rslave'}:
            raise AdoptionError('unsupported Mounts.Mode; SELinux/relabel options require explicit preservation')
        origin=mount.get('Name') if kind=='volume' else mount.get('Source')
        if not origin or type(mount.get('RW')) is not bool:
            raise AdoptionError('exact mount identity/readonly inventory required')
        item={'Type':kind,'Source':origin,'Target':target,'ReadOnly':not mount['RW']}
        declaration=options.get(target,{})
        for name in ('Consistency','BindOptions','VolumeOptions'):
            if name in declaration: item[name]=copy.deepcopy(declaration[name])
        if kind=='bind' and mount.get('Propagation'):
            item.setdefault('BindOptions',{})['Propagation']=mount['Propagation']
        if set(declaration)-{'Type','Source','Target','ReadOnly','Consistency','BindOptions','VolumeOptions'}:
            raise AdoptionError('unsupported mount option')
        targets.add(target); result.append(item)
    if source['HostConfig'].get('VolumesFrom'):
        raise AdoptionError('unsupported HostConfig.VolumesFrom: inherited custody needs explicit ownership')
    if source['HostConfig'].get('AutoRemove'):
        raise AdoptionError('unsupported HostConfig.AutoRemove: predecessor retention required')
    return result


def _request(source):
    if not isinstance(source,dict) or not all(key in source for key in ('Id','Image','Config','HostConfig','Mounts','NetworkSettings','State')):
        raise AdoptionError('incomplete runtime inventory')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',source['Image']):
        raise AdoptionError('exact installed image ID required')
    for field in source['Config']:
        if field not in CONFIG_FIELDS: raise AdoptionError('unsupported Config.'+field)
    for field in source['HostConfig']:
        if field not in HOST_FIELDS: raise AdoptionError('unsupported HostConfig.'+field)
    networks=source['NetworkSettings'].get('Networks')
    if not isinstance(networks,dict) or not networks: raise AdoptionError('complete network endpoints required')
    endpoints={}
    for name, endpoint in networks.items():
        if not isinstance(endpoint,dict): raise AdoptionError('network endpoint unavailable')
        unknown=set(endpoint)-ENDPOINT_FIELDS-ENDPOINT_METADATA
        if unknown: raise AdoptionError('unsupported network endpoint.'+sorted(unknown)[0])
        endpoints[name]={k:copy.deepcopy(v) for k,v in endpoint.items() if k in ENDPOINT_FIELDS}
        if endpoints[name].get('Aliases'):
            endpoints[name]['Aliases']=[v for v in endpoints[name]['Aliases'] if v not in (source['Id'],source['Id'][:12])]
    config=copy.deepcopy(source['Config']); config['Image']=source['Image']
    host=copy.deepcopy(source['HostConfig']); host.pop('Binds',None); host['Mounts']=_mounts(source)
    return {'Config':config,'HostConfig':host,'NetworkingConfig':{'EndpointsConfig':endpoints}}


def _public_monitoring_config(payload):
    """Bounded public schema; unknown credential-bearing contexts are holds.

    Public labels/relabel expressions are intentional metadata. HTTP credentials
    and TLS private material require the explicitly supported file forms. Cloud
    discovery, remote write/read and arbitrary query/header forms are unsupported,
    rather than being declared secret-free by a credential-key denylist.
    """
    from urllib.parse import urlsplit
    try: config=yaml.safe_load(payload)
    except yaml.YAMLError: raise AdoptionError('unsupported public monitoring YAML') from None
    def fields(value,allowed,context):
        if not isinstance(value,dict): raise AdoptionError('unsupported public monitoring context: '+context)
        unknown=set(value)-set(allowed)
        if unknown:
            name=next(iter(unknown)); name=name if isinstance(name,str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*',name) else 'unknown_field'
            raise AdoptionError('unsupported public monitoring context: '+context+'.'+name)
        maps={'global','alerting','external_labels','labels','basic_auth','authorization','oauth2','tls_config','http_headers'}
        lists={'scrape_configs','rule_files','alertmanagers','static_configs','file_sd_configs','http_sd_configs','dns_sd_configs','relabel_configs','metric_relabel_configs','alert_relabel_configs','scopes','source_labels','files','names','targets','scrape_protocols'}
        scalar_lists={'rule_files','scopes','source_labels','files','names','targets','scrape_protocols'}
        for key,item in value.items():
            if key in maps and not isinstance(item,dict) or key in lists and not isinstance(item,list):
                raise AdoptionError('unsupported public monitoring shape: '+context+'.'+key)
            if isinstance(item,(dict,list)) and key not in maps|lists:
                raise AdoptionError('unsupported public monitoring scalar: '+context+'.'+key)
            if key in scalar_lists and any(not isinstance(v,str) for v in item):
                raise AdoptionError('unsupported public monitoring list: '+context+'.'+key)
    def public_scalars(value,context):
        if not isinstance(value,dict) or any(not isinstance(k,str) or not isinstance(v,(str,int,float,bool)) for k,v in value.items()):
            raise AdoptionError('unsupported public metadata: '+context)
    def url(value,context):
        if not isinstance(value,str): raise AdoptionError('unsupported public URL: '+context)
        parsed=urlsplit(value)
        if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise AdoptionError('unsupported inline credentials/query URL: '+context)
    def tls(value,context):
        fields(value,{'ca_file','cert_file','key_file','server_name','insecure_skip_verify','min_version','max_version'},context)
    http={'basic_auth','authorization','oauth2','bearer_token_file','tls_config','proxy_url','no_proxy','proxy_from_environment','follow_redirects','enable_http2','http_headers'}
    def client(value,context):
        if 'basic_auth' in value: fields(value['basic_auth'],{'username','password_file'},context+'.basic_auth')
        if 'authorization' in value: fields(value['authorization'],{'type','credentials_file'},context+'.authorization')
        if 'oauth2' in value:
            auth=value['oauth2']; fields(auth,{'client_id','client_secret_file','scopes','token_url','tls_config','proxy_url','no_proxy','proxy_from_environment','follow_redirects','enable_http2'},context+'.oauth2')
            if 'token_url' in auth: url(auth['token_url'],context+'.oauth2.token_url')
            if 'proxy_url' in auth: url(auth['proxy_url'],context+'.oauth2.proxy_url')
            if 'tls_config' in auth: tls(auth['tls_config'],context+'.oauth2.tls_config')
        if 'tls_config' in value: tls(value['tls_config'],context+'.tls_config')
        if 'proxy_url' in value: url(value['proxy_url'],context+'.proxy_url')
        if 'http_headers' in value:
            if not isinstance(value['http_headers'],dict): raise AdoptionError('unsupported inline HTTP headers')
            for header,entry in value['http_headers'].items():
                fields(entry,{'files'},context+'.http_headers')
                if not entry.get('files') or not isinstance(entry['files'],list): raise AdoptionError('unsupported inline HTTP header form')
    def discovery(value,context):
        for kind,allowed in [('static_configs',{'targets','labels'}),('file_sd_configs',{'files','refresh_interval'}),('dns_sd_configs',{'names','type','port','refresh_interval'}),('http_sd_configs',{'url','refresh_interval'}|http)]:
            if kind not in value: continue
            if not isinstance(value[kind],list): raise AdoptionError('unsupported public discovery: '+context+'.'+kind)
            for row in value[kind]:
                fields(row,allowed,context+'.'+kind)
                if 'labels' in row: public_scalars(row['labels'],context+'.labels')
                if kind=='static_configs' and any(not isinstance(v,str) or '@' in v or '://' in v or '?' in v for v in row.get('targets',[])):
                    raise AdoptionError('unsupported inline target authority')
                if kind=='http_sd_configs': url(row.get('url'),context+'.http_sd_configs.url'); client(row,context+'.http_sd_configs')
    def relabel(value,context):
        if not isinstance(value,list): raise AdoptionError('unsupported public relabel context')
        for row in value: fields(row,{'source_labels','separator','target_label','regex','modulus','replacement','action'},context)
    fields(config,{'global','scrape_configs','rule_files','alerting'},'config')
    if 'global' in config:
        fields(config['global'],{'scrape_interval','scrape_timeout','evaluation_interval','external_labels','scrape_protocols'},'global')
        if 'external_labels' in config['global']: public_scalars(config['global']['external_labels'],'global.external_labels')
    job={'job_name','scheme','metrics_path','honor_labels','honor_timestamps','track_timestamps_staleness','scrape_interval','scrape_timeout','scrape_protocols','fallback_scrape_protocol','scrape_classic_histograms','sample_limit','target_limit','label_limit','label_name_length_limit','label_value_length_limit','body_size_limit','relabel_configs','metric_relabel_configs','static_configs','file_sd_configs','dns_sd_configs','http_sd_configs'}|http
    for row in config.get('scrape_configs',[]):
        fields(row,job,'scrape_configs'); client(row,'scrape_configs'); discovery(row,'scrape_configs')
        for name in ('relabel_configs','metric_relabel_configs'):
            if name in row: relabel(row[name],'scrape_configs.'+name)
    if 'alerting' in config:
        fields(config['alerting'],{'alertmanagers','alert_relabel_configs'},'alerting')
        if 'alert_relabel_configs' in config['alerting']: relabel(config['alerting']['alert_relabel_configs'],'alerting.alert_relabel_configs')
        for row in config['alerting'].get('alertmanagers',[]):
            fields(row,{'scheme','path_prefix','timeout','api_version','relabel_configs','static_configs','file_sd_configs','dns_sd_configs','http_sd_configs'}|http,'alertmanagers')
            client(row,'alertmanagers'); discovery(row,'alertmanagers')
            if 'relabel_configs' in row: relabel(row['relabel_configs'],'alertmanagers.relabel_configs')
    _validate_references(config,tuple(_references(config)))
    return config


def _references(config):
    result=set(config.get('rule_files',[]))
    def visit(node,parent=''):
        if isinstance(node,dict):
            for key,value in node.items():
                if key.endswith('_file') and isinstance(value,str): result.add(value)
                if key=='files' and isinstance(value,list):
                    result.update(value)
                visit(value,key)
        elif isinstance(node,list):
            for value in node: visit(value,parent)
    visit(config)
    return result


def _ordinary_directory_source(inventory, product):
    """Only the published installer's exact directory pair may be retired."""
    roots = [m for m in _mounts(inventory['prometheus']) if m['Target'] == '/etc/prometheus']
    if not roots or roots[0]['Source'] == product: return None
    root = roots[0]
    if root['Type'] != 'bind' or root['ReadOnly'] is not True or set(root) - {'Type','Source','Target','ReadOnly','BindOptions'} or root.get('BindOptions', {}) != {'Propagation':'rprivate'}:
        raise AdoptionError('unsupported predecessor directory mount custody')
    source = _safe_path(root['Source'])
    if not source.is_dir() or source.name != 'prometheus':
        raise AdoptionError('unsupported predecessor directory source')
    dc = _mounts(inventory['dc-overview'])
    writer = {'Type':'bind','Source':str(source),'Target':'/etc/dc-overview/prometheus','ReadOnly':False,'BindOptions':{'Propagation':'rprivate'}}
    if writer not in dc or not any(m['Type']=='bind' and m['Source']==str(source.parent) and m['Target']=='/etc/dc-overview' and m['ReadOnly'] for m in dc):
        raise AdoptionError('ordinary predecessor directory pair/private parent custody required')
    for role, target in (('dc-overview','/etc/dc-overview/prometheus'),('prometheus','/etc/prometheus')):
        for mount in _mounts(inventory[role]):
            if mount['Target'].startswith(target + '/') and not (role=='prometheus' and mount['ReadOnly'] and (mount['Target']=='/etc/prometheus/customer' or mount['Target'].startswith('/etc/prometheus/customer/'))):
                raise AdoptionError('predecessor directory overlap unsupported')
    new = _safe_path(product)
    if new == source or source in new.parents or new in source.parents:
        raise AdoptionError('new product directory overlaps predecessor custody')
    return source


def _directory_state(source):
    """Complete flat member accounting; no credential/subtree inference."""
    metadata = source.stat()
    result = {'source':str(source),'uid':metadata.st_uid,'gid':metadata.st_gid,'mode':stat.S_IMODE(metadata.st_mode),
        'parents':{str(p):{'uid':p.stat().st_uid,'gid':p.stat().st_gid,'mode':stat.S_IMODE(p.stat().st_mode)} for p in source.parents},'members':{}}
    members = list(source.iterdir())
    if len(members)>3: raise AdoptionError('unsupported predecessor directory member inventory')
    for path in members:
        info = path.lstat()
        if path.name not in {'prometheus.yml','recording_rules.yml','prometheus.yml.lock'} or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size>2*1024*1024:
            raise AdoptionError('unsupported predecessor directory member custody')
        if path.name.endswith('.lock'):
            if info.st_size or stat.S_IMODE(info.st_mode) != 0o600:
                raise AdoptionError('unsupported predecessor directory coordination custody')
            # Optional coordination inode is acquired separately; creation of an
            # absent lock by the writer is not customer configuration drift.
            continue
        result['members'][path.name]={'bytes':path.read_bytes().hex(),'uid':info.st_uid,'gid':info.st_gid,
            'mode':stat.S_IMODE(info.st_mode),'inode':info.st_ino,'device':info.st_dev}
    if set(result['members']) != {'prometheus.yml','recording_rules.yml'}:
        raise AdoptionError('ordinary predecessor directory members incomplete')
    return result


def _source_config_path(inventory):
    mounts = _mounts(inventory['prometheus'])
    file = next((m for m in mounts if m['Type']=='bind' and m['Target']=='/etc/prometheus/prometheus.yml'),None)
    if file: return _safe_path(file['Source'])
    root = next((m for m in mounts if m['Type']=='bind' and m['Target']=='/etc/prometheus'),None)
    return _safe_path(Path(root['Source'])/'prometheus.yml') if root else None


def _snapshot(inventory, config_bytes, evidence):
    # These bytes are private. Do not put their low-entropy Env hashes in public output.
    return _encoded({'runtime':{r:_request(v) | {'Id':v['Id'],'Running':v.get('State',{}).get('Running'),'Paused':v.get('State',{}).get('Paused',False)} for r,v in inventory.items()},
        'config':config_bytes.hex(), 'evidence':{k:v for k,v in evidence.items() if k!='reference_files'},
        'reference_files':{k:v.hex() for k,v in evidence.get('reference_files',{}).items()}})


@dataclass
class ControllerPlan:
    declaration: dict
    sources: dict
    requests: dict
    mutations: tuple
    prometheus_bytes: bytes
    evidence: dict
    snapshot: bytes
    operation_id: str

    def public(self):
        return {'schema_version':1,'operation_id':self.operation_id,'state':'planned' if self.mutations else 'already-adopted',
            'mutations':list(self.mutations),'preserved_dependencies':['grafana','cryptolabs-proxy','auth','vast-price-manager'],
            'images':{r:v['Image'] for r,v in self.sources.items()},'persistent_state':'retained; no database or TSDB rewind',
            'required_acceptance':['mounted custody','effective Prometheus configuration','sanctioned write/reload','declared session routes','inventory/outbox continuity']}

    def matches(self,inventory,config_bytes,evidence):
        try: return self.snapshot == _snapshot(inventory,config_bytes,evidence)
        except (AdoptionError,KeyError,TypeError,ValueError): return False

    def private(self):
        return {'declaration':self.declaration,'sources':self.sources,'requests':self.requests,'mutations':list(self.mutations),
            'prometheus_bytes':self.prometheus_bytes.hex(),'evidence':{**self.evidence,'reference_files':{k:v.hex() for k,v in self.evidence.get('reference_files',{}).items()}},
            'snapshot':self.snapshot.hex(),'operation_id':self.operation_id}

    @classmethod
    def from_private(cls,value):
        data=copy.deepcopy(value); data['prometheus_bytes']=bytes.fromhex(data['prometheus_bytes']); data['snapshot']=bytes.fromhex(data['snapshot']); data['mutations']=tuple(data['mutations'])
        data['evidence']['reference_files']={k:bytes.fromhex(v) for k,v in data['evidence']['reference_files'].items()}
        return cls(**data)


def build_plan(inventory,declaration,config_bytes,evidence):
    """Pure bounded topology diff; no config generation or ownership guessing."""
    declaration=_declaration(declaration)
    if not isinstance(inventory,dict) or set(inventory)!=set(ROLES): raise AdoptionError('complete controller inventory required')
    sources=copy.deepcopy(inventory)
    requests={r:_request(v) for r,v in sources.items()}
    if any(sources[r]['State'].get('Running') is not True or sources[r]['State'].get('Paused') is True for r in MUTABLE):
        raise AdoptionError('unsupported stopped/paused topology writer; no service activated')
    if any(sources[r]['State'].get('Paused') is True for r in ROLES):
        raise AdoptionError('unsupported paused controller dependency; no service activated')
    if any(evidence.get('effective_source',{}).get(r) is not True for r in MUTABLE):
        raise AdoptionError('source_normalization_required: reviewed compatible changed-vector update before topology adoption')
    dc=sources['dc-overview']; env=dc['Config'].get('Env') or []
    if 'local-cookie' in declaration['session_routes'] and not any(v.startswith('SECRET_KEY=') and v.partition('=')[2] for v in env):
        raise AdoptionError('local_cookie continuity requires existing stable SECRET_KEY; no key generated')
    try:
        config=_public_monitoring_config(config_bytes)
        if not isinstance(config,dict): raise ValueError('mapping')
        names=_jobs(config.get('scrape_configs',[]))
        if 'dc-managed' in names and 'dc-managed' not in declaration['managed_jobs']: raise AdoptionError('explicit product job ownership required')
        refs=_references(config)
        if any(not isinstance(ref,str) or not ref.startswith('/') or '..' in PurePosixPath(ref).parts or any(c in ref for c in '\0\r\n') for ref in refs):
            raise AdoptionError('monitoring reference requires a safe absolute path')
        if any(not isinstance(ref,str) or any(c in ref for c in '*?[') for ref in refs): raise AdoptionError('unsupported glob monitoring reference')
        _validate_references(config,tuple(refs))
    except AdoptionError: raise
    except (ValueError,TypeError,yaml.YAMLError): raise AdoptionError('inline credentials or unsupported monitoring configuration') from None
    if not refs<=set(evidence.get('reference_files',{})): raise AdoptionError('monitoring reference bytes/custody incomplete')
    prom=sources['prometheus']; commands=prom['Config'].get('Cmd') or []
    if not any(v in ('--config.file=/etc/prometheus/prometheus.yml','/etc/prometheus/prometheus.yml') for v in commands):
        raise AdoptionError('unsupported Prometheus --config.file; exact existing standard path required')
    product=declaration['product_directory']; destination=declaration['dc_destination']
    predecessor = _ordinary_directory_source(sources, product)
    if predecessor:
        state = evidence.get('source_directory')
        if state != _directory_state(predecessor) or state['members']['prometheus.yml']['bytes'] != config_bytes.hex():
            raise AdoptionError('predecessor directory member/config custody unverified')
        if any(state['members']['prometheus.yml'][key] != evidence.get('config_custody', {}).get(key) for key in ('uid','gid','mode')):
            raise AdoptionError('predecessor directory/archive config custody differs')
        if '/etc/prometheus/recording_rules.yml' not in config.get('rule_files', []) or refs.intersection({'/etc/prometheus/prometheus.yml','/etc/prometheus/prometheus.yml.lock','/etc/prometheus/ownership.json'}):
            raise AdoptionError('ordinary predecessor directory references unaccounted')
        if state['members']['recording_rules.yml']['bytes'] != evidence['reference_files'].get('/etc/prometheus/recording_rules.yml',b'').hex():
            raise AdoptionError('predecessor directory reference bytes drift')
        if any(state['members']['recording_rules.yml'][key] != evidence.get('reference_custody', {}).get('/etc/prometheus/recording_rules.yml', {}).get(key) for key in ('uid','gid','mode')):
            raise AdoptionError('predecessor directory/archive rule custody differs')
    candidate=requests['dc-overview']
    candidate['Config']['Env']=[v for v in env if not v.startswith(('PROMETHEUS_CONFIG_PATH=','PROMETHEUS_OWNERSHIP_PATH='))]+[
        'PROMETHEUS_CONFIG_PATH='+destination+'/prometheus.yml','PROMETHEUS_OWNERSHIP_PATH='+destination+'/ownership.json']
    mounts=candidate['HostConfig']['Mounts']
    if predecessor:
        mounts[:] = [m for m in mounts if m['Target'] != '/etc/dc-overview/prometheus']
    target=next((m for m in mounts if m['Target']==destination),None)
    desired={'Type':'bind','Source':product,'Target':destination,'ReadOnly':False,'BindOptions':{'Propagation':'rprivate'}}
    if target and target!=desired: raise AdoptionError('DC writer destination collision')
    if any(m['Target']!=destination and (destination.startswith(m['Target']+'/') or m['Target'].startswith(destination+'/')) for m in mounts):
        raise AdoptionError('DC writer destination overlaps existing mount')
    if not target: mounts.append(desired)
    candidate=requests['prometheus']; mounts=candidate['HostConfig']['Mounts']
    root=next((m for m in mounts if m['Target']=='/etc/prometheus'),None)
    desired={'Type':'bind','Source':product,'Target':'/etc/prometheus','ReadOnly':True,'BindOptions':{'Propagation':'rprivate'}}
    if root and root!=desired and not predecessor:
        # Directory adoption requires reading every potentially visible member;
        # this first contract supports the config-file-mounted predecessor.
        raise AdoptionError('unsupported existing Prometheus directory mount; explicit file custody mapping required')
    retained=[m for m in mounts if m['Target']!='/etc/prometheus/prometheus.yml' and not (predecessor and m['Target']=='/etc/prometheus')]
    if predecessor:
        retained.append({'Type':'bind','Source':str(predecessor/'recording_rules.yml'),'Target':'/etc/prometheus/recording_rules.yml','ReadOnly':True,'BindOptions':{'Propagation':'rprivate'}})
    if any(m['Target']=='/etc/prometheus/ownership.json' for m in retained): raise AdoptionError('monitoring ownership path collision')
    for ref in refs:
        if not any(ref==m['Target'] or ref.startswith(m['Target']+'/') for m in retained):
            raise AdoptionError('external reference mount custody unavailable')
    if not root or predecessor: retained.append(desired)
    candidate['HostConfig']['Mounts']=retained
    mutations=tuple(r for r in MUTABLE if _request(sources[r])!=requests[r])
    snapshot=_snapshot(sources,config_bytes,evidence)
    # Public operation identity depends only on inspected immutable container IDs
    # and public declaration, never on Env or secret-derived hash material.
    identity=hashlib.sha256(_encoded({'ids':{r:v['Id'] for r,v in sources.items()},'declaration':declaration})).hexdigest()[:24]
    return ControllerPlan(declaration,sources,{r:requests[r] for r in mutations},mutations,config_bytes,copy.deepcopy(evidence),snapshot,identity)


@contextmanager
def bounded_lock(path,*,timeout=5):
    path=_safe_path(path)
    descriptor=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'a+b') as handle:
        identity=os.fstat(handle.fileno())
        if not stat.S_ISREG(identity.st_mode) or identity.st_nlink!=1:
            raise AdoptionError('monitoring/lifecycle lock regular inode required')
        def verify():
            try: current=path.lstat()
            except OSError: raise AdoptionError('monitoring/lifecycle lock inode drift') from None
            if (current.st_dev,current.st_ino,current.st_uid,current.st_gid,stat.S_IMODE(current.st_mode)) != (identity.st_dev,identity.st_ino,identity.st_uid,identity.st_gid,stat.S_IMODE(identity.st_mode)):
                raise AdoptionError('monitoring/lifecycle lock inode or custody drift')
        deadline=time.monotonic()+timeout
        while True:
            try: fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB); break
            except BlockingIOError:
                if time.monotonic()>=deadline: raise AdoptionError('lifecycle/monitoring lock busy') from None
                time.sleep(min(.05,max(0,deadline-time.monotonic())))
        try:
            verify(); yield verify
        finally: fcntl.flock(handle,fcntl.LOCK_UN)


class Journal:
    def __init__(self,root): self.root=_safe_path(root); self.path=self.root/'operation.json'
    def read(self):
        if not self.path.exists(): return None
        if self.path.is_symlink() or not self.path.is_file(): raise AdoptionError('unsafe recovery record')
        if stat.S_IMODE(self.root.stat().st_mode)!=0o700 or stat.S_IMODE(self.path.stat().st_mode)!=0o600:
            raise AdoptionError('recovery custody must be private')
        return json.loads(self.path.read_bytes())
    def write(self,value):
        self.root.mkdir(mode=0o700,parents=False,exist_ok=True)
        if stat.S_IMODE(self.root.stat().st_mode)!=0o700: raise AdoptionError('recovery directory must be 0700')
        if self.path.is_symlink(): raise AdoptionError('symlink recovery record')
        descriptor,temp=tempfile.mkstemp(prefix='.operation-',dir=self.root)
        try:
            with os.fdopen(descriptor,'wb') as stream:
                os.fchmod(stream.fileno(),0o600); stream.write(_encoded(value)); stream.flush(); os.fsync(stream.fileno())
            os.replace(temp,self.path)
            fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
        finally:
            if os.path.exists(temp): os.unlink(temp)


def ensure_mutation_allowed(config_dir,*,inventory=None,recovery_directory=None,setup=False):
    """Guard ordinary host setup/upgrade before configuration/selection writes."""
    root=Path(config_dir)
    record=Journal(recovery_directory or root/'controller-recovery').read()
    if record and (record.get('state') not in ('adopted','restored') or record.get('exclusion_released') is not True):
        raise AdoptionError('controller recovery required before normal lifecycle mutation')
    if setup:
        if inventory is None: inventory=probe_controller_inventory()
        if any(v is not None for v in inventory.values()):
            raise AdoptionError('existing controller: use configuration inspect/plan/adopt; setup cannot replace installed identities')
    return True


def probe_controller_inventory():
    """Docker absence requires an exact named diagnostic, never a failed probe."""
    import subprocess
    from .fleet_upgrade import _container_absent
    result={}
    for role in ROLES:
        try: observed=subprocess.run(['docker','container','inspect',role,'--format','{{json .}}'],capture_output=True,text=True,timeout=15)
        except (OSError,subprocess.SubprocessError): raise AdoptionError('controller inventory unavailable; no writes allowed') from None
        if _container_absent(observed,role): result[role]=None; continue
        if observed.returncode!=0: raise AdoptionError('controller inventory unknown; no writes allowed')
        try:
            result[role]=json.loads(observed.stdout)
            if not isinstance(result[role],dict) or not result[role].get('Id'): raise ValueError('inventory')
        except (ValueError,TypeError): raise AdoptionError('controller inventory malformed; no writes allowed') from None
    return result


class InstalledEngine:
    """Adapter to the installed public proxy package, without CLI side effects."""
    def __init__(self,engine=None):
        if engine is None:
            try:
                from cryptolabs_proxy.standard_adoption import AdoptionEngine
                engine=AdoptionEngine(timeout=15)
            except (ImportError,AttributeError): raise AdoptionError('install compatible public cryptolabs-proxy host package') from None
        self.engine=engine
    def __getattr__(self,name): return getattr(self.engine,name)
    def require_guard_capability(self):
        if not callable(getattr(self.engine,'controller_guard',None)):
            raise AdoptionError('installed controller_guard API unavailable; no adoption writes allowed')
        from .fleet_upgrade import proxy_capabilities
        source=self.engine.inspect('cryptolabs-proxy')
        observed=proxy_capabilities(container_id=source['Id'])
        if not isinstance(observed,dict) or observed.get('controller_adoption_guard')!=GUARD_CAPABILITY:
            raise AdoptionError('running proxy lacks durable controller_guard capability; update its reviewed public artifact first')
        image=self.engine.image(source['Image'])
        if not any(v.startswith('ghcr.io/cryptolabsza/cryptolabs-proxy@sha256:') for v in image.get('RepoDigests',[])):
            raise AdoptionError('running proxy published immutable artifact identity unverified')
        changes=self.changes(source['Id'])
        roots=('/app/src/cryptolabs_proxy','/app/cryptolabs_proxy')
        if not self.prove_effective_source(source['Id'],changes,source['Mounts']):
            raise AdoptionError('running proxy updater executable source override; reviewed artifact update required')
    def changes(self,name): return json.loads(self.engine._request('GET','/containers/'+quote(name,safe='')+'/changes'))
    def read_file(self,name,path): return self.engine._file_bytes(name,path)
    def maybe_inspect(self,name):
        try: return self.inspect(name)
        except Exception as error:
            if str(error).endswith('returned HTTP 404'): return None
            raise AdoptionError('container stop/identity inventory unknown') from None
    def readiness(self,name,expected):
        from cryptolabs_proxy.migration import wait_for_container_healthy
        if name=='grafana':
            return self.grafana_readiness(expected)
        if not wait_for_container_healthy(self.engine,name,timeout=150): return False
        actual=self.inspect(name)
        if actual['Image']!=expected['Config']['Image'] or actual.get('State',{}).get('Running') is not True or _request(actual)!=expected:
            return False
        if name == 'prometheus':
            return self.effective_prometheus(actual)
        return True

    def grafana_readiness(self,expected):
        import http.client
        from urllib.parse import urlsplit
        actual=self.inspect('grafana')
        if actual.get('State',{}).get('Running') is not True or _request(actual)!=expected: return False
        binding=actual['HostConfig'].get('PortBindings',{}).get('3000/tcp') or []
        if len(binding)!=1: return False
        host=binding[0].get('HostIp') or '127.0.0.1'
        if host in ('0.0.0.0','::'): host='127.0.0.1'
        environment=dict(v.partition('=')[::2] for v in actual['Config'].get('Env',[]))
        prefix=urlsplit(environment.get('GF_SERVER_ROOT_URL','')).path if environment.get('GF_SERVER_SERVE_FROM_SUB_PATH','').lower()=='true' else ''
        connection=http.client.HTTPConnection(host,int(binding[0]['HostPort']),timeout=10)
        try:
            connection.request('GET',prefix.rstrip('/')+'/api/health'); response=connection.getresponse()
            return response.status==200 and json.loads(response.read()).get('database')=='ok'
        except (OSError,ValueError,TypeError): return False
        finally: connection.close()

    def effective_prometheus(self,source):
        """Read the actual process config through an existing published port."""
        import http.client
        from .monitoring import declared_configuration_matches
        bindings = source['HostConfig'].get('PortBindings',{}).get('9090/tcp') or []
        if len(bindings)!=1: return False
        binding=bindings[0]; host=binding.get('HostIp') or '127.0.0.1'
        if host in ('0.0.0.0','::'): host='127.0.0.1'
        prefix=next((v.partition('=')[2] for v in source['Config'].get('Cmd',[]) if v.startswith('--web.route-prefix=')),None)
        if prefix is None:
            from urllib.parse import urlsplit
            external=next((v.partition('=')[2] for v in source['Config'].get('Cmd',[]) if v.startswith('--web.external-url=')), '')
            prefix=urlsplit(external).path
        connection=http.client.HTTPConnection(host,int(binding['HostPort']),timeout=10)
        try:
            connection.request('GET',prefix.rstrip('/')+'/api/v1/status/config')
            response=connection.getresponse(); value=json.loads(response.read())
            expected=yaml.safe_load(bytes.fromhex(self.running_file_state(source['Id'],'/etc/prometheus/prometheus.yml')['bytes']))
            return response.status==200 and value.get('status')=='success' and declared_configuration_matches(expected,yaml.safe_load(value['data']['yaml']))
        except (OSError,ValueError,KeyError,TypeError,AdoptionError): return False
        finally: connection.close()

    def _remove_owned_helper(self,name):
        if not name.startswith(('dc-controller-source-proof-','dc-controller-config-check-')):
            raise AdoptionError('unsupported helper cleanup identity')
        if callable(getattr(self.engine,'_request',None)):
            self.engine._request('DELETE','/containers/'+quote(name,safe='')+'?force=1&v=true',allowed=(204,))
        else:
            self.engine.remove(name)  # deterministic injected test adapter

    def validate_staged(self,plan,guard):
        """Execute selected same-image promtool on exact config/reference mounts."""
        request = _request(plan.sources['prometheus'])
        mounts = plan.requests.get('prometheus', request)['HostConfig']['Mounts']
        references=set(plan.evidence.get('reference_files',{}))
        mounts = [m for m in mounts if m['Target'] == '/etc/prometheus' or m['Target'].startswith('/etc/prometheus/') or any(ref==m['Target'] or ref.startswith(m['Target']+'/') for ref in references)]
        name = 'dc-controller-config-check-' + plan.operation_id
        if self.maybe_inspect(name) is not None:
            raise AdoptionError('staged validation helper identity collision')
        candidate = {'Config': {'Image': plan.sources['prometheus']['Image'],
            'User': request['Config'].get('User',''), 'Entrypoint': ['/bin/promtool'],
            'Cmd': ['check','config','/etc/prometheus/prometheus.yml'],
            'Labels': {'com.centurylinklabs.watchtower.enable': 'false'}},
            'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'RestartPolicy': {'Name':'no'}, 'Mounts': mounts},
            'NetworkingConfig': {'EndpointsConfig': {}}}
        guard(); self.engine.create(name,candidate); guard()
        try:
            guard(); self.engine.start(name); guard(); deadline=time.monotonic()+60
            while True:
                guard(); actual=self.engine.inspect(name); state=actual.get('State',{})
                if state.get('Running') is False:
                    if state.get('ExitCode') != 0: raise AdoptionError('selected promtool validation failed')
                    return
                if time.monotonic()>=deadline: raise AdoptionError('selected promtool validation timeout')
                time.sleep(.1)
        finally:
            guard(); self.engine.stop(name); guard()
            if self.engine.inspect(name).get('State',{}).get('Running') is not False:
                raise AdoptionError('validation helper stop unverified')
            guard(); self._remove_owned_helper(name); guard()

    def _startup_locations(self,source,image):
        """Bind the bounded executable scope to inspected image startup defaults."""
        config=source.get('Config'); defaults=image.get('Config')
        if not isinstance(config,dict) or not isinstance(defaults,dict) or image.get('Id')!=source.get('Image'):
            raise AdoptionError('unverified startup override: image/runtime declaration unavailable')
        for name in ('Entrypoint','Shell'):
            if (config.get(name) or [])!=(defaults.get(name) or []):
                raise AdoptionError('unverified startup override: '+name)
        if (config.get('WorkingDir') or '')!=(defaults.get('WorkingDir') or ''):
            raise AdoptionError('unverified startup override: WorkingDir')
        entry=config.get('Entrypoint') or []
        # Prometheus's fixed immutable binary accepts customer flag arguments.
        # Other product entrypoint/script command overrides require a reviewed
        # source-specific contract, rather than guessing shell/import semantics.
        if (config.get('Cmd') or [])!=(defaults.get('Cmd') or []) and entry!=['/bin/prometheus']:
            raise AdoptionError('unverified startup override: Cmd')
        if entry==['/bin/prometheus'] and any(not isinstance(v,str) or v.startswith(('/data/','/app/')) or '\0' in v for v in config.get('Cmd') or []):
            raise AdoptionError('unverified startup override: Prometheus arguments')
        if (config.get('Healthcheck') or {}).get('Test')!=(defaults.get('Healthcheck') or {}).get('Test'):
            raise AdoptionError('unverified startup override: Healthcheck.Test')
        def env(value):
            try: return dict(v.split('=',1) for v in value.get('Env') or [])
            except (ValueError,TypeError): raise AdoptionError('unverified startup override: Env') from None
        current,baseline=env(config),env(defaults)
        for name in ('PATH','PYTHONPATH','PYTHONHOME','PYTHONSTARTUP','LD_PRELOAD','LD_LIBRARY_PATH','ENV','BASH_ENV'):
            if current.get(name)!=baseline.get(name) and not (name=='PYTHONPATH' and current.get(name) in ('/app','/app/src')):
                raise AdoptionError('unverified startup override: '+name)
        roots={'/app','/usr','/bin','/sbin','/lib','/opt','/docker-entrypoint.sh','/docker-entrypoint.d','/etc/profile','/etc/profile.d','/etc/environment'}
        for name in ('PATH','PYTHONPATH','PYTHONHOME','PYTHONSTARTUP','LD_PRELOAD','LD_LIBRARY_PATH','ENV','BASH_ENV'):
            value=current.get(name)
            if not value: continue
            paths=re.split(r'[: ]',value) if name in ('PATH','PYTHONPATH','LD_PRELOAD','LD_LIBRARY_PATH') else [value]
            for path in paths:
                if not path.startswith('/') or '..' in PurePosixPath(path).parts or not any(path==r or path.startswith(r+'/') for r in ('/app','/usr','/bin','/sbin','/lib','/opt')):
                    raise AdoptionError('unverified startup override: '+name+' import/search location')
                roots.add(path)
        startup=entry if entry else (config.get('Cmd') or [])[:1]
        for word in startup:
            if not isinstance(word,str): raise AdoptionError('unverified startup override: executable declaration')
            if word.startswith('/'):
                if '..' in PurePosixPath(word).parts or word.startswith('/data/'):
                    raise AdoptionError('unverified startup override: mutable executable location')
                if word.endswith('.sh') and word not in ('/app/entrypoint.sh','/docker-entrypoint.sh'):
                    raise AdoptionError('unverified startup override: shell startup dependencies')
                roots.add(word)
        for word in (config.get('Cmd') or []):
            if isinstance(word,str) and word.startswith('/') and word.endswith(('.py','.sh')):
                if not any(word==r or word.startswith(r+'/') for r in ('/app','/usr','/bin','/sbin','/opt')):
                    raise AdoptionError('unverified startup override: executable/import location')
                roots.add(word)
        return roots

    def directory_custody(self,name,path):
        """Read exactly one tar header through the installed Engine transport.

        The ordinary _request materializes archives; this scoped metadata probe
        closes after512bytes and never consumes or extracts directory contents.
        Only bounded timestamp PAX metadata is accepted; path/owner/link/longname
        extensions and unknown transport metadata remain holds.
        """
        from cryptolabs_proxy.migration import _UnixHTTPConnection
        import tarfile
        if not path.startswith('/') or '..' in PurePosixPath(path).parts or any(c in path for c in '\0\r\n'):
            raise AdoptionError('unverified executable directory path')
        connection=_UnixHTTPConnection(self.engine.socket_path,self.engine.timeout)
        try:
            connection.request('GET','/containers/'+quote(name,safe='')+'/archive?path='+quote(path,safe=''))
            response=connection.getresponse()
            if response.status!=200: raise AdoptionError('unverified executable directory custody')
            header=response.read(512)
            if len(header)!=512: raise AdoptionError('unverified executable directory archive header')
            info=tarfile.TarInfo.frombuf(header,'utf-8','strict')
            # Docker may encode sub-second timestamps in one local PAX header.
            # Only these non-custody fields are accepted; path/link/uid/gid and
            # every other extension remain explicit unsupported metadata.
            if info.type==tarfile.XHDTYPE:
                if not 0<info.size<=4096: raise AdoptionError('unverified executable directory PAX bound')
                length=((info.size+511)//512)*512; extension=response.read(length)
                if len(extension)!=length or any(extension[info.size:]): raise AdoptionError('unverified executable directory PAX padding')
                payload=extension[:info.size]; position=0
                while position<len(payload):
                    space=payload.find(b' ',position)
                    if space<0 or space-position>10: raise AdoptionError('unverified executable directory PAX record')
                    size=int(payload[position:space]); end=position+size
                    if size<=space-position+2 or end>len(payload) or payload[end-1:end]!=b'\n': raise AdoptionError('unverified executable directory PAX length')
                    key,value=payload[space+1:end-1].split(b'=',1)
                    if key not in (b'mtime',b'atime',b'ctime') or not re.fullmatch(rb'-?[0-9]+(?:\.[0-9]+)?',value):
                        raise AdoptionError('unverified executable directory PAX field')
                    position=end
                header=response.read(512)
                if len(header)!=512: raise AdoptionError('unverified executable directory post-PAX header')
                info=tarfile.TarInfo.frombuf(header,'utf-8','strict')
            if not info.isdir() or info.name.rstrip('/')!=PurePosixPath(path).name or info.linkname or info.size!=0 or info.uid<0 or info.gid<0 or info.mode & ~0o7777:
                raise AdoptionError('unverified executable directory archive identity')
            return {'uid':info.uid,'gid':info.gid,'mode':info.mode}
        except (OSError,ValueError,tarfile.TarError,UnicodeError):
            raise AdoptionError('unverified bounded executable directory metadata') from None
        finally: connection.close()

    def prove_effective_source(self,name,changes,mounts):
        """Use the immutable image compiler for bounded normal-cache proof.

        Cached code is decoded only in a disposable isolated helper, never in
        this host process or the customer's serving container. No cached code
        executes. Any executable source amendment remains a changed-vector hold.
        """
        import base64
        source=self.inspect(name); image=self.engine.image(source['Image'])
        roots=self._startup_locations(source,image); retained_image=source['Image']; caches=[]; total=0; directories=[]
        cache_paths=[PurePosixPath(row.get('Path','')) for row in changes if isinstance(row,dict) and re.fullmatch(r'.+\.cpython-[0-9]+(?:\.opt-[012])?\.pyc',PurePosixPath(row.get('Path','')).name)]
        def protected(value):
            return any(value==r or value.startswith(r+'/') or r.startswith(value.rstrip('/')+'/') for r in roots)
        if not isinstance(changes,list) or any(protected(str(m.get('Destination',''))) for m in mounts): return False
        for change in changes:
            path=PurePosixPath(change.get('Path',''))
            if not protected(str(path)): continue
            if path.name=='__pycache__' or any(path in cached.parents for cached in cache_paths):
                if change.get('Kind') not in (0,1): return False
                directories.append({'path':str(path),'kind':change['Kind'],'custody':self.directory_custody(name,str(path))})
                continue
            if '__pycache__' not in path.parts: return False
            if change.get('Kind')==2: continue
            match=re.fullmatch(r'(.+)\.cpython-[0-9]+(?:\.opt-([012]))?\.pyc',path.name)
            if not match: return False
            source=str(path.parent.parent/(match.group(1)+'.py'))
            if any(row.get('Path')==source for row in changes): return False
            cached=bytes.fromhex(self.file_state(name,str(path),max_bytes=256*1024)['bytes'])
            total+=len(cached)
            if len(cached)>256*1024 or total>8*1024*1024: return False
            caches.append({'source':source,'optimize':int(match.group(2) or 0),'cache':base64.b64encode(cached).decode()})
        if not caches and not directories: return True
        return self._prove_caches_in_image(retained_image,caches,directories=directories)

    def _prove_caches_in_image(self,image,caches,*,directories=()):
        import base64
        batches=[]; batch=[]; total=0
        def fits(rows):
            payload=base64.b64encode(_encoded({'caches':rows,'directories':directories})).decode()
            try: _cache_proof_command(payload)
            except AdoptionError: return False
            return True
        if not isinstance(caches,list) or len(caches)>128:
            raise AdoptionError('unsupported cache proof payload count')
        if not fits([]): raise AdoptionError('unsupported cache proof payload argument bound')
        for row in caches:
            try: size=len(base64.b64decode(row['cache'],validate=True))
            except (ValueError,KeyError,TypeError): raise AdoptionError('unsupported cache proof payload') from None
            total+=size
            if size>256*1024 or total>8*1024*1024:
                raise AdoptionError('unsupported cache proof payload size')
            candidate=batch+[row]
            if not fits(candidate):
                if not batch: raise AdoptionError('unsupported cache proof payload argument bound')
                batches.append(batch); batch=[row]
                if not fits(batch): raise AdoptionError('unsupported cache proof payload argument bound')
            else: batch=candidate
        if batch or directories and not batches: batches.append(batch)
        return all(self._prove_cache_batch(image,batch,directories=directories) for batch in batches)

    def _prove_cache_batch(self,image,caches,*,directories=()):
        import base64, uuid
        if not re.fullmatch(r'sha256:[0-9a-f]{64}',image): return False
        name='dc-controller-source-proof-'+uuid.uuid4().hex
        payload=base64.b64encode(_encoded({'caches':caches,'directories':directories})).decode()
        entrypoint,command=_cache_proof_command(payload)
        request={'Config':{'Image':image,'User':'65534:65534',
            'Entrypoint':entrypoint,
            'Cmd':command, 'Env':[], 'Healthcheck':{'Test':['NONE']},
            'Labels':{'com.centurylinklabs.watchtower.enable':'false'}},
            'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'RestartPolicy':{'Name':'no'},
                'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true'],'Memory':128*1024*1024,
                'NanoCpus':250000000,'PidsLimit':16,
                'Ulimits':[{'Name':'stack','Soft':8388608,'Hard':8388608}],
                'Tmpfs':{'/tmp':'rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=65534,gid=65534'},'Mounts':[]},
            'NetworkingConfig':{'EndpointsConfig':{}}}
        check=self.__dict__.get('_controller_guard_check',lambda:None)
        check(); self.engine.create(name,request); check()
        try:
            check(); self.engine.start(name); check(); deadline=time.monotonic()+30
            while True:
                state=self.engine.inspect(name).get('State',{})
                if state.get('Running') is False:
                    if state.get('ExitCode')!=0: return False
                    result=json.loads(self.read_file(name,'/tmp/source-proof.json'))
                    return result=={'equivalent':True}
                if time.monotonic()>=deadline: return False
                time.sleep(.1)
        finally:
            check(); self.engine.stop(name); check()
            if self.engine.inspect(name).get('State',{}).get('Running') is not False:
                raise AdoptionError('isolated source proof stop unverified')
            check(); self._remove_owned_helper(name); check()

    def file_state(self,name,path,*,max_bytes=2*1024*1024):
        """Bounded archive snapshot; Docker may reopen host binds in a fresh view.

        This is not evidence of the running container's mounted inode.
        """
        from cryptolabs_proxy.migration import _UnixHTTPConnection
        import io,tarfile
        if not path.startswith('/') or '..' in PurePosixPath(path).parts or any(c in path for c in '\0\r\n'):
            raise AdoptionError('monitoring reference absolute path unverified')
        connection=_UnixHTTPConnection(self.engine.socket_path,self.engine.timeout)
        limit=max_bytes+65536
        try:
            connection.request('GET','/containers/'+quote(name,safe='')+'/archive?path='+quote(path,safe=''))
            response=connection.getresponse()
            if response.status!=200: raise AdoptionError('monitoring reference archive unavailable')
            data=response.read(limit+1)
            if len(data)>limit: raise AdoptionError('monitoring reference archive exceeds supported bound')
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                members=archive.getmembers()
                if len(members)!=1 or not members[0].isfile() or members[0].name!=PurePosixPath(path).name or members[0].size>max_bytes or members[0].linkname or members[0].uid<0 or members[0].gid<0 or members[0].mode & ~0o7777:
                    raise AdoptionError('monitoring reference regular-file custody unverified')
                member=members[0]
                return {'bytes':archive.extractfile(member).read().hex(),'uid':member.uid,'gid':member.gid,'mode':member.mode}
        except (OSError,ValueError,tarfile.TarError,UnicodeError):
            raise AdoptionError('monitoring reference bounded archive unverified') from None
        finally: connection.close()

    def running_file_state(self,name,path,*,max_bytes=2*1024*1024):
        """Read only through the exact running task's existing mount namespace."""
        if not isinstance(path,str): raise AdoptionError('unsupported running reference path/bound')
        target=PurePosixPath(path)
        if not target.is_absolute() or '..' in target.parts or any(c in path for c in '\0\r\n') or len(path.encode())>4096 or len(target.parts)>64 or type(max_bytes) is not int or not 0<max_bytes<=2*1024*1024:
            raise AdoptionError('unsupported running reference path/bound')
        def identity(value):
            state=value.get('State',{}); config=value.get('Config',{})
            if not isinstance(value.get('Image'),str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',value['Image']) or not isinstance(config.get('User'),str) or not re.fullmatch(r'[0-9a-f]{64}',value.get('Id','')) or state.get('Running') is not True or state.get('Paused',False) is not False or state.get('Restarting',False) is not False or type(state.get('Pid')) is not int or state['Pid']<=0 or not isinstance(state.get('StartedAt'),str) or not state['StartedAt']:
                raise AdoptionError('running reference container identity unavailable')
            return (value['Id'],value.get('Image'),config.get('User'),state['Pid'],state['StartedAt'])
        before=self.engine.inspect(name); expected=identity(before); container_id=expected[0]
        if re.fullmatch(r'[0-9a-f]{64}',name) and name!=container_id:
            raise AdoptionError('running reference container ID differs')
        connection=None
        try:
            from cryptolabs_proxy.migration import _UnixHTTPConnection
            created=json.loads(self.engine._request('POST','/containers/'+container_id+'/exec',{
                'AttachStdin':False,'AttachStdout':True,'AttachStderr':True,'Tty':False,'Privileged':False,'WorkingDir':'/',
                'Env':['ENV=','BASH_ENV=','LD_PRELOAD=','LD_LIBRARY_PATH='],
                'Cmd':['/bin/busybox','timeout','10','/bin/busybox','sh','-c',RUNNING_FILE_PROOF_SCRIPT,'dc-reference-proof',str(max_bytes),path]}))
            exec_id=created.get('Id')
            if not isinstance(exec_id,str) or not re.fullmatch(r'[0-9a-f]{64}',exec_id): raise AdoptionError('running reference exec identity unavailable')
            connection=_UnixHTTPConnection(self.engine.socket_path,min(self.engine.timeout,15))
            connection.request('POST','/exec/'+exec_id+'/start',body=b'{"Detach":false,"Tty":false}',headers={'Content-Type':'application/json'})
            # od emits three characters per byte plus each 16-byte row's newline.
            # Reserve additional bounded headroom for metadata and multiplex frames;
            # the decoded payload below still cannot exceed max_bytes.
            response=connection.getresponse(); limit=max_bytes*4+65536
            if response.status!=200: raise AdoptionError('running reference exec start failed')
            raw=response.read(limit+1)
            if len(raw)>limit: raise AdoptionError('running reference output bound exceeded')
            output=bytearray(); offset=0
            while offset<len(raw):
                header=raw[offset:offset+8]
                if len(header)!=8 or header[0]!=1 or header[1:4]!=b'\0\0\0': raise AdoptionError('running reference stream unsupported')
                size=int.from_bytes(header[4:8],'big'); offset+=8
                if size>len(raw)-offset: raise AdoptionError('running reference stream truncated')
                output.extend(raw[offset:offset+size]); offset+=size
            result=json.loads(self.engine._request('GET','/exec/'+exec_id+'/json'))
            if result.get('ContainerID')!=container_id or result.get('Running') is not False or type(result.get('ExitCode')) is not int or result['ExitCode']!=0:
                raise AdoptionError('running reference read did not complete; required BusyBox interface unavailable or read denied')
            if identity(self.engine.inspect(container_id))!=expected: raise AdoptionError('running reference container identity drift')
            lines=bytes(output).decode('ascii').splitlines(); parents=[p for p in target.parents if str(p)!='/']; count=1+len(parents)
            if lines[count]!='DATA': raise ValueError('shape')
            end=lines.index('END',count+1)
            if lines[:count]!=lines[end+1:] or len(lines[end+1:])!=count: raise ValueError('custody drift')
            metadata=lines[0].split()
            if len(metadata)!=6 or any(not re.fullmatch(r'[0-9]+',v) for v in metadata): raise ValueError('metadata')
            uid,gid,mode,size,inode,device=int(metadata[0]),int(metadata[1]),int(metadata[2],8),int(metadata[3]),int(metadata[4]),int(metadata[5])
            encoded=''.join(''.join(line.split()) for line in lines[count+1:end])
            if mode>0o7777 or size>max_bytes or len(encoded)!=size*2 or not re.fullmatch(r'[0-9a-f]*',encoded): raise ValueError('payload')
            custody={}
            for parent,line in zip(parents,lines[1:count]):
                values=line.split()
                if len(values)!=5 or any(not re.fullmatch(r'[0-9]+',v) for v in values) or int(values[2],8)>0o7777: raise ValueError('parent')
                custody[str(parent)]={'uid':int(values[0]),'gid':int(values[1]),'mode':int(values[2],8)}
            return {'bytes':encoded,'uid':uid,'gid':gid,'mode':mode,'inode':inode,'device':device,'parents':custody}
        except AdoptionError: raise
        except Exception: raise AdoptionError('running reference namespace proof unavailable; no archive fallback') from None
        finally:
            if connection is not None: connection.close()

    def reference_state(self,name,path):
        return self.running_file_state(name,path)

    def public_input_state(self,declaration):
        result={}
        for value in declaration['public_inputs']:
            path=_safe_path(value); metadata=path.stat()
            if not stat.S_ISREG(metadata.st_mode): raise AdoptionError('public input regular-file custody unverified')
            result[value]={'bytes':path.read_bytes().hex(),'uid':metadata.st_uid,'gid':metadata.st_gid,'mode':stat.S_IMODE(metadata.st_mode),
                'parents':{str(parent):{'uid':parent.stat().st_uid,'gid':parent.stat().st_gid,'mode':stat.S_IMODE(parent.stat().st_mode)} for parent in path.parents if str(parent)!='/'} }
        return result

    def monitoring_snapshot(self,plan):
        """Current bytes and custody, independent of terminal journal claims."""
        prom=self.inspect('prometheus')
        config=self.running_file_state(prom['Id'],'/etc/prometheus/prometheus.yml')
        mapping=_public_monitoring_config(bytes.fromhex(config['bytes']))
        if _references(mapping)!=set(plan.evidence['reference_files']):
            raise AdoptionError('terminal monitoring reference declaration drift')
        references={r:self.reference_state(prom['Id'],r) for r in plan.evidence['reference_files']}
        if self.inspect('prometheus')['Id']!=prom['Id']: raise AdoptionError('terminal monitoring role identity drift')
        if any(m.get('Source')==plan.declaration['product_directory'] and m.get('Destination')=='/etc/prometheus' for m in prom['Mounts']):
            from .monitoring import validate_product_monitoring_custody
            validate_product_monitoring_custody(plan.declaration['product_directory'])
            ownership=_safe_path(Path(plan.declaration['product_directory'])/'ownership.json')
            metadata=ownership.stat()
            if metadata.st_uid!=1000 or metadata.st_gid!=1000 or stat.S_IMODE(metadata.st_mode)&0o644!=0o644 or ownership.read_bytes()!=_public_ownership(plan):
                raise AdoptionError('terminal ownership declaration custody/bytes drift')
        return {'config':config['bytes'],'config_custody':{k:config[k] for k in ('uid','gid','mode')},
            'references':{r:v['bytes'] for r,v in references.items()},
            'reference_custody':{r:{k:v[k] for k in ('uid','gid','mode','parents')} for r,v in references.items()},
            'public_inputs':self.public_input_state(plan.declaration)}

    def collect(self,declaration):
        declaration=_declaration(declaration)
        inventory={r:self.inspect(r) for r in ROLES}
        evidence={'effective_source':{},'reference_files':{},'public_inputs':{}}
        for role in MUTABLE:
            changed=self.changes(inventory[role]['Id'])
            if not isinstance(changed,list): raise AdoptionError('effective executable source inventory unavailable')
            evidence['effective_source'][role]=self.prove_effective_source(inventory[role]['Id'],changed,inventory[role]['Mounts'])
            image=self.engine.image(inventory[role]['Image'])
            if image.get('Id')!=inventory[role]['Image'] or image.get('Os')!='linux' or not image.get('Architecture') or not image.get('RepoDigests'):
                raise AdoptionError('retained image/platform identity unavailable')
        config_state=self.running_file_state(inventory['prometheus']['Id'],'/etc/prometheus/prometheus.yml')
        config=bytes.fromhex(config_state['bytes'])
        evidence['config_custody']={k:config_state[k] for k in ('uid','gid','mode')}
        evidence['reference_custody']={}
        try: refs=_references(yaml.safe_load(config))
        except Exception: raise AdoptionError('monitoring config inventory unavailable') from None
        for ref in refs:
            if not isinstance(ref,str) or any(c in ref for c in '*?['): raise AdoptionError('unsupported glob monitoring reference')
            state=self.reference_state(inventory['prometheus']['Id'],ref)
            evidence['reference_files'][ref]=bytes.fromhex(state['bytes'])
            evidence['reference_custody'][ref]={k:state[k] for k in ('uid','gid','mode','parents')}
        evidence['public_inputs']=self.public_input_state(declaration)
        predecessor = _ordinary_directory_source(inventory, declaration['product_directory'])
        if predecessor: evidence['source_directory'] = _directory_state(predecessor)
        return inventory,declaration,config,evidence


def _maybe(engine,name):
    if hasattr(engine,'maybe_inspect'): return engine.maybe_inspect(name)
    try: return engine.inspect(name)
    except (KeyError,StopIteration): return None  # injected deterministic test adapter only


class ControllerAdoption:
    """Fixed compensating transition; journal intents precede all Engine calls."""
    def __init__(self,engine,journal): self.engine=engine; self.journal=journal
    def _action(self,record,role,step,guard,call):
        guard(); record['intent']={'role':role,'step':step}
        if step=='restore-start' and role not in record.setdefault('original_restart_intents',[]):
            record['original_restart_intents'].append(role)
        self.journal.write(record)
        value=call()
        guard(); record['completed'].append({'role':role,'step':step}); self.journal.write(record)
        return value
    def _stopped(self,name):
        value=_maybe(self.engine,name)
        if value is None or value.get('State',{}).get('Running') is not False:
            raise AdoptionError('writer stop state unknown; forward-repair-required')
        return value
    def apply(self,plan,*,current,guard):
        inventory,_,config,evidence=current()
        if not plan.matches(inventory,config,evidence): raise AdoptionError('controller plan drift; inspect and plan again')
        guard()
        previous=self.journal.read()
        if previous and previous['state'] not in ('adopted','restored') and not (previous['state']=='prepared' and previous['operation_id']==plan.operation_id):
            raise AdoptionError('controller recovery required')
        if not plan.mutations: return {**plan.public(),'state':'already-adopted'}
        record={'schema_version':1,'operation_id':plan.operation_id,'state':'applying','plan':plan.private(),'completed':[],
                'predecessors':{r:r+'-controller-retained-'+plan.operation_id for r in plan.mutations},'candidate_ids':{}}
        self.journal.write(record)
        try:
            # DC writers stop before any Prometheus path transition.
            for role in plan.mutations:
                source=plan.sources[role]
                self._action(record,role,'stop-source',guard,lambda s=source:self.engine.stop(s['Id']))
                self._stopped(source['Id'])
            for role in reversed(plan.mutations):
                source=plan.sources[role]; request=plan.requests[role]
                endpoints=request['NetworkingConfig']['EndpointsConfig']
                for net in endpoints:
                    self._action(record,role,'disconnect-source:'+net,guard,lambda n=net,s=source:self.engine.disconnect(s['Id'],n))
                self._action(record,role,'rename-source',guard,lambda r=role,s=source:self.engine.rename(s['Id'],record['predecessors'][r]))
                self._action(record,role,'create-candidate',guard,lambda r=role,q=request:self.engine.create(r,q))
                record['candidate_ids'][role]=self.engine.inspect(role)['Id']; self.journal.write(record)
                self._action(record,role,'start-candidate',guard,lambda r=role:self.engine.start(r))
                guard(); ready=self.engine.readiness(role,request); guard()
                if not ready: raise AdoptionError('candidate function/health did not verify')
            guard(); record['state']='adopted'; self.verify_terminal(record,guard,capture=True)
            return {**plan.public(),'state':'adopted'}
        except Exception:
            # Error details may contain sensitive transport/configuration values.
            # Recovery uses journal + actual Engine identity, never a guess.
            return self._restore(record,guard)
    def _restore(self,record,guard):
        plan=ControllerPlan.from_private(record['plan'])
        try:
            if record['state']=='prepared':
                for role in ROLES:
                    actual=self.engine.inspect(role)
                    if actual['Id']!=plan.sources[role]['Id'] or _request(actual)!=_request(plan.sources[role]) or actual.get('State',{}).get('Running')!=plan.sources[role]['State'].get('Running'):
                        raise AdoptionError('prepared operation runtime drift')
                guard(); record['state']='restored'; self.verify_terminal(record,guard,capture=True)
                return {'state':'restored','operation_id':record['operation_id']}
            # First stop ALL candidate writers. No original is started unless
            # every possibly created candidate has a positive stopped proof.
            for role in plan.mutations:
                held=role+'-controller-failed-'+plan.operation_id
                failed=_maybe(self.engine,held)
                if failed is not None:
                    detached=copy.deepcopy(failed); detached['NetworkSettings']={'Networks':plan.requests[role]['NetworkingConfig']['EndpointsConfig']}
                    if _request(detached)!=plan.requests[role]: raise AdoptionError('retained candidate runtime drift')
                    self._action(record,role,'stop-retained-candidate',guard,lambda h=held:self.engine.stop(h))
                    self._stopped(held)
                active=_maybe(self.engine,role)
                if active is not None and active['Id']!=plan.sources[role]['Id']:
                    if (record['candidate_ids'].get(role) and active['Id']!=record['candidate_ids'][role]) or _request(active)!=plan.requests[role]:
                        raise AdoptionError('candidate identity/runtime drift')
                    self._action(record,role,'stop-candidate',guard,lambda r=role:self.engine.stop(r))
                    self._stopped(role)
                    for net in plan.requests[role]['NetworkingConfig']['EndpointsConfig']:
                        self._action(record,role,'disconnect-candidate:'+net,guard,lambda r=role,n=net:self.engine.disconnect(r,n))
                    held=role+'-controller-failed-'+plan.operation_id
                    if _maybe(self.engine,held): raise AdoptionError('failed candidate name collision')
                    self._action(record,role,'retain-candidate',guard,lambda r=role,h=held:self.engine.rename(r,h))
            # Historical/current-host source guard only. Archive may reopen
            # binds; running namespace continuity is proved after restoration
            # by readiness and verify_terminal, never by this stopped read.
            if hasattr(self.engine,'read_file') and self.engine.read_file(plan.sources['prometheus']['Id'],'/etc/prometheus/prometheus.yml')!=plan.prometheus_bytes:
                raise AdoptionError('original configuration changed; forward repair required')
            for role in reversed(plan.mutations):
                source=self.engine.inspect(plan.sources[role]['Id'])
                if source.get('State',{}).get('Running') is True and role in record.get('original_restart_intents',[]):
                    if _request(source)!=_request(plan.sources[role]) or not self.engine.readiness(role,_request(plan.sources[role])):
                        raise AdoptionError('restored original runtime/function drift')
                    continue
                attempted=any(v['role']==role for v in record['completed']) or record.get('intent',{}).get('role')==role
                if not attempted and source.get('State',{}).get('Running') is True:
                    if not self.engine.readiness(role,_request(plan.sources[role])): raise AdoptionError('untouched original did not verify')
                    continue
                # Even a stop request that failed/was interrupted must prove
                # stopped before restarting any peer; unknown means hold.
                self._stopped(source['Id'])
                if source.get('Name')!='/'+role:
                    self._action(record,role,'restore-name',guard,lambda s=source,r=role:self.engine.rename(s['Id'],r))
                endpoints=plan.requests[role]['NetworkingConfig']['EndpointsConfig']
                for net,endpoint in endpoints.items():
                    if net in self.engine.inspect(role).get('NetworkSettings',{}).get('Networks',{}):
                        continue
                    self._action(record,role,'restore-network:'+net,guard,lambda r=role,n=net,e=endpoint:self.engine.connect(r,n,e))
                self._action(record,role,'restore-start',guard,lambda r=role:self.engine.start(r))
                guard(); ready=self.engine.readiness(role,_request(plan.sources[role])); guard()
                if not ready: raise AdoptionError('original function did not verify')
            record['state']='restored'; self.verify_terminal(record,guard,capture=True)
            return {'operation_id':record['operation_id'],'state':'restored','persistent_state':'retained; no rewind'}
        except Exception:
            record['state']='forward-repair-required'; self.journal.write(record)
            return {'operation_id':record['operation_id'],'state':'forward-repair-required','reason':'writer stop/restore proof unavailable; recovery exclusion retained'}
    def verify_terminal(self,record,guard,*,capture=False):
        plan=ControllerPlan.from_private(record['plan']); outcome=record['state']
        if outcome not in ('adopted','restored'): raise AdoptionError('terminal outcome unavailable')
        guard(); inventory={r:self.engine.inspect(r) for r in ROLES}
        for role,actual in inventory.items():
            expected_id=record['candidate_ids'][role] if outcome=='adopted' and role in plan.mutations else plan.sources[role]['Id']
            expected_request=plan.requests[role] if outcome=='adopted' and role in plan.mutations else _request(plan.sources[role])
            expected_running=plan.sources[role]['State'].get('Running')
            if actual['Id']!=expected_id or _request(actual)!=expected_request or actual.get('State',{}).get('Running')!=expected_running or actual.get('State',{}).get('Paused',False)!=plan.sources[role]['State'].get('Paused',False):
                raise AdoptionError('terminal post-state drift: runtime/running')
            if expected_running:
                guard(); ready=self.engine.readiness(role,expected_request); guard()
                if not ready: raise AdoptionError('terminal service function/health unverified')
        # Retained peers must still be stopped. Recovery never activates them
        # merely to get a health result and never assumes a name proves absence.
        for role in plan.mutations:
            held=record['predecessors'].get(role) if outcome=='adopted' else role+'-controller-failed-'+plan.operation_id
            if held:
                actual=_maybe(self.engine,held)
                if outcome=='adopted' and actual is None: raise AdoptionError('terminal retained predecessor unavailable')
                if actual is not None and actual.get('State',{}).get('Running') is not False:
                    raise AdoptionError('terminal retained writer stop unverified')
        guard(); monitoring=self.engine.monitoring_snapshot(plan); guard()
        if capture:
            expected_refs={r:v.hex() for r,v in plan.evidence['reference_files'].items()}
            if monitoring['references']!=expected_refs or monitoring['public_inputs']!=plan.evidence.get('public_inputs',{}):
                raise AdoptionError('terminal public/reference bytes drift')
            expected_custody=copy.deepcopy(plan.evidence.get('reference_custody'))
            if outcome=='adopted' and expected_custody is not None:
                # The reviewed new public root is the sole allowed parent
                # custody delta; all customer file/directory identities remain.
                directory=_safe_path(plan.declaration['product_directory']); metadata=directory.stat()
                product={'uid':metadata.st_uid,'gid':metadata.st_gid,'mode':stat.S_IMODE(metadata.st_mode)}
                if product['uid']!=1000 or product['gid']!=1000 or product['mode'] & 0o705!=0o705:
                    raise AdoptionError('terminal product parent custody unverified')
                for value in expected_custody.values():
                    if '/etc/prometheus' in value.get('parents',{}): value['parents']['/etc/prometheus']=product
            if expected_custody is not None and monitoring['reference_custody']!=expected_custody:
                raise AdoptionError('terminal reference custody drift')
            before=_public_monitoring_config(plan.prometheus_bytes)
            current=_public_monitoring_config(bytes.fromhex(monitoring['config']))
            if outcome=='restored':
                if monitoring['config']!=plan.prometheus_bytes.hex() or (plan.evidence.get('config_custody') is not None and monitoring['config_custody']!=plan.evidence['config_custody']):
                    raise AdoptionError('terminal restored monitoring bytes/custody drift')
            else:
                owned=set(plan.declaration['managed_jobs'])|{'dc-managed'}
                for value in (before,current): value['scrape_configs']=[row for row in value.get('scrape_configs',[]) if row['job_name'] not in owned]
                if before!=current: raise AdoptionError('terminal customer monitoring semantics drift')
            record['terminal_monitoring']=monitoring
            record['post_ids']={r:v['Id'] for r,v in inventory.items()}
            record['post_runtime']={r:_request(v) for r,v in inventory.items()}
            self.journal.write(record)
        elif monitoring!=record.get('terminal_monitoring'):
            raise AdoptionError('terminal monitoring/reference/public bytes or custody drift')
        guard()

    def recover(self,*,guard):
        record=self.journal.read()
        if not record: raise AdoptionError('no controller recovery record')
        if record['state'] in ('adopted','restored'):
            self.verify_terminal(record,guard)
            return {'state':record['state'],'operation_id':record['operation_id']}
        return self._restore(record,guard)


def upgrade_requires_adoption():
    """Read-only eligibility guard for ordinary selected image normalization.

    This does not assert changed-vector compatibility. Release ownership/pins
    remain enforced by the normal selector/updater; unsafe monitoring writes
    defer until the topology has its sanctioned writer surface.
    """
    inventory=probe_controller_inventory()
    if not any(v is not None for v in inventory.values()): return False
    if any(inventory[r] is None for r in ('dc-overview','prometheus','grafana')):
        raise AdoptionError('partial existing controller inventory; repair before upgrade')
    dc=inventory['dc-overview']; env=dc.get('Config',{}).get('Env',[])
    path=next((v.partition('=')[2] for v in env if v.startswith('PROMETHEUS_CONFIG_PATH=')),None)
    ownership=next((v.partition('=')[2] for v in env if v.startswith('PROMETHEUS_OWNERSHIP_PATH=')),None)
    if not path or not ownership: return True
    dc_mount=next((m for m in dc.get('Mounts',[]) if m.get('RW') is True and path.startswith(m.get('Destination','')+'/') and ownership.startswith(m.get('Destination','')+'/')),None)
    return not (dc_mount and any(m.get('Source')==dc_mount.get('Source') and m.get('Destination')=='/etc/prometheus' and m.get('RW') is False for m in inventory['prometheus'].get('Mounts',[])))


def _public_ownership(plan):
    return _encoded({'schema_version':1,'managed_jobs':plan.declaration['managed_jobs'],
                      'file_references':sorted(plan.evidence.get('reference_files',{}))})


def stage_product_directory(plan):
    """Create only the new secret-free subtree, never chmod/chown its ancestors."""
    from .monitoring import validate_product_monitoring_custody
    directory=_safe_path(plan.declaration['product_directory'])
    if not directory.parent.is_dir(): raise AdoptionError('product parent must already exist')
    for parent in directory.parents:
        mode=parent.stat().st_mode
        if not (mode & stat.S_IXOTH or parent.stat().st_uid==1000 and mode & stat.S_IXUSR or parent.stat().st_gid==1000 and mode & stat.S_IXGRP):
            raise AdoptionError('product parent not traversable by DC UID1000; private parents unchanged')
    _public_monitoring_config(plan.prometheus_bytes)
    required={'prometheus.yml':plan.prometheus_bytes,'ownership.json':_public_ownership(plan)}
    directories=set()
    # Mountpoints must exist before mounting the new root read-only. Retained
    # references still resolve to their original stores, never copied secrets.
    request=plan.requests.get('prometheus',_request(plan.sources['prometheus']))
    for mount in request['HostConfig']['Mounts']:
        if not mount['Target'].startswith('/etc/prometheus/'): continue
        relative=PurePosixPath(mount['Target']).relative_to('/etc/prometheus')
        if '..' in relative.parts or mount['Type']!='bind' or not mount['ReadOnly']:
            raise AdoptionError('unsupported public reference mountpoint')
        source=_safe_path(mount['Source'])
        if source.is_dir(): directories.add(relative)
        elif source.is_file(): required[str(relative)]=b''
        else: raise AdoptionError('reference mountpoint source custody unavailable')
        directories.update(p for p in relative.parents if str(p)!='.')
    if directory.exists():
        validate_product_monitoring_custody(directory)
        ownership=directory/'ownership.json'
        if ownership.exists():
            custody=ownership.stat()
            if custody.st_uid!=1000 or custody.st_gid!=1000 or stat.S_IMODE(custody.st_mode)&0o644!=0o644:
                raise AdoptionError('existing ownership declaration requires public DC custody')
        if any(not (directory/name).is_file() or (directory/name).is_symlink() or (directory/name).read_bytes()!=payload for name,payload in required.items()):
            raise AdoptionError('existing product directory differs; no files overwritten')
        if any(not (directory/name).is_dir() or (directory/name).is_symlink() for name in directories):
            raise AdoptionError('existing product directory mountpoints differ')
        return
    import shutil
    if shutil.disk_usage(directory.parent).free < len(plan.snapshot)*3 + len(plan.prometheus_bytes)*3 + 16*1024*1024:
        raise AdoptionError('insufficient staging/recovery disk capacity')
    directory.mkdir(mode=0o700)
    try:
        os.chown(directory,1000,1000)
        os.chmod(directory,0o755)
        for name in sorted(directories,key=lambda p:len(p.parts)):
            child=directory/name; child.mkdir(mode=0o755); os.chown(child,1000,1000); os.chmod(child,0o755)
        for name,payload in required.items():
            descriptor=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
            with os.fdopen(descriptor,'wb') as stream:
                os.fchown(stream.fileno(),1000,1000); os.fchmod(stream.fileno(),0o644); stream.write(payload); stream.flush(); os.fsync(stream.fileno())
        descriptor=os.open(directory/'prometheus.yml.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try: os.fchown(descriptor,1000,1000); os.fchmod(descriptor,0o600); os.fsync(descriptor)
        finally: os.close(descriptor)
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
        validate_product_monitoring_custody(directory)
    except Exception:
        # Staged files remain for diagnosis; they are never mounted automatically.
        raise AdoptionError('product custody staging failed; services unchanged') from None


def save_private_plan(path,plan):
    path=_safe_path(path)
    if not path.parent.is_dir() or stat.S_IMODE(path.parent.stat().st_mode)!=0o700:
        raise AdoptionError('plan output parent must already be private mode0700')
    writer=Journal(path.parent); writer.path=path; writer.write(plan.private())


def read_private_plan(path):
    path=_safe_path(path); reader=Journal(path.parent); reader.path=path
    value=reader.read()
    if value is None: raise AdoptionError('private plan unavailable')
    try:
        plan=ControllerPlan.from_private(value)
        recomputed=build_plan(plan.sources,plan.declaration,plan.prometheus_bytes,plan.evidence)
        if recomputed.private()!=plan.private(): raise AdoptionError('private plan integrity mismatch; inspect and plan again')
        return plan
    except (KeyError,TypeError,ValueError): raise AdoptionError('private plan malformed') from None


def _maintenance_proof(path,plan):
    """Bind operator-owned positive checks to this exact bounded operation.

    This records explicit maintenance gates; it does not replace Linux rehearsal
    or assert that a supplied statement proves actual customer acceptance.
    """
    path=_safe_path(path)
    try: value=json.loads(path.read_bytes())
    except (ValueError,OSError): raise AdoptionError('maintenance proof unavailable') from None
    fields={'schema_version','operation_id','owners_excluded','backup_restore_drill','same_image_state_compatible','session_routes_verified'}
    if not isinstance(value,dict) or set(value)!=fields or value['schema_version']!=1 or value['operation_id']!=plan.operation_id:
        raise AdoptionError('maintenance proof must match this plan operation')
    if set(value.get('owners_excluded',[]))!=set(plan.declaration['maintenance_owners']) or set(value.get('session_routes_verified',[]))!=set(plan.declaration['session_routes']):
        raise AdoptionError('declared owner/session maintenance checks incomplete')
    if value['backup_restore_drill'] is not True or value['same_image_state_compatible'] is not True:
        raise AdoptionError('compatible state and rehearsed owner backup recovery required')
    return value


def host_adopt(config_dir,plan_path,maintenance_proof,*,adapter=None):
    """Actual host lifecycle → durable updater → same-inode file lock order."""
    adapter=adapter or InstalledEngine(); adapter.require_guard_capability()
    config_dir=_safe_path(config_dir); plan=read_private_plan(plan_path)
    proof=_maintenance_proof(maintenance_proof,plan)
    journal=Journal(config_dir/'controller-recovery')
    ensure_mutation_allowed(config_dir)
    with bounded_lock(config_dir/'.lifecycle-config.lock'):
        ensure_mutation_allowed(config_dir)
        current=adapter.collect(plan.declaration)
        if not plan.matches(current[0],current[2],current[3]): raise AdoptionError('controller plan drift')
        if not plan.mutations: return {**plan.public(),'state':'already-adopted'}
        journal.write({'schema_version':1,'operation_id':plan.operation_id,'state':'prepared','plan':plan.private(),'completed':[],
                       'predecessors':{r:r+'-controller-retained-'+plan.operation_id for r in plan.mutations},'candidate_ids':{}})
        proxy=current[0]['cryptolabs-proxy']
        with adapter.controller_guard(proxy,proxy['Image'],plan.operation_id) as guard:
            adapter._controller_guard_check=guard
            guard()
            with ExitStack() as locks:
                # Use the source writer's actual file lock inode. Do not copy it.
                source=_source_config_path(current[0])
                source_guard=locks.enter_context(bounded_lock(Path(source).with_name(Path(source).name+'.lock'))) if source else lambda:None
                product_guard=lambda:None
                def locked_guard(): guard(); source_guard(); product_guard()
                adapter._controller_guard_check=locked_guard
                locked_guard(); stage_product_directory(plan)
                product=Path(plan.declaration['product_directory'])
                product_guard=source_guard if source and Path(source).parent==product else locks.enter_context(bounded_lock(product/'prometheus.yml.lock'))
                locked_guard(); adapter.validate_staged(plan,locked_guard); locked_guard()
                # Validation/operator delay invalidates an earlier snapshot.
                current=adapter.collect(plan.declaration)
                if not plan.matches(current[0],current[2],current[3]): raise AdoptionError('controller plan drift after validation')
                result=ControllerAdoption(adapter,journal).apply(plan,current=lambda:adapter.collect(plan.declaration),guard=locked_guard)
                if result['state'] in ('adopted','restored'):
                    locked_guard(); record=journal.read(); record['maintenance_proof']=proof; journal.write(record)
                    ControllerAdoption(adapter,journal).verify_terminal(record,locked_guard)
                    guard.complete()
                    record=journal.read(); record['exclusion_released']=True; journal.write(record)
                return result


def host_recover(config_dir,*,adapter=None):
    adapter=adapter or InstalledEngine(); adapter.require_guard_capability()
    config_dir=_safe_path(config_dir); journal=Journal(config_dir/'controller-recovery')
    record=journal.read()
    if not record: raise AdoptionError('no recovery record')
    plan=ControllerPlan.from_private(record['plan'])
    with bounded_lock(config_dir/'.lifecycle-config.lock'):
        record=journal.read()
        if not record or record['operation_id']!=plan.operation_id: raise AdoptionError('recovery record drift')
        record['exclusion_released']=False; journal.write(record)
        proxy=adapter.inspect('cryptolabs-proxy')
        with adapter.controller_guard(proxy,proxy['Image'],plan.operation_id,recover=True) as guard:
            adapter._controller_guard_check=guard
            with ExitStack() as locks:
                original=_source_config_path(plan.sources)
                source_guard=locks.enter_context(bounded_lock(Path(original).with_name(Path(original).name+'.lock'))) if original else lambda:None
                product_guard=lambda:None
                product=Path(plan.declaration['product_directory'])
                if product.is_dir():
                    product_guard=source_guard if original and Path(original).parent==product else locks.enter_context(bounded_lock(product/'prometheus.yml.lock'))
                elif record['state']!='prepared':
                    raise AdoptionError('active recovery product directory missing; forward repair required')
                def locked_guard(): guard(); source_guard(); product_guard()
                adapter._controller_guard_check=locked_guard
                result=ControllerAdoption(adapter,journal).recover(guard=locked_guard)
                if result['state'] in ('adopted','restored'):
                    guard(); guard.complete()
                    record=journal.read(); record['exclusion_released']=True; journal.write(record)
                return result
