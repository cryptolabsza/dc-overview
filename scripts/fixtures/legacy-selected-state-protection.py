#!/usr/bin/env python3
# TRACEWEAVER: file-role=native-verification; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
# TRACEWEAVER: verifies=VER-FLEETUPDATE-001; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001
# TRACEWEAVER: file-role=native-verification; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001

"""Synthetic-only selected-table fixture producer; never a customer installer.
Adapted from retained bounded protection helper SHA256 7b4977a162e1787d4a5c957efad1b95d8c488ab484383567c643e74e6ebc5fc4.
Historical site PINS and operational entrypoint deliberately excluded.
"""

import base64

import datetime

import hashlib

import json

import os

from pathlib import Path

import signal

import socket

import sqlite3

import stat

import subprocess


import time

import uuid

PINS = {}  # populated only with newly created synthetic guest objects

BASE = Path('/var/backups/cryptolabs/ipmi132')

SECONDS = 180

MAX_STATE = 8*1024**2

FLOOR = 1024**3

MAX_WAL_GROWTH = 256*1024**2

HISTORY = ('ai_result','alert_history','ipmi_event','power_reading','recovery_action_log','recovery_log','sensor_reading','ssh_logs')

INTERNAL = ('sqlite_sequence',)

SELECTED = ('account_link_attempt','admin_config','alert_rule','cloud_sync','ecc_error_tracker','inventory_binding','maintenance_task','notification_config','o_auth_link_state','recovery_permissions','server','server_config','server_inventory','server_status','server_uptime','ssh_key','system_settings','user')

IDENTITY_KEYS = ('ai_link_email','ai_link_user_id','ai_link_customer_id','ai_link_linked_at','ai_link_key_digest')

def canonical_mounts(records):
    destinations = [m['Destination'] for m in records]
    assert len(destinations) == len(set(destinations)), 'Duplicate mount Destination'
    return sorted(records, key=lambda m: (str(m.get('Destination','')), str(m.get('Source','')),
        json.dumps(m,sort_keys=True,separators=(',',':'))))

def identity_contract(saved, credential, sync_enabled, site):
    assert site == 'ltx'
    assert set(saved) == set(IDENTITY_KEYS)
    count = len(saved)
    assert all(saved.values()), 'Empty saved identity value'
    assert isinstance(credential,str) and credential, 'Existing credential required'
    matches = saved['ai_link_key_digest'] == hashlib.sha256(credential.encode()).hexdigest()
    assert matches, 'Existing stored credential digest mismatch'
    assert not sync_enabled, 'Synthetic recovery sync must remain off'
    return {'saved_identity_field_count':count,'saved_identity_complete':count==5,
        'identity_mode':'saved_sso',
        'stored_key_digest_matches':matches,'expected_email_matches':None,
        'credential_present':True,'credential_sha256':hashlib.sha256(credential.encode()).hexdigest(),
        'sync_enabled':bool(sync_enabled)}


def need(value, category):
    if not value: raise RuntimeError(category)

def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False,
        default=lambda v: {'sqlite_blob_base64':base64.b64encode(v).decode()} if isinstance(v,bytes) else str(v)).encode()

def fingerprint(value): return hashlib.sha256(encoded(value)).hexdigest()

def check_time(deadline): need(time.monotonic()<=deadline,'deadline')

def metadata(path):
    s=path.lstat()
    return {'path':str(path),'device':s.st_dev,'inode':s.st_ino,'bytes':s.st_size,
        'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),
        'symlink':stat.S_ISLNK(s.st_mode),'mtime_ns':s.st_mtime_ns}

def safe_chain(path):
    for p in reversed((path,*path.parents)):
        s=p.lstat();need(not stat.S_ISLNK(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'root-custody-chain')
    return path.lstat()

def exclusive(path):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    os.fchmod(fd,0o600);return fd

def write_private(path,value):
    raw=encoded(value)+b'\n'
    with os.fdopen(exclusive(path),'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    before=metadata(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        opened=os.fstat(f.fileno())
        need(stat.S_ISREG(opened.st_mode) and opened.st_uid==os.getuid() and stat.S_IMODE(opened.st_mode)==0o600,'private-readback-custody')
        need((opened.st_dev,opened.st_ino)==(before['device'],before['inode']),'private-readback-identity')
        actual=f.read(len(raw)+1)
    need(metadata(path)==before and actual==raw,'private-readback-bytes')
    need(json.loads(actual)==value,'private-readback-parsed-content')
    return dict(before,sha256=hashlib.sha256(actual).hexdigest(),independent_readback=True)

def digest_file(path,deadline):
    h=hashlib.sha256()
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as f:
        for block in iter(lambda:f.read(1024**2),b''):check_time(deadline);h.update(block)
    return h.hexdigest()

def free(path):
    s=os.statvfs(path);return s.f_bavail*s.f_frsize,s.f_favail

def space_guard(path,required):
    available,inodes=free(path);need(available>=required and inodes>=32,'capacity-and-inodes')
    return {'free_bytes':available,'free_inodes':inodes,'required_bytes':required}

def quote(name):return '"'+name.replace('"','""')+'"'

def open_ro(path,deadline):
    c=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=2)
    c.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
    c.execute('PRAGMA query_only=ON');need(c.execute('PRAGMA query_only').fetchone()[0]==1,'query-only');return c

def sidecars(db,mode):
    out={}
    for suffix in ('-wal','-shm','-journal'):
        p=Path(str(db)+suffix)
        try:s=p.lstat()
        except FileNotFoundError:out[suffix]={'exists':False};continue
        need(stat.S_ISREG(s.st_mode),'sidecar-regular-no-symlink');out[suffix]=dict(metadata(p),exists=True)
    need(out['-journal'].get('bytes',0)==0,'hot-rollback-journal')
    if mode=='delete':need(all(not out[s].get('exists') for s in ('-wal','-shm')),'rollback-sidecar-drift')
    return out

def table_snapshot(c,names):
    result={};used=0
    for name in sorted(names):
        sql=c.execute('SELECT sql FROM sqlite_master WHERE type=\'table\' AND name=?',(name,)).fetchone()
        need(sql and sql[0] and not sql[0].lstrip().upper().startswith('CREATE VIRTUAL TABLE'),'ordinary-table-schema')
        info=c.execute('PRAGMA table_xinfo('+quote(name)+')').fetchall()
        need(info and all(r[6]==0 for r in info),'generated-or-hidden-column')
        columns=[r[1] for r in info];pk=[r[1] for r in sorted(info,key=lambda r:r[5]) if r[5]]
        order=','.join(quote(k) for k in pk) if pk else 'rowid'
        rows=[]
        for row in c.execute('SELECT '+','.join(map(quote,columns))+' FROM '+quote(name)+' ORDER BY '+order):
            used+=len(encoded(row));need(used<=MAX_STATE,'selected-state-size');rows.append(row)
        result[name]={'create_sql':sql[0],'columns':columns,'rows':rows}
        used+=len(encoded([name,sql[0],columns]));need(used<=MAX_STATE,'selected-state-size')
    return result

def state_aggregate(state,site):
    need({'system_settings','cloud_sync','server'}<=set(state),'required-state-tables')
    settings=state['system_settings'];records=[dict(zip(settings['columns'],r)) for r in settings['rows']]
    saved={r['key']:r['value'] for r in records if r['key'] in IDENTITY_KEYS}
    cloud=state['cloud_sync'];need(len(cloud['rows'])==1,'cloud-row-count');row=dict(zip(cloud['columns'],cloud['rows'][0]))
    link=identity_contract(saved,row.get('license_key'),row.get('sync_enabled'),site)
    cloud_volatile=('last_sync','last_sync_status','last_sync_message','updated_at')
    stable_cloud_columns=[n for n in cloud['columns'] if n not in cloud_volatile]
    stable_cloud_rows=[tuple(dict(zip(cloud['columns'],r))[n] for n in stable_cloud_columns) for r in cloud['rows']]
    inventory=state['server'];inventory_volatile=('status','updated_at')
    stable_inventory_columns=[n for n in inventory['columns'] if n not in inventory_volatile]
    stable_inventory_rows=[tuple(dict(zip(inventory['columns'],r))[n] for n in stable_inventory_columns) for r in inventory['rows']]
    settings_pairs=sorted((r['key'],r['value']) for r in records)
    return {'state_sha256':fingerprint(state),'counts':{n:len(v['rows']) for n,v in state.items()},
        'table_sha256':{n:fingerprint(v) for n,v in state.items()},'saved_identity_sha256':fingerprint(saved),
        'stable_cloud_sha256':fingerprint([stable_cloud_columns,stable_cloud_rows]),
        'settings_sha256':fingerprint(settings_pairs),
        'stable_inventory_sha256':fingerprint([stable_inventory_columns,stable_inventory_rows]),
        'cached_subscription_valid':bool(row.get('subscription_valid')),**link}

def baseline_guard(baseline,pin):
    for key in ('stable_cloud_sha256','settings_sha256','stable_inventory_sha256','cached_subscription_valid'):
        need(baseline[key]==pin['protection_baseline'][key],'stable-protection-baseline')
    need(baseline['cached_subscription_valid'] is True,'cached-valid-predicate')
    need(set(baseline['counts'])==set(pin['selected_count_bounds']),'selected-count-coverage')
    for name,count in baseline['counts'].items():
        low,high=pin['selected_count_bounds'][name]
        need(low<=count<=high,'selected-table-count-bound')

def roundtrip_selected(state,path,site,deadline,guard):
    fd=exclusive(path);identity=os.fstat(fd);os.close(fd)
    dest=sqlite3.connect(str(path),timeout=2)
    dest.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
    try:
        dest.execute('PRAGMA foreign_keys=OFF') # Isolated partial-schema verification only; never production DB.
        dest.execute('BEGIN')
        for name,table in state.items():
            check_time(deadline);guard();dest.execute(table['create_sql'])
            columns=table['columns'];statement='INSERT INTO '+quote(name)+' ('+','.join(map(quote,columns))+') VALUES ('+','.join('?' for _ in columns)+')'
            for start in range(0,len(table['rows']),256):
                check_time(deadline);guard();dest.executemany(statement,table['rows'][start:start+256])
        dest.commit()
    finally:dest.close()
    actual=path.lstat();need((actual.st_dev,actual.st_ino)==(identity.st_dev,identity.st_ino) and stat.S_IMODE(actual.st_mode)==0o600,'destination-identity')
    verify=open_ro(path,deadline)
    try:
        need(verify.execute('PRAGMA quick_check').fetchall()==[('ok',)],'isolated-selected-quick-check')
        readback=table_snapshot(verify,state.keys())
        need(encoded(readback)==encoded(state),'isolated-selected-roundtrip')
        need(state_aggregate(readback,site)==state_aggregate(state,site),'selected-aggregate-roundtrip')
    finally:verify.close()
    need(not any(Path(str(path)+s).exists() for s in ('-wal','-shm','-journal')),'destination-sidecars')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as f:os.fsync(f.fileno())
    return dict(metadata(path),sha256=digest_file(path,deadline),quick_check='ok',selected_state_roundtrip=True)

def runtime(pin):
    q=json.loads(subprocess.check_output(['/usr/bin/docker','container','inspect','ipmi-monitor'],timeout=15,stderr=subprocess.PIPE))[0]
    need(q['Id']==pin['container_id'] and q['Image']==pin['image_id'] and q['State']['Running'],'runtime-identity')
    need(canonical_mounts(q['Mounts'])==canonical_mounts(pin['mounts']),'runtime-full-mount-records')
    return q

def main(site):
    need(site in PINS and bool(PINS[site]) and os.geteuid()==0,'bound-site-and-root')
    pin=PINS[site];need(pin.get('synthetic_fixture_only') is True,'synthetic-only-binding');need(socket.gethostname()==pin['hostname'],'hostname')
    deadline=time.monotonic()+SECONDS
    def alarm(signum,frame):raise RuntimeError('deadline')
    signal.signal(signal.SIGALRM,alarm);signal.alarm(SECONDS);os.umask(0o077)
    q=runtime(pin);mount=[m for m in q['Mounts'] if m['Destination']=='/app/data']
    need(len(mount)==1 and mount[0].get('Name')==pin.get('data_volume_name') and
         isinstance(pin.get('data_volume_name'),str) and bool(pin['data_volume_name']) and
         mount[0]['Type']=='volume','data-mount')
    db=Path(mount[0]['Source'])/'ipmi_events.db';s=safe_chain(db);need(stat.S_ISREG(s.st_mode),'source-regular')
    need((s.st_dev,s.st_ino)==(pin['database_device'],pin['database_inode']),'source-identity')
    with db.open('rb') as f:header=f.read(100)
    need(header[:16]==b'SQLite format 3\0' and list(header[18:20])==pin['journal_header_bytes'],'source-header')
    mode={b'\x01\x01':'delete',b'\x02\x02':'wal'}[header[18:20]]
    need(mode!='wal' or sqlite3.sqlite_version_info>=(3,22,0),'sqlite-ro-wal-version');before_sidecars=sidecars(db,mode)
    secret_metadata=[]
    for expected in pin['secret_mount_metadata']:
        observed=metadata(Path(expected['path']));need(observed==expected,'readonly-secret-mount-custody');secret_metadata.append(observed)
    safe_chain(Path('/var/backups'));capacity=space_guard(Path('/var/backups'),FLOOR+4*MAX_STATE);space_guard(db.parent,FLOOR+MAX_WAL_GROWTH)
    c=open_ro(db,deadline);operation=None
    try:
        need(c.execute('PRAGMA journal_mode').fetchone()[0]==mode,'journal-mode');c.execute('BEGIN')
        snapshot_started_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
        schema=c.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name').fetchall()
        need(fingerprint(schema)==pin['schema_sha256'],'schema-pin')
        names={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        need(names==set(pin['table_names']) and names<=set(SELECTED+HISTORY+INTERNAL),'exact-table-inventory')
        selected=names&set(SELECTED);state=table_snapshot(c,selected);baseline=state_aggregate(state,site)
        for k,v in pin['link_baseline'].items():need(baseline[k]==v,'link-baseline-continuity')
        baseline_guard(baseline,pin)
        pinned_sidecars=sidecars(db,mode)
        for directory in (BASE.parent,BASE):
            try:directory.mkdir(mode=0o700)
            except FileExistsError:pass
            s=safe_chain(directory);need(stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode)==0o700,'backup-parent-private')
        operation=BASE/(site+'-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ-')+uuid.uuid4().hex)
        operation.mkdir(mode=0o700);safe_chain(operation)
        def guard():
            check_time(deadline);space_guard(operation,FLOOR);space_guard(db.parent,FLOOR)
            s=db.lstat();need((s.st_dev,s.st_ino)==(pin['database_device'],pin['database_inode']),'source-inode-drift')
            current=sidecars(db,mode)
            need(current['-wal'].get('bytes',0)-pinned_sidecars['-wal'].get('bytes',0)<=MAX_WAL_GROWTH,'wal-growth')
        artifacts=[write_private(operation/'runtime-config.private.json',{k:q[k] for k in ('Id','Image','Config','HostConfig','Mounts','NetworkSettings')})]
        configs={};config_mount=[m for m in q['Mounts'] if m['Destination']=='/app/config/servers.yaml']
        need(len(config_mount)==1 and config_mount[0]['Type']=='bind','config-mount')
        for index,(name,path) in enumerate(sorted({'/app/config/servers.yaml':Path(config_mount[0]['Source']),'/app/data/servers.json':db.parent/'servers.json'}.items())):
            expected=pin['declared_config'][name]
            if not path.exists() and not path.is_symlink():need(not expected['present'],'config-presence');configs[name]={'present':False};continue
            s=safe_chain(path);need(stat.S_ISREG(s.st_mode) and s.st_size<=MAX_STATE,'config-source-custody')
            before=metadata(path)
            with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as f:raw=f.read(MAX_STATE+1)
            need(len(raw)<=MAX_STATE and metadata(path)==before,'config-coherence');need(expected['present'] and hashlib.sha256(raw).hexdigest()==expected['sha256'],'config-pin')
            target=operation/('config-'+str(index)+'.private')
            with os.fdopen(exclusive(target),'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
            copied=dict(metadata(target),sha256=digest_file(target,deadline));need(copied['sha256']==expected['sha256'],'config-copy-usability')
            configs[name]={'present':True,'source':before,'backup':copied};artifacts.append(copied)
        artifacts.append(roundtrip_selected(state,operation/'selected-state.private.sqlite',site,deadline,guard));guard()
    finally:c.rollback();c.close()
    need(runtime(pin)['Config']==q['Config'],'runtime-config-drift')
    need([metadata(Path(m['path'])) for m in secret_metadata]==secret_metadata,'readonly-secret-final-custody')
    for name,receipt in configs.items():
        p=Path(config_mount[0]['Source']) if name=='/app/config/servers.yaml' else db.parent/'servers.json'
        need((p.exists() or p.is_symlink())==receipt['present'],'config-final-presence')
        if receipt['present']:need(metadata(p)==receipt['source'] and digest_file(p,deadline)==receipt['backup']['sha256'],'config-final-drift')
    with db.open('rb') as f:need(f.read(20)[18:20]==header[18:20],'source-final-header')
    result={'status':'verified-bounded-selected-state-protection','site':site,'hostname':socket.gethostname(),'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'operation_dir':str(operation),'source':{'path':str(db),'device':pin['database_device'],'inode':pin['database_inode'],'schema_sha256':pin['schema_sha256']},
        'source_snapshot_started_at':snapshot_started_at,'source_sql_read_only':True,'source_journal_mode':mode,'source_sidecars_before':before_sidecars,'source_sidecars_after':sidecars(db,mode),
        'baseline':baseline,'selected_tables':sorted(selected),'excluded_history_tables':sorted(names&set(HISTORY)),'excluded_internal_tables':sorted(names&set(INTERNAL)),
        'artifacts':artifacts,'declared_config':configs,'readonly_secret_mount_custody':secret_metadata,'capacity':capacity,'deadline_seconds':SECONDS,'elapsed_seconds':round(SECONDS-(deadline-time.monotonic()),3),
        'private_key_directories_traversed_or_copied':False,'new_full_database_snapshot':False,'production_database_restore':False,
        'recovery_scope':'Isolated selected-table typed-row roundtrip and current declared-config copies only. Primary recovery is intact shared original database plus exact old image/native rollback. Remaining history, internal allocator state and filesystem secret mounts remain in place. This is not whole-database disaster/history restore or a production restore test.'}
    receipt=write_private(operation/'receipt.json',result)
    fd=os.open(operation,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    check_time(deadline);signal.alarm(0);print(json.dumps(dict(result,receipt=receipt),sort_keys=True))
