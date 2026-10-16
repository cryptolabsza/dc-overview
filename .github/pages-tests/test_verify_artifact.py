"""Actual API shapes, adapted explicitly for accepted/denied identity scenarios."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[2]/'.github/pages'
sys.path.insert(0,str(ROOT))
import verify_artifact as v

FIXTURE=json.loads((Path(__file__).parent/'fixtures/producer-api-shapes.json').read_text())
NOW='2026-10-16T14:00:00Z'
RUN=38895924564
ART=12048805786
SHA=FIXTURE['run']['head_sha']
POLICY=v.Policy(repository='Oxiom-Systems/Convergence',repository_id=1306996892,
 workflow_path='.github/workflows/verify.yml',
 recipe_ref='Oxiom-Systems/Convergence/.github/workflows/ci-build-recipe.yml@05de2fe7997b85206c5188c3ef2ccd931075ec41',
 producer_job='l0-l2 / l0-l2',group_id=4,build_label='ci-linux-cpu-v1-r1306996892',
 artifact_kind='site',artifact_stem='site')

def archive(entries=(('index.html',b'hello'),)):
 b=io.BytesIO()
 with zipfile.ZipFile(b,'w',zipfile.ZIP_DEFLATED) as z:
  for name,content in entries:z.writestr(name,content)
 return b.getvalue()

class Scenario:
 def __init__(self):
  self.run=copy.deepcopy(FIXTURE['run']);self.run.update(event='push',head_branch='dev',pull_requests=[])
  self.job=copy.deepcopy(FIXTURE['job'])
  self.artifact=copy.deepcopy(FIXTURE['artifact']);self.artifact.update(name=f'site-{RUN}-1',created_at='2026-10-16T11:58:00Z',expires_at='2026-10-17T00:00:00Z')
  self.artifact['workflow_run'].update(id=RUN,repository_id=POLICY.repository_id,head_repository_id=POLICY.repository_id,head_branch='dev',head_sha=SHA)
  self.data=archive();self.artifact.update(digest='sha256:'+hashlib.sha256(self.data).hexdigest(),size_in_bytes=len(self.data))
  self.latest=self.run;self.attempt=self.run;self.jobs=[self.job];self.artifacts=[self.artifact]
  self.repo={'id':POLICY.repository_id,'full_name':POLICY.repository}
  self.branch={'name':'dev','protected':True,'commit':{'sha':'a'*40}}
  self.compare={'status':'ahead','base_commit':{'sha':SHA},'merge_base_commit':{'sha':SHA}}
  self.calls=[]
 def api(self,path):
  self.calls.append(path)
  if path.endswith('/attempts/1/jobs?per_page=100&page=1'):return {'jobs':self.jobs,'total_count':len(self.jobs)}
  if path.endswith(f'/runs/{RUN}/artifacts?per_page=100&page=1'):return {'artifacts':self.artifacts,'total_count':len(self.artifacts)}
  if path.endswith(f'/runs/{RUN}/attempts/1'):return self.attempt
  if path.endswith(f'/runs/{RUN}'):return self.latest
  if path.endswith(f'/artifacts/{ART}'):return self.artifact
  if '/branches/' in path:return self.branch
  if '/compare/' in path:return self.compare
  if path==f'/repos/{POLICY.repository}':return self.repo
  raise AssertionError(path)
 def check(self):return v.verify_metadata(self.api,POLICY,RUN,1,ART,now=NOW)

class ProducerIdentity(unittest.TestCase):
 def test_actual_pr_shape_is_not_publishable(self):
  s=Scenario();s.run['event']=FIXTURE['run']['event']
  with self.assertRaises(v.Refused):s.check()
 def test_protected_source_and_independent_artifact_identity(self):
  s=Scenario();x=s.check();self.assertEqual(x['head_sha'],SHA);self.assertEqual(x['artifact_id'],ART)
  self.assertTrue(any('/compare/'+SHA+'...' in c for c in s.calls))
 def test_wrong_identity_and_source_negative_matrix(self):
  edits=[('repo','id',1),('run','head_repository',{'id':1,'full_name':'fork/repo'}),
   ('run','repository',{'id':1,'full_name':POLICY.repository}),('run','path','.github/workflows/evil.yml'),
   ('run','event','pull_request_target'),('run','event','release'),('run','head_branch','feature'),
   ('run','head_sha','refs/heads/dev'),('run','run_attempt',2),('branch','protected',False),
   ('compare','status','behind'),('compare','merge_base_commit',{'sha':'b'*40}),
   ('job','conclusion','failure'),('job','run_attempt',2),('job','runner_group_id',6),
   ('job','labels',['ci-linux-publish-v1-r1306996892']),('job','head_sha','c'*40),
   ('artifact','expired',True),('artifact','digest',None),('artifact','name',f'site-{RUN}-2'),
   ('artifact','created_at','2026-10-16T11:59:00Z'),('artifact','expires_at','2026-10-16T12:00:00Z')]
  for obj,key,value in edits:
   with self.subTest(obj=obj,key=key,value=value):
    s=Scenario();getattr(s,obj)[key]=value
    with self.assertRaises(v.Refused):s.check()
 def test_wrong_recipe_pin_and_duplicate_jobs_artifacts(self):
  for mode in ['recipe','jobs','artifacts','artifact-source','attempt-source']:
   with self.subTest(mode=mode):
    s=Scenario()
    if mode=='recipe':s.run['referenced_workflows'][0]['sha']='b'*40
    elif mode=='jobs':s.jobs.append(copy.deepcopy(s.job))
    elif mode=='artifacts':s.artifacts.append(copy.deepcopy(s.artifact))
    elif mode=='artifact-source':s.artifact['workflow_run']['head_repository_id']=1
    else:s.attempt=copy.deepcopy(s.run);s.attempt['head_sha']='b'*40
    with self.assertRaises(v.Refused):s.check()
 def test_manual_protected_branch_and_identical_compare(self):
  s=Scenario();s.run['event']='workflow_dispatch';s.compare['status']='identical';s.branch['commit']['sha']=SHA
  self.assertEqual(s.check()['run_attempt'],1)
 def test_fixed_policy_rejects_wrong_types_role_group_or_unpinned_recipe(self):
  for key,value in [('repository_id',True),('group_id',6),('build_label','self-hosted'),('recipe_ref','owner/repo/build.yml@dev'),('artifact_stem','../oops'),('artifact_kind','shell')]:
   with self.subTest(key=key):
    fields=dict(POLICY.__dict__);fields[key]=value
    with self.assertRaises(v.Refused):v.Policy(**fields)

class ArchiveSafety(unittest.TestCase):
 def unpack(self,data):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'a.zip';p.write_bytes(data);dest=Path(d)/'files';dest.mkdir()
   files=v.extract_zip(p,dest)
   return files,{str(x.relative_to(dest)):x.read_bytes() for x in dest.rglob('*') if x.is_file()}
 def test_regular_oci_docker_pypi_apk_site_files_are_opaque_not_executed(self):
  entries=[('image.tar',b'opaque tar'),('package.whl',b'opaque wheel'),('unsigned.apk',b'apk'),('site/index.html',b'<h1>safe</h1>')]
  files,data=self.unpack(archive(entries));self.assertEqual(set(data),{x[0] for x in entries});self.assertEqual(len(files),4)
  self.assertEqual(files[0]['sha256'],hashlib.sha256(entries[0][1]).hexdigest())
 def test_traversal_absolute_symlink_duplicate_and_special_files(self):
  for name in ['../escape','/absolute','a/../../bad','a\\bad','C:/bad','a//bad','./bad','control\x1bfile']:
   with self.subTest(name=name):
    with self.assertRaises(v.Refused):self.unpack(archive([(name,b'x')]))
  for mode in [stat.S_IFLNK|0o777,stat.S_IFIFO|0o644]:
   z=io.BytesIO()
   with zipfile.ZipFile(z,'w') as f:
    x=zipfile.ZipInfo('link');x.create_system=3;x.external_attr=mode<<16;f.writestr(x,b'../outside')
   with self.assertRaises(v.Refused):self.unpack(z.getvalue())
  with self.assertRaises(v.Refused):self.unpack(archive([('A',b'x'),('a',b'y')]))
 def test_bomb_limits_empty_and_malformed_archives(self):
  from unittest.mock import patch
  with patch.object(v,'MAX_EXPANDED_BYTES',10):
   with self.assertRaises(v.Refused):self.unpack(archive([('large',b'x'*11)]))
  for data in [archive([]),b'not zip']:
   with self.assertRaises(v.Refused):self.unpack(data)
 def test_central_directory_memory_bound_checked_before_zipfile_parsing(self):
  import struct
  from unittest.mock import patch
  data=bytearray(archive());offset=data.rfind(b'PK\x05\x06')
  struct.pack_into('<L',data,offset+12,100*1024**2)
  with patch.object(v.zipfile,'ZipFile') as parser:
   with self.assertRaises(v.Refused):self.unpack(data)
   parser.assert_not_called()
 def test_implicit_directory_expansion_refuses_before_any_mkdir(self):
  from unittest.mock import patch
  # Astra reproduction:60 ZIP entries would create18,060 implicit directories.
  data=archive([(f'{i:03d}/'+('x/'*300)+'f',b'') for i in range(60)])
  self.assertLess(len(data),80*1024)
  with tempfile.TemporaryDirectory() as d:
   source=Path(d)/'a.zip';source.write_bytes(data);dest=Path(d)/'files';dest.mkdir()
   with patch.object(Path,'mkdir') as mkdir:
    with self.assertRaisesRegex(v.Refused,'ZIP namespace bound'):v.extract_zip(source,dest)
    mkdir.assert_not_called()
   self.assertEqual(list(dest.iterdir()),[])
 def test_shared_explicit_and_implicit_parent_counted_once(self):
  from unittest.mock import patch
  with patch.object(v,'MAX_FILES',3):
   files,data=self.unpack(archive([('dir/',b''),('dir/a',b'x'),('dir/b',b'y')]))
  self.assertEqual(set(data),{'dir/a','dir/b'});self.assertEqual(len(files),2)

class EndToEnd(unittest.TestCase):
 def setUp(self):
  from unittest.mock import patch
  from types import SimpleNamespace
  disk=patch.object(v.shutil,'disk_usage',return_value=SimpleNamespace(free=30*1024**3))
  disk.start();self.addCleanup(disk.stop)
 def test_disk_reserve_refuses_before_download(self):
  from unittest.mock import patch,Mock
  from types import SimpleNamespace
  s=Scenario();download=Mock()
  with tempfile.TemporaryDirectory() as d,patch.object(v.shutil,'disk_usage',return_value=SimpleNamespace(free=0)):
   with self.assertRaises(v.Refused):v.verify(POLICY,RUN,1,ART,output=Path(d)/'verified',api=s.api,download=download,now=NOW)
  download.assert_not_called()
 def test_verified_bytes_are_exposed_only_after_second_metadata_check(self):
  s=Scenario()
  def download(path,dest,maximum):dest.write_bytes(s.data)
  with tempfile.TemporaryDirectory() as d:
   output=Path(d)/'verified'
   x=v.verify(POLICY,RUN,1,ART,output=output,api=s.api,download=download,now=NOW)
   self.assertEqual((output/'files/index.html').read_bytes(),b'hello')
   self.assertEqual(x['artifact_digest'],s.artifact['digest']);self.assertEqual(len([p for p in s.calls if p.endswith(f'/runs/{RUN}')]),2)
 def test_altered_bytes_and_rerun_during_download_leave_no_output(self):
  for mode in ['bytes','rerun','oversize']:
   with self.subTest(mode=mode),tempfile.TemporaryDirectory() as d:
    s=Scenario();output=Path(d)/'verified'
    def download(path,dest,maximum):
     dest.write_bytes(b'altered' if mode=='bytes' else s.data)
     if mode=='rerun':s.run['run_attempt']=2
     if mode=='oversize':dest.write_bytes(s.data+b'x')
    with self.assertRaises(v.Refused):v.verify(POLICY,RUN,1,ART,output=output,api=s.api,download=download,now=NOW)
    self.assertFalse(output.exists());self.assertEqual(list(Path(d).iterdir()),[])
 def test_no_policy_or_arbitrary_policy_cli_and_invalid_dynamic_ids(self):
  for value in [True,0,-1,'123']:
   with self.subTest(value=value):
    with self.assertRaises(v.Refused):v.verify_metadata(Scenario().api,POLICY,value,1,ART,now=NOW)
  with self.assertRaises(v.Refused):v.main(None,[])

class StreamingTransport(unittest.TestCase):
 def invoke(self,script,maximum=1024,timeout=2,installed_paths=None):
  from unittest.mock import patch
  import subprocess
  real=subprocess.Popen;captured=[]
  def child(command,**kwargs):
   captured.extend(command)
   return real([sys.executable,'-c',script],**kwargs)
  output=io.BytesIO()
  installed=lambda path:installed_paths is None or path in installed_paths
  with patch.object(v.subprocess,'Popen',side_effect=child),patch.object(v.os.path,'isfile',side_effect=installed):
   v.gh_stream('/repos/owner/repo/actions/artifacts/1/zip',output,maximum,timeout)
  return output.getvalue(),captured
 def test_binary_download_and_fixed_get_command(self):
  data,command=self.invoke("import sys;sys.stdout.buffer.write(b'PK\\x00\\x1b\\xff')")
  self.assertEqual(data,b'PK\x00\x1b\xff')
  self.assertIn('--allow-escape-sequences',command);self.assertIn('GET',command)
  self.assertEqual(command[command.index('--hostname')+1],'github.com')
 def test_fixed_normal_user_tool_path_without_path_or_input_override(self):
  from unittest.mock import patch
  with patch.dict(os.environ,{'PATH':'/caller-controlled','GH_BIN':'/caller-controlled/gh'}):
   data,command=self.invoke("print('fixture')",installed_paths={'/tmp/ci-publish-tools/gh'})
  self.assertEqual(data,b'fixture\n')
  self.assertEqual(command[0],'/tmp/ci-publish-tools/gh')
  with self.assertRaisesRegex(v.Refused,'installed gh required'):
   self.invoke("print('must not execute')",installed_paths={'/caller-controlled/gh'})
 def test_response_limit_timeout_and_exit_failure_are_controlled(self):
  for script,maximum,timeout in [("import sys;sys.stdout.write('x'*100)",10,2),
   ('import time;time.sleep(5)',1024,.03),("import sys;sys.stderr.write('signed-redirect-secret');sys.exit(1)",1024,2)]:
   with self.subTest(script=script):
    with self.assertRaises(v.Refused) as caught:self.invoke(script,maximum,timeout)
    self.assertNotIn('signed-redirect-secret',str(caught.exception))

if __name__=='__main__':unittest.main()
