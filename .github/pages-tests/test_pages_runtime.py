"""Exercise the real Pages runtime using a controlled metadata/data boundary."""
from contextlib import contextmanager
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'.github/pages'))
import pages_runtime as runtime

class PagesRuntimeTest(unittest.TestCase):
    @contextmanager
    def scenario(self):
        previous=os.getcwd()
        with tempfile.TemporaryDirectory() as directory:
            os.chdir(directory)
            files=Path('verified-artifact/files');files.mkdir(parents=True)
            with tarfile.open(files/'artifact.tar','w') as tar:
                for name,data in [('index.html',b'ok'),('CNAME',b'oxiomsystems.com\n')]:
                    info=tarfile.TarInfo(name);info.size=len(data);tar.addfile(info,io.BytesIO(data))
            env={'GITHUB_REPOSITORY':runtime.POLICY.repository,'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'push','GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'2','GITHUB_SHA':'a'*40,'GITHUB_OUTPUT':str(Path(directory)/'outputs')}
            summary={'branch':'main','head_sha':'a'*40,'artifact_name':'pages-site-123-2'}
            try:
                with patch.dict(os.environ,env),patch.object(runtime,'verify',return_value=summary) as verify:
                    yield files,summary,verify,Path(env['GITHUB_OUTPUT'])
            finally:os.chdir(previous)

    def test_only_same_run_fixed_policy_site_produces_action_output(self):
        with self.scenario() as (files,summary,verify,output):
            result=runtime.run('456')
            verify.assert_called_once_with(runtime.POLICY,123,2,456)
            self.assertEqual(output.read_text(),'artifact_name=pages-site-123-2\n')
            self.assertTrue(Path('verified-artifact/pages-receipt.json').is_file())

    def test_wrong_source_extra_payload_and_dev_ref_never_authorize_deployment(self):
        for mode in ('source','branch','extra','ref','event'):
            with self.subTest(mode=mode),self.scenario() as (files,summary,verify,output):
                if mode=='source':summary['head_sha']='b'*40
                elif mode=='branch':summary['branch']='dev'
                elif mode=='extra':(files/'run.sh').write_text('untrusted')
                elif mode=='ref':os.environ['GITHUB_REF']='refs/heads/dev'
                else:os.environ['GITHUB_EVENT_NAME']='pull_request'
                with self.assertRaises((runtime.Refused,ValueError)):runtime.run('456')
                self.assertFalse(output.exists())
                if mode in {'ref','event'}:verify.assert_not_called()

if __name__=='__main__':unittest.main()
