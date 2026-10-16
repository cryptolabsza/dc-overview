"""Verify the real workflow boundaries, immutable helper snapshot, and fixed policy."""
from pathlib import Path
import re
import unittest
import yaml
ROOT=Path(__file__).resolve().parents[2]

class PagesRouteTest(unittest.TestCase):
    def test_producer_is_read_only_and_has_unique_artifact(self):
        recipe=yaml.safe_load((ROOT/'.github/workflows/ci-pages-build-recipe.yml').read_text())
        job=recipe['jobs']['build']
        self.assertEqual(recipe['permissions'], {'contents':'read'})
        self.assertEqual(job['permissions'], {'contents':'read'})
        self.assertEqual(job['runs-on']['group'], 'ci-build-public-ephemeral')
        self.assertEqual(job['timeout-minutes'],45)
        upload=next(s for s in job['steps'] if s.get('id')=='upload')
        self.assertEqual(upload['with']['name'],'pages-site-${{ github.run_id }}-${{ github.run_attempt }}')
        self.assertNotIn('secrets',str(recipe))
        for step in job['steps']:
            if 'uses' in step: self.assertRegex(step['uses'],r'@[0-9a-f]{40}$')

    def test_fresh_publisher_has_no_source_execution_and_main_only_permissions(self):
        path=ROOT/'.github/workflows/ci-pages-publish-recipe.yml'
        data=yaml.safe_load(path.read_text());job=data['jobs']['publish']
        self.assertEqual(job['runs-on']['group'],'ci-publish-ephemeral')
        self.assertEqual(job['environment']['name'],'github-pages')
        self.assertEqual(job['permissions'],{'contents':'read','actions':'read','pages':'write','id-token':'write'})
        self.assertIn("github.ref == 'refs/heads/main'",job['if'])
        self.assertIn('github.ref_protected == true',job['if'])
        self.assertNotIn('inputs.producer',path.read_text())
        checkout=next(s for s in job['steps'] if s.get('uses','').startswith('actions/checkout@'))
        self.assertRegex(checkout['with']['ref'],r'^[0-9a-f]{40}$')
        self.assertIs(checkout['with']['persist-credentials'],False)
        self.assertEqual(checkout['with']['sparse-checkout'],'/.github/pages/')
        runs='\n'.join(s.get('run','') for s in job['steps'])
        self.assertNotIn('pip ',runs)
        self.assertIn('publisher-code/.github/pages/pages_runtime.py',runs)
        self.assertNotIn('jekyll',runs)
        deploy=next(s for s in job['steps'] if s.get('id')=='deployment')
        self.assertEqual(deploy['with']['artifact_name'],'${{ steps.verify.outputs.artifact_name }}')

    def test_policy_uses_actual_site_kind_and_fixed_producer(self):
        text=(ROOT/'.github/pages/pages_policy.py').read_text()
        self.assertIn("artifact_kind='site'",text)
        self.assertIn("producer_job='build / build'",text)
        self.assertRegex(text,r"recipe_ref='[^']+/ci-pages-build-recipe.yml@[0-9a-f]{40}'")
        runtime=(ROOT/'.github/pages/pages_runtime.py').read_text()
        self.assertIn("summary['branch'] == 'main'",runtime)
        self.assertIn("{'artifact.tar'}",runtime)

if __name__=='__main__':unittest.main()
