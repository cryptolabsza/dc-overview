"""Immutable local build recipe changes only artifact transport steps."""
import copy,hashlib,json,subprocess,unittest,yaml
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BH='42fdbb7dc237b59861b9bb59670f3f980559ce1e'
BH_BASE='b3280034af9414026c610a18d9a9e26ab8755126'
class LocalBuildRecipeTests(unittest.TestCase):
 def test_build_recipe_pins_actual_producer_and_only_uploads_tiny_manifest(self):
  path='.github/workflows/ci-image-build-recipe.yml';recipe=yaml.safe_load((ROOT/path).read_text());job=recipe['jobs']['build'];steps=job['steps']
  checkout=next(s for s in steps if s['name']=='Checkout immutable local image producer')
  self.assertEqual(checkout['with']['ref'],BH);self.assertEqual(checkout['with']['repository'],'cryptolabsza/dc-overview');self.assertFalse(checkout['with']['persist-credentials']);self.assertEqual(checkout['with']['path'],'.local-image-producer')
  self.assertEqual(checkout['with']['sparse-checkout'].splitlines(),['/.github/image-publisher/local_handoff.py','/.github/image-publisher/local_artifacts/'])
  verify=next(s for s in steps if s['name']=='Verify immutable local producer bytes')
  for name in ['local_handoff.py','local_artifacts/local_artifact.py','local_artifacts/local_artifact_routes.py','local_artifacts/verify_artifact.py']:
   raw=subprocess.check_output(['git','show',BH+':.github/image-publisher/'+name],cwd=ROOT);self.assertIn(hashlib.sha256(raw).hexdigest()+'  .local-image-producer/.github/image-publisher/'+name,verify['run'])
  handoff=next(s for s in steps if s['name']=='Upload fixed image bundle to local store');self.assertEqual(handoff['run'],'python3 .local-image-producer/.github/image-publisher/local_handoff.py');self.assertNotIn('env',handoff)
  upload=next(s for s in steps if s.get('id')=='upload');self.assertEqual(upload['with']['path'],'${{ runner.temp }}/image-local-manifest/manifest.json');self.assertEqual(upload['with']['compression-level'],0);self.assertEqual(upload['with']['retention-days'],7)
  baseline=yaml.safe_load(subprocess.check_output(['git','show',BH_BASE+':'+path],cwd=ROOT));normal=copy.deepcopy(recipe);normal['jobs']['build']['steps']=[s for s in normal['jobs']['build']['steps'] if s['name'] not in {checkout['name'],verify['name'],handoff['name']}]
  target=next(s for s in normal['jobs']['build']['steps'] if s.get('id')=='upload');target['with']=next(s for s in baseline['jobs']['build']['steps'] if s.get('id')=='upload')['with']
  next(s for s in normal['jobs']['build']['steps'] if s.get('name')=='Build Docker image')['name']='Build actual dc-overview without publication'
  self.assertEqual(normal['jobs']['build']['timeout-minutes'],120);normal['jobs']['build']['timeout-minutes']=45
  self.assertEqual(normal,baseline)

PH='786763be47e68c8859a4b6fdd1f1e6148992d137'
PH_BASE='3828ff628d6c5450275cd49d069c9653c1acd234'
class LocalPublicationRecipeTests(unittest.TestCase):
 def test_publisher_recipe_uses_exact_real_common_snapshot_without_permission_changes(self):
  path='.github/workflows/ci-image-publish-recipe.yml';actual=yaml.safe_load((ROOT/path).read_text());baseline=yaml.safe_load(subprocess.check_output(['git','show',PH_BASE+':'+path],cwd=ROOT));normal=copy.deepcopy(actual)
  for name,job in actual['jobs'].items():
   old=baseline['jobs'][name];checkout=job['steps'][0];self.assertEqual(checkout['with']['ref'],PH)
   sparse=checkout['with']['sparse-checkout'].splitlines();self.assertIn('/.github/image-publisher/local_artifact.py',sparse);self.assertIn('/.github/image-publisher/local_artifact_routes.py',sparse)
   verify=next(s for s in job['steps'] if s.get('name')=='Verify frozen upstream verifier and OCI parser');previous=next(s for s in old['steps'] if s.get('name')==verify['name'])
   oldhash='54bd08ddf7e59e755c0f21b3413699459cb837d152ff4b57716660f2ff71c7c3';newhash=hashlib.sha256(subprocess.check_output(['git','show',PH+':.github/image-publisher/verify_artifact.py'],cwd=ROOT)).hexdigest();extra=''
   for filename in ('local_artifact.py','local_artifact_routes.py'):
    raw=subprocess.check_output(['git','show',PH+':.github/image-publisher/'+filename],cwd=ROOT);extra+="echo '"+hashlib.sha256(raw).hexdigest()+'  publisher/.github/image-publisher/'+filename+"' | sha256sum --check -\n"
   self.assertEqual(verify['run'],previous['run'].replace(oldhash,newhash)+extra)
   normal['jobs'][name]['steps'][0]['with']=copy.deepcopy(old['steps'][0]['with'])
   next(s for s in normal['jobs'][name]['steps'] if s.get('name')==verify['name'])['run']=previous['run']
  self.assertEqual(normal,baseline)

P='a46fe6681498cca8c8f1dfef4046d31b9fe2983e'
P_BASE='c4ecff559264c9a3be297ce91516ee0304987b27'
BR_REAL='751d216a4e7eb37c0286177601ed8f01f84a6034'
class LocalCallerTests(unittest.TestCase):
 def test_only_image_handoff_caller_pins_change_and_real_git_objects_resolve(self):
  path='.github/workflows/docker-build.yml';actual=yaml.safe_load((ROOT/path).read_text());baseline=yaml.safe_load(subprocess.check_output(['git','show',P_BASE+':'+path],cwd=ROOT));normal=copy.deepcopy(actual)
  expected={'build':('ci-image-build-recipe.yml',BR_REAL),'publish-build':('ci-image-publish-recipe.yml',P)}
  for job,(filename,sha) in expected.items():
   self.assertEqual(actual['jobs'][job]['uses'],'cryptolabsza/dc-overview'+'/.github/workflows/'+filename+'@'+sha)
   frozen=yaml.safe_load(subprocess.check_output(['git','show',sha+':.github/workflows/'+filename],cwd=ROOT));self.assertIn('jobs',frozen)
   normal['jobs'][job]['uses']=baseline['jobs'][job]['uses']
  self.assertEqual(normal,baseline)
