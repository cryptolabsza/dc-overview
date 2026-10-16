from verify_artifact import Policy
from transport import main
POLICY=Policy(repository='cryptolabsza/dc-overview',repository_id=1133295682,workflow_path='.github/workflows/docker-build.yml',recipe_ref='cryptolabsza/dc-overview/.github/workflows/ci-image-build-recipe.yml@3561d105715442e7b029b885304aab82d96204fe',producer_job='build / build',group_id=11,build_label='ci-linux-cpu-v1-r1133295682',artifact_kind='oci',artifact_stem='cpu-image')
IMAGES=['dc-overview', 'runpod-exporter', 'vastai-exporter']
if __name__=='__main__':raise SystemExit(main(POLICY,IMAGES))
