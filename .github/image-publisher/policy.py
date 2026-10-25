from verify_artifact import Policy
from transport import main
POLICY=Policy(repository='cryptolabsza/dc-overview',repository_id=1133295682,workflow_path='.github/workflows/docker-build.yml',recipe_ref='cryptolabsza/dc-overview/.github/workflows/ci-image-build-recipe.yml@751d216a4e7eb37c0286177601ed8f01f84a6034',producer_job='build / build',group_id=11,build_label='ci-linux-cpu-v1-r1133295682',artifact_kind='oci',artifact_stem='cpu-image',transport_schema=2)
IMAGES=['dc-overview', 'runpod-exporter', 'vastai-exporter']
if __name__=='__main__':raise SystemExit(main(POLICY,IMAGES))
