"""Fixed Pages authority; producer inputs never supply policy."""
from verify_artifact import Policy
POLICY = Policy(
    repository='cryptolabsza/dc-overview',
    repository_id=1133295682,
    workflow_path='.github/workflows/pages.yml',
    recipe_ref='cryptolabsza/dc-overview/.github/workflows/ci-pages-build-recipe.yml@751d216a4e7eb37c0286177601ed8f01f84a6034',
    producer_job='build / build',
    group_id=11,
    build_label='ci-linux-cpu-v1-r1133295682',
    artifact_kind='site',
    artifact_stem='pages-site',
)
CNAME = None
