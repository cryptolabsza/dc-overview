from verify_artifact import Policy

POLICY = Policy(
    repository='cryptolabsza/dc-overview',
    repository_id=1133295682,
    workflow_path='.github/workflows/publish.yml',
    recipe_ref='cryptolabsza/dc-overview/.github/workflows/ci-python-build-recipe.yml@751d216a4e7eb37c0286177601ed8f01f84a6034',
    producer_job='cpu-build / build',
    group_id=11,
    build_label='ci-linux-cpu-v1-r1133295682',
    artifact_kind='pypi',
    artifact_stem='cpu-python',
)
PROJECT = 'dc-overview'
PROJECT_FILE = 'pyproject.toml'
MIRROR_GITHUB = True
