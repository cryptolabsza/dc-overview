from verify_artifact import Policy

POLICY = Policy(
    repository='cryptolabsza/dc-overview',
    repository_id=1133295682,
    workflow_path='.github/workflows/publish.yml',
    recipe_ref='cryptolabsza/dc-overview/.github/workflows/ci-python-build-recipe.yml@f995901eb7fbb1bf6d94fd75d1a8b69d8edfdcef',
    producer_job='cpu-build / build',
    group_id=11,
    build_label='ci-linux-cpu-v1-r1133295682',
    artifact_kind='pypi',
    artifact_stem='cpu-python',
)
PROJECT = 'dc-overview'
PROJECT_FILE = 'pyproject.toml'
MIRROR_GITHUB = True
