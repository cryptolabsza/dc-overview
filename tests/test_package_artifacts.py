"""Release archives must build from source, never tracked build output."""
import subprocess
from pathlib import Path


def test_generated_build_and_distribution_artifacts_are_not_tracked():
    root = Path(__file__).parents[1]
    tracked = subprocess.run(
        ['git', 'ls-files', 'build', 'dist'], cwd=root, check=True,
        capture_output=True, text=True,
    ).stdout.splitlines()
    assert not tracked
