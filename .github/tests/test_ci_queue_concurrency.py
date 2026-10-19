"""Branch CPU jobs must not share a blank global release lane."""
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]

class QueueConcurrency(unittest.TestCase):
    def test_python_retains_tag_lane_with_nonrelease_ref_fallback(self):
        config = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
        self.assertEqual(config["concurrency"], {
            "group": "python-release-${{ github.repository }}-${{ inputs.release_tag || github.event.release.tag_name || github.ref }}",
            "cancel-in-progress": False,
        })
        def lane(tag, release, ref):
            return tag or release or ref
        self.assertEqual(lane("v1.2.3", "", "refs/heads/dev"), "v1.2.3")
        self.assertEqual(lane("", "v1.2.3", "refs/tags/v1.2.3"), "v1.2.3")
        self.assertNotEqual(lane("", "", "refs/pull/5/merge"), lane("", "", "refs/heads/dev"))

    def test_docker_serializes_tags_and_separates_branch_cpu_lanes(self):
        config = yaml.safe_load((ROOT / ".github/workflows/docker-build.yml").read_text())
        self.assertEqual(config["concurrency"], {
            "group": "image-release-publication-${{ github.repository }}-${{ startsWith(github.ref, 'refs/tags/') && 'release' || github.ref }}",
            "cancel-in-progress": False,
        })
        def lane(ref):
            return "release" if ref.startswith("refs/tags/") else ref
        self.assertEqual(lane("refs/tags/v1.2.3"), lane("refs/tags/v1.2.4"))
        self.assertNotEqual(lane("refs/heads/dev"), lane("refs/pull/5/merge"))

if __name__ == "__main__":
    unittest.main()

