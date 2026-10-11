# Python release publication

The ordinary `publish.yml` workflow builds one pure Python wheel and one sdist
from the released tag, then publishes those same bytes to PyPI and the GitHub
release. `SHA256SUMS` is attached to GitHub. The verified Actions receipt records
the source commit, tag, version, filenames, URLs, sizes and SHA256 values after
downloading both publishers' files and checking their bytes.

Create a normal release whose tag is `vX.Y.Z` and whose committed
`pyproject.toml` version is `X.Y.Z`. Manual dispatch requires that existing
published release tag and its matching version; dispatching against a branch
cannot publish branch code. Build and publication independently compare the
checked-out commit to the local and remote release tag. The helper rejects
drafts, source changes, unexpected archive outputs and mismatched package
metadata. It runs only in GitHub Actions.

The read-only build job exports the exact commit to a temporary source tree,
then calls `python -m build` once. Its Git context retains the source commit for
DC Overview's existing build-info hook without modifying the source checkout.
Only the publication job has `contents: write`. The existing organisation
`PYPI_API_TOKEN` and ephemeral GitHub token remain process environment values;
Twine is pointed at the official publisher with an empty configuration file.
Runners need Python setup support and the `gh` CLI. No local credentials are
required or read by the helper, and uploader output is not printed.

Existing identical files are verified and reused; only missing files are
uploaded. Existing different bytes, yanked PyPI files, unknown files at the
same PyPI version, publisher errors and unverifiable metadata hold the workflow.
There is no overwrite or `--skip-existing` path. Upload completion alone does
not produce a receipt or success summary. A partial upload can leave files at
one publisher; rerun the failed publication job using the retained build
artifact to complete and verify the same bytes. A new build may differ, so
starting a fresh dispatch is not equivalent to resuming the retained artifact.

Version changes follow the repository release policy: no version bump on `dev`;
choose the new release version when merging to `main`. These helpers do not
change versions, create releases, tag, commit or deploy. A candidate built from
changed source must not be relabelled as an already published version.

The release receipt supplies the normal GitHub wheel URL and its actual hash
for an approved customer manifest. The manifest still requires the operator's
approval; successful package publication does not prove host installation,
installed `direct_url.json`, container/worker readiness, authentication or
site adoption. Publisher permissions and protection against changes by other
actors remain organisation responsibilities.
