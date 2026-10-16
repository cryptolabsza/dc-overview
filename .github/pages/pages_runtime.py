"""Verify this run's immutable Pages artifact and validate its tar as data."""
import json
import os
from pathlib import Path
import sys
from pages_policy import POLICY, CNAME
from site_archive import validate
from verify_artifact import Refused, require, verify

def run(artifact_id):
    run_id = int(os.environ['GITHUB_RUN_ID'])
    attempt = int(os.environ['GITHUB_RUN_ATTEMPT'])
    require(os.environ['GITHUB_REPOSITORY'] == POLICY.repository, 'publisher repository')
    require(os.environ['GITHUB_REF'] == 'refs/heads/main', 'publisher main ref')
    require(os.environ['GITHUB_EVENT_NAME'] in {'push', 'workflow_dispatch'}, 'publisher event')
    summary = verify(POLICY, run_id, attempt, int(artifact_id))
    require(summary['branch'] == 'main', 'Pages source must be protected main')
    require(summary['head_sha'] == os.environ['GITHUB_SHA'], 'Pages source must match publisher')
    files = Path('verified-artifact/files')
    require({entry.name for entry in files.iterdir()} == {'artifact.tar'}, 'single site tar required')
    summary['site'] = validate(files/'artifact.tar', CNAME)
    Path('verified-artifact/pages-receipt.json').write_text(json.dumps(summary,sort_keys=True))
    with open(os.environ['GITHUB_OUTPUT'],'a') as output:
        output.write('artifact_name='+summary['artifact_name']+'\n')
    return summary

if __name__ == '__main__':
    try:
        require(len(sys.argv) == 2, 'artifact ID required')
        run(sys.argv[1])
    except (Refused, ValueError, KeyError, TypeError, OSError):
        print('Pages artifact verification refused; no deployment authorized.',file=sys.stderr)
        sys.exit(1)
