"""Execute workflow temp/build paths with offline package/publisher boundaries."""
import concurrent.futures
import glob
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/publish.yml'
publisher_spec = importlib.util.spec_from_file_location('publisher_fixtures', ROOT / 'tests/test_release_publication.py')
publisher_fixtures = importlib.util.module_from_spec(publisher_spec)
publisher_spec.loader.exec_module(publisher_fixtures)
Publisher = publisher_fixtures.Publisher


def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def step(job, name):
    return next(s for s in workflow()['jobs'][job]['steps'] if s.get('name') == name)


def action(job, prefix):
    return next(s for s in workflow()['jobs'][job]['steps'] if s.get('uses', '').startswith(prefix))


def shell(script, env, cwd):
    return subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], env=env, cwd=cwd,
                          capture_output=True, text=True, timeout=15)


def initialize(job, env, env_file, cwd):
    env = {**env, 'GITHUB_ENV': str(env_file)}
    allocators = [s for s in workflow()['jobs'][job]['steps'] if 'mktemp -d' in s.get('run', '')]
    if allocators:
        assert len(allocators) == 1
        result = shell(allocators[0]['run'], env, cwd)
        assert result.returncode == 0, result.stderr
        for line in env_file.read_text().splitlines():
            key, value = line.split('=', 1)
            env[key] = value
    return env


def expand(value, env):
    return value.replace('${{ env.RELEASE_JOB_DIR }}', env.get('RELEASE_JOB_DIR', '')) \
        .replace('${{ runner.temp }}', env['RUNNER_TEMP'])


@pytest.fixture
def boundary(tmp_path):
    workspace = tmp_path / 'checkout'; workspace.mkdir()
    source = (ROOT / 'pyproject.toml').read_text()
    project = re.search(r'^name = "([^"]+)"', source, re.M).group(1)
    version = re.search(r'^version = "([^"]+)"', source, re.M).group(1)
    (workspace / 'pyproject.toml').write_text(f'[project]\nname="{project}"\nversion="{version}"\n')
    subprocess.run(['git', 'init', '-q', str(workspace)], check=True)
    subprocess.run(['git', '-C', str(workspace), 'add', 'pyproject.toml'], check=True)
    subprocess.run(['git', '-C', str(workspace), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                    '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture'], check=True)
    sha = subprocess.check_output(['git', '-C', str(workspace), 'rev-parse', 'HEAD']).decode().strip()
    context = {'project': project, 'version': version, 'tag': 'v' + version,
               'repository': 'cryptolabsza/' + project, 'source_sha': sha}
    context_file = tmp_path / 'context.json'; context_file.write_text(json.dumps(context))
    bins = tmp_path / 'bin'; bins.mkdir()
    bridge = bins / 'python'
    bridge.write_text('#!' + sys.executable + '\n' + '''import hashlib, importlib.util, io, json, os, pathlib, sys, tarfile, zipfile
args=sys.argv[1:]
context=json.loads(pathlib.Path(os.environ['FIXTURE_CONTEXT']).read_text())
def flag(name): return pathlib.Path(args[args.index(name)+1])
spec=importlib.util.spec_from_file_location('release_helper',os.environ['FIXTURE_HELPER'])
helper=importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
if args[:2]==['-m','build']:
    source=pathlib.Path(args[2]); assert (source/'pyproject.toml').is_file()
    dist=flag('--outdir'); stem=context['project'].replace('-','_')+'-'+context['version']
    metadata=('Metadata-Version: 2.1\\nName: '+context['project']+'\\nVersion: '+context['version']+'\\n').encode()
    with zipfile.ZipFile(dist/(stem+'-py3-none-any.whl'),'w') as archive:
        archive.writestr(stem+'.dist-info/METADATA',metadata)
    with tarfile.open(dist/(stem+'.tar.gz'),'w:gz') as archive:
        info=tarfile.TarInfo(stem+'/PKG-INFO');info.size=len(metadata);archive.addfile(info,io.BytesIO(metadata))
elif args[1]=='prepare':
    plan=helper.prepare(pathlib.Path(os.environ['GITHUB_WORKSPACE']),flag('--dist'),context)
    flag('--plan').write_text(json.dumps(plan))
elif args[1]=='publish':
    plan=json.loads(flag('--plan').read_text());helper.verify_local(plan,flag('--dist'))
    pathlib.Path(os.environ['FIXTURE_CALL']).write_text(json.dumps({'dist':str(flag('--dist')),'plan':str(flag('--plan')),'receipt':str(flag('--receipt'))}))
else: raise AssertionError(args)
''')
    bridge.chmod(0o755)
    temp = tmp_path / 'shared runner temp'; temp.mkdir()
    env = {**os.environ, 'PATH': str(bins) + os.pathsep + os.environ['PATH'], 'RUNNER_TEMP': str(temp),
           'GITHUB_WORKSPACE': str(workspace), 'RELEASE_TAG': context['tag'],
           'FIXTURE_CONTEXT': str(context_file), 'FIXTURE_HELPER': str(ROOT / 'scripts/release_publication.py')}
    return tmp_path, workspace, temp, env, context


def build(boundary, number):
    base, workspace, _, env, _ = boundary
    env = initialize('build', env, base / f'build-{number}.env', workspace)
    for name in ['Build once from the checked-out revision', 'Validate wheel and sdist metadata and retain checksums']:
        result = shell(step('build', name)['run'], env, workspace)
        assert result.returncode == 0, result.stderr
    patterns = expand(action('build', 'actions/upload-artifact')['with']['path'], env).splitlines()
    paths = [Path(p) for pattern in patterns for p in glob.glob(pattern)]
    common = Path(os.path.commonpath(paths))
    bundle = {str(p.relative_to(common)): p.read_bytes() for p in paths}
    assert set(bundle) == {'build-receipt.json', 'release-dist/SHA256SUMS'} | {
        'release-dist/' + item['filename'] for item in json.loads(bundle['build-receipt.json'])['artifacts']}
    return env, common, bundle


def publish_paths(boundary, bundle, number):
    base, workspace, _, env, _ = boundary
    env = initialize('publish', env, base / f'publish-{number}.env', workspace)
    download = Path(expand(action('publish', 'actions/download-artifact')['with']['path'], env))
    for relative, raw in bundle.items():
        target = download / relative; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
    call = base / f'publish-{number}.json'; env['FIXTURE_CALL'] = str(call)
    result = shell(step('publish', 'Publish and verify exact artifacts')['run'], env, workspace)
    assert result.returncode == 0, result.stderr
    paths = json.loads(call.read_text())
    assert Path(paths['dist']) == download / 'release-dist'
    assert Path(paths['plan']) == download / 'build-receipt.json'
    receipt_upload = Path(expand(action('publish', 'actions/upload-artifact')['with']['path'], env))
    assert receipt_upload == Path(paths['receipt'])
    return download.parent, paths


def test_stale_shared_build_paths_are_preserved(boundary):
    _, _, temp, _, _ = boundary
    for name in ['release-source', 'release-dist', 'release-bundle']:
        (temp / name).mkdir(); (temp / name / 'unrelated').write_bytes(b'preserve stale bytes')
    (temp / 'build-receipt.json').write_bytes(b'stale unrelated receipt')
    (temp / 'verified-publication.json').write_bytes(b'stale unrelated verification')
    old = {str(p.relative_to(temp)): p.read_bytes() for p in temp.rglob('*') if p.is_file()}
    _, owned, bundle = build(boundary, 1)
    assert owned.parent == temp and owned != temp
    assert bundle
    assert all((temp / rel).read_bytes() == raw for rel, raw in old.items())


def test_concurrent_build_jobs_use_distinct_owned_directories(boundary):
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda number: build(boundary, number), [1, 2]))
    assert results[0][1] != results[1][1]
    assert all(root.parent == boundary[2] for _, root, _ in results)


def test_retained_bundle_recovers_exact_bytes_on_new_publish_job(boundary):
    _, _, temp, _, context = boundary
    (temp / 'verified-publication.json').write_bytes(b'unrelated stale receipt')
    _, _, bundle = build(boundary, 1)
    spec = importlib.util.spec_from_file_location('publication_temp', ROOT / 'scripts/release_publication.py')
    helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
    client = Publisher(context); upload = client.upload_github
    client.upload_github = lambda *args: (_ for _ in ()).throw(RuntimeError('synthetic github upload failure'))
    first_root, first = publish_paths(boundary, bundle, 1)
    first_dist = Path(first['dist']); plan = json.loads(Path(first['plan']).read_text())
    with pytest.raises(RuntimeError, match='synthetic github'):
        helper.publish(plan, first_dist, client, attempts=1)
    assert client.files and not Path(first['receipt']).exists()
    client.upload_github = upload
    second_root, second = publish_paths(boundary, bundle, 2)
    assert first_root != second_root and first_root.parent == second_root.parent == temp
    assert Path(second['plan']).read_bytes() == bundle['build-receipt.json']
    receipt = helper.publish(plan, Path(second['dist']), client, attempts=1)
    Path(second['receipt']).write_text(json.dumps(receipt))
    assert receipt['status'] == 'verified' and receipt['source_sha'] == context['source_sha']
    assert [name for name, _ in client.writes].count('pypi') == 1
    for relative, raw in bundle.items():
        assert (Path(second['plan']).parent / relative).read_bytes() == raw
    assert (temp / 'verified-publication.json').read_bytes() == b'unrelated stale receipt'


def test_unique_verified_receipt_is_retained_after_post_verification_failure(boundary, monkeypatch):
    base, workspace, _, _, context = boundary
    _, _, bundle = build(boundary, 1)
    _, paths = publish_paths(boundary, bundle, 1)
    spec = importlib.util.spec_from_file_location('publication_summary', ROOT / 'scripts/release_publication.py')
    helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
    client = Publisher(context)
    summary = base / 'summary-is-directory'; summary.mkdir()
    for key, value in {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': context['repository'],
                       'RELEASE_TAG': context['tag'], 'RELEASE_VERSION': context['version'],
                       'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_SHA': context['source_sha'],
                       'GITHUB_STEP_SUMMARY': str(summary)}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(helper, 'Client', lambda repository: client)
    monkeypatch.setattr(helper, 'git', lambda root, *args: context['source_sha'] if args[0] == 'rev-parse' else '')
    monkeypatch.setattr(helper.sys, 'argv', ['release_publication.py', 'publish', '--root', str(workspace),
                        '--dist', paths['dist'], '--plan', paths['plan'], '--receipt', paths['receipt']])
    assert helper.main() == 1  # The verified publication does not mask a failed step.
    assert json.loads(Path(paths['receipt']).read_text())['status'] == 'verified'
    retain = action('publish', 'actions/upload-artifact')
    assert 'always()' in retain.get('if', '')
    assert retain['with']['if-no-files-found'] == 'error'
    assert '${{ env.RELEASE_JOB_DIR }}' in retain['with']['path']
    assert not any(s.get('continue-on-error') for s in workflow()['jobs']['publish']['steps'])


def test_allocator_failure_does_not_write_a_false_job_path(boundary):
    base, workspace, _, env, _ = boundary
    allocator = next((s for s in workflow()['jobs']['build']['steps'] if 'mktemp -d' in s.get('run', '')), None)
    assert allocator is not None
    bad = base / 'bad'; bad.mkdir(); executable = bad / 'mktemp'; executable.write_text('#!/bin/sh\nexit 1\n'); executable.chmod(0o755)
    env_file = base / 'bad.env'; env = {**env, 'PATH': str(bad) + os.pathsep + env['PATH'], 'GITHUB_ENV': str(env_file)}
    result = shell(allocator['run'], env, workspace)
    assert result.returncode != 0
    assert not env_file.exists() or not env_file.read_bytes()


def test_receipt_retention_does_not_read_an_unallocated_root_path():
    allocator = next(s for s in workflow()['jobs']['publish']['steps'] if 'mktemp -d' in s.get('run', ''))
    retain = action('publish', 'actions/upload-artifact')
    # An unset base expands to /verified-publication.json; never retain it.
    assert allocator.get('id')
    assert f"steps.{allocator['id']}.outcome == 'success'" in retain.get('if', '')
    assert 'always()' in retain['if']
