"""Offline publisher fixtures: PyPI JSON URLs/digests and GitHub release asset records.

Archive bytes are synthetic. Field shapes mirror the retained 2026-10-11
published-package preflight; these tests do not assert a real release exists.
"""
import copy
import hashlib
import importlib.util
import io
import json
import re
import sys
from pathlib import Path
import tarfile
import zipfile

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PROJECT = re.search(r'^name = "([^"]+)"', (ROOT/'pyproject.toml').read_text(), re.M).group(1)
VERSION = re.search(r'^version = "([^"]+)"', (ROOT/'pyproject.toml').read_text(), re.M).group(1)
SHA = 'a' * 40


@pytest.fixture
def mod():
    if sys.version_info < (3, 11):
        pytest.skip('Release helper runs in the Python 3.11 Actions job')
    path = ROOT / 'scripts/release_publication.py'
    spec = importlib.util.spec_from_file_location('publication', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def built(tmp_path):
    root = tmp_path / 'source'; root.mkdir()
    (root/'pyproject.toml').write_text(f'[project]\nname = "{PROJECT}"\nversion = "{VERSION}"\n')
    dist = tmp_path / 'dist'; dist.mkdir()
    name = PROJECT.replace('-', '_')
    metadata = f'Metadata-Version: 2.1\nName: {PROJECT}\nVersion: {VERSION}\n'
    wheel = dist/f'{name}-{VERSION}-py3-none-any.whl'
    with zipfile.ZipFile(wheel, 'w') as archive:
        archive.writestr(f'{name}-{VERSION}.dist-info/METADATA', metadata)
        archive.writestr(f'{name}/__init__.py', '# synthetic offline fixture\n')
    sdist = dist/f'{name}-{VERSION}.tar.gz'
    with tarfile.open(sdist, 'w:gz') as archive:
        data = metadata.encode(); item = tarfile.TarInfo(f'{name}-{VERSION}/PKG-INFO')
        item.size = len(data); archive.addfile(item, io.BytesIO(data))
    context = {'project': PROJECT, 'version': VERSION, 'tag': f'v{VERSION}',
               'repository': f'cryptolabsza/{PROJECT}', 'source_sha': SHA}
    return root, dist, context


class Publisher:
    def __init__(self, context):
        self.context = context; self.repository = context['repository']; self.files = {}; self.assets = {}; self.writes = []
        self.pypi_exists = False; self.failure = None; self.corrupt = False
        self.release_data = {'tag_name': context['tag'], 'draft': False,
                             'id': 123, 'html_url': f"https://github.com/{context['repository']}/releases/tag/{context['tag']}"}
    def tag_commit(self, tag):
        return self.context['source_sha']
    def release(self, tag):
        if self.failure == 'github': raise RuntimeError('github_metadata_unavailable')
        return {**self.release_data, 'assets': list(self.assets.values())}
    def pypi(self, project, version):
        if self.failure == 'pypi': raise RuntimeError('pypi_metadata_unavailable')
        if not self.pypi_exists: return None
        return {'info': {'name': project, 'version': version}, 'urls': list(self.files.values())}
    def download(self, url):
        records = list(self.files.values()) + list(self.assets.values())
        return next(r['_bytes'] for r in records if r.get('url', r.get('browser_download_url')) == url)
    def upload_pypi(self, paths):
        self.writes.append(('pypi', [p.name for p in paths])); self.pypi_exists = True
        for path in paths:
            data = path.read_bytes()
            self.files[path.name] = {'filename': path.name,
                'url': f'https://files.pythonhosted.org/packages/offline/{path.name}',
                'digests': {'sha256': hashlib.sha256(data).hexdigest()}, 'size': len(data),
                'yanked': False, '_bytes': b'corrupt' if self.corrupt else data}
    def upload_github(self, tag, paths):
        self.writes.append(('github', [p.name for p in paths]))
        for path in paths:
            data = path.read_bytes()
            self.assets[path.name] = {'name': path.name, 'id': len(self.assets)+1,
                'browser_download_url': f"https://github.com/{self.context['repository']}/releases/download/{tag}/{path.name}",
                'size': len(data), '_bytes': data}


def bundle(mod, built):
    root, dist, context = built
    return mod.prepare(root, dist, context)


def test_normal_publication_verifies_both_downloads_and_retains_exact_identity(mod, built):
    root, dist, context = built; plan = bundle(mod, built); client = Publisher(context)
    receipt = mod.publish(plan, dist, client, attempts=1)
    assert receipt['status'] == 'verified'
    assert receipt['source_sha'] == SHA and receipt['tag'] == context['tag']
    assert len(receipt['artifacts']) == 2
    for entry in receipt['artifacts']:
        data = (dist/entry['filename']).read_bytes()
        assert entry['sha256'] == hashlib.sha256(data).hexdigest()
        assert client.download(entry['pypi_url']) == data
        assert client.download(entry['github_url']) == data
    sums = (dist/'SHA256SUMS').read_bytes()
    assert client.assets['SHA256SUMS']['_bytes'] == sums


@pytest.mark.parametrize('field,value', [('tag', 'v9.9.9'), ('version', '9.9.9'),
    ('tag', 'v1.4.0\n$(touch /tmp/unwanted)'), ('tag', 'main'), ('version', '')])
def test_context_rejects_wrong_or_injected_dispatch_before_build(mod, built, monkeypatch, field, value):
    root, dist, context = built
    monkeypatch.setattr(mod, 'git', lambda root, *args: SHA if args[0]=='rev-parse' else '')
    supplied = {'tag': context['tag'], 'version': VERSION}; supplied[field] = value
    with pytest.raises(ValueError):
        mod.check_context(root, supplied['tag'], supplied['version'], 'workflow_dispatch', SHA, Publisher(context))


@pytest.mark.parametrize('failure', ['sha', 'tag-sha', 'draft', 'release-tag', 'dirty', 'event'])
def test_context_rejects_wrong_checkout_or_unreleased_source(mod, built, monkeypatch, failure):
    root, dist, context = built; client = Publisher(context)
    if failure == 'tag-sha': client.context = {**context, 'source_sha': 'b'*40}
    if failure == 'draft': client.release_data['draft'] = True
    if failure == 'release-tag': client.release_data['tag_name'] = 'v9.9.9'
    def git(root, *args):
        if args[0] == 'rev-parse': return SHA
        return ' M source.py' if failure == 'dirty' else ''
    monkeypatch.setattr(mod, 'git', git)
    with pytest.raises(ValueError):
        mod.check_context(root, context['tag'], VERSION, 'push' if failure=='event' else 'release',
                          'b'*40 if failure=='sha' else SHA, client)


def test_context_accepts_manual_tag_when_dispatch_sha_is_default_branch(mod, built, monkeypatch):
    root, dist, context = built
    monkeypatch.setattr(mod, 'git', lambda root, *args: SHA if args[0]=='rev-parse' else '')
    assert mod.check_context(root, context['tag'], VERSION, 'workflow_dispatch', 'b'*40, Publisher(context)) == context


@pytest.mark.parametrize('failure', ['wheel-version', 'sdist-name', 'extra-file', 'missing-sdist'])
def test_build_metadata_mismatch_or_ambiguous_outputs_are_held(mod, built, failure):
    root, dist, context = built; name = PROJECT.replace('-', '_')
    if failure == 'wheel-version':
        with zipfile.ZipFile(next(dist.glob('*.whl')), 'w') as archive:
            archive.writestr(f'{name}-{VERSION}.dist-info/METADATA', f'Name: {PROJECT}\nVersion: 9.9.9\n')
    if failure == 'sdist-name':
        with tarfile.open(next(dist.glob('*.tar.gz')), 'w:gz') as archive:
            data=b'Name: malicious-project\nVersion: 1.0.0\n'; item=tarfile.TarInfo(f'{name}-{VERSION}/PKG-INFO')
            item.size=len(data); archive.addfile(item, io.BytesIO(data))
    if failure == 'extra-file': (dist/'stale.whl').write_bytes(b'stale')
    if failure == 'missing-sdist': next(dist.glob('*.tar.gz')).unlink()
    with pytest.raises(ValueError): mod.prepare(root, dist, context)


@pytest.mark.parametrize('publisher', ['pypi', 'github'])
def test_existing_different_bytes_refuse_before_any_write(mod, built, publisher):
    root, dist, context = built; plan = bundle(mod, built); client = Publisher(context)
    paths = [dist/a['filename'] for a in plan['artifacts']]
    if publisher == 'pypi':
        client.upload_pypi(paths); entry = next(iter(client.files.values()))
        entry['digests']['sha256'] = 'b'*64
    else:
        client.upload_github(context['tag'], paths); next(iter(client.assets.values()))['_bytes'] = b'different'
    client.writes.clear()
    with pytest.raises(ValueError): mod.publish(plan, dist, client, attempts=1)
    assert client.writes == []


def test_resume_identical_existing_files_uploads_only_missing_and_never_clobbers(mod, built):
    root, dist, context = built; plan = bundle(mod, built); client = Publisher(context)
    client.upload_pypi([dist/plan['artifacts'][0]['filename']])
    client.upload_github(context['tag'], [dist/plan['artifacts'][1]['filename']]); client.writes.clear()
    assert mod.publish(plan, dist, client, attempts=1)['status'] == 'verified'
    assert client.writes == [('pypi', [plan['artifacts'][1]['filename']]),
        ('github', [plan['artifacts'][0]['filename'], 'SHA256SUMS'])]
    client.writes.clear()
    assert mod.publish(plan, dist, client, attempts=1)['status'] == 'verified'
    assert client.writes == []


@pytest.mark.parametrize('failure', ['pypi', 'github'])
def test_metadata_failure_is_not_a_new_version_and_never_writes(mod, built, failure):
    root, dist, context = built; client = Publisher(context); client.failure = failure
    with pytest.raises(RuntimeError): mod.publish(bundle(mod, built), dist, client, attempts=1)
    assert client.writes == []


@pytest.mark.parametrize('failure', ['download', 'missing', 'yanked', 'url', 'unrelated-file'])
def test_publisher_success_does_not_replace_exact_file_verification(mod, built, failure):
    root, dist, context = built; plan = bundle(mod, built); client = Publisher(context)
    client.upload_pypi([dist/a['filename'] for a in plan['artifacts']])
    entry = next(iter(client.files.values()))
    if failure == 'download': entry['_bytes'] = b'corrupted-download'
    if failure == 'yanked': entry['yanked'] = True
    if failure == 'url': entry['url'] = 'https://evil.invalid/artifact.whl'
    if failure == 'unrelated-file': client.files['extra'] = {**entry, 'filename': 'unrelated.whl'}
    if failure == 'missing':
        client.files.clear(); client.upload_pypi = lambda paths: None
    client.writes.clear()
    with pytest.raises(ValueError): mod.publish(plan, dist, client, attempts=1)
    if failure != 'missing': assert client.writes == []


@pytest.mark.parametrize('failure', ['artifact', 'checksums', 'receipt'])
def test_transport_tamper_is_held_before_publisher_writes(mod, built, failure):
    root, dist, context = built; plan = bundle(mod, built); client = Publisher(context)
    if failure == 'artifact': (dist/plan['artifacts'][0]['filename']).write_bytes(b'tampered')
    if failure == 'checksums': (dist/'SHA256SUMS').write_text('wrong checksum\n')
    if failure == 'receipt': plan['artifacts'][0]['sha256'] = 'c'*64
    with pytest.raises(ValueError): mod.publish(plan, dist, client, attempts=1)
    assert client.writes == []


def test_workflow_separates_artifact_producer_from_publisher_authority():
    text = (ROOT/'.github/workflows/publish.yml').read_text()
    jobs = yaml.safe_load(text)['jobs']
    assert set(jobs) == {'cpu-build', 'publish'}
    assert jobs['cpu-build']['permissions'] == {'contents': 'read'}
    assert 'secrets' not in jobs['cpu-build']
    assert '/ci-python-build-recipe.yml@' in jobs['cpu-build']['uses']
    assert jobs['publish']['permissions'] == {'actions': 'read', 'contents': 'write'}
    assert jobs['publish']['needs'] == 'cpu-build'
    assert '/ci-pypi-publish-recipe.yml@' in jobs['publish']['uses']
    assert jobs['publish']['secrets'] == {'PYPI_API_TOKEN': '${{ secrets.PYPI_API_TOKEN }}'}
    assert 'python -m build' not in text and '--skip-existing' not in text
    assert 'release_publication.py' not in text


@pytest.mark.parametrize('phase', ['before', 'after'])
def test_remote_tag_drift_cannot_produce_verified_publication(mod, built, phase):
    root, dist, context = built; plan = bundle(mod, built); client = Publisher(context)
    count = []
    def tag_commit(tag):
        count.append(tag)
        return 'b'*40 if phase == 'before' or len(count)>1 else SHA
    client.tag_commit = tag_commit
    with pytest.raises(ValueError): mod.publish(plan, dist, client, attempts=1)
    if phase == 'before': assert client.writes == []


def test_failed_upload_never_returns_verified_receipt(mod, built):
    root, dist, context = built; plan = bundle(mod, built); client = Publisher(context)
    def failed(paths): raise RuntimeError('upload failed')
    client.upload_pypi = failed
    with pytest.raises(RuntimeError): mod.publish(plan, dist, client, attempts=1)
    assert client.writes == []


def test_actual_upload_commands_never_skip_or_overwrite(mod, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setenv('TWINE_PASSWORD', 'synthetic-not-a-credential')
    monkeypatch.setattr(mod.subprocess, 'run', lambda args, **kwargs:
        calls.append(args) or type('Result', (), {'returncode': 0})())
    client = mod.Client(f'cryptolabsza/{PROJECT}')
    paths = [tmp_path/'normal.whl']; client.upload_pypi(paths)
    client.upload_github(f'v{VERSION}', paths)
    assert '--skip-existing' not in calls[0] and '--clobber' not in calls[1]
    assert 'synthetic-not-a-credential' not in str(calls)
    assert 'https://upload.pypi.org/legacy/' in calls[0]
    assert calls[0][calls[0].index('--config-file')+1] == '/dev/null'


@pytest.mark.parametrize('status,absent', [(404, True), (403, False), (429, False), (500, False)])
def test_official_metadata_http_failure_distinguishes_only_absence(mod, monkeypatch, status, absent):
    def failed(*args, **kwargs):
        raise mod.HTTPError('https://pypi.org/fixture', status, 'offline fixture', {}, None)
    monkeypatch.setattr(mod, 'urlopen', failed)
    client = mod.Client(f'cryptolabsza/{PROJECT}')
    if absent: assert client.pypi(PROJECT, VERSION) is None
    else:
        with pytest.raises(RuntimeError, match='publisher_metadata_unavailable'):
            client.pypi(PROJECT, VERSION)


def test_cli_failure_never_writes_receipt_or_success_summary(mod, built, monkeypatch, tmp_path):
    root, dist, context = built; plan = bundle(mod, built); client = Publisher(context)
    plan_path=tmp_path/'build.json'; plan_path.write_text(json.dumps(plan))
    receipt=tmp_path/'verified.json'; summary=tmp_path/'summary.md'
    monkeypatch.setenv('GITHUB_ACTIONS', 'true')
    monkeypatch.setenv('GITHUB_REPOSITORY', context['repository'])
    monkeypatch.setenv('RELEASE_TAG', context['tag'])
    monkeypatch.setenv('RELEASE_VERSION', VERSION)
    monkeypatch.setenv('GITHUB_EVENT_NAME', 'workflow_dispatch')
    monkeypatch.setenv('GITHUB_SHA', SHA)
    monkeypatch.setenv('GITHUB_STEP_SUMMARY', str(summary))
    monkeypatch.setattr(mod, 'git', lambda root, *args: SHA if args[0]=='rev-parse' else '')
    monkeypatch.setattr(mod, 'Client', lambda repository: client)
    monkeypatch.setattr(mod.time, 'sleep', lambda duration: None)
    client.corrupt = True
    monkeypatch.setattr(mod.sys, 'argv', ['release_publication.py', 'publish', '--root', str(root),
        '--dist', str(dist), '--plan', str(plan_path), '--receipt', str(receipt)])
    assert mod.main() == 1
    assert not receipt.exists() and not summary.exists()
