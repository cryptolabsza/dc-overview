#!/usr/bin/env python3
"""Publish one normal release build; a success receipt requires both exact downloads.

Run in GitHub Actions only. Credentials stay in the process environment. The
helper never rebuilds, overwrites assets, or treats an upload response as proof.
"""
import argparse
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time
import tomllib
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen
import zipfile

PROJECTS = {'dc-overview', 'cryptolabs-proxy'}
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+')
SHA = re.compile(r'[0-9a-f]{40}')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True, check=False)
    if result.returncode:
        raise ValueError('source_revision_unavailable')
    return result.stdout.decode().strip()


def project_identity(root):
    project = tomllib.loads((root/'pyproject.toml').read_text())['project']
    name, version = project['name'], project['version']
    if name not in PROJECTS or not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError('unsupported_project_version')
    return name, version


def check_context(root, tag, version, event, event_sha, client):
    """Match source, tag and publisher release before building or uploading."""
    name, source_version = project_identity(root)
    if event not in ('release', 'workflow_dispatch'):
        raise ValueError('unsupported_event')
    if version != source_version or tag != 'v' + source_version:
        raise ValueError('release_version_mismatch')
    source_sha = git(root, 'rev-parse', 'HEAD')
    if not SHA.fullmatch(source_sha) or git(root, 'rev-parse', f'refs/tags/{tag}^{{commit}}') != source_sha:
        raise ValueError('checkout_tag_mismatch')
    if git(root, 'status', '--porcelain', '--untracked-files=normal'):
        raise ValueError('dirty_source')
    if event == 'release' and event_sha != source_sha:
        raise ValueError('event_revision_mismatch')
    if client.tag_commit(tag) != source_sha:
        raise ValueError('publisher_tag_revision_mismatch')
    release = client.release(tag)
    if release.get('tag_name') != tag or release.get('draft') is not False:
        raise ValueError('published_release_required')
    return {'project': name, 'version': source_version, 'tag': tag,
            'repository': 'cryptolabsza/' + name, 'source_sha': source_sha}


def metadata_identity(data, project, version):
    metadata = BytesParser().parsebytes(data)
    if metadata.get_all('Name') != [project] or metadata.get_all('Version') != [version]:
        raise ValueError('archive_metadata_mismatch')


def inspect_build(root, dist, context):
    name, version = project_identity(root)
    if context['project'] != name or context['version'] != version:
        raise ValueError('source_metadata_mismatch')
    if (context['tag'] != 'v'+version or context['repository'] != 'cryptolabsza/'+name
            or not SHA.fullmatch(context['source_sha'])):
        raise ValueError('invalid_build_context')
    stem = name.replace('-', '_') + '-' + version
    wheel_name, sdist_name = stem+'-py3-none-any.whl', stem+'.tar.gz'
    expected = {wheel_name, sdist_name}
    if {p.name for p in dist.iterdir()} - {'SHA256SUMS'} != expected:
        raise ValueError('ambiguous_build_outputs')
    if any((dist/f).is_symlink() or not (dist/f).is_file() for f in expected):
        raise ValueError('unsafe_build_output')
    with zipfile.ZipFile(dist/wheel_name) as archive:
        metadata_paths = [p for p in archive.namelist() if p.endswith('.dist-info/METADATA')]
        if metadata_paths != [stem+'.dist-info/METADATA']:
            raise ValueError('wheel_metadata_missing_or_ambiguous')
        metadata_identity(archive.read(metadata_paths[0]), name, version)
    with tarfile.open(dist/sdist_name, 'r:gz') as archive:
        paths = [m for m in archive.getmembers() if m.name == stem+'/PKG-INFO']
        if len(paths) != 1 or not paths[0].isfile():
            raise ValueError('sdist_metadata_missing_or_ambiguous')
        metadata_identity(archive.extractfile(paths[0]).read(), name, version)
    return {'schema_version': 1, **context, 'artifacts': [
        {'filename': f, 'sha256': digest((dist/f).read_bytes()), 'size': (dist/f).stat().st_size}
        for f in (wheel_name, sdist_name)]}


def checksum_bytes(plan):
    return ''.join(f"{item['sha256']}  {item['filename']}\n" for item in plan['artifacts']).encode()


def prepare(root, dist, context):
    plan = inspect_build(root, dist, context)
    (dist/'SHA256SUMS').write_bytes(checksum_bytes(plan))
    return plan


def verify_local(plan, dist):
    if plan.get('schema_version') != 1 or plan.get('project') not in PROJECTS:
        raise ValueError('invalid_build_receipt')
    version = plan.get('version')
    if (not isinstance(version, str) or not VERSION.fullmatch(version)
            or plan.get('tag') != 'v'+version or plan.get('repository') != 'cryptolabsza/'+plan['project']
            or not SHA.fullmatch(plan.get('source_sha', ''))):
        raise ValueError('invalid_build_receipt')
    stem = plan['project'].replace('-', '_')+'-'+version
    names = [stem+'-py3-none-any.whl', stem+'.tar.gz']
    if [a.get('filename') for a in plan['artifacts']] != names:
        raise ValueError('unexpected_artifact_identity')
    if {p.name for p in dist.iterdir()} != set(names + ['SHA256SUMS']):
        raise ValueError('ambiguous_transported_outputs')
    for item in plan['artifacts']:
        path = dist/item['filename']
        if path.is_symlink() or not path.is_file():
            raise ValueError('unsafe_artifact')
        if digest(path.read_bytes()) != item['sha256'] or path.stat().st_size != item['size']:
            raise ValueError('transported_artifact_changed')
    sums = dist/'SHA256SUMS'
    if sums.is_symlink() or sums.read_bytes() != checksum_bytes(plan):
        raise ValueError('transported_checksums_changed')


def index(records, field):
    result = {}
    for item in records:
        name = item[field]
        if name in result:
            raise ValueError('duplicate_publisher_filename')
        result[name] = item
    return result


def check_pypi(plan, client, required=False):
    """Only 404 means absent; metadata and actual download hashes must agree."""
    metadata = client.pypi(plan['project'], plan['version'])
    if metadata is None:
        if required:
            raise ValueError('pypi_files_not_visible')
        return {}
    info = metadata['info']
    if info['name'] != plan['project'] or info['version'] != plan['version']:
        raise ValueError('pypi_identity_mismatch')
    files = index(metadata['urls'], 'filename')
    expected = {a['filename'] for a in plan['artifacts']}
    if set(files) - expected:
        raise ValueError('pypi_existing_version_has_unexpected_files')
    if required and set(files) != expected:
        raise ValueError('pypi_files_not_visible')
    for artifact in plan['artifacts']:
        record = files.get(artifact['filename'])
        if record is None:
            continue
        url = urlsplit(record['url'])
        if (url.scheme != 'https' or url.netloc != 'files.pythonhosted.org' or url.query
                or url.fragment or url.path.rsplit('/', 1)[-1] != artifact['filename']):
            raise ValueError('unsafe_pypi_url')
        if (record.get('yanked') is not False or record['digests']['sha256'] != artifact['sha256']
                or record['size'] != artifact['size']):
            raise ValueError('pypi_existing_file_conflict')
        data = client.download(record['url'])
        if digest(data) != artifact['sha256'] or len(data) != artifact['size']:
            raise ValueError('pypi_download_conflict')
    return files


def check_github(plan, client, required=False):
    release = client.release(plan['tag'])
    if release['tag_name'] != plan['tag'] or release.get('draft') is not False:
        raise ValueError('published_release_required')
    files = index(release['assets'], 'name')
    expected = {a['filename']: a for a in plan['artifacts']}
    sums = checksum_bytes(plan)
    expected['SHA256SUMS'] = {'sha256': digest(sums), 'size': len(sums)}
    if required and not set(expected) <= set(files):
        raise ValueError('github_assets_not_visible')
    for name, artifact in expected.items():
        record = files.get(name)
        if record is None:
            continue
        url = f"https://github.com/{plan['repository']}/releases/download/{plan['tag']}/{name}"
        if record['browser_download_url'] != url or record['size'] != artifact['size']:
            raise ValueError('github_existing_asset_conflict')
        data = client.download(url)
        if digest(data) != artifact['sha256'] or len(data) != artifact['size']:
            raise ValueError('github_download_conflict')
    return files


def publish(plan, dist, client, *, attempts=6):
    verify_local(plan, dist)
    if client.tag_commit(plan['tag']) != plan['source_sha']:
        raise ValueError('publisher_tag_revision_mismatch')
    # Check BOTH publishers before the first upload, including a partial retry.
    pypi_files = check_pypi(plan, client)
    github_files = check_github(plan, client)
    paths = [dist/a['filename'] for a in plan['artifacts']]
    missing = [p for p in paths if p.name not in pypi_files]
    if missing:
        client.upload_pypi(missing)
    missing = [p for p in paths + [dist/'SHA256SUMS'] if p.name not in github_files]
    if missing:
        client.upload_github(plan['tag'], missing)
    for attempt in range(attempts):
        try:
            pypi_files = check_pypi(plan, client, required=True)
            github_files = check_github(plan, client, required=True)
            break
        except (ValueError, RuntimeError):
            if attempt+1 == attempts:
                raise
            time.sleep(5)
    verify_local(plan, dist)
    if client.tag_commit(plan['tag']) != plan['source_sha']:
        raise ValueError('publisher_tag_changed_during_publication')
    return {'schema_version': 1, 'status': 'verified',
            'verified_utc': datetime.now(timezone.utc).isoformat(),
            **{k: plan[k] for k in ('project', 'version', 'repository', 'tag', 'source_sha')},
            'artifacts': [{**a, 'pypi_url': pypi_files[a['filename']]['url'],
                           'github_url': github_files[a['filename']]['browser_download_url']}
                          for a in plan['artifacts']],
            'checksums_sha256': digest(checksum_bytes(plan))}


class Client:
    """Fixed official endpoints; no persisted credentials or token CLI arguments."""
    def __init__(self, repository):
        if repository not in {'cryptolabsza/'+p for p in PROJECTS}:
            raise ValueError('unsupported_repository')
        self.repository = repository

    def get_json(self, url, *, absent=False, github=False):
        headers = {'Accept': 'application/vnd.github+json' if github else 'application/json'}
        if github:
            headers['Authorization'] = 'Bearer ' + os.environ['GH_TOKEN']
        try:
            with urlopen(Request(url, headers=headers), timeout=30) as response:
                return json.load(response)
        except HTTPError as error:
            if absent and error.code == 404:
                return None
            raise RuntimeError('publisher_metadata_unavailable') from None
        except (URLError, json.JSONDecodeError, OSError):
            raise RuntimeError('publisher_metadata_unavailable') from None

    def api(self, path):
        return self.get_json(f'https://api.github.com/repos/{self.repository}/{path}', github=True)

    def tag_commit(self, tag):
        value = self.api('git/ref/tags/'+quote(tag, safe=''))['object']
        for _ in range(5):
            if value['type'] == 'commit':
                return value['sha']
            if value['type'] != 'tag' or not SHA.fullmatch(value['sha']):
                break
            value = self.api('git/tags/'+value['sha'])['object']
        raise ValueError('unresolved_publisher_tag')

    def release(self, tag):
        release = self.api('releases/tags/'+quote(tag, safe=''))
        assets = []
        for page in range(1, 11):
            batch = self.api(f"releases/{int(release['id'])}/assets?per_page=100&page={page}")
            assets.extend(batch)
            if len(batch) < 100:
                release['assets'] = assets
                return release
        raise ValueError('too_many_release_assets')

    def pypi(self, project, version):
        return self.get_json(f'https://pypi.org/pypi/{project}/{version}/json', absent=True)

    def download(self, url):
        try:
            with urlopen(url, timeout=60) as response:
                return response.read()
        except (URLError, OSError):
            raise RuntimeError('publisher_download_unavailable') from None

    @staticmethod
    def run(args):
        result = subprocess.run(args, capture_output=True, check=False)
        # Tool diagnostics may contain credentials. Retain only safe status.
        if result.returncode:
            raise RuntimeError('publisher_upload_failed')

    def upload_pypi(self, paths):
        if not os.environ.get('TWINE_PASSWORD'):
            raise RuntimeError('publisher_credential_unavailable')
        self.run([sys.executable, '-m', 'twine', 'upload', '--non-interactive',
                  '--disable-progress-bar', '--config-file', '/dev/null', '--repository-url', 'https://upload.pypi.org/legacy/',
                  *map(str, paths)])

    def upload_github(self, tag, paths):
        self.run(['gh', 'release', 'upload', tag, '--repo', self.repository, *map(str, paths)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['context', 'prepare', 'publish'])
    parser.add_argument('--root', type=Path, default=Path('.'))
    parser.add_argument('--dist', type=Path)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    try:
        if os.environ.get('GITHUB_ACTIONS') != 'true':
            raise ValueError('actions_only')
        root = args.root.resolve()
        name, version = project_identity(root)
        client = Client('cryptolabsza/'+name)
        if os.environ['GITHUB_REPOSITORY'] != client.repository:
            raise ValueError('repository_mismatch')
        tag = os.environ['RELEASE_TAG']
        event = os.environ['GITHUB_EVENT_NAME']
        requested_version = tag[1:] if event == 'release' else os.environ['RELEASE_VERSION']
        context = check_context(root, tag, requested_version, event, os.environ['GITHUB_SHA'], client)
        if args.command == 'context':
            return 0
        if not args.dist or not args.plan:
            raise ValueError('build_paths_required')
        if args.command == 'prepare':
            # The build uses a git archive outside the source checkout.
            plan = prepare(root, args.dist, context)
            args.plan.write_text(json.dumps(plan, indent=2)+'\n')
        else:
            if not args.receipt or args.receipt.exists():
                raise ValueError('fresh_receipt_path_required')
            plan = json.loads(args.plan.read_text())
            if {k: plan.get(k) for k in context} != context:
                raise ValueError('transported_source_identity_changed')
            if inspect_build(root, args.dist, context) != plan:
                raise ValueError('transported_build_changed')
            receipt = publish(plan, args.dist, client)
            args.receipt.write_text(json.dumps(receipt, indent=2)+'\n')
            summary = os.environ.get('GITHUB_STEP_SUMMARY')
            if summary:
                with open(summary, 'a') as out:
                    out.write(f"## Verified {name} {version}\n\nSource `{context['source_sha']}`; exact wheel and sdist verified at PyPI and GitHub.\n\n")
                    for item in receipt['artifacts']:
                        out.write(f"- [{item['filename']}]({item['github_url']}): `{item['sha256']}`\n")
        return 0
    except (ValueError, RuntimeError, OSError, KeyError, TypeError, zipfile.BadZipFile, tarfile.TarError):
        print('Release publication held; no verified receipt was produced.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
