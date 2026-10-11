"""Post-build release vectors. Policy is data, never remotely supplied commands."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform as host_platform
import re
import tempfile
from urllib.parse import urlsplit

SELECTION_CONTRACT = 1
PLATFORMS = {'linux/amd64', 'linux/arm64'}
COMPONENTS = {
    'cryptolabs-proxy': ('proxy-updater', 'ghcr.io/cryptolabsza/cryptolabs-proxy', 'oci'),
    'dc-overview': ('proxy-updater', 'ghcr.io/cryptolabsza/dc-overview', 'oci'),
    'ipmi-monitor': ('proxy-updater', 'ghcr.io/cryptolabsza/ipmi-monitor', 'oci'),
    'prometheus': ('proxy-updater', 'prom/prometheus', 'oci'),
    'grafana': ('proxy-updater', 'grafana/grafana', 'oci'),
    'vastai-exporter': ('proxy-updater', 'ghcr.io/cryptolabsza/vastai-exporter', 'oci'),
    'runpod-exporter': ('proxy-updater', 'ghcr.io/cryptolabsza/runpod-exporter', 'oci'),
    'vast-price-manager': ('dc-vpm', 'ghcr.io/cryptolabsza/vast-price-manager', 'oci'),
    'dc-overview-cli': ('host-cli', 'cryptolabsza/dc-overview', 'wheel'),
    'dc-exporter': ('dc-worker', 'cryptolabsza/dc-exporter-releases', 'binary'),
    'node-exporter': ('dc-worker', 'prometheus/node_exporter', 'binary'),
    'dc-watchdog-agent': ('dc-worker', 'cryptolabsza/dc-watchdog', 'binary'),
}
HEX = re.compile(r'[0-9a-f]{64}')
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}')


def current_platform():
    architecture = {'x86_64':'amd64', 'amd64':'amd64', 'aarch64':'arm64', 'arm64':'arm64'}.get(host_platform.machine().lower())
    if host_platform.system() != 'Linux' or not architecture:
        raise ValueError('unsupported platform: a Linux amd64 or arm64 host is required')
    return 'linux/' + architecture


def _object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _json(raw):
    if len(raw) > 1024 * 1024:
        raise ValueError('release document too large')
    try:
        return json.loads(raw, object_pairs_hook=_object_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('invalid release JSON') from error


def _keys(value, required, optional=()):
    if not isinstance(value, dict) or set(value) - set(required) - set(optional) or set(required) - set(value):
        raise ValueError('invalid release document fields')


def artifact_identity(artifact):
    return artifact['reference'] if artifact['kind'] == 'oci' else artifact['sha256']


@dataclass(frozen=True)
class Manifest:
    raw: bytes
    sha256: str
    data: dict

    @classmethod
    def from_bytes(cls, raw):
        data = _json(raw)
        _keys(data, {'schema_version', 'baseline_id', 'selection_contract', 'components'})
        if type(data['schema_version']) is not int or data['schema_version'] != 1:
            raise ValueError('unsupported manifest schema')
        if type(data['selection_contract']) is not int or data['selection_contract'] != SELECTION_CONTRACT:
            raise ValueError('unsupported selection contract')
        if not isinstance(data['baseline_id'], str) or not IDENTIFIER.fullmatch(data['baseline_id']):
            raise ValueError('invalid baseline ID')
        if not isinstance(data['components'], dict) or not data['components']:
            raise ValueError('missing manifest components')
        for name, component in data['components'].items():
            if name not in COMPONENTS:
                raise ValueError('unknown component')
            _keys(component, {'release', 'owner', 'artifacts'})
            owner, repository, kind = COMPONENTS[name]
            if component['owner'] != owner:
                raise ValueError('invalid lifecycle owner')
            if not isinstance(component['release'], str) or not IDENTIFIER.fullmatch(component['release']):
                raise ValueError('invalid release ID')
            artifacts = component['artifacts']
            if not isinstance(artifacts, dict) or not artifacts:
                raise ValueError('missing artifacts')
            for architecture, artifact in artifacts.items():
                if architecture not in ({'any'} if kind == 'wheel' else PLATFORMS):
                    raise ValueError('unsupported artifact platform')
                _keys(artifact, {'kind', 'reference'} if kind == 'oci' else {'kind', 'url', 'sha256'})
                if artifact['kind'] != kind:
                    raise ValueError('invalid artifact kind')
                if kind == 'oci':
                    reference = artifact['reference']
                    if not isinstance(reference, str) or not re.fullmatch(re.escape(repository) + r'@sha256:[0-9a-f]{64}', reference):
                        raise ValueError('invalid immutable image repository/digest')
                else:
                    digest = artifact['sha256']
                    if not isinstance(digest, str) or not HEX.fullmatch(digest):
                        raise ValueError('invalid artifact checksum')
                    url = artifact['url']
                    if not isinstance(url, str):
                        raise ValueError('invalid release URL')
                    parsed = urlsplit(url)
                    pattern = re.escape('/' + repository + '/releases/download/') + r'[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*'
                    if parsed.scheme != 'https' or parsed.netloc != 'github.com' or parsed.query or parsed.fragment or not re.fullmatch(pattern, parsed.path):
                        raise ValueError('invalid immutable release URL')
                    if kind == 'wheel' and not parsed.path.endswith('.whl'):
                        raise ValueError('CLI artifact must be a wheel')
        return cls(bytes(raw), hashlib.sha256(raw).hexdigest(), data)


def resolve(manifest, selection, platform, *, required_components=()):
    _keys(selection, {'schema_version', 'selection_id', 'manifest_sha256', 'components'})
    if type(selection['schema_version']) is not int or selection['schema_version'] != 1:
        raise ValueError('unsupported selection schema')
    if not isinstance(selection['selection_id'], str) or not IDENTIFIER.fullmatch(selection['selection_id']):
        raise ValueError('invalid selection ID')
    if selection['manifest_sha256'] != manifest.sha256:
        raise ValueError('manifest hash mismatch')
    if platform not in PLATFORMS:
        raise ValueError('unsupported host platform')
    if not isinstance(selection['components'], dict) or set(selection['components']) != set(manifest.data['components']):
        raise ValueError('selection must cover exactly the manifest components')
    targets = {}
    for name, policy in selection['components'].items():
        _keys(policy, {'origin', 'enabled'}, {'pin'})
        if type(policy['enabled']) is not bool or policy['origin'] not in ('baseline', 'customer-pin', 'unmanaged'):
            raise ValueError('invalid component selection policy')
        if policy['origin'] == 'customer-pin':
            if not isinstance(policy.get('pin'), str) or not policy['pin']:
                raise ValueError('customer pin requires an exact artifact')
            candidates = [artifact_identity(item) for item in manifest.data['components'][name]['artifacts'].values()]
            if policy['pin'] not in candidates:
                raise ValueError('pin_conflict: ' + name)
        elif 'pin' in policy:
            raise ValueError('pin requires customer-pin origin')
        if not policy['enabled']:
            continue
        if policy['origin'] == 'unmanaged':
            raise ValueError('enabled required role is unmanaged')
        component = manifest.data['components'][name]
        artifacts = component['artifacts']
        artifact = artifacts.get(platform, artifacts.get('any'))
        if artifact is None:
            raise ValueError('missing enabled component platform artifact: ' + name)
        if policy['origin'] == 'customer-pin' and policy['pin'] != artifact_identity(artifact):
            raise ValueError('pin_conflict: ' + name)
        targets[name] = {**artifact, 'release':component['release'], 'owner':component['owner'],
                         'platform':'any' if 'any' in artifacts else platform, 'origin':policy['origin']}
    if set(required_components) - set(targets):
        raise ValueError('missing required enabled components: ' + ', '.join(sorted(set(required_components)-set(targets))))
    return targets


@dataclass(frozen=True)
class PreparedSelection:
    manifest: Manifest
    selection: dict
    selection_raw: bytes
    selection_sha256: str
    targets: dict
    platform: str


def _require_root():
    if os.geteuid() != 0:
        raise PermissionError('release import/select requires host root')


def _check_root_path(path, *, directory=False):
    path = Path(path)
    info = path.lstat()
    if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
        raise PermissionError('release store must be root-owned and not writable by other users')
    if directory and not path.is_dir():
        raise PermissionError('release store must be a directory')
    if not directory and not path.is_file():
        raise PermissionError('release record must be a regular file')


def _atomic_write(path, raw, *, immutable=False):
    if immutable and path.exists():
        _check_root_path(path)
        if path.read_bytes() != raw:
            raise ValueError('immutable manifest hash collision')
        return
    descriptor, temporary = tempfile.mkstemp(prefix='.selection-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644); os.fchown(stream.fileno(), 0, 0)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class ReleaseStore:
    def __init__(self, root):
        self.root = Path(root)
        if not self.root.is_absolute():
            raise ValueError('release storage directory must be absolute')
        if '..' in self.root.parts:
            raise ValueError('release storage directory cannot contain parent traversal')

    def prepare(self, manifest_path, *, policies=None, required_components=(), platform=None, enabled_components=None):
        platform = platform or current_platform()
        manifest = Manifest.from_bytes(Path(manifest_path).read_bytes())
        previous = {}
        if (self.root/'selection.json').exists():
            previous = self.load(platform=platform).selection['components']
        policies = policies or {}
        if set(policies) - set(manifest.data['components']):
            raise ValueError('policy references missing manifest component')
        chosen = {}
        for name in manifest.data['components']:
            default = {'origin':'baseline','enabled': enabled_components is None or name in enabled_components}
            chosen[name] = dict(policies.get(name, previous.get(name, default)))
        selection = {'schema_version':1,'selection_id':manifest.data['baseline_id'],
                     'manifest_sha256':manifest.sha256,'components':chosen}
        targets = resolve(manifest, selection, platform, required_components=required_components)
        raw = (json.dumps(selection, sort_keys=True, separators=(',',':'))+'\n').encode()
        return PreparedSelection(manifest, selection, raw, hashlib.sha256(raw).hexdigest(), targets, platform)

    def commit(self, prepared):
        _require_root()
        if hashlib.sha256(prepared.selection_raw).hexdigest() != prepared.selection_sha256:
            raise ValueError('selection hash mismatch')
        exact = _json(prepared.selection_raw)
        if resolve(Manifest.from_bytes(prepared.manifest.raw), exact, prepared.platform) != prepared.targets:
            raise ValueError('selection changed after preparation')
        for directory in (self.root, self.root/'manifests'):
            if directory.exists():
                _check_root_path(directory, directory=True)
            else:
                directory.mkdir(parents=True, mode=0o755)
                os.chown(directory, 0, 0)
        _atomic_write(self.root/'manifests'/f'{prepared.manifest.sha256}.json', prepared.manifest.raw, immutable=True)
        _atomic_write(self.root/'selection.json', prepared.selection_raw)

    def recover_publication(self, public_path):
        """Recover only a byte-proven interrupted publication, under caller lock."""
        journal = self.root / '.lifecycle-publication.json'
        if not journal.exists():
            return
        _require_root()
        _check_root_path(journal)
        value = _json(journal.read_bytes())
        import base64
        import yaml
        prior_public = base64.b64decode(value['before_public'], validate=True)
        prior_selection = None if value['before_selection'] is None else base64.b64decode(value['before_selection'], validate=True)
        candidate = base64.b64decode(value['candidate_selection'], validate=True)
        selection_path = self.root / 'selection.json'
        current = selection_path.read_bytes() if selection_path.exists() else None
        public = public_path.read_bytes() if public_path.exists() else b''
        expected = _json(candidate)
        references = (yaml.safe_load(public) or {}).get('release_selection', {})
        if current == candidate and references.get('selection_id') == expected['selection_id'] and references.get('selection_sha256') == hashlib.sha256(candidate).hexdigest():
            journal.unlink()
            return
        if public != prior_public or current not in (candidate, prior_selection):
            raise RuntimeError('interrupted release publication conflicts with customer edits; preserve evidence and reconcile before retry')
        if prior_selection is None:
            selection_path.unlink(missing_ok=True)
        else:
            _atomic_write(selection_path, prior_selection)
        journal.unlink()

    def begin_publication(self, prepared, before_public):
        import base64
        _require_root()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o755)
        _check_root_path(self.root, directory=True)
        path = self.root / 'selection.json'
        if path.exists():
            _check_root_path(path)
        prior = path.read_bytes() if path.exists() else None
        value = {'before_public':base64.b64encode(before_public).decode(),
                 'before_selection':None if prior is None else base64.b64encode(prior).decode(),
                 'candidate_selection':base64.b64encode(prepared.selection_raw).decode()}
        _atomic_write(self.root / '.lifecycle-publication.json', (json.dumps(value)+'\n').encode())

    def finish_publication(self):
        (self.root / '.lifecycle-publication.json').unlink(missing_ok=True)

    def load(self, *, platform=None, expected_id=None, expected_sha256=None, required_components=()):
        platform = platform or current_platform()
        _check_root_path(self.root, directory=True)
        _check_root_path(self.root/'manifests', directory=True)
        path = self.root/'selection.json'; _check_root_path(path)
        raw = path.read_bytes(); selection = _json(raw)
        digest = hashlib.sha256(raw).hexdigest()
        if expected_sha256 and digest != expected_sha256:
            raise ValueError('selection hash mismatch')
        if expected_id and selection.get('selection_id') != expected_id:
            raise ValueError('selection ID mismatch')
        manifest_hash = selection.get('manifest_sha256')
        if not isinstance(manifest_hash, str) or not HEX.fullmatch(manifest_hash):
            raise ValueError('invalid manifest hash')
        path = self.root/'manifests'/f'{manifest_hash}.json'; _check_root_path(path)
        manifest = Manifest.from_bytes(path.read_bytes())
        targets = resolve(manifest, selection, platform, required_components=required_components)
        return PreparedSelection(manifest, selection, raw, digest, targets, platform)
