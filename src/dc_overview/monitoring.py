"""Small ownership and preservation helpers for customer monitoring resources."""
from __future__ import annotations

import copy
import fcntl
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Callable, Optional
from urllib.parse import urlsplit

import yaml

CUSTOMER_NAMESPACE = '/etc/prometheus/customer'
PRODUCT_JOB_NAMES = frozenset({'prometheus', 'dc-managed', 'vastai', 'runpod', 'ipmi-monitor',
    'cadvisor', 'node-exporter', 'grafana', 'dc-overview'})
_INLINE_SECRETS = frozenset({'password', 'bearer_token', 'credentials', 'client_secret'})
_FILE_REFERENCES = frozenset({'password_file', 'bearer_token_file', 'credentials_file',
    'client_secret_file', 'ca_file', 'cert_file', 'key_file'})
_UNSPECIFIED_PREVIOUS = object()


def validate_product_monitoring_custody(directory):
    """Refuse incompatible existing product custody without adopting customer files."""
    directory = Path(directory)
    if any(path.is_symlink() for path in (directory, *directory.parents)):
        raise ValueError('product monitoring directory cannot traverse a symlink')
    if not directory.exists():
        return
    metadata = directory.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    if not directory.is_dir() or metadata.st_uid != 1000 or mode & 0o705 != 0o705:
        raise ValueError('existing product monitoring directory requires DC UID 1000 write custody and public traversal; no ownership changes applied')
    for name in ('prometheus.yml', 'recording_rules.yml', 'prometheus.yml.lock'):
        path = directory / name
        if path.is_symlink():
            raise ValueError('product monitoring file cannot be a symlink')
        if not path.exists():
            continue
        metadata = path.stat()
        mode = stat.S_IMODE(metadata.st_mode)
        required = 0o600 if name.endswith('.lock') else 0o604
        replacement_group = name.endswith('.lock') or metadata.st_gid == 1000
        if not path.is_file() or metadata.st_uid != 1000 or not replacement_group or mode & required != required:
            raise ValueError('existing product monitoring file requires DC UID 1000 custody and supported access; no ownership changes applied')


def validate_customer_directory(value: str) -> Path:
    """Validate an existing declared mount directory without reading secrets."""
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts or path.is_symlink() or not path.is_dir():
        raise ValueError('customer directory must be an existing absolute nonsymlink directory')
    if any(parent.is_symlink() for parent in path.parents):
        raise ValueError('customer directory cannot traverse a symlink')
    return path


def _reference(value, allowed=()):
    if not isinstance(value, str) or not value.startswith('/') or '..' in PurePosixPath(value).parts or any(char in value for char in '\x00\r\n'):
        raise ValueError('monitoring file reference must be a safe absolute path')
    if not value.startswith(CUSTOMER_NAMESPACE + '/') and value not in allowed:
        raise ValueError('monitoring file reference requires customer namespace or explicit adoption')


def _validate_references(value, allowed=(), parent=''):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == 'http_headers':
                if not isinstance(item, dict):
                    raise ValueError('monitoring header credentials require file references')
                for header in item.values():
                    if not isinstance(header, dict) or set(header) - {'files'} or not isinstance(header.get('files'), list):
                        raise ValueError('monitoring header credentials require file references, never inline values')
                    for reference in header['files']:
                        _reference(reference, allowed)
            if key in _INLINE_SECRETS:
                raise ValueError('monitoring credentials must use file references, never inline values')
            if key in _FILE_REFERENCES:
                _reference(item, allowed)
            elif key == 'files' and parent == 'file_sd_configs':
                for reference in item:
                    _reference(reference, allowed)
            elif key in {'url', 'proxy_url'} and isinstance(item, str):
                parsed = urlsplit(item)
                if parsed.username is not None or parsed.password is not None:
                    raise ValueError('monitoring URLs cannot contain embedded credentials')
            _validate_references(item, allowed, key)
    elif isinstance(value, list):
        for item in value:
            _validate_references(item, allowed, parent)


def _jobs(value):
    if not isinstance(value, list):
        raise ValueError('scrape_configs must be a list')
    names = set()
    for row in value:
        if not isinstance(row, dict) or not isinstance(row.get('job_name'), str) or not row['job_name'].strip():
            raise ValueError('each monitoring job requires a nonempty job_name')
        if row['job_name'] in names:
            raise ValueError('duplicate monitoring job name')
        names.add(row['job_name'])
    return names


def _check_endpoints(jobs):
    seen = set()
    for row in jobs:
        # Relabeling can change address/path/scheme; only claim duplicates for
        # static configurations whose effective scrape identity is known here.
        if row.get('relabel_configs'):
            continue
        scheme = row.get('scheme', 'http')
        path = row.get('metrics_path', '/metrics')
        params = json.dumps(row.get('params', {}), sort_keys=True)
        for group in row.get('static_configs', []):
            for target in group.get('targets', []):
                try:
                    parsed = urlsplit('//' + target)
                    if not parsed.hostname or parsed.username is not None or parsed.path:
                        raise ValueError('target')
                    host = parsed.hostname.lower()
                    port = parsed.port or (443 if scheme == 'https' else 80)
                except (TypeError, ValueError):
                    raise ValueError('invalid monitoring endpoint') from None
                identity = (scheme, host, port, path, params)
                if identity in seen:
                    raise ValueError('duplicate known monitoring endpoint scrape')
                seen.add(identity)



def validate_known_discovery_targets(config, targets):
    """Reject static duplicates with explicitly known inventory endpoint data."""
    rows = [row for row in config.get('scrape_configs', []) if row.get('job_name') != 'dc-managed']
    rows = copy.deepcopy(rows) + [{'job_name':'dc-managed', 'static_configs':copy.deepcopy(targets)}]
    _check_endpoints(rows)
    return True

def merge_prometheus_config(existing, generated, extra_scrape_configs=(), rule_files=(),
                             legacy_managed_jobs=(), *, adopted_file_references=()):
    """Replace declared product jobs, preserving all other customer resources.

    Extra jobs repeated unchanged are idempotent. A different existing job with
    the same name is a collision unless explicitly declared a retired legacy
    owner. No hostname or missing-inventory heuristic establishes ownership.
    """
    existing = copy.deepcopy(existing or {})
    generated = copy.deepcopy(generated)
    if not isinstance(existing, dict) or not isinstance(generated, dict):
        raise ValueError('Prometheus configuration must be a mapping')
    old_jobs = existing.get('scrape_configs', [])
    new_jobs = generated.get('scrape_configs', [])
    extra = copy.deepcopy(list(extra_scrape_configs))
    _jobs(old_jobs)
    product_names = _jobs(new_jobs)
    extra_names = _jobs(extra)
    if extra_names & (PRODUCT_JOB_NAMES | product_names):
        raise ValueError('customer job name collides with a reserved product job')
    legacy = set(legacy_managed_jobs)
    if any(not isinstance(name, str) or not name.strip() for name in legacy):
        raise ValueError('legacy managed jobs must declare exact job names')
    retained = [row for row in old_jobs if row['job_name'] not in product_names | legacy]
    by_name = {row['job_name']: row for row in retained}
    for row in extra:
        prior = by_name.get(row['job_name'])
        if prior is not None and prior != row:
            raise ValueError('customer job name collides with an existing job; explicit adoption required')
    result = copy.deepcopy(generated)
    result.update(existing)
    for key, default in generated.items():
        if key not in result:
            result[key] = copy.deepcopy(default)
    if 'global' in generated or 'global' in existing:
        result['global'] = {**generated.get('global', {}), **existing.get('global', {})}
    # Stable order matters for repeat configuration and effective-config proof.
    result['scrape_configs'] = [row for row in retained if row['job_name'] not in extra_names] + new_jobs + extra
    _jobs(result['scrape_configs'])
    _check_endpoints(result['scrape_configs'])
    rules = list(dict.fromkeys(existing.get('rule_files', []) + generated.get('rule_files', []) + list(rule_files)))
    allowed = tuple(adopted_file_references) + tuple(generated.get('rule_files', []))
    for reference in rules:
        _reference(reference, allowed)
    if rules or 'rule_files' in result:
        result['rule_files'] = rules
    _validate_references(result, allowed)
    return result


@contextmanager
def _file_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_name(path.name + '.lock')
    if lock.is_symlink():
        raise ValueError('monitoring lock cannot be a symlink')
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        descriptor = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
    else:
        try:
            if path.exists():
                metadata = path.stat()
                current = os.fstat(descriptor)
                if (current.st_uid, current.st_gid) != (metadata.st_uid, metadata.st_gid):
                    os.fchown(descriptor, metadata.st_uid, metadata.st_gid)
        except BaseException:
            os.close(descriptor)
            raise
    with os.fdopen(descriptor, 'a+b') as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def atomic_write_bytes(path, payload: bytes, *, new_owner=None):
    """Replace complete bytes atomically, retaining prior ownership and mode."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError('monitoring file cannot be a symlink')
    path.parent.mkdir(parents=True, exist_ok=True)
    metadata = path.stat() if path.exists() else None
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    candidate = Path(temporary)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            if metadata is not None:
                os.fchmod(handle.fileno(), stat.S_IMODE(metadata.st_mode))
                current = os.fstat(handle.fileno())
                if (current.st_uid, current.st_gid) != (metadata.st_uid, metadata.st_gid):
                    os.fchown(handle.fileno(), metadata.st_uid, metadata.st_gid)
            else:
                # Public Prometheus configuration has no inline secrets and
                # must be readable by the selected image's non-root UID.
                os.fchmod(handle.fileno(), 0o644)
                if new_owner is not None:
                    os.fchown(handle.fileno(), *new_owner)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(candidate, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        candidate.unlink(missing_ok=True)


_DURATION_PATTERN = re.compile(r'(?:(\d+)y)?(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?(?:(\d+)ms)?')
_DURATION_MS = (365*24*60*60*1000, 7*24*60*60*1000, 24*60*60*1000, 60*60*1000, 60*1000, 1000, 1)


def _prometheus_duration(value):
    # Prometheus common/model.ParseDuration: ordered integer y,w,d,h,m,s,ms
    # units (365-day years), plus unitless zero. No arbitrary string coercion.
    if value == '0' or (type(value) is int and value == 0):
        return 0
    if not isinstance(value, str) or not value:
        return None
    match = _DURATION_PATTERN.fullmatch(value)
    if not match or not any(part is not None for part in match.groups()):
        return None
    result = sum(int(part or 0)*scale for part, scale in zip(match.groups(), _DURATION_MS))
    return result if result <= (2**63-1)//1000000 else None


def _duration_field(path):
    # Only schema locations supported by this verifier, never label/URL/file
    # strings that happen to have a duration field's spelling.
    if len(path) == 2 and path[0] == 'global':
        return path[1] in {'scrape_interval', 'scrape_timeout', 'evaluation_interval', 'rule_query_offset'}
    if len(path) == 3 and path[:2] == ('scrape_configs', '*'):
        return path[2] in {'scrape_interval', 'scrape_timeout'}
    if len(path) == 5 and path[:2] == ('scrape_configs', '*') and path[3] == '*':
        return path[2] in {'http_sd_configs', 'file_sd_configs', 'dns_sd_configs'} and path[4] == 'refresh_interval'
    return False


def declared_configuration_matches(expected, loaded, *, _path=()):
    """Allow server defaults while proving every declared value and list member."""
    if isinstance(expected, dict):
        return isinstance(loaded, dict) and all(key in loaded and declared_configuration_matches(value, loaded[key], _path=_path+(key,)) for key, value in expected.items())
    if isinstance(expected, list):
        return isinstance(loaded, list) and len(expected) == len(loaded) and all(declared_configuration_matches(a, b, _path=_path+('*',)) for a, b in zip(expected, loaded))
    if _duration_field(_path):
        duration = _prometheus_duration(expected)
        return duration is not None and duration == _prometheus_duration(loaded)
    return expected == loaded


def apply_prometheus_config(path, config, *, validate_candidate: Callable, reload_config: Callable,
                            expected_previous_bytes=_UNSPECIFIED_PREVIOUS):
    """Require real candidate/reload proof; failed reload restores original bytes.

    Host installers validate through their selected promtool artifact. A web
    writer can use server reload validation, but must verify the effective loaded
    candidate. Callbacks must return exactly True, not a subprocess/mock object.
    """
    path = Path(path)
    payload = yaml.safe_dump(config, sort_keys=False).encode()
    with _file_lock(path):
        before = path.read_bytes() if path.exists() else None
        if expected_previous_bytes is not _UNSPECIFIED_PREVIOUS and before != expected_previous_bytes:
            raise RuntimeError('Prometheus configuration changed after preparation; replan before replacement')
        descriptor, temporary = tempfile.mkstemp(prefix='.prometheus-candidate-', suffix='.yml', dir=path.parent)
        candidate = Path(temporary)
        try:
            with os.fdopen(descriptor, 'wb') as handle:
                handle.write(payload)
            try:
                valid = validate_candidate(candidate) is True
            except Exception:
                valid = False
            if not valid:
                raise RuntimeError('Prometheus candidate validation failed; previous file retained')
        finally:
            candidate.unlink(missing_ok=True)
        current = path.read_bytes() if path.exists() else None
        if current != before:
            raise RuntimeError('Prometheus configuration changed during validation; replan before replacement')
        atomic_write_bytes(path, payload)
        try:
            accepted = reload_config() is True
        except Exception:
            accepted = False
        current = path.read_bytes() if path.exists() else None
        if current != payload:
            raise RuntimeError('Prometheus configuration conflict during reload; customer bytes retained, runtime requires forward reconciliation')
        if accepted:
            return True
        if before is None:
            path.unlink(missing_ok=True)
        else:
            atomic_write_bytes(path, before)
        try:
            restored = reload_config() is True
        except Exception:
            restored = False
        if (path.read_bytes() if path.exists() else None) != before:
            raise RuntimeError('Prometheus configuration conflict during recovery reload; customer bytes retained, runtime requires forward reconciliation')
        if not restored:
            raise RuntimeError('Prometheus reload failed; previous bytes restored but runtime recovery is unverified')
        raise RuntimeError('Prometheus reload failed; previous configuration restored and reloaded')


def select_prometheus_datasource(datasources, explicit_uid: Optional[str] = None):
    uids = [row.get('uid') for row in datasources]
    if any(not isinstance(uid, str) or not uid for uid in uids) or len(set(uids)) != len(uids):
        raise ValueError('datasource UID is missing or duplicated')
    candidates = [row for row in datasources if row.get('type') == 'prometheus']
    if explicit_uid:
        if sum(row.get('uid') == explicit_uid for row in candidates) != 1:
            raise ValueError('declared Prometheus datasource UID is unavailable or duplicated')
        return explicit_uid
    defaults = [row for row in candidates if row.get('isDefault') is True]
    selected = defaults if defaults else candidates
    if len(selected) != 1 or not isinstance(selected[0].get('uid'), str) or not selected[0]['uid']:
        raise ValueError('Prometheus datasource identity is missing or ambiguous; declare a stable UID')
    return selected[0]['uid']


def load_customer_dashboards(directory):
    path = validate_customer_directory(directory)
    dashboards = []
    for source in sorted(path.glob('*.json')):
        if source.is_symlink():
            raise ValueError('customer dashboard file cannot be a symlink')
        if not source.is_file() or source.stat().st_size > 10 * 1024 * 1024:
            raise ValueError('customer dashboard file is invalid or oversized')
        try:
            dashboard = json.loads(source.read_text())
        except (ValueError, UnicodeError):
            raise ValueError('customer dashboard JSON is invalid') from None
        if isinstance(dashboard, dict) and 'dashboard' in dashboard:
            dashboard = dashboard['dashboard']
        dashboards.append(dashboard)
    return dashboards


def _dashboard_uids(dashboards):
    found = set()
    for row in dashboards:
        if not isinstance(row, dict) or not isinstance(row.get('uid'), str) or not row['uid']:
            raise ValueError('dashboard requires a stable UID')
        if row['uid'] in found:
            raise ValueError('duplicate dashboard UID')
        found.add(row['uid'])
    return found


def _product_datasource(value, uid):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == 'datasource':
                if item in ('${DS_PROMETHEUS}', '${datasource}', 'Prometheus', 'prometheus'):
                    value[key] = {'type': 'prometheus', 'uid': uid}
                elif isinstance(item, dict) and item.get('type') == 'prometheus' and item.get('uid') in ('${DS_PROMETHEUS}', '${datasource}', 'prometheus'):
                    item['uid'] = uid
            else:
                _product_datasource(item, uid)
    elif isinstance(value, list):
        for item in value:
            _product_datasource(item, uid)


def prepare_grafana_dashboards(product_dashboards, customer_dashboards, existing_dashboards, *,
                              prometheus_datasource_uid, overwrite_product_dashboards=False):
    """Prepare imports before mutation; customer mapping/edit ownership is stable."""
    if type(overwrite_product_dashboards) is not bool:
        raise ValueError('product overwrite selection must be a boolean')
    if not isinstance(prometheus_datasource_uid, str) or not prometheus_datasource_uid.strip():
        raise ValueError('Prometheus datasource requires a stable UID')
    product_uids = _dashboard_uids(product_dashboards)
    customer_uids = _dashboard_uids(customer_dashboards)
    existing_uids = _dashboard_uids(existing_dashboards)
    if product_uids & customer_uids:
        raise ValueError('customer dashboard UID collides with a product-owned UID')
    payloads, skipped = [], []
    for owned, dashboards in ((True, product_dashboards), (False, customer_dashboards)):
        for source in dashboards:
            uid = source['uid']
            overwrite = owned and overwrite_product_dashboards
            if uid in existing_uids and not overwrite:
                skipped.append(uid)
                continue
            prepared = copy.deepcopy(source)
            if owned or 'id' in prepared:
                prepared['id'] = None
            if owned:
                _product_datasource(prepared, prometheus_datasource_uid)
            payloads.append({'dashboard': prepared, 'overwrite': overwrite, 'folderId': 0})
    return {'payloads': payloads, 'skipped_uids': skipped, 'product_uids': sorted(product_uids),
            'customer_uids': sorted(customer_uids), 'prometheus_datasource_uid': prometheus_datasource_uid}
