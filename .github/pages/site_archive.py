"""Validate a bounded official Pages tar as data; never extract or execute it."""
from pathlib import Path
import tarfile

class Refused(ValueError): pass

def require(condition, reason):
    if not condition: raise Refused(reason)

def validate(path, cname, maximum_bytes=512*1024**2, maximum_members=10000):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= maximum_bytes, 'site archive size')
    seen = set(); files = set(); directories = set(); total = 0; count = 0; found_cname = None; found_index = False
    try:
        with tarfile.open(path, 'r|') as archive:
            for member in archive:
                count += 1
                require(count <= maximum_members, 'site member count')
                raw = member.name
                if raw in {'.', './'} and member.isdir(): continue
                name = raw[2:] if raw.startswith('./') else raw
                name = name.rstrip('/') if member.isdir() else name
                parts = name.split('/')
                require(name and len(name) <= 1024 and all(p and p not in {'.', '..'} and len(p) <= 240 for p in parts) and not name.startswith('/') and ':' not in name and '\\' not in name and all(ord(c) >= 32 for c in name), 'unsafe site path')
                require(member.isfile() or member.isdir(), 'site link or special file')
                key = name.casefold()
                require(key not in seen, 'duplicate site path'); seen.add(key)
                parents = {'/'.join(parts[:n]).casefold() for n in range(1,len(parts))}
                require(not parents & files, 'site file parent conflict')
                directories.update(parents)
                require(len(directories | files) <= maximum_members, 'site namespace bound')
                if member.isdir():
                    require(key not in files, 'site directory conflict'); directories.add(key); continue
                require(key not in directories, 'site file directory conflict')
                files.add(key); total += member.size
                require(0 <= member.size <= maximum_bytes and total <= maximum_bytes, 'site expanded size')
                require(len(directories | files) <= maximum_members, 'site namespace bound')
                if name == 'index.html':
                    require(member.size > 0, 'empty site index'); found_index = True
                if name == 'CNAME':
                    require(member.size <= 254, 'site CNAME size')
                    found_cname = archive.extractfile(member).read(255).decode('ascii').strip()
            # tar readers can differ on concatenated archives. Refuse every
            # nonzero trailing byte instead of leaving another payload opaque.
            while trailing := archive.fileobj.read(64*1024):
                require(not any(trailing), 'site trailing payload')
    except (tarfile.TarError, OSError, UnicodeError, ValueError) as error:
        if isinstance(error, Refused): raise
        raise Refused('site archive invalid') from None
    require(found_index, 'site index required')
    require(cname is None or found_cname == cname, 'site CNAME changed')
    return {'files': len(files), 'bytes': total, 'cname': found_cname}
