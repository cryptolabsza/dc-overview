"""Exercise actual site-data validation before any Pages deployment."""
import importlib.util
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / '.github/pages'
sys.path.insert(0, str(HELPERS))
import site_archive as site

class SiteArchiveTest(unittest.TestCase):
    def archive(self, root, entries):
        path = root / 'artifact.tar'
        with tarfile.open(path, 'w') as output:
            for name, data, kind in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.size = len(data) if kind == tarfile.REGTYPE else 0
                member.linkname = '../../escape' if kind in {tarfile.LNKTYPE, tarfile.SYMTYPE} else ''
                output.addfile(member, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        return path

    def test_actual_pages_tar_accepts_root_directory_and_static_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.archive(root, [('.', b'', tarfile.DIRTYPE), ('./index.html', b'<html>ok</html>', tarfile.REGTYPE), ('./CNAME', b'oxiomsystems.com\n', tarfile.REGTYPE)])
            result = site.validate(path, 'oxiomsystems.com')
            self.assertEqual(result['files'], 2)
            self.assertEqual(result['bytes'], 32)

    def test_refuses_links_traversal_absolute_duplicates_and_special_files(self):
        for name, kind in [('../outside', tarfile.REGTYPE), ('/outside', tarfile.REGTYPE), ('./a/../bad', tarfile.REGTYPE), ('a\\bad', tarfile.REGTYPE), ('a:b', tarfile.REGTYPE), ('link', tarfile.SYMTYPE), ('hard', tarfile.LNKTYPE), ('pipe', tarfile.FIFOTYPE), ('index.html', tarfile.REGTYPE)]:
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as directory:
                path = self.archive(Path(directory), [('./index.html', b'ok', tarfile.REGTYPE), (name, b'bad', kind)])
                with self.assertRaises(site.Refused): site.validate(path, None)

    def test_refuses_wrong_cname_missing_index_and_size_overflow(self):
        for entries, cname in [([('index.html', b'ok', tarfile.REGTYPE), ('CNAME', b'other.com', tarfile.REGTYPE)], 'oxiomsystems.com'), ([('a.html', b'ok', tarfile.REGTYPE)], None)]:
            with tempfile.TemporaryDirectory() as directory:
                path = self.archive(Path(directory), entries)
                with self.assertRaises(site.Refused): site.validate(path, cname)
        with tempfile.TemporaryDirectory() as directory:
            path = self.archive(Path(directory), [('index.html', b'too large', tarfile.REGTYPE)])
            with self.assertRaises(site.Refused): site.validate(path, None, maximum_bytes=4)

    def test_refuses_case_collisions_and_file_directory_conflicts(self):
        for names in [('Index.html', 'index.html'), ('a', 'a/b')]:
            with tempfile.TemporaryDirectory() as directory:
                path = self.archive(Path(directory), [('index.html', b'ok', tarfile.REGTYPE)] + [(name,b'x',tarfile.REGTYPE) for name in names])
                with self.assertRaises(site.Refused): site.validate(path, None)

if __name__ == '__main__': unittest.main()
