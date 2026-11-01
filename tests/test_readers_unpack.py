import hashlib
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import zstandard

from code_health import readers_lock


def bundle(entries):
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode='w') as archive:
        for name, content, kind in entries:
            item = tarfile.TarInfo(name)
            if kind == 'link':
                item.type = tarfile.SYMTYPE
                item.linkname = 'elsewhere'
                archive.addfile(item)
            else:
                item.size = len(content)
                archive.addfile(item, io.BytesIO(content))
    return zstandard.ZstdCompressor().compress(tar.getvalue())


def locked(data, platform='linux-x86_64'):
    asset = readers_lock.ReaderArchive(platform, 'unused', hashlib.sha256(data).hexdigest(), len(data))
    return readers_lock.ReaderLock('1.6.2', 'a' * 64, (asset,))


class ReaderUnpackTests(unittest.TestCase):
    def unpack(self, directory, data, *, lock=None, platform='linux-x86_64'):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            return readers_lock.unpack_archive(data, lock=lock or locked(data, platform), platform=platform,
                                               destination_fd=fd)
        finally:
            os.close(fd)

    def test_verified_bundle_extracts_exact_regular_read_only_files(self):
        data = bundle([('./libtree_sitter_tsx.so', b'tsx bytes', 'file'),
                       ('./libtree_sitter_python.so', b'python bytes', 'file')])
        with tempfile.TemporaryDirectory() as directory:
            files = self.unpack(directory, data)
            self.assertEqual({'libtree_sitter_tsx.so', 'libtree_sitter_python.so'}, set(files))
            for name, expected in [('libtree_sitter_tsx.so', b'tsx bytes'), ('libtree_sitter_python.so', b'python bytes')]:
                target = Path(directory) / name
                self.assertEqual(expected, target.read_bytes())
                self.assertEqual(0o400, target.stat().st_mode & 0o777)
                self.assertEqual(hashlib.sha256(expected).hexdigest(), files[name])

    def test_bad_digest_and_nonempty_destination_never_overwrite(self):
        data = bundle([('./libtree_sitter_tsx.so', b'tsx', 'file')])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'approved lock'):
                self.unpack(directory, data + b'x', lock=locked(data))
            sentinel = Path(directory) / 'sentinel'
            sentinel.write_bytes(b'keep')
            with self.assertRaisesRegex(ValueError, 'empty private'):
                self.unpack(directory, data)
            self.assertEqual(b'keep', sentinel.read_bytes())

    def test_refuses_links_traversal_duplicates_and_oversized_entries(self):
        cases = [[('../escape.so', b'bad', 'file')],
                 [('./libtree_sitter_tsx.so', b'', 'link')],
                 [('./libtree_sitter_tsx.so', b'a', 'file'), ('libtree_sitter_tsx.so', b'b', 'file')],
                 [('./libtree_sitter_tsx.so', b'12345', 'file')]]
        for entries in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as directory:
                data = bundle(entries)
                with patch.object(readers_lock, 'MAX_READER_BYTES', 4):
                    with self.assertRaises(ValueError):
                        self.unpack(directory, data)

    def test_wrong_platform_extension_and_unsafe_permissions_fail(self):
        data = bundle([('./libtree_sitter_tsx.so', b'tsx', 'file')])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                self.unpack(directory, data, platform='macos-arm64')
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o755)
            with self.assertRaisesRegex(ValueError, 'empty private'):
                self.unpack(directory, data)


if __name__ == '__main__':
    unittest.main()
