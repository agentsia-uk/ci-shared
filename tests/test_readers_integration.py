"""Check the real upstream reader archive on a hosted Linux runner."""
import os
from pathlib import Path
import tempfile
import unittest
import urllib.request

from code_health import readers_lock


@unittest.skipUnless(os.environ.get('CODE_HEALTH_READER_INTEGRATION') == '1', 'hosted reader integration only')
class ReaderIntegrationTests(unittest.TestCase):
    def test_candidate_reader_version_inventory(self):
        item = readers_lock.ReaderArchive('macos-arm64',
            'https://github.com/xberg-io/tree-sitter-language-pack/releases/download/v1.7.0/parsers-macos-arm64.tar.zst',
            '8780758a115f25149e2be1bf1075088efb42d997f44a43fd66c5b3f988f45fa7', 21115268)
        lock = readers_lock.ReaderLock('1.7.0', '', (item,))
        with urllib.request.urlopen(item.url, timeout=60) as response:
            data = response.read(readers_lock.MAX_ARCHIVE_BYTES + 1)
        with tempfile.TemporaryDirectory(prefix='reader-candidate-') as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                files = readers_lock.unpack_archive(data, lock=lock, platform=item.platform, destination_fd=fd)
            finally:
                os.close(fd)
        print('Candidate 1.7.0 includes Mac Nim reader:', 'libtree_sitter_nim.dylib' in files, flush=True)

    def test_real_archive_contains_all_scanner_readers(self):
        import tree_sitter_language_pack as pack

        root = Path(__file__).resolve().parents[1] / 'code_health'
        lock = readers_lock.verify_selected_manifest((root / 'readers-lock.json').read_bytes(),
                                                     (root / 'readers-upstream.json').read_bytes())
        platform_readers = {}
        for archive in lock.archives:
            with self.subTest(platform=archive.platform):
                with urllib.request.urlopen(archive.url, timeout=60) as response:
                    data = response.read(readers_lock.MAX_ARCHIVE_BYTES + 1)
                with tempfile.TemporaryDirectory(prefix='verified-readers-') as directory:
                    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        files = readers_lock.unpack_archive(data, lock=lock, platform=archive.platform, destination_fd=fd)
                    finally:
                        os.close(fd)
                    platform_readers[archive.platform] = {name.rsplit('.', 1)[0] for name in files}
        for platform, names in platform_readers.items():
            with self.subTest(platform=platform), tempfile.TemporaryDirectory(prefix='reader-inventory-') as inventory:
                for name in names:
                    (Path(inventory) / (name + '.so')).touch()
                pack.configure(cache_dir=inventory)
                missing = readers_lock.required_grammars() - set(pack.downloaded_languages())
                self.assertFalse(missing, f'{platform} is missing scanner readers: {sorted(missing)}')


if __name__ == '__main__':
    unittest.main()
