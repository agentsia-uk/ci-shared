"""Check the real upstream reader archive on a hosted Linux runner."""
import os
from pathlib import Path
import tempfile
import unittest
import urllib.request

from code_health import readers_lock


@unittest.skipUnless(os.environ.get('CODE_HEALTH_READER_INTEGRATION') == '1', 'hosted reader integration only')
class ReaderIntegrationTests(unittest.TestCase):
    def test_real_archive_contains_all_scanner_readers(self):
        import tree_sitter_language_pack as pack

        root = Path(__file__).resolve().parents[1] / 'code_health'
        lock = readers_lock.verify_selected_manifest((root / 'readers-lock.json').read_bytes(),
                                                     (root / 'readers-upstream.json').read_bytes())
        for archive in lock.archives:
            with self.subTest(platform=archive.platform):
                with urllib.request.urlopen(archive.url, timeout=60) as response:
                    data = response.read(readers_lock.MAX_ARCHIVE_BYTES + 1)
                with tempfile.TemporaryDirectory(prefix='verified-readers-') as directory:
                    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        readers_lock.unpack_archive(data, lock=lock, platform=archive.platform, destination_fd=fd)
                    finally:
                        os.close(fd)
                    if archive.platform == 'linux-x86_64':
                        pack.configure(cache_dir=directory)
                        self.assertTrue(readers_lock.required_grammars() <= set(pack.downloaded_languages()))


if __name__ == '__main__':
    unittest.main()
