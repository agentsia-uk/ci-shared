"""Check the real upstream reader archive on a hosted Linux runner."""
import os
import io
from pathlib import Path
import tarfile
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
        archive = next(item for item in lock.archives if item.platform == 'linux-x86_64')
        with urllib.request.urlopen(archive.url, timeout=60) as response:
            data = response.read(readers_lock.MAX_ARCHIVE_BYTES + 1)
        readers_lock.verify_archive(data, lock=lock, platform=archive.platform)
        import zstandard
        with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)) as stream:
            with tarfile.open(fileobj=stream, mode='r|') as contents:
                entries = [(item.name, item.size) for item in contents if item.isfile()]
        print('Reader archive files:', len(entries), 'total bytes:', sum(size for _, size in entries),
              'largest:', sorted(entries, key=lambda item: item[1], reverse=True)[:5], flush=True)
        with tempfile.TemporaryDirectory(prefix='verified-readers-') as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                readers_lock.unpack_archive(data, lock=lock, platform=archive.platform, destination_fd=fd)
            finally:
                os.close(fd)
            pack.configure(cache_dir=directory)
            self.assertTrue(readers_lock.required_grammars() <= set(pack.downloaded_languages()))


if __name__ == '__main__':
    unittest.main()
