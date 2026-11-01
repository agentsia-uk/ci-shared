"""Check the real upstream reader archive on a hosted Linux runner."""
import os
from pathlib import Path
import tempfile
import unittest

from code_health import readers_lock
from code_health.build_release_bundle import download_reader_archives


@unittest.skipUnless(os.environ.get('CODE_HEALTH_READER_INTEGRATION') == '1', 'hosted reader integration only')
class ReaderIntegrationTests(unittest.TestCase):
    def test_real_archive_contains_all_scanner_readers(self):
        import tree_sitter_language_pack as pack

        root = Path(__file__).resolve().parents[1] / 'code_health'
        lock = readers_lock.verify_selected_manifest((root / 'readers-lock.json').read_bytes(),
                                                     (root / 'readers-upstream.json').read_bytes())
        platform_readers = {}
        archives = download_reader_archives(lock)
        for archive in lock.archives:
            with self.subTest(platform=archive.platform):
                with tempfile.TemporaryDirectory(prefix='verified-readers-') as directory:
                    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        files = readers_lock.unpack_archive(archives[archive.platform], lock=lock,
                                                            platform=archive.platform, destination_fd=fd)
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
