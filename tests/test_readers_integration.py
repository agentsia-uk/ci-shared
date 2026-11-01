"""Check the real upstream reader archive on a hosted Linux runner."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from code_health import readers_lock
from code_health.build_release_bundle import build_bundle, runtime_files
from code_health.release_bundle import read_bundle


@unittest.skipUnless(os.environ.get('CODE_HEALTH_READER_INTEGRATION') == '1', 'hosted reader integration only')
class ReaderIntegrationTests(unittest.TestCase):
    def test_real_archive_contains_all_scanner_readers(self):
        import tree_sitter_language_pack as pack

        repo = Path(__file__).resolve().parents[1]
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
        allowed_files = runtime_files(repo, commit)
        bundle = build_bundle(repo, commit, allowed_files, download_readers=True)
        _, files, _ = read_bundle(bundle, policy_commit=commit, allowed_files=allowed_files)
        lock = readers_lock.verify_selected_manifest(files['code_health/readers-lock.json'],
                                                     files['code_health/readers-upstream.json'])
        platform_readers = {}
        for archive in lock.archives:
            with self.subTest(platform=archive.platform):
                with tempfile.TemporaryDirectory(prefix='verified-readers-') as directory:
                    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        unpacked = readers_lock.unpack_archive(files[readers_lock.ASSET_NAMES[archive.platform]],
                                                               lock=lock, platform=archive.platform, destination_fd=fd)
                    finally:
                        os.close(fd)
                    platform_readers[archive.platform] = {name.rsplit('.', 1)[0] for name in unpacked}
        for platform, names in platform_readers.items():
            with self.subTest(platform=platform), tempfile.TemporaryDirectory(prefix='reader-inventory-') as inventory:
                for name in names:
                    (Path(inventory) / (name + '.so')).touch()
                pack.configure(cache_dir=inventory)
                missing = readers_lock.required_grammars() - set(pack.downloaded_languages())
                self.assertFalse(missing, f'{platform} is missing scanner readers: {sorted(missing)}')


if __name__ == '__main__':
    unittest.main()
