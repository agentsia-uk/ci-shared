"""Check the real upstream reader archive on a hosted Linux runner."""
import os
import ctypes
from pathlib import Path
import platform as system_platform
import subprocess
import sys
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
                    if archive.platform == 'linux-' + system_platform.machine():
                        ctypes.CDLL('libstdc++.so.6', mode=ctypes.RTLD_GLOBAL)
                        pack.configure(cache_dir=directory)
                        os.chmod(directory, 0o500)
                        try:
                            for language in sorted(readers_lock.required_grammars()):
                                try:
                                    self.assertIsNotNone(pack.get_parser(language).parse(b''))
                                except Exception as error:
                                    try:
                                        ctypes.CDLL(str(Path(directory) / f'libtree_sitter_{language}.so'))
                                    except OSError as load_error:
                                        raise AssertionError(f'{language} library failed to load: {load_error}') from error
                                    raise
                            program = ('import sys; sys.path.insert(0,sys.argv.pop(1)); '
                                       'from code_health import scanner_entrypoint as entry; '
                                       'entry.READER_DIR=sys.argv.pop(1); sys.argv=["desloppify","--help"]; '
                                       'entry.main()')
                            subprocess.run([sys.executable, '-I', '-c', program, str(repo), directory], check=True,
                                           env={'PATH': os.defpath, 'HOME': directory}, stdout=subprocess.DEVNULL,
                                           stderr=subprocess.PIPE, timeout=60)
                        finally:
                            os.chmod(directory, 0o700)
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
