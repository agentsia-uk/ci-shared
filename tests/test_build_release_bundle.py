import subprocess
import tempfile
import unittest
from pathlib import Path

from code_health.build_release_bundle import build_bundle
from code_health.release_bundle import read_bundle

FILES = {'code_health/cli.py', 'code_health/policy.json', 'code_health/requirements.lock'}


class BuildReleaseBundleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        subprocess.run(['git', 'config', 'user.name', 'fixture'], cwd=self.root, check=True)
        subprocess.run(['git', 'config', 'user.email', 'fixture@example.test'], cwd=self.root, check=True)
        (self.root / 'code_health').mkdir()
        (self.root / 'code_health/cli.py').write_text('committed')
        (self.root / 'code_health/policy.json').write_text('{"desloppifyVersion":"1.0"}')
        (self.root / 'code_health/requirements.lock').write_text('locked')
        subprocess.run(['git', 'add', '.'], cwd=self.root, check=True)
        subprocess.run(['git', 'commit', '-qm', 'fixture'], cwd=self.root, check=True)
        self.commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()

    def test_deterministic_bundle_reads_committed_bytes(self):
        (self.root / 'code_health/cli.py').write_text('uncommitted')
        data = build_bundle(self.root, self.commit, FILES)
        self.assertEqual(data, build_bundle(self.root, self.commit, FILES))
        manifest, files, _ = read_bundle(data, policy_commit=self.commit, allowed_files=FILES)
        self.assertEqual(files['code_health/cli.py'], b'committed')
        self.assertEqual(manifest['desloppifyVersion'], '1.0')

    def test_rejects_missing_files_and_invalid_refs(self):
        for commit, paths in [(self.commit, FILES | {'code_health/missing.py'}), ('main', FILES),
                              (self.commit, FILES | {'code_health/../outside'})]:
            with self.subTest(commit=commit, paths=paths), self.assertRaises(ValueError):
                build_bundle(self.root, commit, paths)

    def test_rejects_committed_symlink(self):
        (self.root / 'code_health/cli.py').unlink()
        (self.root / 'code_health/cli.py').symlink_to('/etc/passwd')
        subprocess.run(['git', 'add', '.'], cwd=self.root, check=True)
        subprocess.run(['git', 'commit', '-qm', 'symlink'], cwd=self.root, check=True)
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()
        with self.assertRaises(ValueError):
            build_bundle(self.root, commit, FILES)
