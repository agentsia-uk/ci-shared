import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TRUSTED_ROOT = Path(__file__).parents[1]
TEST_ID = 'test_code_health.Probe.test_case'
TEST_HASH = hashlib.sha256((TEST_ID + '\n').encode()).hexdigest()


class QualificationReceiptTests(unittest.TestCase):
    def run_fixture(self, body, expected_hash=TEST_HASH):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tests = root / 'tests'
            tests.mkdir()
            test_file = tests / 'test_code_health.py'
            test_file.write_text(
                'import os, unittest\nclass Probe(unittest.TestCase):\n    def test_case(self):\n        ' + body + '\n'
            )
            file_hash = hashlib.sha256(test_file.read_bytes()).hexdigest()
            receipt = root / 'receipt.json'
            script = ('import sys; sys.path.insert(0, sys.argv[1]); '
                      'from pathlib import Path; from code_health.qualification_tests import run_qualification; '
                      'run_qualification("tests", Path(sys.argv[2]), 1, sys.argv[3], sys.argv[4])')
            result = subprocess.run([sys.executable, '-c', script, str(TRUSTED_ROOT), str(receipt), expected_hash, file_hash],
                                    cwd=root, env={**os.environ, 'PYTHONPATH': ''}, capture_output=True, timeout=20)
            return result.returncode, receipt.exists()

    def test_success_creates_a_completion_receipt(self):
        self.assertEqual(self.run_fixture('self.assertTrue(True)'), (0, True))

    def test_process_exit_zero_does_not_create_a_receipt(self):
        self.assertEqual(self.run_fixture('os._exit(0)'), (0, False))

    def test_changed_test_inventory_is_refused_without_receipt(self):
        code, receipt = self.run_fixture('self.assertTrue(True)', expected_hash='0' * 64)
        self.assertNotEqual(code, 0)
        self.assertFalse(receipt)

    def test_skipped_qualification_is_not_success(self):
        code, receipt = self.run_fixture('self.skipTest("not available")')
        self.assertNotEqual(code, 0)
        self.assertFalse(receipt)

    def test_changed_pinned_test_bytes_do_not_create_a_receipt(self):
        code, receipt = self.run_fixture('open(__file__, "a").write("# changed\\n")')
        self.assertNotEqual(code, 0)
        self.assertFalse(receipt)

    def test_installed_package_cannot_replace_the_bundled_policy(self):
        self.check_installed_package(regular=True)

    def test_installed_namespace_cannot_supply_missing_modules(self):
        self.check_installed_package(regular=False)

    def check_installed_package(self, *, regular):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / 'candidate'
            (candidate / 'code_health').mkdir(parents=True)
            cli = candidate / 'code_health/cli.py'
            cli.write_text('value = "candidate"\n')
            tests = candidate / 'tests'
            tests.mkdir()
            test_file = tests / 'test_code_health.py'
            test_file.write_text('import unittest\nclass Probe(unittest.TestCase):\n    def test_case(self):\n        self.assertTrue(True)\n')
            installed = root / 'installed/code_health'
            installed.mkdir(parents=True)
            if regular:
                (installed / '__init__.py').write_text('')
            (installed / 'cli.py').write_text('value = "installed"\n')
            script = ('import importlib.util, sys; from pathlib import Path; '
                      's=importlib.util.spec_from_file_location("trusted_qualifier", sys.argv[1]); '
                      'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); '
                      'm.run_qualification("tests", Path(sys.argv[2]), 1, sys.argv[3], sys.argv[4], sys.argv[5])')
            receipt = root / 'receipt.json'
            result = subprocess.run([sys.executable, '-c', script, str(TRUSTED_ROOT / 'code_health/qualification_tests.py'),
                                     str(receipt), TEST_HASH, hashlib.sha256(test_file.read_bytes()).hexdigest(),
                                     hashlib.sha256(cli.read_bytes()).hexdigest()], cwd=candidate,
                                    env={**os.environ, 'PYTHONPATH': str(installed.parent)}, capture_output=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'candidate qualification requires isolated execution', result.stderr)
            self.assertFalse(receipt.exists())

    def test_candidate_cannot_forge_test_completion_in_trusted_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'code_health').mkdir()
            (root / 'code_health/__init__.py').write_text('')
            cli = root / 'code_health/cli.py'
            cli.write_text('import unittest\nclass Forged:\n testsRun=1\n skipped=[]\n expectedFailures=[]\n def wasSuccessful(self): return True\nunittest.TextTestRunner.run=lambda self,suite: Forged()\n')
            tests = root / 'tests'
            tests.mkdir()
            test_file = tests / 'test_code_health.py'
            test_file.write_text('import unittest\nclass Probe(unittest.TestCase):\n def test_case(self): self.fail("must execute")\n')
            receipt = root / 'receipt.json'
            script = ('import importlib.util,sys; from pathlib import Path; '
                      's=importlib.util.spec_from_file_location("trusted_qualifier",sys.argv[1]); '
                      'm=importlib.util.module_from_spec(s);s.loader.exec_module(m); '
                      'm.run_qualification("tests",Path(sys.argv[2]),1,sys.argv[3],sys.argv[4],sys.argv[5])')
            result = subprocess.run([sys.executable, '-c', script, str(TRUSTED_ROOT / 'code_health/qualification_tests.py'),
                                     str(receipt), TEST_HASH, hashlib.sha256(test_file.read_bytes()).hexdigest(),
                                     hashlib.sha256(cli.read_bytes()).hexdigest()], cwd=root,
                                    env={**os.environ, 'PYTHONPATH': ''}, capture_output=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(receipt.exists())
