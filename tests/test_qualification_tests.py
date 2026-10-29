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
    def run_fixture(self, body):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tests = root / 'tests'
            tests.mkdir()
            (tests / 'test_code_health.py').write_text(
                'import os, unittest\nclass Probe(unittest.TestCase):\n    def test_case(self):\n        ' + body + '\n'
            )
            receipt = root / 'receipt.json'
            script = ('import sys; sys.path.insert(0, sys.argv[1]); '
                      'from pathlib import Path; from code_health.qualification_tests import run_qualification; '
                      'run_qualification("tests", Path(sys.argv[2]), 1, sys.argv[3])')
            result = subprocess.run([sys.executable, '-c', script, str(TRUSTED_ROOT), str(receipt), TEST_HASH],
                                    cwd=root, env={**os.environ, 'PYTHONPATH': ''}, capture_output=True, timeout=20)
            return result.returncode, receipt.exists()

    def test_success_creates_a_completion_receipt(self):
        self.assertEqual(self.run_fixture('self.assertTrue(True)'), (0, True))

    def test_process_exit_zero_does_not_create_a_receipt(self):
        self.assertEqual(self.run_fixture('os._exit(0)'), (0, False))
