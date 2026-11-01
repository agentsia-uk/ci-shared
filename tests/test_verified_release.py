import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from code_health.verified_release import load_verified_release
from code_health.release_bundle import read_bundle
from test_release_bundle import COMMIT, archive

SIGNER = 'b' * 40
ALLOWED = {'code_health/cli.py', 'code_health/requirements.lock', 'code_health/policy.json'}


class VerifiedReleaseTests(unittest.TestCase):
    def test_rejects_non_regular_and_symbolic_link_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            target = root / 'target'
            target.write_bytes(b'data')
            link = root / 'link'
            link.symlink_to(target)
            program = '''import sys
from code_health.verified_release import load_verified_release
try:
    load_verified_release(sys.argv[1], policy_commit="a"*40, signer_commit="b"*40, allowed_files=set())
except (OSError, ValueError):
    sys.exit(0)
sys.exit(1)
'''
            for asset in (fifo, link):
                with self.subTest(asset=asset):
                    result = subprocess.run([sys.executable, '-c', program, str(asset)], timeout=5, check=False)
                    self.assertEqual(result.returncode, 0)

    def test_verification_precedes_parsing_and_evidence_is_derived(self):
        with tempfile.TemporaryDirectory() as tmp:
            asset = Path(tmp) / 'download.tar'
            archive(asset)
            original_digest = hashlib.sha256(asset.read_bytes()).hexdigest()
            def verify(frozen, **kwargs):
                self.assertEqual(frozen.name, 'policy-bundle.tar')
                self.assertEqual(frozen.read_bytes(), asset.read_bytes())
                self.assertEqual(kwargs, {'policy_commit': COMMIT, 'signer_commit': SIGNER})
                return 'code-health-' + COMMIT
            with patch('code_health.verified_release.verify_release', side_effect=verify), \
                 patch('code_health.verified_release.read_bundle', wraps=read_bundle) as parse:
                files, evidence = load_verified_release(asset, policy_commit=COMMIT, signer_commit=SIGNER, allowed_files=ALLOWED)
            self.assertIsInstance(parse.call_args.args[0], bytes)
            self.assertEqual(files['code_health/cli.py'], b'policy')
            self.assertEqual(evidence['bundleSha256'], original_digest)
            self.assertEqual(evidence['qualificationWorkflowSha'], SIGNER)
            self.assertEqual(evidence['requirementsLockSha256'], hashlib.sha256(files['code_health/requirements.lock']).hexdigest())

    def test_refuses_asset_changed_during_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            asset = Path(tmp) / 'download.tar'
            archive(asset)
            def replace(frozen, **kwargs):
                frozen.write_bytes(b'changed')
                return 'code-health-' + COMMIT
            with patch('code_health.verified_release.verify_release', side_effect=replace):
                with self.assertRaisesRegex(ValueError, 'changed during verification'):
                    load_verified_release(asset, policy_commit=COMMIT, signer_commit=SIGNER, allowed_files=ALLOWED)
