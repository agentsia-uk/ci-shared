import hashlib
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
