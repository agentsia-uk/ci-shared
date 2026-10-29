import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from code_health.release_attestation import GH_EXECUTABLE, REPOSITORY_ID, read_command, verify_release

POLICY = 'a' * 40
SIGNER = 'b' * 40


class ReleaseAttestationTests(unittest.TestCase):
    def run_verifier(self, *, immutable=True, commit=POLICY, repository_id=REPOSITORY_ID, fail=None):
        calls = []

        def fake_run(argv):
            calls.append(argv)
            if fail is not None and fail in argv:
                raise subprocess.CalledProcessError(1, argv)
            if argv[1] == 'api' and '/releases/' in argv[2]:
                value = {'immutable': immutable, 'draft': False, 'tag_name': 'code-health-' + POLICY}
            elif argv[1] == 'api':
                value = {'sha': commit}
            elif argv[1] == 'attestation':
                value = [{'verificationResult': {'signature': {'certificate': {'sourceRepositoryIdentifier': repository_id}}}}]
            else:
                value = {}
            return json.dumps(value).encode()

        with patch('code_health.release_attestation.read_command', side_effect=fake_run):
            result = verify_release('asset.tar', policy_commit=POLICY, signer_commit=SIGNER)
        return result, calls

    def test_verifies_immutable_release_asset_and_pinned_workflow(self):
        result, calls = self.run_verifier()
        self.assertEqual(result, 'code-health-' + POLICY)
        self.assertEqual(len(calls), 5)
        self.assertTrue(all(call[0] == GH_EXECUTABLE for call in calls))
        self.assertIn('verify-asset', calls[3])
        self.assertIn('--signer-digest', calls[4])
        self.assertIn(SIGNER, calls[4])
        self.assertIn('--source-digest', calls[4])
        self.assertIn(POLICY, calls[4])

    def test_rejects_untrusted_release_and_failed_crypto(self):
        for kwargs in [{'immutable': False}, {'commit': 'c' * 40}, {'repository_id': '7'}, {'fail': 'verify-asset'}]:
            with self.subTest(kwargs=kwargs), self.assertRaises((ValueError, subprocess.CalledProcessError)):
                self.run_verifier(**kwargs)

    def test_rejects_mutable_commit_references(self):
        with self.assertRaises(ValueError):
            verify_release('asset.tar', policy_commit='main', signer_commit=SIGNER)

    def test_subprocess_output_and_runtime_are_bounded(self):
        self.assertEqual(read_command([sys.executable, '-c', 'print("ok")']), b'ok\n')
        with self.assertRaisesRegex(ValueError, 'exceeds limit'):
            read_command([sys.executable, '-c', 'print("x" * 10000)'], limit=128)
        with self.assertRaises(subprocess.TimeoutExpired):
            read_command([sys.executable, '-c', 'import time; time.sleep(5)'], timeout=0.1)
