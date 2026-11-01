import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from code_health.release_attestation import GH_EXECUTABLE, REPOSITORY_ID, CALLER, read_command, verify_local_attestation, verify_release

POLICY = 'a' * 40
SIGNER = 'b' * 40


class ReleaseAttestationTests(unittest.TestCase):
    def run_verifier(self, *, immutable=True, commit=POLICY, repository_id=REPOSITORY_ID, fail=None, version='2.102.0'):
        calls = []

        def fake_run(argv):
            calls.append(argv)
            if fail is not None and fail in argv:
                raise subprocess.CalledProcessError(1, argv)
            if argv[1] == '--version':
                return f'gh version {version} (test)\n'.encode()
            if argv[1] == 'api' and '/releases/' in argv[2]:
                value = {'immutable': immutable, 'draft': False, 'tag_name': 'code-health-' + POLICY}
            elif argv[1] == 'api':
                value = {'sha': commit}
            elif argv[1] == 'attestation':
                value = [{'verificationResult': {'signature': {'certificate': {'sourceRepositoryIdentifier': repository_id, 'buildConfigURI': CALLER, 'buildConfigDigest': POLICY}}}}]
            else:
                value = {}
            return json.dumps(value).encode()

        with patch('code_health.release_attestation.read_command', side_effect=fake_run):
            result = verify_release('asset.tar', policy_commit=POLICY, signer_commit=SIGNER)
        return result, calls

    def test_verifies_immutable_release_asset_and_pinned_workflow(self):
        result, calls = self.run_verifier()
        self.assertEqual(result, 'code-health-' + POLICY)
        self.assertEqual(len(calls), 6)
        self.assertTrue(all(call[0] == GH_EXECUTABLE for call in calls))
        self.assertIn('verify-asset', calls[4])
        self.assertIn('--signer-digest', calls[5])
        self.assertIn(SIGNER, calls[5])
        self.assertIn('--source-digest', calls[5])
        self.assertIn(POLICY, calls[5])

    def test_rejects_untrusted_release_and_failed_crypto(self):
        for kwargs in [{'immutable': False}, {'commit': 'c' * 40}, {'repository_id': '7'}, {'fail': 'verify-asset'},
                       {'version': '2.101.0'}, {'version': 'unknown'}]:
            with self.subTest(kwargs=kwargs), self.assertRaises((ValueError, subprocess.CalledProcessError)):
                self.run_verifier(**kwargs)

    def test_local_attestation_is_bound_to_exact_run_and_attempt(self):
        certificate = {'sourceRepositoryIdentifier': REPOSITORY_ID, 'buildConfigURI': CALLER, 'buildConfigDigest': POLICY, 'buildTrigger': 'push',
                       'runInvocationURI': 'https://github.com/agentsia-uk/ci-shared/actions/runs/12/attempts/2'}
        def command(argv):
            if argv[1] == '--version':
                return b'gh version 2.102.0 (test)\n'
            return json.dumps([{'verificationResult': {'signature': {'certificate': certificate}}}]).encode()
        with patch('code_health.release_attestation.read_command', side_effect=command):
            verify_local_attestation('asset.tar', policy_commit=POLICY, signer_commit=SIGNER, run_id=12, run_attempt=2)
            for altered in ({'runInvocationURI': 'https://github.com/agentsia-uk/ci-shared/actions/runs/12/attempts/1'},
                            {'buildTrigger': 'pull_request'}, {'runInvocationURI': None}):
                original = certificate.copy()
                certificate.update(altered)
                with self.assertRaisesRegex(ValueError, 'run identity'):
                    verify_local_attestation('asset.tar', policy_commit=POLICY, signer_commit=SIGNER, run_id=12, run_attempt=2)
                certificate.clear()
                certificate.update(original)
            certificate['buildConfigURI'] = 'https://github.com/agentsia-uk/ci-shared/.github/workflows/other.yml@refs/heads/main'
            with self.assertRaisesRegex(ValueError, 'calling workflow'):
                verify_local_attestation('asset.tar', policy_commit=POLICY, signer_commit=SIGNER, run_id=12, run_attempt=2)
            certificate['buildConfigURI'] = CALLER
            with self.assertRaisesRegex(ValueError, 'run identity'):
                verify_local_attestation('asset.tar', policy_commit=POLICY, signer_commit=SIGNER, run_id=12)
        prior = {**certificate, 'runInvocationURI': 'https://github.com/agentsia-uk/ci-shared/actions/runs/11/attempts/1'}
        multi = [{'verificationResult': {'signature': {'certificate': item}}} for item in (prior, certificate)]
        with patch('code_health.release_attestation.read_command', return_value=json.dumps(multi).encode()):
            verify_local_attestation('asset.tar', policy_commit=POLICY, signer_commit=SIGNER,
                                     check_version=False, run_id=12, run_attempt=2)

    def test_rejects_mutable_commit_references(self):
        with self.assertRaises(ValueError):
            verify_release('asset.tar', policy_commit='main', signer_commit=SIGNER)

    def test_subprocess_output_and_runtime_are_bounded(self):
        self.assertEqual(read_command([sys.executable, '-c', 'print("ok")']), b'ok\n')
        with self.assertRaisesRegex(ValueError, 'exceeds limit'):
            read_command([sys.executable, '-c', 'print("x" * 10000)'], limit=128)
        with self.assertRaises(subprocess.TimeoutExpired):
            read_command([sys.executable, '-c', 'import time; time.sleep(5)'], timeout=0.1)

    def test_cleanup_wait_is_bounded(self):
        real_popen = subprocess.Popen
        children = []
        def stalled_cleanup(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            original_wait = child.wait
            def wait(timeout=None):
                if timeout == 5:
                    raise subprocess.TimeoutExpired(args[0], timeout)
                return original_wait(timeout=timeout)
            child.wait = wait
            children.append(child)
            return child
        with patch('code_health.release_attestation.subprocess.Popen', side_effect=stalled_cleanup), self.assertRaises(subprocess.TimeoutExpired):
            read_command([sys.executable, '-c', 'print("ok")'])
        self.assertTrue(children[0].stdout.closed)

    def test_read_only_administration_token_is_not_inherited_by_cli(self):
        with patch.dict('os.environ', {'RELEASE_ADMIN_READ_TOKEN': 'test-secret'}):
            result = read_command([sys.executable, '-c', 'import os; print("present" if "RELEASE_ADMIN_READ_TOKEN" in os.environ else "absent")'])
        self.assertEqual(result, b'absent\n')
