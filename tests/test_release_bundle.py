import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from code_health.release_bundle import read_bundle

COMMIT = 'a' * 40


def archive(path, *, content=b'policy', name='code_health/cli.py', indexed=None, extra=None, lock_claim=None, policy_version='1.0'):
    digest = hashlib.sha256(content).hexdigest()
    lock = b'locked dependencies'
    lock_digest = hashlib.sha256(lock).hexdigest()
    policy = json.dumps({'desloppifyVersion': policy_version}).encode()
    manifest = {'schemaVersion': 1, 'kind': 'agentsia.code-health.policy-release', 'policyCommitSha': COMMIT,
                'desloppifyVersion': '1.0', 'requirementsLockSha256': lock_claim or lock_digest,
                'files': [{'path': name, 'size': len(content), 'sha256': indexed or digest},
                          {'path': 'code_health/requirements.lock', 'size': len(lock), 'sha256': lock_digest},
                          {'path': 'code_health/policy.json', 'size': len(policy), 'sha256': hashlib.sha256(policy).hexdigest()}]}
    with tarfile.open(path, 'w') as target:
        for filename, data in [('release.json', json.dumps(manifest).encode()), (name, content),
                               ('code_health/requirements.lock', lock), ('code_health/policy.json', policy)] + (extra or []):
            entry = tarfile.TarInfo(filename)
            entry.size = len(data)
            target.addfile(entry, io.BytesIO(data))


class ReleaseBundleTests(unittest.TestCase):
    def test_valid_bundle_is_bound_to_commit_allowlist_and_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'bundle.tar'
            archive(path)
            allowed = {'code_health/cli.py', 'code_health/requirements.lock', 'code_health/policy.json'}
            manifest, files, manifest_hash = read_bundle(path, policy_commit=COMMIT, allowed_files=allowed)
            self.assertEqual(manifest['policyCommitSha'], COMMIT)
            self.assertEqual(len(manifest_hash), 64)
            self.assertEqual(files['code_health/cli.py'], b'policy')
            self.assertEqual(files['code_health/requirements.lock'], b'locked dependencies')
            for commit, allowed in [('c' * 40, allowed), (COMMIT, {'other.py'})]:
                with self.assertRaises(ValueError):
                    read_bundle(path, policy_commit=commit, allowed_files=allowed)

    def test_rejects_tampering_traversal_and_duplicate_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'bundle.tar'
            for kwargs in [{'indexed': '0' * 64}, {'name': '../escape'}, {'extra': [('code_health/cli.py', b'other')]}]:
                archive(path, **kwargs)
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    read_bundle(path, policy_commit=COMMIT, allowed_files={'code_health/cli.py', 'code_health/requirements.lock', 'code_health/policy.json'})

    def test_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'bundle.tar'
            with tarfile.open(path, 'w') as target:
                entry = tarfile.TarInfo('release.json')
                entry.type = tarfile.SYMTYPE
                entry.linkname = '/etc/passwd'
                target.addfile(entry)
            with self.assertRaises(ValueError):
                read_bundle(path, policy_commit=COMMIT, allowed_files=set())

    def test_rejects_duplicate_manifest_fields_and_extended_attributes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'bundle.tar'
            for payload, attributes in [(b'{"schemaVersion":1,"schemaVersion":1}', {}),
                                        (b'{}', {'comment': 'untrusted'})]:
                with self.subTest(attributes=attributes), tarfile.open(path, 'w', format=tarfile.PAX_FORMAT) as target:
                    entry = tarfile.TarInfo('release.json')
                    entry.pax_headers = attributes
                    entry.size = len(payload)
                    target.addfile(entry, io.BytesIO(payload))
                with self.assertRaises(ValueError):
                    read_bundle(path, policy_commit=COMMIT, allowed_files=set())

    def test_rejects_false_dependency_lock_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'bundle.tar'
            archive(path, lock_claim='0' * 64)
            with self.assertRaisesRegex(ValueError, 'dependency lock digest mismatch'):
                read_bundle(path, policy_commit=COMMIT, allowed_files={'code_health/cli.py', 'code_health/requirements.lock', 'code_health/policy.json'})

    def test_rejects_policy_version_claim_that_differs_from_policy_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'bundle.tar'
            archive(path, policy_version='9.9')
            with self.assertRaisesRegex(ValueError, 'policy version mismatch'):
                read_bundle(path, policy_commit=COMMIT, allowed_files={'code_health/cli.py', 'code_health/requirements.lock', 'code_health/policy.json'})
