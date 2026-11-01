import copy
import hashlib
import json
from pathlib import Path
import unittest

from code_health import readers_lock

ROOT = Path(__file__).resolve().parents[1] / 'code_health'


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def fixture():
    manifest = {'version': '1.6.2', 'languages': {'tsx': {'group': 'all', 'size': 0}},
                'groups': {'all': ['tsx']}, 'platforms': {}}
    payloads = {}
    for platform in readers_lock.PLATFORMS:
        payload = ('fixture-' + platform).encode()
        payloads[platform] = payload
        manifest['platforms'][platform] = {
            'url': 'https://github.com/kreuzberg-dev/tree-sitter-language-pack/releases/download/v1.6.2/parsers-' + platform + '.tar.zst',
            'sha256': hashlib.sha256(payload).hexdigest(), 'size': len(payload)}
    manifest_raw = encoded(manifest)
    lock = {'schemaVersion': 1, 'package': 'tree-sitter-language-pack', 'version': '1.6.2',
            'manifestSha256': hashlib.sha256(manifest_raw).hexdigest(), 'platforms': copy.deepcopy(manifest['platforms'])}
    return lock, manifest, payloads


def verify(lock, manifest, grammars=None):
    return readers_lock.verify_manifest(encoded(lock), encoded(manifest), package_version='1.6.2',
                                        grammars={'tsx'} if grammars is None else grammars)


class ReaderLockTests(unittest.TestCase):
    def test_real_manifest_covers_every_language_of_the_pinned_scanner(self):
        result = readers_lock.verify_selected_manifest((ROOT / 'readers-lock.json').read_bytes(),
                                                       (ROOT / 'readers-upstream.json').read_bytes())
        self.assertEqual('1.6.2', result.version)
        self.assertEqual(readers_lock.PLATFORMS, {item.platform for item in result.archives})
        self.assertIn('tsx', readers_lock.required_grammars())

    def test_dependency_lock_requires_one_exact_reader_version(self):
        self.assertEqual('1.6.2', readers_lock.locked_package_version(b'tree-sitter-language-pack==1.6.2\n'))
        for invalid in [b'', b'tree-sitter-language-pack>=1.6.2\n',
                        b'tree-sitter-language-pack==1.6.2\ntree-sitter-language-pack==1.6.2\n']:
            with self.assertRaises(ValueError):
                readers_lock.locked_package_version(invalid)

    def test_archive_bytes_and_platform_are_bound_to_the_lock(self):
        lock, manifest, payloads = fixture()
        selected = verify(lock, manifest)
        for platform, payload in payloads.items():
            self.assertEqual(payload, readers_lock.verify_archive(payload, lock=selected, platform=platform))
            with self.assertRaises(ValueError):
                readers_lock.verify_archive(payload + b'x', lock=selected, platform=platform)
            with self.assertRaises(ValueError):
                readers_lock.verify_archive(b'x' * len(payload), lock=selected, platform=platform)
        with self.assertRaises(ValueError):
            readers_lock.verify_archive(b'', lock=selected, platform='unknown')

    def test_rehashed_manifest_cannot_hide_a_required_language(self):
        lock, manifest, _ = fixture()
        manifest['languages'].pop('tsx')
        lock['manifestSha256'] = hashlib.sha256(encoded(manifest)).hexdigest()
        with self.assertRaisesRegex(ValueError, 'does not cover'):
            verify(lock, manifest)

    def test_missing_group_membership_and_untrusted_urls_fail(self):
        lock, manifest, _ = fixture()
        manifest['groups']['all'] = []
        lock['manifestSha256'] = hashlib.sha256(encoded(manifest)).hexdigest()
        with self.assertRaisesRegex(ValueError, 'language entry'):
            verify(lock, manifest)
        lock, manifest, _ = fixture()
        platform = 'linux-x86_64'
        lock['platforms'][platform]['url'] = manifest['platforms'][platform]['url'] = 'https://example.invalid/readers'
        lock['manifestSha256'] = hashlib.sha256(encoded(manifest)).hexdigest()
        with self.assertRaisesRegex(ValueError, 'platform differs'):
            verify(lock, manifest)

    def test_corrupt_or_mismatched_manifest_and_duplicate_keys_fail(self):
        lock, manifest, _ = fixture()
        with self.assertRaises(ValueError):
            readers_lock.verify_manifest(encoded(lock), encoded(manifest) + b' ', package_version='1.6.2', grammars={'tsx'})
        with self.assertRaises(ValueError):
            readers_lock.verify_manifest(encoded(lock), encoded(manifest), package_version='1.6.3', grammars={'tsx'})
        with self.assertRaises(ValueError):
            readers_lock.verify_manifest(b'{"schemaVersion":1,"schemaVersion":1}', encoded(manifest),
                                         package_version='1.6.2', grammars={'tsx'})


if __name__ == '__main__':
    unittest.main()
