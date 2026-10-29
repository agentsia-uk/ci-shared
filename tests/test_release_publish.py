import hashlib
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from code_health.release_publish import BOT_ID, publish

COMMIT = 'a' * 40
TAG = 'code-health-' + COMMIT


class ReleasePublishTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.asset = Path(self.directory.name) / 'policy-bundle.tar'
        self.asset.write_bytes(b'qualified bundle')
        self.digest = 'sha256:' + hashlib.sha256(self.asset.read_bytes()).hexdigest()
        self.ref = None
        self.release = None
        self.enabled = True
        self.main_commit = COMMIT
        self.extra_releases = []
        self.commands = []
        self.mutations = []
        self.replace_before_upload = False
        self.replace_before_publish = False

    def valid_draft(self):
        return {'id': 12, 'tag_name': TAG, 'author': {'id': BOT_ID}, 'draft': True, 'immutable': False, 'assets': []}

    def call(self):
        def get(request, timeout):
            url = request.full_url
            if url.endswith('/immutable-releases'):
                self.assertEqual(request.get_header('Authorization'), 'Bearer read-token')
                value = {'enabled': self.enabled}
            elif url.endswith('/branches/main'):
                value = {'commit': {'sha': self.main_commit}}
            elif url.endswith('/git/refs') and request.get_method() == 'POST':
                self.assertEqual(request.get_header('Authorization'), 'Bearer test-token')
                data = json.loads(request.data)
                self.ref = {'ref': data['ref'], 'object': {'type': 'commit', 'sha': data['sha']}}
                value = self.ref
            elif '/git/ref/tags/' in url:
                value = self.ref
            elif '/assets?name=' in url and request.get_method() == 'POST':
                if self.replace_before_upload:
                    self.release = {**self.valid_draft(), 'id': 13}
                    raise urllib.error.HTTPError(url, 404, 'release replaced', {}, None)
                self.mutations.append('upload')
                self.release['assets'] = [{'name': self.asset.name, 'state': 'uploaded', 'size': len(request.data),
                                           'digest': 'sha256:' + hashlib.sha256(request.data).hexdigest()}]
                value = self.release['assets'][0]
            elif url.endswith('/releases/12') and request.get_method() == 'PATCH':
                if self.replace_before_publish:
                    self.release = {**self.valid_draft(), 'id': 13}
                    raise urllib.error.HTTPError(url, 404, 'release replaced', {}, None)
                self.mutations.append('publish')
                self.release['draft'] = False
                self.release['immutable'] = True
                value = self.release
            elif '/assets?' in url:
                value = self.release['assets']
            elif '/releases?' in url:
                value = ([self.release] if self.release else []) + self.extra_releases
            else:
                raise AssertionError(url)
            if value is None:
                raise urllib.error.HTTPError(url, 404, 'missing', {}, None)
            return io.BytesIO(json.dumps(value).encode())

        def command(args):
            self.commands.append(args)
            operation = args[2]
            if operation == 'create':
                self.release = self.valid_draft()
            return b''

        with patch.dict('os.environ', {'GH_TOKEN': 'test-token', 'RELEASE_ADMIN_READ_TOKEN': 'read-token'}), \
             patch('code_health.release_publish.ensure_gh_version'), \
             patch('code_health.release_publish.urllib.request.urlopen', side_effect=get), \
             patch('code_health.release_publish.read_command', side_effect=command):
            publish(self.asset, COMMIT)

    def test_creates_draft_uploads_and_publishes_only_after_checks(self):
        self.call()
        self.assertEqual([c[2] for c in self.commands], ['create', 'verify', 'verify-asset'])
        self.assertEqual(self.mutations, ['upload', 'publish'])
        self.assertTrue(self.release['immutable'])

    def test_resumes_exact_draft_without_replacing_asset(self):
        self.ref = {'ref': 'refs/tags/' + TAG, 'object': {'type': 'commit', 'sha': COMMIT}}
        self.release = self.valid_draft()
        self.release['assets'] = [{'name': self.asset.name, 'state': 'uploaded', 'size': self.asset.stat().st_size, 'digest': self.digest}]
        self.call()
        self.assertEqual([c[2] for c in self.commands], ['verify', 'verify-asset'])
        self.assertEqual(self.mutations, ['publish'])

    def test_recovers_owned_draft_with_missing_tag(self):
        self.release = self.valid_draft()
        self.call()
        self.assertEqual(self.ref['object']['sha'], COMMIT)
        self.assertEqual([c[2] for c in self.commands], ['verify', 'verify-asset'])
        self.assertEqual(self.mutations, ['upload', 'publish'])

    def test_wrong_tag_or_existing_asset_never_publishes(self):
        self.ref = {'ref': 'refs/tags/' + TAG, 'object': {'type': 'commit', 'sha': 'b' * 40}}
        with self.assertRaisesRegex(ValueError, 'different commit'):
            self.call()
        self.assertEqual(self.commands, [])
        self.ref['object']['sha'] = COMMIT
        self.release = self.valid_draft()
        self.release['assets'] = [{'name': self.asset.name, 'state': 'uploaded', 'size': 1, 'digest': 'sha256:' + '0' * 64}]
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.call()
        self.assertEqual(self.commands, [])

    def test_unowned_draft_without_tag_is_never_modified(self):
        self.release = self.valid_draft()
        self.release['author']['id'] = 7
        with self.assertRaisesRegex(ValueError, 'bot-owned'):
            self.call()
        self.assertIsNone(self.ref)
        self.assertEqual(self.commands, [])

    def test_published_release_is_verified_without_mutation(self):
        self.ref = {'ref': 'refs/tags/' + TAG, 'object': {'type': 'commit', 'sha': COMMIT}}
        self.release = self.valid_draft()
        self.release.update(draft=False, immutable=True, assets=[{'name': self.asset.name, 'state': 'uploaded', 'size': self.asset.stat().st_size, 'digest': self.digest}])
        self.call()
        self.assertEqual([c[2] for c in self.commands], ['verify', 'verify-asset'])

    def test_requires_both_separate_credentials(self):
        with patch.dict('os.environ', {'GH_TOKEN': 'test-token'}, clear=True):
            with self.assertRaisesRegex(ValueError, 'administration-read tokens'):
                publish(self.asset, COMMIT)

    def test_mutable_setting_and_duplicate_drafts_are_rejected_before_mutation(self):
        self.enabled = False
        with self.assertRaisesRegex(ValueError, 'not enabled'):
            self.call()
        self.assertEqual(self.commands, [])
        self.enabled = True
        self.ref = {'ref': 'refs/tags/' + TAG, 'object': {'type': 'commit', 'sha': COMMIT}}
        self.release = self.valid_draft()
        self.extra_releases = [self.valid_draft()]
        with self.assertRaisesRegex(ValueError, 'multiple releases'):
            self.call()
        self.assertEqual(self.commands, [])

    def test_replaced_draft_is_not_uploaded_to_or_published(self):
        for phase in ['upload', 'publish']:
            with self.subTest(phase=phase):
                self.ref = {'ref': 'refs/tags/' + TAG, 'object': {'type': 'commit', 'sha': COMMIT}}
                self.release = self.valid_draft()
                self.commands.clear()
                self.mutations.clear()
                self.replace_before_upload = phase == 'upload'
                self.replace_before_publish = phase == 'publish'
                with self.assertRaises(urllib.error.HTTPError):
                    self.call()
                self.assertEqual(self.release['id'], 13)
                self.assertTrue(self.release['draft'])
                self.assertNotIn('publish', self.mutations)

    def test_stale_main_refuses_to_create_tag_or_release(self):
        self.main_commit = 'b' * 40
        with self.assertRaisesRegex(ValueError, 'main moved'):
            self.call()
        self.assertIsNone(self.ref)
        self.assertEqual(self.commands, [])
        self.assertEqual(self.mutations, [])
