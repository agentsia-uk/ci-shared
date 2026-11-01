import hashlib
import io
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from code_health.release_publish import BOT_ID, _publish_verified as publish
import code_health.release_publish as release_publish
from code_health.cli import open_upgrade_api

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
        self.ruleset = {'id': 123, 'source_type': 'Repository', 'source': 'agentsia-uk/ci-shared',
                        'target': 'tag', 'enforcement': 'active', 'bypass_actors': [],
                        'conditions': {'ref_name': {'include': ['refs/tags/code-health-*'], 'exclude': []}},
                        'rules': [{'type': 'update'}, {'type': 'deletion'}]}
        self.main_commit = COMMIT
        self.extra_releases = []
        self.commands = []
        self.mutations = []
        self.replace_before_upload = False
        self.replace_before_publish = False
        self.ruleset_reads = 0
        self.disable_ruleset_before_publish = False

    def valid_draft(self):
        return {'id': 12, 'tag_name': TAG, 'author': {'id': BOT_ID}, 'draft': True, 'immutable': False, 'assets': []}

    def call(self):
        def get(request, timeout):
            url = request.full_url
            if request.get_method() == 'GET':
                self.assertEqual(request.get_header('Cache-control'), 'no-cache')
                url = url.split('&code_health_read=', 1)[0].split('?code_health_read=', 1)[0]
            if url.endswith('/immutable-releases'):
                self.assertEqual(request.get_header('Authorization'), 'Bearer read-token')
                value = {'enabled': self.enabled}
            elif url.endswith('/rulesets/123'):
                self.assertEqual(request.get_header('Authorization'), 'Bearer read-token')
                self.ruleset_reads += 1
                if self.disable_ruleset_before_publish and self.ruleset_reads > 1:
                    self.ruleset['enforcement'] = 'disabled'
                value = self.ruleset
            elif url.endswith('/branches/main'):
                value = {'commit': {'sha': self.main_commit}}
            elif url.endswith('/git/refs') and request.get_method() == 'POST':
                self.assertEqual(request.get_header('Authorization'), 'Bearer test-token')
                self.assertEqual(request.get_header('Content-type'), 'application/json')
                data = json.loads(request.data)
                self.ref = {'ref': data['ref'], 'object': {'type': 'commit', 'sha': data['sha']}}
                value = self.ref
            elif '/git/ref/tags/' in url:
                value = self.ref
            elif '/assets?name=' in url and request.get_method() == 'POST':
                self.assertEqual(request.get_header('Content-type'), 'application/octet-stream')
                if self.replace_before_upload:
                    self.release = {**self.valid_draft(), 'id': 13}
                    raise urllib.error.HTTPError(url, 404, 'release replaced', {}, None)
                self.mutations.append('upload')
                self.release['assets'] = [{'name': self.asset.name, 'state': 'uploaded', 'size': len(request.data),
                                           'digest': 'sha256:' + hashlib.sha256(request.data).hexdigest()}]
                value = self.release['assets'][0]
            elif url.endswith('/releases/12') and request.get_method() == 'PATCH':
                self.assertEqual(request.get_header('Content-type'), 'application/json')
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

        with patch.dict('os.environ', {'GH_TOKEN': 'test-token', 'RELEASE_ADMIN_READ_TOKEN': 'read-token',
                                      'CODE_HEALTH_TAG_RULESET_ID': '123'}), \
             patch('code_health.release_publish.ensure_gh_version'), \
             patch('code_health.release_publish.open_api', side_effect=get), \
             patch('code_health.release_publish.read_command', side_effect=command):
            publish(self.asset, COMMIT)

    def test_publication_requires_matching_bundle_qualification_and_attestation(self):
        qualification = Path(self.directory.name) / 'observations.json'
        qualification.write_bytes(b'observations')
        original = self.asset.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        with patch('code_health.release_publish.candidate_bundle', return_value=(original, {}, digest)), \
             patch('code_health.release_publish.validate_results') as validate, \
             patch('code_health.release_publish.verify_local_attestation') as verify, \
             patch('code_health.release_publish._publish_verified') as publish_verified:
            def run():
                release_publish.publish(self.asset, COMMIT, repo=Path(self.directory.name), qualification=qualification,
                                        run_id=1, run_attempt=1, signer_commit='b' * 40)
            self.asset.write_bytes(b'different')
            with self.assertRaisesRegex(ValueError, 'differs'):
                run()
            publish_verified.assert_not_called()
            self.asset.write_bytes(original)
            validate.side_effect = ValueError('invalid observations')
            with self.assertRaisesRegex(ValueError, 'invalid observations'):
                run()
            publish_verified.assert_not_called()
            validate.side_effect = None
            verify.side_effect = ValueError('invalid attestation')
            with self.assertRaisesRegex(ValueError, 'invalid attestation'):
                run()
            publish_verified.assert_not_called()
            verify.side_effect = lambda *_args, **_kwargs: self.asset.write_bytes(b'changed after verification')
            def check_snapshot(path, commit):
                self.assertEqual(path.read_bytes(), original)
                self.assertEqual(commit, COMMIT)
            publish_verified.side_effect = check_snapshot
            run()
            publish_verified.assert_called_once()
            self.assertEqual((verify.call_args.kwargs['run_id'], verify.call_args.kwargs['run_attempt']), (1, 1))

    def test_publication_refuses_symlinked_inputs(self):
        qualification = Path(self.directory.name) / 'observations.json'
        qualification.write_bytes(b'observations')
        link = Path(self.directory.name) / 'linked'
        link.symlink_to(qualification)
        original = self.asset.read_bytes()
        with patch('code_health.release_publish.candidate_bundle', return_value=(original, {}, hashlib.sha256(original).hexdigest())), \
             patch('code_health.release_publish._publish_verified') as publish_verified:
            with self.assertRaises(OSError):
                release_publish.publish(self.asset, COMMIT, repo=Path(self.directory.name), qualification=link,
                                        run_id=1, run_attempt=1, signer_commit='b' * 40)
            publish_verified.assert_not_called()

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

    def test_unprotected_or_bypassable_tags_are_rejected_before_mutation(self):
        from copy import deepcopy
        original = deepcopy(self.ruleset)
        variants = [
            {'enforcement': 'disabled'},
            {'target': 'branch'},
            {'source': 'agentsia-uk/another'},
            {'bypass_actors': [{'actor_type': 'RepositoryRole', 'actor_id': 5, 'bypass_mode': 'always'}]},
            {'conditions': {'ref_name': {'include': ['refs/tags/*'], 'exclude': []}}},
            {'conditions': {'ref_name': {'include': ['refs/tags/code-health-*'], 'exclude': ['refs/tags/code-health-*']}}},
            {'rules': [{'type': 'update'}]},
        ]
        for variant in variants:
            with self.subTest(variant=variant):
                self.ruleset = {**deepcopy(original), **variant}
                with self.assertRaisesRegex(ValueError, 'tag protection'):
                    self.call()
                self.assertIsNone(self.ref)
                self.assertEqual(self.commands, [])
                self.assertEqual(self.mutations, [])

    def test_protection_removed_after_draft_refuses_publication(self):
        self.disable_ruleset_before_publish = True
        with self.assertRaisesRegex(ValueError, 'tag protection'):
            self.call()
        self.assertEqual(self.mutations, ['upload'])
        self.assertTrue(self.release['draft'])

    def test_authenticated_requests_do_not_follow_redirects(self):
        received = []

        class Destination(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.headers.get('Authorization'))
                self.send_response(200)
                self.end_headers()
            def log_message(self, *_args):
                pass

        destination = ThreadingHTTPServer(('127.0.0.1', 0), Destination)

        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header('Location', f'http://127.0.0.1:{destination.server_port}/capture')
                self.end_headers()
            def log_message(self, *_args):
                pass

        origin = ThreadingHTTPServer(('127.0.0.1', 0), Redirect)
        threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (origin, destination)]
        for thread in threads:
            thread.start()
        try:
            request = urllib.request.Request(f'http://127.0.0.1:{origin.server_port}/',
                                             headers={'Authorization': 'Bearer synthetic-test-token'})
            for opener in (release_publish.open_api, open_upgrade_api):
                with self.subTest(opener=opener.__name__), self.assertRaises(urllib.error.HTTPError) as error:
                    opener(request, timeout=3)
                self.assertEqual(error.exception.code, 302)
                self.assertEqual(received, [])
        finally:
            for server in (origin, destination):
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=3)
