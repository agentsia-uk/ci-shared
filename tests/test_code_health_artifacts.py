import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from code_health import artifacts as a

REPOSITORY = {'id': 1259100960, 'fullName': 'agentsia-uk/ci-shared'}
RUN = {'id': 40834508277, 'attempt': 1, 'event': 'push', 'ref': 'refs/heads/main'}
LINUX = {'pythonVersion': '3.13.13', 'sysPlatform': 'linux', 'machine': 'x86_64', 'glibcVersion': '2.39'}


def config():
    return {'schemaVersion': 1, 'policyRef': 'a' * 40, 'workflowRef': 'b' * 40, 'areas': [{'id': 'project-python', 'language': 'python', 'path': '.', 'exclusions': []}], 'unsupportedLanguages': [{'language': 'yaml', 'rationale': 'Validated separately with actionlint.'}]}


def execution():
    # Shape fixtures only; these tests do not claim cryptographic qualification.
    return {'launcher': {'repository': 'agentsia-uk/ci-shared', 'workflowPath': '.github/workflows/org-code-health.yml', 'workflowSha': 'b' * 40, 'actionRef': 'c' * 40}, 'release': {'repository': 'agentsia-uk/ci-shared', 'tag': 'policy-20261029', 'policyCommitSha': 'a' * 40, 'bundleSha256': '1' * 64, 'releaseManifestSha256': '2' * 64, 'qualificationWorkflowSha': 'd' * 40, 'requirementsLockSha256': '3' * 64}}


class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git = lambda *args: subprocess.check_output(['git', *args], cwd=self.repo).decode().strip()
        self.git('init', '-q')
        self.git('config', 'user.name', 'test')
        self.git('config', 'user.email', 'test@example.invalid')
        (self.repo / '.github').mkdir()
        self.definition = config()
        self.manifest_raw = (json.dumps(self.definition, indent=2) + '\n').encode()
        (self.repo / a.cli.CONFIG).write_bytes(self.manifest_raw)
        (self.repo / '.gitattributes').write_text('.github/code-health.json export-ignore export-subst\n')
        (self.repo / 'service.py').write_text('pass\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'source')
        self.commit = self.git('rev-parse', 'HEAD')
        self.result = {'schemaVersion': 1, 'base': self.commit, 'head': self.commit, 'desloppifyVersion': '1.0', 'configSha256': a.sha256(json.dumps(self.definition, sort_keys=True).encode()), 'areas': [{'area': 'project-python', 'objectiveBefore': 90, 'objectiveAfter': 90}]}
        self.result_path = self.root / 'result.json'
        self.result_path.write_text(json.dumps(self.result))
        self.evidence_path = self.root / 'trusted-execution.json'
        self.evidence_path.write_text(json.dumps(execution()))

    def build(self):
        with patch.object(a, 'current_runtime', return_value=copy.deepcopy(LINUX)):
            return a.build_envelope(self.repo, self.commit, self.commit, self.result_path, self.evidence_path, REPOSITORY, RUN)

    def test_envelope_hashes_actual_git_and_result_bytes_with_distinct_identities(self):
        envelope = self.build()
        self.assertTrue(envelope['collectorValidationRequired'])
        self.assertEqual(self.git('rev-parse', 'HEAD^{tree}'), envelope['source']['treeSha'])
        self.assertEqual(self.git('rev-parse', 'HEAD:' + a.cli.CONFIG), envelope['manifest']['gitBlobSha'])
        self.assertEqual(hashlib.sha256(self.manifest_raw).hexdigest(), envelope['manifest']['sha256'])
        self.assertEqual(hashlib.sha256(self.result_path.read_bytes()).hexdigest(), envelope['result']['sha256'])
        self.assertNotEqual(envelope['launcher']['actionRef'], envelope['release']['policyCommitSha'])
        self.assertEqual(LINUX, envelope['runtime'])
        self.assertEqual(envelope, a.validate_envelope(envelope))

    def test_registry_covers_manifest_areas_and_arbitrary_active_repository(self):
        definition = config()
        definition['areas'].append({'id': 'nested-typescript', 'language': 'typescript', 'path': 'nested', 'exclusions': [{'pattern': 'dist', 'kind': 'build', 'rationale': 'Compiler output.'}]})
        repository = {'id': 999, 'fullName': 'agentsia-uk/new-project'}
        raw = json.dumps(definition).encode()
        registry = a.project_registry(repository, self.commit, raw)
        self.assertEqual(repository, registry['repository'])
        self.assertEqual(definition['areas'], registry['areas'])
        self.assertEqual(definition['unsupportedLanguages'], registry['unsupportedLanguages'])
        definition['areas'].clear()
        self.assertEqual(2, len(registry['areas']))
        unsupported = {**config(), 'areas': []}
        self.assertEqual([], a.project_registry(repository, self.commit, json.dumps(unsupported).encode())['areas'])

    def test_strict_envelope_rejects_weakening_spoofed_registry_and_mixed_pins(self):
        for mutate in [lambda x: x.update(collectorValidationRequired=False), lambda x: x.update(unrecognised=True), lambda x: x['repository'].update(id=True), lambda x: x['run'].update(attempt=0), lambda x: x['launcher'].update(actionRef='main'), lambda x: x['release'].update(bundleSha256='unknown'), lambda x: x['release'].update(policyCommitSha='f' * 40), lambda x: x['registry']['areas'].clear(), lambda x: x['manifest'].update(path='../manifest.json'), lambda x: x['source'].update(commitSha='main')]:
            envelope = self.build()
            mutate(envelope)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                a.validate_envelope(envelope)

    def test_result_must_match_exact_source_config_tool_and_area_set(self):
        for change in [{'head': 'e' * 40}, {'base': 'f' * 40}, {'configSha256': '0' * 64}, {'desloppifyVersion': '0.9'}, {'areas': []}, {'areas': [{'area': 'project-python'}, {'area': 'project-python'}]}, {'areas': ['not-an-area']}, {'schemaVersion': True}]:
            self.result_path.write_text(json.dumps({**self.result, **change}))
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.build()

    def test_candidate_checkout_cannot_supply_execution_evidence(self):
        self.evidence_path = self.repo / 'forged-evidence.json'
        self.evidence_path.write_text(json.dumps(execution()))
        with self.assertRaisesRegex(ValueError, 'outside the caller checkout'):
            self.build()

    def test_inputs_are_bounded_and_json_ambiguity_is_rejected(self):
        for raw in [b'{"key":1,"key":2}', b'{"key":NaN}', b'{"key":Infinity}']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                a.json_bytes(raw, 100)
        with self.assertRaises(ValueError):
            a.json_bytes(b'{}', 1)
        with self.assertRaises(ValueError):
            a.read_bounded(self.result_path, 1)
        with patch.object(a, 'MAX_MANIFEST_BYTES', 1), self.assertRaises(ValueError):
            self.build()

    def test_manifest_nonblob_and_missing_object_fail_instead_of_omission(self):
        oid = self.git('rev-parse', 'HEAD:' + a.cli.CONFIG)
        (self.repo / '.git/objects' / oid[:2] / oid[2:]).unlink()
        with self.assertRaises(subprocess.CalledProcessError):
            self.build()
        (self.repo / a.cli.CONFIG).unlink()
        (self.repo / a.cli.CONFIG).symlink_to('other.json')
        self.git('add', a.cli.CONFIG)
        self.git('commit', '-qm', 'symlink')
        self.commit = self.git('rev-parse', 'HEAD')
        with self.assertRaisesRegex(ValueError, 'regular Git blob'):
            self.build()

    def test_runtime_matches_actual_supported_platform_and_rejects_others(self):
        for machine in ['x86_64', 'aarch64']:
            with patch.object(a.platform, 'libc_ver', return_value=('glibc', '2.34')), patch.object(a.platform, 'python_version', return_value='3.13.13'), patch.object(a.platform, 'machine', return_value=machine), patch.object(a.sys, 'platform', 'linux'):
                self.assertEqual(machine, a.current_runtime()['machine'])
        for change in [{'pythonVersion': '3.12.1'}, {'sysPlatform': 'darwin'}, {'machine': 'armv7l'}, {'glibcVersion': '2.28'}, {'glibcVersion': ''}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                a.validate_runtime({**LINUX, **change})
        with patch.object(a.platform, 'libc_ver', return_value=('musl', '1.2')), self.assertRaises(ValueError):
            a.current_runtime()

    def test_standalone_entry_writes_once_and_requires_github_context(self):
        help_result = subprocess.run([a.sys.executable, '-m', 'code_health.artifacts', '--help'], cwd=Path(a.__file__).parents[1], check=True, capture_output=True, timeout=30)
        self.assertIn(b'--execution-evidence', help_result.stdout)
        output = self.root / 'producer.json'
        argv = ['artifacts', '--repo', str(self.repo), '--base', self.commit, '--head', self.commit, '--result', str(self.result_path), '--execution-evidence', str(self.evidence_path), '--output', str(output)]
        env = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY_ID': str(REPOSITORY['id']), 'GITHUB_REPOSITORY': REPOSITORY['fullName'], 'GITHUB_RUN_ID': str(RUN['id']), 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': RUN['ref']}
        with patch.object(a.sys, 'argv', argv), patch.dict(a.os.environ, env), patch.object(a, 'current_runtime', return_value=LINUX):
            a.main()
            written = output.read_bytes()
            self.assertEqual(self.commit, json.loads(written)['source']['commitSha'])
            with self.assertRaises(FileExistsError):
                a.main()
            self.assertEqual(written, output.read_bytes())
        with patch.object(a.sys, 'argv', argv), patch.dict(a.os.environ, {'GITHUB_ACTIONS': 'false'}), self.assertRaisesRegex(ValueError, 'trusted GitHub workflow'):
            a.main()


if __name__ == '__main__':
    unittest.main()
