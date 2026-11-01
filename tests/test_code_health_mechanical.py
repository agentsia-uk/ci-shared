import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from code_health import mechanical as m

RAW_EVIDENCE = 'SYNTHETIC-RAW-SOURCE-MUST-NOT-SHIP'
AREA = {'id': 'app-python', 'language': 'python', 'path': '.', 'exclusions': []}
SCAN_CONFIG = {'ignore': [], 'trust_plugins': False, 'hermes_enabled': False, 'exclude': ['nested-project']}
COMMIT = 'a' * 40


def inputs():
    scores = {'overall_score': 24, 'strict_score': 23, 'objective_score': 96, 'verified_strict_score': 91}
    dimensions = [{'name': 'Code quality', 'score': 90.2, 'strict': 89.1, 'tier': 3, 'subjective': False}, {'name': 'Security', 'score': 80, 'strict': 75, 'tier': 4, 'subjective': False}]
    status = {**scores, 'last_scan': '2026-10-29T10:00:00+00:00', 'scorecard_dimensions': dimensions}
    def finding(id, detector='smells', path='src/app/[id]/page.tsx', status='open'):
        return {'id': id, 'detector': detector, 'file': path, 'tier': 2, 'confidence': 'high', 'status': status, 'summary': 'A native finding.', 'work_item_kind': 'mechanical_defect', 'detail': {'line': 12, 'content': RAW_EVIDENCE, 'evidence': [RAW_EVIDENCE]}, 'note': RAW_EVIDENCE}
    items = [finding('one'), finding('two', detector='cycles', path='.'), finding('debt', detector='security', status='wontfix'), finding('fixed', status='fixed'), finding('false', status='false_positive')]
    state = {**scores, 'version': 3, 'last_scan': status['last_scan'], 'scan_path': '.', 'scan_completeness': {'python': 'fast'}, 'subjective_assessments': {}, 'work_items': {f['id']: f for f in items}, 'dimension_scores': {'Code quality': {'detectors': {'smells': {}, 'cycles': {}}}, 'Security': {'detectors': {'security': {}}}}, 'stats': {'total': 5, 'open': 2, 'fixed': 1, 'wontfix': 1, 'false_positive': 1}, 'scan_coverage': {'python': {'status': 'full', 'confidence': 1, 'detectors': {}, 'warnings': []}}, 'potentials': {'python': {'smells': 10, 'cycles': 5, 'security': 10}}, 'raw_extra': RAW_EVIDENCE}
    return status, state


def project(status=None, state=None, **changes):
    defaults = inputs()
    return m.project_mechanical(status if status is not None else defaults[0], state if state is not None else defaults[1], changes.pop('area', AREA), changes.pop('scan_config', SCAN_CONFIG), commit_sha=changes.pop('commit_sha', COMMIT), tool_version=changes.pop('tool_version', '1.0'), scanner_patch=changes.pop('scanner_patch', m.a.cli.POLICY['scannerPatch']), **changes)


class MechanicalProjectionTests(unittest.TestCase):
    def test_native_scores_dimensions_counts_and_hotspots_keep_their_distinctions(self):
        status, state = inputs()
        before = copy.deepcopy((status, state))
        result = project(status, state)
        self.assertEqual({'overall': 24, 'strict': 23, 'objective': 96, 'verified': 91}, result['scores'])
        self.assertEqual('absent', result['subjectiveAssessment'])
        self.assertEqual('fast', result['scanCompleteness'])
        self.assertNotIn('subjectiveDimensions', result)
        self.assertEqual('2026-10-29T10:00:00.000Z', result['capturedAt'])
        self.assertEqual(2, result['mechanicalDimensions'][0]['openIssueCount'])
        self.assertEqual(['cycles', 'smells'], result['mechanicalDimensions'][0]['detectors'])
        self.assertEqual({'total': 5, 'open': 2, 'fixed': 1, 'wontfix': 1, 'byDetector': [{'detector': 'cycles', 'open': 1, 'fixed': 0, 'wontfix': 0}, {'detector': 'security', 'open': 0, 'fixed': 0, 'wontfix': 1}, {'detector': 'smells', 'open': 1, 'fixed': 1, 'wontfix': 0}]}, result['counts'])
        self.assertEqual([{'path': 'src/app/[id]/page.tsx', 'open': 1}], result['hotspots']['files'])
        self.assertEqual([{'path': '.', 'open': 1}, {'path': 'src/app/[id]', 'open': 1}], result['hotspots']['directories'])
        self.assertEqual(['nested-project'], result['excludes'])
        self.assertEqual(before, (status, state))

    def test_only_explicit_finding_fields_ship_without_any_raw_evidence(self):
        result = project()
        expected = {'id', 'detector', 'dimension', 'tier', 'confidence', 'summary', 'file', 'line', 'redacted'}
        self.assertTrue(all(set(finding) == expected and finding['redacted'] for finding in result['findings']))
        self.assertNotIn(RAW_EVIDENCE, json.dumps(result))
        self.assertEqual(['one', 'two'], [finding['id'] for finding in result['findings']])
        self.assertEqual('code_quality', result['findings'][0]['dimension'])

    def test_untrusted_extra_fields_cannot_select_code_or_execute_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / 'must-not-exist'
            payload = '__import__("pathlib").Path(' + repr(str(marker)) + ').write_text("executed")'
            status, state = inputs()
            status['runner_command'] = payload
            state['raw_extra'] = {'__reduce__': payload, 'module_path': str(marker), 'command': payload}
            state['work_items']['one']['detail']['runner_command'] = payload
            self.assertEqual(project(), project(status, state))
            self.assertFalse(marker.exists())

    def test_summaries_are_scrubbed_before_clipping_for_every_approved_base_pattern(self):
        # Synthetic values are assembled so no credential-shaped literal is stored.
        samples = [''.join(['g', 'h', 'p', '_']) + 'Q7' * 18, ''.join(['g', 'i', 't', 'h', 'u', 'b', '_', 'p', 'a', 't', '_']) + 'Q7' * 18,
                   'sk' + '-ant-api03-' + 'q9' * 30, 'AI' + 'za' + 'q9' * 20, 'sk' + '-or-v1-' + 'q9' * 20, 's' + 'k-' + 'q9' * 20,
                   'ey' + 'J' + 'b' * 16 + '.' + 'c' * 16 + '.' + 'd' * 16, 'PASS' + 'WORD=' + 'synthetic-value',
                   '-' * 5 + 'BEGIN ' + 'PRIVATE KEY' + '-' * 5 + '\nsynthetic\n' + '-' * 5 + 'END ' + 'PRIVATE KEY' + '-' * 5]
        for secret in samples:
            status, state = inputs()
            state['work_items']['one']['summary'] = 'x' * 410 + ' α' + secret
            with self.subTest(pattern=secret[:4]):
                result = project(status, state)
                self.assertEqual(m.WITHHELD_SUMMARY, result['findings'][0]['summary'])
                self.assertNotIn(secret, json.dumps(result))

    def test_output_boundary_refuses_secret_identity_and_scope_instead_of_rewriting_them(self):
        secret = 'g' + 'hp_' + 'Q7' * 18
        status, state = inputs()
        state['work_items']['one']['file'] = 'src/' + secret + '.py'
        with self.assertRaisesRegex(ValueError, 'output boundary'):
            project(status, state)
        status, state = inputs()
        item = state['work_items'].pop('one')
        item['id'] = secret
        state['work_items'][secret] = item
        with self.assertRaisesRegex(ValueError, 'output boundary'):
            project(status, state)
        with self.assertRaisesRegex(ValueError, 'output boundary'):
            project(scan_config={**SCAN_CONFIG, 'exclude': [secret]})

    def test_reduced_coverage_and_other_languages_are_reported_without_invented_scores(self):
        for language in ['python', 'typescript', 'javascript']:
            status, state = inputs()
            state['scan_coverage'] = {language: {'status': 'reduced', 'confidence': .5, 'detectors': {'compiler': {'status': 'reduced', 'confidence': .5, 'tool': 'compiler', 'reason': 'parser_error', 'summary': 'Compiler unavailable.', 'impact': 'partial'}}, 'warnings': [{'detector': 'compiler', 'status': 'reduced', 'reason': 'parser_error', 'summary': 'Compiler unavailable.', 'stderr': RAW_EVIDENCE}]}}
            state['potentials'] = {language: state['potentials']['python']}
            state['scan_completeness'] = {language: 'fast'}
            result = project(status, state, area={**AREA, 'language': language})
            self.assertEqual(language, result['language'])
            self.assertEqual('reduced', result['coverage']['status'])
            self.assertEqual(.5, result['coverage']['confidence'])
            self.assertEqual([{'detector': 'compiler', 'status': 'reduced', 'confidence': .5, 'details': {'tool': 'compiler', 'reason': 'parser_error', 'summary': 'Compiler unavailable.', 'impact': 'partial'}}], result['coverage']['detectors'])
            self.assertEqual([{'detector': 'compiler', 'status': 'reduced', 'reason': 'parser_error', 'summary': 'Compiler unavailable.'}], result['coverage']['notes'])
            self.assertNotIn(RAW_EVIDENCE, json.dumps(result))

    def test_no_missing_invalid_or_mismatched_native_values_are_zero_filled(self):
        for key in ['overall_score', 'strict_score', 'objective_score', 'verified_strict_score']:
            status, state = inputs()
            del status[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                project(status, state)
        for value in [None, True, float('nan'), float('inf'), -1, 101]:
            status, state = inputs()
            status['objective_score'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                project(status, state)
        for change in [{'last_scan': '2026-10-29T10:01:00Z'}, {'last_scan': '2026-10-29T10:00:00'}, {'objective_score': 95}, {'scan_path': 'different'}, {'version': 2}, {'subjective_assessments': {'naming': {'score': 80}}}]:
            status, state = inputs()
            state.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                project(status, state)
        for change in [{'ignore': ['*']}, {'trust_plugins': True}, {'hermes_enabled': True}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                project(scan_config={**SCAN_CONFIG, **change})

    def test_lines_paths_and_payload_limits_match_existing_dashboard_rules(self):
        for value in [True, 0, -1, '12', 1.5]:
            status, state = inputs()
            state['work_items']['one']['detail']['line'] = value
            self.assertIsNone(project(status, state)['findings'][0]['line'])
        for path in ['/tmp/source.py', '../secret.py', 'src\\hidden.py']:
            status, state = inputs()
            state['work_items']['one']['file'] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                project(status, state)
        with patch.object(m, 'MAX_FINDINGS', 1), self.assertRaises(ValueError):
            project()
        with patch.object(m, 'MAX_PROJECTION_BYTES', 1), self.assertRaises(ValueError):
            project()
        status, state = inputs()
        state['work_items']['one']['summary'] = '😀' * 250
        result = project(status, state)
        self.assertLessEqual(len(result['findings'][0]['summary'].encode('utf-16-le')) // 2, 400)

    def test_scanner_patch_and_detector_coverage_are_required(self):
        result = project()
        self.assertEqual(2, result['schemaVersion'])
        self.assertEqual(m.a.cli.POLICY['scannerPatch'], result['scannerPatch'])
        for invalid in [None, {}, {'id': 'other', 'sha256': 'a' * 64}]:
            with self.subTest(patch=invalid), self.assertRaisesRegex(ValueError, 'scanner correction'):
                project(scanner_patch=invalid)
        for invalid in [True, -1, 1.1, float('nan')]:
            status, state = inputs()
            state['scan_coverage']['python']['detectors'] = {'security': {'status': 'full', 'confidence': invalid}}
            with self.subTest(confidence=invalid), self.assertRaisesRegex(ValueError, 'detector coverage'):
                project(status, state)

    def test_comparison_changes_when_scanner_or_coverage_changes(self):
        baseline = project()
        other_patch = {'id': 'corrected-scanner-v2', 'sha256': 'b' * 64}
        with patch.dict(m.a.cli.POLICY, {'scannerPatch': other_patch}):
            changed = project(scanner_patch=other_patch)
        self.assertNotEqual(baseline['comparabilityKey'], changed['comparabilityKey'])
        status, state = inputs()
        state['scan_coverage']['python']['detectors'] = {'security': {'status': 'full', 'confidence': .8}}
        self.assertNotEqual(baseline['comparabilityKey'], project(status, state)['comparabilityKey'])
        first = project(scan_config={**SCAN_CONFIG, 'exclude': ['one', 'two']})
        second = project(scan_config={**SCAN_CONFIG, 'exclude': ['two', 'one']})
        self.assertEqual(first['comparabilityKey'], second['comparabilityKey'])

    def test_standalone_reads_private_files_and_writes_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status, state = inputs()
            manifest = {'schemaVersion': 1, 'policyRef': 'a' * 40, 'workflowRef': 'b' * 40, 'areas': [AREA]}
            for name, value in [('status', status), ('state', state), ('manifest', manifest), ('config', SCAN_CONFIG)]:
                (root / (name + '.json')).write_text(json.dumps(value))
            output = root / 'mechanical.json'
            argv = ['mechanical', '--status', str(root / 'status.json'), '--state', str(root / 'state.json'), '--manifest', str(root / 'manifest.json'), '--scan-config', str(root / 'config.json'), '--area', AREA['id'], '--commit', COMMIT, '--output', str(output)]
            with patch.object(m.a.cli.sys, 'argv', argv):
                m.main()
                self.assertEqual('absent', json.loads(output.read_text())['subjectiveAssessment'])
                with self.assertRaises(FileExistsError):
                    m.main()
            help_result = subprocess.run([m.a.cli.sys.executable, '-m', 'code_health.mechanical', '--help'], cwd=Path(m.__file__).parents[1], check=True, capture_output=True, timeout=30)
            self.assertIn(b'--scan-config', help_result.stdout)


if __name__ == '__main__':
    unittest.main()
