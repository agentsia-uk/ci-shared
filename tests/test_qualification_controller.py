import json
import unittest

from code_health import cli, qualification_bridge
from code_health.qualification_controller import evaluate_observation, qualification_cases, run_qualification_cases
from code_health.qualification_protocol import decode_observation


def simulated_runner(*, image, candidate, bridge, readers, case_id, request):
    del image, candidate, bridge, readers
    if request['operation'] == 'scanner-new-area':
        return {'schemaVersion': 1, 'caseId': case_id, 'outcome': 'returned',
                'value': {'baselineKind': 'new-area', 'objectiveBefore': None, 'errors': []}}
    if request['operation'] == 'scanner-security':
        return {'schemaVersion': 1, 'caseId': case_id, 'outcome': 'returned',
                'value': {'securityCoverage': 'full', 'hasSecurityFinding': True, 'hasSecurityError': True}}
    raw = json.dumps(qualification_bridge.observe(request, cli), allow_nan=False).encode()
    return decode_observation(raw, expected_case=case_id)


class QualificationControllerTests(unittest.TestCase):
    def test_simulated_observations_match_the_qualification_cases(self):
        self.assertEqual(run_qualification_cases(image=None, candidate=None, bridge=None, readers=None, runner=simulated_runner), len(qualification_cases()))
        self.assertEqual(len(qualification_cases()), 47)

    def test_candidate_cannot_forge_verdict_or_switch_cases(self):
        def forged(**kwargs):
            return {'schemaVersion': 1, 'caseId': kwargs['case_id'], 'outcome': 'returned', 'value': None, 'passed': True}
        with self.assertRaisesRegex(ValueError, 'expected case'):
            run_qualification_cases(image=None, candidate=None, bridge=None, readers=None, runner=forged)
        observation = {'schemaVersion': 1, 'caseId': 'wrong-case', 'outcome': 'returned', 'value': None}
        with self.assertRaisesRegex(ValueError, 'expected case'):
            evaluate_observation(observation, 'config-valid', 'returned')

    def test_wrong_policy_behaviour_is_rejected_by_controller(self):
        def always_accept(**kwargs):
            return {'schemaVersion': 1, 'caseId': kwargs['case_id'], 'outcome': 'returned', 'value': None}
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            run_qualification_cases(image=None, candidate=None, bridge=None, readers=None, runner=always_accept)
        observation = {'schemaVersion': 1, 'caseId': 'score-decreased', 'outcome': 'returned', 'value': {'errors': []}}
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            expected = next(case[3] for case in qualification_cases() if case[0] == 'score-decreased')
            evaluate_observation(observation, 'score-decreased', expected)
        observation['value'] = {**expected, 'errors': ['unrelated failure']}
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            evaluate_observation(observation, 'score-decreased', expected)

    def test_unknown_operation_is_not_a_valid_policy_rejection(self):
        request = {'schemaVersion': 1, 'caseId': 'unknown', 'operation': 'not-a-policy-operation', 'arguments': {}}
        with self.assertRaises(RuntimeError):
            qualification_bridge.observe(request, cli)

    def test_unrelated_snapshot_error_is_not_counted_as_symlink_protection(self):
        class BrokenSnapshot:
            @staticmethod
            def snapshot(*_args):
                raise ValueError('unrelated failure')
        request = {'schemaVersion': 1, 'caseId': 'git-snapshot-escape',
                   'operation': 'git-snapshot', 'arguments': {'escape': True}}
        observation = qualification_bridge.observe(request, BrokenSnapshot())
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            evaluate_observation(observation, 'git-snapshot-escape', 'rejected')

    def test_finding_move_cases_reject_wrong_regression_decisions(self):
        for case_id, wrong in [('finding-move-typescript', ['new finding']), ('finding-move-tsx', ['new finding']),
                               ('finding-move-typescript-changed', []), ('finding-move-unchanged', ['new finding']), ('finding-move-native', ['new finding']), ('finding-move-top-level', ['new finding']),
                               ('finding-move-severity', []), ('finding-move-changed', []), ('finding-move-priority', [])]:
            expected = next(case[3] for case in qualification_cases() if case[0] == case_id)
            observation = {'schemaVersion': 1, 'caseId': case_id, 'outcome': 'returned',
                           'value': {'errors': wrong}}
            with self.assertRaisesRegex(ValueError, 'disagrees'):
                evaluate_observation(observation, case_id, expected)

    def test_scanner_mapping_requires_expected_bytes_and_unambiguous_results(self):
        expected = next(case[3] for case in qualification_cases() if case[0] == 'scanner-mapping')
        for change in ({'patchSha256': '0' * 64}, {'exact': 'src/api/routes/health.ts'},
                       {'ambiguousName': 'src/db/health.ts'}, {'ambiguousExact': 'src/db/health.ts'}):
            observation = {'schemaVersion': 1, 'caseId': 'scanner-mapping', 'outcome': 'returned',
                           'value': {**expected, **change}}
            with self.assertRaisesRegex(ValueError, 'disagrees'):
                evaluate_observation(observation, 'scanner-mapping', expected)

    def test_git_identity_case_rejects_path_dependent_policy(self):
        import subprocess
        class PathDependent:
            @staticmethod
            def snapshot(repo, sha, destination):
                subprocess.run(['git', 'archive', sha], cwd=repo, check=True)
        request = {'schemaVersion': 1, 'caseId': 'git-identity', 'operation': 'git-identity', 'arguments': {}}
        with self.assertRaises(subprocess.CalledProcessError):
            qualification_bridge.observe(request, PathDependent())

    def test_scanner_security_requires_finding_and_full_coverage(self):
        expected = next(case[3] for case in qualification_cases() if case[0] == 'scanner-security')
        observation = {'schemaVersion': 1, 'caseId': 'scanner-security', 'outcome': 'returned',
                       'value': {**expected, 'hasSecurityFinding': False}}
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            evaluate_observation(observation, 'scanner-security', expected)
        observation['value'] = {**expected, 'securityCoverage': 'reduced'}
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            evaluate_observation(observation, 'scanner-security', expected)

    def test_boolean_observations_cannot_be_replaced_by_numbers(self):
        expected = next(case[3] for case in qualification_cases() if case[0] == 'scanner-security')
        observation = {'schemaVersion': 1, 'caseId': 'scanner-security', 'outcome': 'returned',
                       'value': {**expected, 'hasSecurityFinding': 1}}
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            evaluate_observation(observation, 'scanner-security', expected)
        observation['value'] = {'nested': [1]}
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            evaluate_observation(observation, 'scanner-security', {'nested': [True]})
        observation['value'] = {'nested': [True]}
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            evaluate_observation(observation, 'scanner-security', {'nested': [1]})
        observation['value'] = {'score': 90.0}
        evaluate_observation(observation, 'scanner-security', {'score': 90})

    def test_unrelated_workflow_error_is_not_counted_as_pin_enforcement(self):
        class BrokenWorkflow:
            @staticmethod
            def validate_workflow_pin(*_args):
                raise ValueError('unrelated failure')
        request = {'schemaVersion': 1, 'caseId': 'workflow-mutable',
                   'operation': 'workflow-pin', 'arguments': {'mode': 'mutable'}}
        observation = qualification_bridge.observe(request, BrokenWorkflow())
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            evaluate_observation(observation, 'workflow-mutable', 'rejected')

    def test_unrelated_rejections_do_not_satisfy_any_negative_case(self):
        for case_id, _, _, expected in qualification_cases():
            if expected == 'rejected':
                observation = {'schemaVersion': 1, 'caseId': case_id, 'outcome': 'rejected', 'value': 'unrelated failure'}
                with self.subTest(case_id=case_id), self.assertRaisesRegex(ValueError, 'disagrees'):
                    evaluate_observation(observation, case_id, expected)


if __name__ == '__main__':
    unittest.main()
