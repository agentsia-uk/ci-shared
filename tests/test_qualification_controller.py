import json
import unittest

from code_health import cli, qualification_bridge
from code_health.qualification_controller import evaluate_observation, pure_cases, run_pure_cases
from code_health.qualification_protocol import decode_observation


def simulated_runner(*, image, candidate, bridge, case_id, request):
    del image, candidate, bridge
    raw = json.dumps(qualification_bridge.observe(request, cli), allow_nan=False).encode()
    return decode_observation(raw, expected_case=case_id)


class QualificationControllerTests(unittest.TestCase):
    def test_current_policy_matches_all_pure_cases_in_local_simulation(self):
        self.assertEqual(run_pure_cases(image=None, candidate=None, bridge=None, runner=simulated_runner), len(pure_cases()))
        self.assertEqual(len(pure_cases()), 17)

    def test_candidate_cannot_forge_verdict_or_switch_cases(self):
        def forged(**kwargs):
            return {'schemaVersion': 1, 'caseId': kwargs['case_id'], 'outcome': 'returned', 'value': None, 'passed': True}
        with self.assertRaisesRegex(ValueError, 'expected case'):
            run_pure_cases(image=None, candidate=None, bridge=None, runner=forged)
        observation = {'schemaVersion': 1, 'caseId': 'wrong-case', 'outcome': 'returned', 'value': None}
        with self.assertRaisesRegex(ValueError, 'expected case'):
            evaluate_observation(observation, 'config-valid', 'returned')

    def test_wrong_policy_behaviour_is_rejected_by_controller(self):
        def always_accept(**kwargs):
            return {'schemaVersion': 1, 'caseId': kwargs['case_id'], 'outcome': 'returned', 'value': None}
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            run_pure_cases(image=None, candidate=None, bridge=None, runner=always_accept)
        observation = {'schemaVersion': 1, 'caseId': 'score-decreased', 'outcome': 'returned', 'value': {'errors': []}}
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            expected = next(case[3] for case in pure_cases() if case[0] == 'score-decreased')
            evaluate_observation(observation, 'score-decreased', expected)
        observation['value'] = {**expected, 'errors': ['unrelated failure']}
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            evaluate_observation(observation, 'score-decreased', expected)

    def test_unknown_operation_is_not_a_valid_policy_rejection(self):
        request = {'schemaVersion': 1, 'caseId': 'unknown', 'operation': 'not-a-policy-operation', 'arguments': {}}
        with self.assertRaises(RuntimeError):
            qualification_bridge.observe(request, cli)


if __name__ == '__main__':
    unittest.main()
