import copy
import json
import unittest

from code_health.qualification_controller import qualification_cases
from code_health.qualification_results import collect_results, validate_results
from tests.test_qualification_controller import simulated_runner


class QualificationResultsTests(unittest.TestCase):
    def setUp(self):
        observations = []
        for case_id, operation, arguments, _ in qualification_cases():
            request = {'schemaVersion': 1, 'caseId': case_id, 'operation': operation, 'arguments': arguments}
            observations.append(simulated_runner(image=None, candidate=None, bridge=None, readers=None, case_id=case_id, request=request))
        self.result = {'schemaVersion': 1, 'runId': 123, 'runAttempt': 2,
                       'candidateSha256': 'a' * 64, 'observations': observations}

    def validate(self, result):
        return validate_results(json.dumps(result).encode(), run_id=123, run_attempt=2, candidate_sha256='a' * 64)

    def test_complete_current_run(self):
        self.assertEqual(self.validate(self.result), len(qualification_cases()))

    def test_collected_observations_are_independently_checked(self):
        data = collect_results(image=None, candidate=None, bridge=None, readers=None, run_id=123, run_attempt=2,
                               candidate_sha256='a' * 64, runner=simulated_runner)
        self.assertEqual(validate_results(data, run_id=123, run_attempt=2, candidate_sha256='a' * 64),
                         len(qualification_cases()))

    def test_collection_does_not_accept_forged_case_or_verdict(self):
        def forged(**kwargs):
            return {'schemaVersion': 1, 'caseId': kwargs['case_id'], 'outcome': 'returned', 'value': None, 'passed': True}
        with self.assertRaises(ValueError):
            collect_results(image=None, candidate=None, bridge=None, readers=None, run_id=123, run_attempt=2,
                            candidate_sha256='a' * 64, runner=forged)

    def test_wrong_identity_missing_reordered_or_forged_results_fail(self):
        variants = []
        for field, value in [('runId', 124), ('runAttempt', 1), ('candidateSha256', 'b' * 64), ('extra', True)]:
            altered = copy.deepcopy(self.result)
            altered[field] = value
            variants.append(altered)
        missing = copy.deepcopy(self.result)
        missing['observations'].pop()
        variants.append(missing)
        reordered = copy.deepcopy(self.result)
        reordered['observations'][0:2] = reversed(reordered['observations'][0:2])
        variants.append(reordered)
        forged = copy.deepcopy(self.result)
        forged['observations'][0]['passed'] = True
        variants.append(forged)
        for result in variants:
            with self.subTest(result=str(result)[:120]), self.assertRaises(ValueError):
                self.validate(result)

    def test_duplicate_metadata_and_untrusted_identity_are_rejected(self):
        data = b'{"schemaVersion":1,"runId":123,"runId":123}'
        with self.assertRaises(ValueError):
            validate_results(data, run_id=123, run_attempt=2, candidate_sha256='a' * 64)
        with self.assertRaises(ValueError):
            validate_results(b'{}', run_id=True, run_attempt=2, candidate_sha256='a' * 64)


if __name__ == '__main__':
    unittest.main()
