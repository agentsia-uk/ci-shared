import json
import unittest

from code_health.qualification_protocol import MAX_RESPONSE_BYTES, decode_observation


class CandidateObservationTests(unittest.TestCase):
    def test_accepts_only_case_bound_observations(self):
        data = json.dumps({'schemaVersion': 1, 'caseId': 'score-drop', 'outcome': 'returned',
                           'value': {'errors': ['score decreased']}}).encode()
        self.assertEqual(decode_observation(data, expected_case='score-drop')['value']['errors'], ['score decreased'])
        with self.assertRaises(ValueError):
            decode_observation(data, expected_case='another-case')

    def test_candidate_cannot_submit_its_own_verdict_or_extra_fields(self):
        data = b'{"schemaVersion":1,"caseId":"case","outcome":"returned","value":{},"passed":true}'
        with self.assertRaises(ValueError):
            decode_observation(data, expected_case='case')

    def test_refuses_duplicate_keys_nonfinite_values_and_oversize(self):
        invalid = [
            b'{"schemaVersion":1,"caseId":"case","caseId":"other","outcome":"returned","value":null}',
            b'{"schemaVersion":1,"caseId":"case","outcome":"returned","value":{"score":1e999}}',
            b'{"schemaVersion":1,"caseId":"case","outcome":"returned","value":NaN}',
            b' ' * (MAX_RESPONSE_BYTES + 1),
        ]
        for data in invalid:
            with self.subTest(data=data[:80]), self.assertRaises(ValueError):
                decode_observation(data, expected_case='case')

    def test_rejection_carries_only_a_bounded_reason(self):
        for value in ({'passed': True}, None, '', 'x' * 1025):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decode_observation(json.dumps({'schemaVersion': 1, 'caseId': 'case', 'outcome': 'rejected',
                                               'value': value}).encode(), expected_case='case')
        result = decode_observation(b'{"schemaVersion":1,"caseId":"case","outcome":"rejected","value":"reason"}',
                                    expected_case='case')
        self.assertEqual(result['outcome'], 'rejected')


if __name__ == '__main__':
    unittest.main()
