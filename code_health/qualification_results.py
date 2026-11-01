"""Validate untrusted job results against independently obtained run identity.

This validates data only. The caller must obtain identity from trusted CI metadata
and must not issue a release receipt until the complete qualification is wired.
"""
import json
import re

from .qualification_controller import evaluate_observation, qualification_cases
from .qualification_protocol import MAX_RESPONSE_BYTES, _unique_object, decode_observation

MAX_RESULTS_BYTES = 2 * 1024 * 1024
SHA256 = re.compile(r'[0-9a-f]{64}\Z')


def validate_results(data: bytes, *, run_id: int, run_attempt: int, candidate_sha256: str):
    if (not isinstance(data, bytes) or len(data) > MAX_RESULTS_BYTES or
            type(run_id) is not int or run_id < 1 or type(run_attempt) is not int or run_attempt < 1 or
            not isinstance(candidate_sha256, str) or not SHA256.fullmatch(candidate_sha256)):
        raise ValueError('invalid trusted identity or results size')
    try:
        result = json.loads(data, object_pairs_hook=_unique_object,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-finite JSON')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid qualification results JSON') from error
    if (not isinstance(result, dict) or set(result) != {'schemaVersion', 'runId', 'runAttempt', 'candidateSha256', 'observations'} or
            type(result['schemaVersion']) is not int or result['schemaVersion'] != 1 or
            type(result['runId']) is not int or result['runId'] != run_id or
            type(result['runAttempt']) is not int or result['runAttempt'] != run_attempt or
            result['candidateSha256'] != candidate_sha256 or not isinstance(result['observations'], list)):
        raise ValueError('qualification results identity mismatch')
    cases = qualification_cases()
    if len(result['observations']) != len(cases):
        raise ValueError('qualification results inventory mismatch')
    for observation, (case_id, _, _, expected) in zip(result['observations'], cases):
        try:
            encoded = json.dumps(observation, allow_nan=False, separators=(',', ':')).encode()
        except (TypeError, ValueError, RecursionError) as error:
            raise ValueError('invalid qualification observation') from error
        if len(encoded) > MAX_RESPONSE_BYTES:
            raise ValueError('qualification observation exceeds size limit')
        evaluate_observation(decode_observation(encoded, expected_case=case_id), case_id, expected)
    return len(cases)
