"""Validate candidate observations before a trusted controller scores them.

This module does not execute a candidate or issue a qualification receipt.
"""
import json
import math
import re

MAX_RESPONSE_BYTES = 64 * 1024
CASE_ID = re.compile(r'[a-z][a-z0-9-]{0,63}\Z')


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate candidate response field')
        result[key] = value
    return result


def _reject_nonfinite(value):
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError('non-finite candidate response value')
    if isinstance(value, dict):
        for child in value.values():
            _reject_nonfinite(child)
    elif isinstance(value, list):
        for child in value:
            _reject_nonfinite(child)


def decode_observation(data: bytes, *, expected_case: str) -> dict:
    """Read one bounded, case-bound observation; never accept a candidate verdict."""
    if not isinstance(data, bytes) or len(data) > MAX_RESPONSE_BYTES:
        raise ValueError('invalid candidate response size')
    if not isinstance(expected_case, str) or not CASE_ID.fullmatch(expected_case):
        raise ValueError('invalid expected qualification case')
    try:
        value = json.loads(data, object_pairs_hook=_unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-finite JSON')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid candidate response JSON') from error
    if (not isinstance(value, dict) or set(value) != {'schemaVersion', 'caseId', 'outcome', 'value'} or
            type(value['schemaVersion']) is not int or value['schemaVersion'] != 1 or
            value['caseId'] != expected_case or value['outcome'] not in ('returned', 'rejected') or
            (value['outcome'] == 'rejected' and
             (not isinstance(value['value'], str) or not 0 < len(value['value']) <= 1024))):
        raise ValueError('invalid candidate observation envelope')
    try:
        _reject_nonfinite(value['value'])
    except RecursionError as error:
        raise ValueError('candidate response nesting is too deep') from error
    return value
