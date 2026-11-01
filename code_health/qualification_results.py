"""Validate untrusted job results against independently obtained run identity.

This validates data only. The caller must obtain identity from trusted CI metadata
and must not issue a release receipt until the complete qualification is wired.
"""
import json
import hashlib
import os
from pathlib import Path
import platform
import re
import tempfile
from contextlib import contextmanager

from .qualification_controller import evaluate_observation, qualification_cases
from .qualification_container import run_candidate
from .qualification_candidate import candidate_snapshot
from .qualification_protocol import MAX_RESPONSE_BYTES, _unique_object, decode_observation
from .release_bundle import read_bundle
from .readers_lock import ASSET_NAMES, unpack_archive, verify_selected_manifest

MAX_RESULTS_BYTES = 2 * 1024 * 1024
SHA256 = re.compile(r'[0-9a-f]{64}\Z')


@contextmanager
def reader_snapshot(bundle, *, expected_sha256, policy_commit, allowed_files):
    if not isinstance(bundle, bytes) or hashlib.sha256(bundle).hexdigest() != expected_sha256:
        raise ValueError('candidate bundle digest mismatch')
    _, files, _ = read_bundle(bundle, policy_commit=policy_commit, allowed_files=allowed_files)
    lock = verify_selected_manifest(files['code_health/readers-lock.json'], files['code_health/readers-upstream.json'])
    selected = 'linux-' + platform.machine()
    if selected not in ASSET_NAMES:
        raise ValueError('qualification architecture is not supported')
    with tempfile.TemporaryDirectory(prefix='qualification-readers-') as directory:
        root = Path(directory)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            readers = unpack_archive(files[ASSET_NAMES[selected]], lock=lock, platform=selected, destination_fd=fd)
        finally:
            os.close(fd)
        for name in readers:
            (root / name).chmod(0o444)
        root.chmod(0o755)
        yield root


def collect_bundle_results(*, bundle, expected_sha256, policy_commit, allowed_files,
                           image, bridge, run_id, run_attempt, runner=run_candidate):
    """Collect only from a snapshot of the independently identified bundle."""
    with candidate_snapshot(bundle, expected_sha256=expected_sha256,
                            policy_commit=policy_commit, allowed_files=allowed_files) as candidate, \
            reader_snapshot(bundle, expected_sha256=expected_sha256, policy_commit=policy_commit,
                            allowed_files=allowed_files) as readers:
        return collect_results(image=image, candidate=candidate, bridge=bridge, readers=readers, run_id=run_id,
                               run_attempt=run_attempt, candidate_sha256=expected_sha256, runner=runner)


def collect_results(*, image, candidate, bridge, readers, run_id, run_attempt, candidate_sha256, runner=run_candidate):
    """Collect observations without issuing a verdict or release receipt."""
    if (type(run_id) is not int or run_id < 1 or type(run_attempt) is not int or run_attempt < 1 or
            not isinstance(candidate_sha256, str) or not SHA256.fullmatch(candidate_sha256)):
        raise ValueError('invalid qualification identity')
    observations = []
    for case_id, operation, arguments, _ in qualification_cases():
        request = {'schemaVersion': 1, 'caseId': case_id, 'operation': operation, 'arguments': arguments}
        observation = runner(image=image, candidate=candidate, bridge=bridge, readers=readers, case_id=case_id, request=request)
        try:
            encoded = json.dumps(observation, allow_nan=False, separators=(',', ':')).encode()
        except (TypeError, ValueError, RecursionError) as error:
            raise ValueError('invalid qualification observation') from error
        observations.append(decode_observation(encoded, expected_case=case_id))
    result = {'schemaVersion': 1, 'runId': run_id, 'runAttempt': run_attempt,
              'candidateSha256': candidate_sha256, 'observations': observations}
    encoded = json.dumps(result, allow_nan=False, separators=(',', ':')).encode()
    if len(encoded) > MAX_RESULTS_BYTES:
        raise ValueError('qualification results exceed size limit')
    return encoded


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
