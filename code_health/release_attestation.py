"""Verify an immutable policy asset and its pinned qualification workflow."""
import json
import os
import re
import selectors
import signal
import subprocess
import time

REPOSITORY = 'agentsia-uk/ci-shared'
REPOSITORY_ID = '1259100960'
SIGNER = REPOSITORY + '/.github/workflows/code-health-release.yml'
SHA = re.compile(r'[0-9a-f]{40}\Z')
GH_EXECUTABLE = '/usr/bin/gh'
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def read_command(argv: list[str], *, timeout: float = 120, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    """Bound both output and elapsed time without retaining sensitive stderr."""
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + timeout
    chunks = []
    total = 0
    completed = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise subprocess.TimeoutExpired(argv, timeout)
                chunk = os.read(child.stdout.fileno(), min(65536, limit - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise ValueError('verification response exceeds limit')
                chunks.append(chunk)
        code = child.wait(timeout=max(0, deadline - time.monotonic()))
        if code:
            raise subprocess.CalledProcessError(code, argv)
        completed = True
        return b''.join(chunks)
    finally:
        if not completed:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        child.wait()
        child.stdout.close()


def verify_release(asset: str | os.PathLike[str], *, policy_commit: str, signer_commit: str) -> str:
    if not SHA.fullmatch(policy_commit) or not SHA.fullmatch(signer_commit):
        raise ValueError('policy and signer commits must be full SHAs')
    tag = 'code-health-' + policy_commit

    def gh(*args):
        return read_command([GH_EXECUTABLE, *args])

    release = json.loads(gh('api', f'repos/{REPOSITORY}/releases/tags/{tag}'))
    if release.get('immutable') is not True or release.get('draft') is not False or release.get('tag_name') != tag:
        raise ValueError('policy release is not an immutable published release')
    commit = json.loads(gh('api', f'repos/{REPOSITORY}/commits/{tag}'))
    if commit.get('sha') != policy_commit:
        raise ValueError('release tag does not identify the selected policy commit')
    gh('release', 'verify', tag, '-R', REPOSITORY)
    gh('release', 'verify-asset', tag, str(asset), '-R', REPOSITORY)
    verified = json.loads(gh('attestation', 'verify', str(asset), '--repo', REPOSITORY,
                             '--signer-workflow', SIGNER, '--signer-digest', signer_commit,
                             '--source-ref', 'refs/heads/main', '--source-digest', policy_commit,
                             '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com',
                             '--predicate-type', 'https://slsa.dev/provenance/v1', '--format', 'json'))
    if not isinstance(verified, list) or not verified:
        raise ValueError('no verified policy attestations')
    for item in verified:
        try:
            repo_id = item['verificationResult']['signature']['certificate']['sourceRepositoryIdentifier']
        except (KeyError, TypeError) as error:
            raise ValueError('verified certificate lacks repository identity') from error
        if repo_id != REPOSITORY_ID:
            raise ValueError('verified certificate has the wrong repository identity')
    return tag
