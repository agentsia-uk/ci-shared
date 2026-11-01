"""Verify an immutable policy asset and its pinned qualification workflow."""
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import time

REPOSITORY = 'agentsia-uk/ci-shared'
REPOSITORY_ID = '1259100960'
SIGNER = REPOSITORY + '/.github/workflows/code-health-release.yml'
CALLER = 'https://github.com/' + REPOSITORY + '/.github/workflows/code-health-release-dispatch.yml@refs/heads/main'
SHA = re.compile(r'[0-9a-f]{40}\Z')
GH_EXECUTABLE = '/usr/bin/gh'
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def _verified_gh_fd(path: str) -> int:
    from .prepare_release_gh import BINARY_SHA256, BINARY_SIZE
    if not os.path.isabs(path) or not os.path.isdir('/proc/self/fd'):
        raise ValueError('pinned GitHub CLI requires an absolute Linux path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid not in {0, os.geteuid()} or
                metadata.st_mode & 0o022 or metadata.st_size != BINARY_SIZE):
            raise ValueError('pinned GitHub CLI has unsafe metadata')
        with os.fdopen(os.dup(fd), 'rb') as source:
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
        if digest != BINARY_SHA256:
            raise ValueError('pinned GitHub CLI binary does not match')
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_command(argv: list[str], *, timeout: float = 120, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    """Bound both output and elapsed time without retaining sensitive stderr."""
    env = {key: value for key, value in os.environ.items() if key != 'RELEASE_ADMIN_READ_TOKEN'}
    pinned = os.environ.get('CODE_HEALTH_GH_EXECUTABLE') if argv[0] == GH_EXECUTABLE else None
    fd = _verified_gh_fd(pinned) if pinned else None
    try:
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True, env=env,
                                 **({'executable': f'/proc/self/fd/{fd}', 'pass_fds': (fd,)} if fd is not None else {}))
    finally:
        if fd is not None:
            os.close(fd)
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
        try:
            child.wait(timeout=5)
        finally:
            child.stdout.close()


def ensure_gh_version() -> None:
    version = re.match(rb'gh version (\d+)\.(\d+)\.(\d+)(?:\s|$)', read_command([GH_EXECUTABLE, '--version']))
    if version is None or tuple(int(part) for part in version.groups()) < (2, 102, 0):
        raise ValueError('GitHub CLI 2.102.0 or newer is required for attestation verification')


def verify_release(asset: str | os.PathLike[str], *, policy_commit: str, signer_commit: str) -> str:
    if not SHA.fullmatch(policy_commit) or not SHA.fullmatch(signer_commit):
        raise ValueError('policy and signer commits must be full SHAs')
    tag = 'code-health-' + policy_commit

    def gh(*args):
        return read_command([GH_EXECUTABLE, *args])

    ensure_gh_version()
    release = json.loads(gh('api', f'repos/{REPOSITORY}/releases/tags/{tag}'))
    if release.get('immutable') is not True or release.get('draft') is not False or release.get('tag_name') != tag:
        raise ValueError('policy release is not an immutable published release')
    commit = json.loads(gh('api', f'repos/{REPOSITORY}/commits/{tag}'))
    if commit.get('sha') != policy_commit:
        raise ValueError('release tag does not identify the selected policy commit')
    gh('release', 'verify', tag, '-R', REPOSITORY)
    gh('release', 'verify-asset', tag, str(asset), '-R', REPOSITORY)
    verify_local_attestation(asset, policy_commit=policy_commit, signer_commit=signer_commit, check_version=False)
    return tag


def verify_local_attestation(asset: str | os.PathLike[str], *, policy_commit: str, signer_commit: str,
                             check_version: bool = True, run_id: int | None = None, run_attempt: int | None = None) -> None:
    if not SHA.fullmatch(policy_commit) or not SHA.fullmatch(signer_commit):
        raise ValueError('policy and signer commits must be full SHAs')
    if (run_id is None) != (run_attempt is None) or (run_id is not None and
            (type(run_id) is not int or run_id < 1 or type(run_attempt) is not int or run_attempt < 1)):
        raise ValueError('invalid trusted run identity')
    if check_version:
        ensure_gh_version()

    def gh(*args):
        return read_command([GH_EXECUTABLE, *args])

    verified = json.loads(gh('attestation', 'verify', str(asset), '--repo', REPOSITORY,
                             '--signer-workflow', SIGNER, '--signer-digest', signer_commit,
                             '--source-ref', 'refs/heads/main', '--source-digest', policy_commit,
                             '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com',
                             '--predicate-type', 'https://slsa.dev/provenance/v1', '--format', 'json'))
    if not isinstance(verified, list) or not verified:
        raise ValueError('no verified policy attestations')
    matching_run = run_id is None
    for item in verified:
        try:
            certificate = item['verificationResult']['signature']['certificate']
            repo_id = certificate['sourceRepositoryIdentifier']
        except (KeyError, TypeError) as error:
            raise ValueError('verified certificate lacks repository identity') from error
        if repo_id != REPOSITORY_ID:
            raise ValueError('verified certificate has the wrong repository identity')
        if certificate.get('buildConfigURI') != CALLER or certificate.get('buildConfigDigest') != policy_commit:
            raise ValueError('verified certificate has the wrong calling workflow identity')
        if run_id is not None and (certificate.get('runInvocationURI') ==
                f'https://github.com/{REPOSITORY}/actions/runs/{run_id}/attempts/{run_attempt}' and
                certificate.get('buildTrigger') == 'push'):
            matching_run = True
    if not matching_run:
        raise ValueError('verified certificate has the wrong qualification run identity')
