"""Run a single candidate observation without mounting controller state or credentials.

The caller supplies a verified policy snapshot, a trusted bridge and a preapproved
image digest. This module never issues a qualification receipt.
"""
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

from .qualification_protocol import CASE_ID, MAX_RESPONSE_BYTES, decode_observation

DOCKER = '/usr/bin/docker'
MAX_REQUEST_BYTES = 64 * 1024
IMAGE = re.compile(r'(?:[a-z0-9][a-z0-9./:_-]*@)?sha256:[0-9a-f]{64}\Z')
CONTAINER_ID = re.compile(r'[0-9a-f]{64}\Z')
ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'DOCKER_CONFIG': '/nonexistent'}


def docker_environment():
    env = dict(ENVIRONMENT)
    host = os.environ.get('DOCKER_HOST')
    if host:
        expected = f'unix:///run/user/{os.getuid()}/docker.sock'
        if host != expected:
            raise ValueError('Docker must use the caller-owned rootless socket')
        metadata = os.stat(f'/run/user/{os.getuid()}/docker.sock', follow_symlinks=False)
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ValueError('rootless Docker socket identity differs')
        env['DOCKER_HOST'] = host
    return env


def _require_seccomp(env=ENVIRONMENT):
    result = subprocess.run([DOCKER, 'info', '--format', '{{json .SecurityOptions}}'], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=True).stdout
    if len(result) > 4096:
        raise ValueError('invalid Docker security options')
    try:
        options = json.loads(result)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError('invalid Docker security options') from error
    if (not isinstance(options, list) or any(not isinstance(option, str) for option in options) or
            not any(option.split(',')[0] == 'name=seccomp' for option in options)):
        raise ValueError('Docker seccomp support is required for qualification')


def _mount(path: Path, target: str, *, directory: bool) -> str:
    resolved = path.resolve(strict=True)
    if ',' in str(resolved) or (not resolved.is_dir() if directory else not resolved.is_file()):
        raise ValueError('invalid qualification mount')
    return f'type=bind,src={resolved},dst={target},readonly'


def _exchange(container_id: str, request: bytes, timeout: float) -> bytes:
    process = subprocess.Popen([DOCKER, 'start', '--attach', '--interactive', container_id],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env=ENVIRONMENT, start_new_session=True)
    deadline = time.monotonic() + timeout
    output = bytearray()
    position = 0
    try:
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdin, selectors.EVENT_WRITE)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('candidate observation timed out')
                events = selector.select(remaining)
                if not events:
                    raise TimeoutError('candidate observation timed out')
                for key, event in events:
                    if event & selectors.EVENT_WRITE:
                        try:
                            written = os.write(key.fileobj.fileno(), request[position:position + 8192])
                        except BrokenPipeError as error:
                            raise ValueError('candidate closed request early') from error
                        if written <= 0:
                            raise ValueError('candidate request made no progress')
                        position += written
                        if position == len(request):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        chunk = os.read(key.fileobj.fileno(), MAX_RESPONSE_BYTES + 1 - len(output))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                        else:
                            output.extend(chunk)
                            if len(output) > MAX_RESPONSE_BYTES:
                                raise ValueError('candidate observation exceeds size limit')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('candidate observation timed out')
        if process.wait(timeout=remaining) != 0:
            raise ValueError('candidate process failed')
        return bytes(output)
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=5)
        finally:
            for stream in (process.stdin, process.stdout):
                if not stream.closed:
                    stream.close()


def run_candidate(*, image: str, candidate: Path, bridge: Path, readers: Path, case_id: str,
                  request: dict, timeout: float = 30) -> dict:
    if not isinstance(image, str) or not IMAGE.fullmatch(image):
        raise ValueError('qualification image must have a full immutable digest')
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 120:
        raise ValueError('invalid candidate timeout')
    if (not isinstance(case_id, str) or not CASE_ID.fullmatch(case_id) or
            not isinstance(request, dict) or request.get('caseId') != case_id):
        raise ValueError('candidate request does not identify the expected case')
    payload = json.dumps(request, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    if len(payload) > MAX_REQUEST_BYTES:
        raise ValueError('candidate request exceeds size limit')
    _require_seccomp()
    args = [DOCKER, 'create', '--interactive', '--pull', 'never', '--network', 'none', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--security-opt', 'seccomp=builtin', '--pids-limit', '64', '--memory', '512m',
            '--memory-swap', '512m', '--cpus', '1', '--user', '65534:65534', '--ipc', 'none',
            '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m', '--ulimit', 'nofile=64:64',
            '--mount', _mount(candidate, '/candidate', directory=True),
            '--mount', _mount(bridge, '/qualification-bridge.py', directory=False),
            '--mount', _mount(readers, '/opt/code-health/readers', directory=True),
            '--entrypoint', '/opt/tool/bin/python', image, '-I', '-B', '/qualification-bridge.py']
    created = subprocess.run(args, env=ENVIRONMENT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=30, check=True).stdout.decode('ascii').strip()
    if not CONTAINER_ID.fullmatch(created):
        raise ValueError('invalid container identity')
    try:
        response = _exchange(created, payload, timeout)
        return decode_observation(response, expected_case=case_id)
    finally:
        subprocess.run([DOCKER, 'rm', '--force', created], env=ENVIRONMENT, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30, check=True)
