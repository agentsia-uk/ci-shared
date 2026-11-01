"""Run a caller-verified scanner image with private, read-only inputs."""
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time

from .qualification_container import DOCKER, ENVIRONMENT, _require_seccomp

IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
CONTAINER = re.compile(r'[0-9a-f]{64}\Z')
MAX_LOG_BYTES = 64 * 1024 * 1024


def _capture(command, env):
    child = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 1800
    chunks = []
    size = 0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError('isolated scanner timed out')
                chunk = os.read(child.stdout.fileno(), min(65536, MAX_LOG_BYTES - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_LOG_BYTES:
                    raise ValueError('scanner output exceeds its size limit')
                chunks.append(chunk)
        if child.wait(timeout=max(0, deadline - time.monotonic())):
            raise ValueError('isolated scanner failed')
        return b''.join(chunks)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdout.close()


def run_scanner(*, image, source, readers, output, arguments):
    """The caller must verify the image and reader bytes before invoking this function."""
    if not isinstance(image, str) or not IMAGE.fullmatch(image) or os.geteuid() == 0:
        raise ValueError('scanner requires an exact image ID and a non-root owner')
    if not isinstance(arguments, list) or any(not isinstance(item, str) or '\0' in item for item in arguments):
        raise ValueError('invalid scanner arguments')
    paths = []
    for supplied in (source, readers, output):
        path = Path(supplied).absolute()
        if path.resolve(strict=True) != path or ',' in str(path):
            raise ValueError('scanner directory must be a direct path')
        metadata = path.stat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise ValueError('scanner directories must be private and owned by the caller')
        paths.append(path)
    if any(a == b or a in b.parents or b in a.parents for i, a in enumerate(paths) for b in paths[i + 1:]):
        raise ValueError('scanner directories must not overlap')
    _require_seccomp()
    mounts = [(paths[0], '/source', 'readonly'), (paths[1], '/opt/code-health/readers', 'readonly'),
              (paths[2], '/output', '')]
    command = [DOCKER, 'create', '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges', '--security-opt', 'seccomp=builtin', '--pids-limit', '256',
               '--memory', '8g', '--memory-swap', '8g', '--cpus', '4', '--user', f'{os.getuid()}:{os.getgid()}',
               '--ipc', 'none', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=4g',
               '-e', 'HOME=/tmp', '-e', 'DESLOPPIFY_ROOT=/source', '-e', 'CI=true', '-e', 'NO_COLOR=1',
               '-e', 'npm_config_yes=false']
    for host, target, mode in mounts:
        command.extend(['--mount', f'type=bind,src={host},dst={target}' + (',' + mode if mode else '')])
    command.extend([image, *arguments])
    env = ENVIRONMENT
    created = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=60, check=True).stdout.decode('ascii').strip()
    if not CONTAINER.fullmatch(created):
        raise ValueError('invalid scanner container identity')
    try:
        return _capture([DOCKER, 'start', '--attach', created], env)
    finally:
        subprocess.run([DOCKER, 'rm', '--force', created], env=env, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=60, check=True)
