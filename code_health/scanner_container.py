"""Run a caller-verified scanner image with private, read-only inputs."""
import os
import json
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import threading
import time

from .qualification_container import DOCKER, ENVIRONMENT, _require_seccomp

IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
CONTAINER = re.compile(r'[0-9a-f]{64}\Z')
MAX_LOG_BYTES = 64 * 1024 * 1024


def _container_id(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_size > 65:
            raise ValueError('invalid scanner container identity file')
        value = os.read(fd, 66).decode('ascii').strip()
    finally:
        os.close(fd)
    if not CONTAINER.fullmatch(value):
        raise ValueError('invalid scanner container identity file')
    return value


def _capture(command, env):
    child = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.monotonic() + 1800
    chunks = []
    size = 0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            selector.register(child.stderr, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                events = selector.select(max(0, remaining))
                if remaining <= 0 or not events:
                    raise TimeoutError('isolated scanner timed out')
                for key, _ in events:
                    chunk = os.read(key.fileobj.fileno(), min(65536, MAX_LOG_BYTES - size + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    size += len(chunk)
                    if size > MAX_LOG_BYTES:
                        raise ValueError('scanner output exceeds its size limit')
                    if key.fileobj is child.stdout:
                        chunks.append(chunk)
        if child.wait(timeout=max(0, deadline - time.monotonic())):
            raise ValueError('isolated scanner failed')
        return b''.join(chunks)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdout.close()
        child.stderr.close()


def _inspect(container, image, mounts, env):
    raw = subprocess.run([DOCKER, 'inspect', '--format', '{{json .}}', container], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=True).stdout
    if len(raw) > 1024 * 1024:
        raise ValueError('scanner container inspection exceeds its size limit')
    try:
        record = json.loads(raw)
        host = record['HostConfig']
        actual = {(item['Source'], item['Destination'], item['RW']) for item in record['Mounts']}
        expected = {(str(source), target, mode != 'readonly') for source, target, mode in mounts}
        if (record['Image'] != image or record['Config']['User'] != f'{os.getuid()}:{os.getgid()}'
                or host['NetworkMode'] != 'none' or host['ReadonlyRootfs'] is not True
                or host['Privileged'] is not False or host['AutoRemove'] is not True or host['IpcMode'] != 'none'
                or host['CapDrop'] != ['ALL'] or 'no-new-privileges' not in host['SecurityOpt']
                or 'seccomp=builtin' not in host['SecurityOpt'] or actual != expected):
            raise ValueError('scanner container restrictions differ from the required policy')
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('invalid scanner container inspection') from error


def _remove(container, env):
    result = subprocess.run([DOCKER, 'rm', '--force', container], env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=60)
    if result.returncode:
        listing = subprocess.run([DOCKER, 'ps', '--all', '--no-trunc', '--filter', 'id=' + container,
                                  '--format', '{{.ID}}'], env=env, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, timeout=30, check=True).stdout
        if listing.strip():
            raise ValueError('scanner container could not be removed')


def run_scanner(*, image, source, readers, output, arguments):
    """The caller must verify the image and reader bytes before invoking this function."""
    if not isinstance(image, str) or not IMAGE.fullmatch(image) or os.geteuid() == 0:
        raise ValueError('scanner requires an exact image ID and a non-root owner')
    if threading.current_thread() is not threading.main_thread():
        raise ValueError('scanner container must run on the main thread for cancellation cleanup')
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
    command = [DOCKER, 'create', '--rm', '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges', '--security-opt', 'seccomp=builtin', '--pids-limit', '256',
               '--memory', '8g', '--memory-swap', '8g', '--cpus', '4', '--user', f'{os.getuid()}:{os.getgid()}',
               '--ipc', 'none', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=4g',
               '-e', 'HOME=/tmp', '-e', 'DESLOPPIFY_ROOT=/source', '-e', 'CI=true', '-e', 'NO_COLOR=1',
               '-e', 'npm_config_yes=false']
    for host, target, mode in mounts:
        command.extend(['--mount', f'type=bind,src={host},dst={target}' + (',' + mode if mode else '')])
    env = ENVIRONMENT
    previous = signal.getsignal(signal.SIGTERM)
    def interrupted(_signum, _frame):
        raise InterruptedError('scanner cancelled')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        with tempfile.TemporaryDirectory(prefix='code-health-container-') as temporary:
            cidfile = Path(temporary) / 'id'
            created = None
            try:
                result = subprocess.run([*command, '--cidfile', str(cidfile), image, *arguments], env=env,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60, check=True)
                created = result.stdout.decode('ascii').strip()
                if not CONTAINER.fullmatch(created) or _container_id(cidfile) != created:
                    raise ValueError('invalid scanner container identity')
                _inspect(created, image, mounts, env)
                return _capture([DOCKER, 'start', '--attach', created], env)
            finally:
                recorded = _container_id(cidfile)
                if recorded is not None:
                    _remove(recorded, env)
    finally:
        signal.signal(signal.SIGTERM, previous)
