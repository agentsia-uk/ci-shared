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

from .qualification_container import DOCKER, ENVIRONMENT, _require_seccomp, docker_environment
from . import scanner_recovery

IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
CONTAINER = re.compile(r'[0-9a-f]{64}\Z')
MAX_LOG_BYTES = 64 * 1024 * 1024
OUTPUT_NAME = '.scanner-stdout'
CONTAINER_USER = '10001:10001'


def _make_readable(root):
    for _, directories, files, directory_fd in os.fwalk(root, follow_symlinks=False):
        metadata = os.fstat(directory_fd)
        if metadata.st_uid != os.geteuid():
            raise ValueError('scanner input directory has an unexpected owner')
        os.fchmod(directory_fd, stat.S_IMODE(metadata.st_mode) | 0o555)
        for name in files:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
                raise ValueError('scanner input contains an unsafe file')
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
            try:
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise ValueError('scanner input changed while preparing it')
                os.fchmod(fd, stat.S_IMODE(opened.st_mode) | 0o444)
            finally:
                os.close(fd)


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
        try:
            child.wait(timeout=5)
        finally:
            child.stdout.close()
            child.stderr.close()


def _read_output(directory):
    target = Path(directory) / OUTPUT_NAME
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_LOG_BYTES:
            raise ValueError('invalid scanner output file')
        chunks, remaining = [], before.st_size
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                raise ValueError('scanner output is truncated')
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        current = target.lstat()
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or
                (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)):
            raise ValueError('scanner output changed while reading')
        target.unlink()
        return b''.join(chunks)
    finally:
        os.close(fd)


def _inspect(container, image, mounts, env):
    raw = subprocess.run([DOCKER, 'inspect', '--format', '{{json .}}', container], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=True).stdout
    if len(raw) > 1024 * 1024:
        raise ValueError('scanner container inspection exceeds its size limit')
    try:
        record = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('invalid scanner container inspection') from error
    if not isinstance(record, dict) or record.get('Id') != container:
        raise ValueError('scanner container inspection identity differs')
    _validate_inspection(record, image, mounts)


def _validate_inspection(record, image, mounts):
    try:
        host = record['HostConfig']
        actual = {(item['Source'], item['Destination'], item['RW']) for item in record['Mounts']}
        expected = {(str(source), target, mode != 'readonly') for source, target, mode in mounts}
        if (record['Image'] != image or record['Config']['User'] != CONTAINER_USER
                or host['NetworkMode'] != 'none' or host['ReadonlyRootfs'] is not True
                or host['Privileged'] is not False or host['AutoRemove'] is not True or host['IpcMode'] != 'none'
                or host['CapDrop'] != ['ALL'] or 'no-new-privileges' not in host['SecurityOpt']
                or 'seccomp=builtin' not in host['SecurityOpt'] or actual != expected):
            raise ValueError('scanner container restrictions differ from the required policy')
    except (KeyError, TypeError) as error:
        raise ValueError('invalid scanner container inspection') from error


def _present(container, env):
    listing = subprocess.run([DOCKER, 'ps', '--all', '--no-trunc', '--filter', 'id=' + container,
                              '--format', '{{.ID}}'], env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=30, check=True).stdout
    if listing.strip() not in (b'', container.encode()):
        raise ValueError('invalid scanner container lookup')
    return bool(listing.strip())


def _remove(container, env):
    result = subprocess.run([DOCKER, 'rm', '--force', container], env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=60)
    if result.returncode and _present(container, env):
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
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise ValueError('scanner directories must be owned by the caller')
        paths.append(path)
    if any(a == b or a in b.parents or b in a.parents for i, a in enumerate(paths) for b in paths[i + 1:]):
        raise ValueError('scanner directories must not overlap')
    labels = scanner_recovery.labels(paths)
    _make_readable(paths[0])
    _make_readable(paths[1])
    os.chmod(paths[2], 0o777)
    env = docker_environment()
    _require_seccomp(env)
    mounts = [(paths[0], '/source', 'readonly'), (paths[1], '/opt/code-health/readers', 'readonly'),
              (paths[2], '/output', '')]
    command = [DOCKER, 'create', '--rm', '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges', '--security-opt', 'seccomp=builtin', '--pids-limit', '256',
               '--memory', '8g', '--memory-swap', '8g', '--cpus', '4', '--user', CONTAINER_USER,
               '--ipc', 'none', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=4g',
               '-e', 'HOME=/tmp', '-e', 'DESLOPPIFY_ROOT=/source', '-e', 'CI=true', '-e', 'NO_COLOR=1',
               '-e', 'npm_config_yes=false']
    for key, value in sorted(labels.items()):
        command.extend(['--label', key + '=' + value])
    for host, target, mode in mounts:
        command.extend(['--mount', f'type=bind,src={host},dst={target}' + (',' + mode if mode else '')])
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
                _capture([DOCKER, 'start', '--attach', created], env)
                return _read_output(paths[2])
            finally:
                recorded = _container_id(cidfile)
                if recorded is not None:
                    _remove(recorded, env)
    finally:
        signal.signal(signal.SIGTERM, previous)
