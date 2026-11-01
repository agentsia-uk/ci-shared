"""Identify abandoned scanner containers without disturbing live jobs."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from .cleanup_task import cleanup
from .qualification_container import DOCKER, ENVIRONMENT

PREFIX = 'org.agentsia.code-health.'
SHA = re.compile(r'[0-9a-f]{64}\Z')
TASK = re.compile(r'code-health-task\.[A-Za-z0-9_]{8}\Z')
IDENTITY = re.compile(r'[0-9]+:[0-9]+\Z')
BOOT = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')


def _boot():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if not BOOT.fullmatch(value):
        raise ValueError('invalid host boot identity')
    return value


def _start(pid):
    try:
        raw = Path(f'/proc/{pid}/stat').read_text()
    except FileNotFoundError:
        return None
    end = raw.rfind(')')
    fields = raw[end + 2:].split() if end >= 0 else []
    if len(fields) < 20 or not fields[19].isdigit():
        raise ValueError('invalid process identity')
    return None if fields[0] == 'Z' else fields[19]


def _namespace():
    metadata = os.stat('/proc/self/ns/pid')
    return f'{metadata.st_dev}:{metadata.st_ino}'


def _task(parent, path, identity, *, missing_ok=False):
    parent = Path(parent).resolve(strict=True)
    path = Path(path).absolute()
    if path.parent != parent or not TASK.fullmatch(path.name) or not IDENTITY.fullmatch(identity):
        raise ValueError('invalid scanner task identity')
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return path
        raise
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
            or identity != f'{metadata.st_dev}:{metadata.st_ino}'):
        raise ValueError('scanner task identity changed')
    return path


def labels(paths):
    parent, task, identity = (os.environ.get(key, '') for key in
                              ('RUNNER_TEMP', 'CODE_HEALTH_TASK_DIR', 'CODE_HEALTH_TASK_ID'))
    task = _task(parent, task, identity)
    if any(not path.is_relative_to(task) for path in paths):
        raise ValueError('scanner inputs must belong to the managed task')
    start = _start(os.getpid())
    if start is None:
        raise ValueError('scanner owner identity is unavailable')
    return {PREFIX + 'task': str(task), PREFIX + 'identity': identity,
            PREFIX + 'boot': _boot(), PREFIX + 'namespace': _namespace(),
            PREFIX + 'pid': str(os.getpid()), PREFIX + 'start': start}


def sweep(parent):
    """Recover only containers whose exact owner is no longer alive."""
    from .scanner_container import _present, _remove, _validate_inspection
    parent = Path(parent).resolve(strict=True)
    listing = subprocess.run([DOCKER, 'ps', '--all', '--no-trunc', '--filter', 'label=' + PREFIX + 'task',
                              '--format', '{{.ID}}'], env=ENVIRONMENT, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=30, check=True).stdout
    if len(listing) > 128 * 1024:
        raise ValueError('scanner container inventory exceeds its limit')
    groups = {}
    for raw in listing.splitlines():
        container = raw.decode('ascii')
        if not SHA.fullmatch(container):
            raise ValueError('invalid scanner container inventory')
        inspected = subprocess.run([DOCKER, 'inspect', '--format', '{{json .}}', container], env=ENVIRONMENT,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
        if inspected.returncode:
            if not _present(container, ENVIRONMENT):
                continue
            raise ValueError('scanner container could not be inspected')
        data = inspected.stdout
        if len(data) > 1024 * 1024:
            raise ValueError('scanner container inspection exceeds its limit')
        record = json.loads(data)
        if record.get('Id') != container:
            raise ValueError('scanner container identity differs from inventory')
        if record['Config']['User'] != f'{os.getuid()}:{os.getgid()}':
            continue
        tags = record['Config']['Labels']
        if not isinstance(tags, dict):
            continue
        values = [tags.get(PREFIX + key) for key in ('task', 'identity', 'boot', 'namespace', 'pid', 'start')]
        if any(not isinstance(value, str) for value in values):
            continue
        task_text, identity, boot, namespace, pid, start = values
        if (not BOOT.fullmatch(boot) or not IDENTITY.fullmatch(namespace) or not pid.isascii()
                or not pid.isdecimal() or len(pid) > 10 or int(pid) < 1
                or not start.isascii() or not start.isdecimal() or len(start) > 20):
            continue
        task = Path(task_text).absolute()
        if task.parent != parent:
            continue
        if not TASK.fullmatch(task.name) or not IDENTITY.fullmatch(identity):
            raise ValueError('invalid scanner task identity')
        try:
            _task(parent, task, identity, missing_ok=True)
            cleanup_allowed = task.exists()
        except ValueError:
            cleanup_allowed = False
        mounts = []
        for item in record['Mounts']:
            source = Path(item['Source'])
            if not source.is_absolute() or source.resolve() != source or not source.is_relative_to(task):
                raise ValueError('scanner container mount is outside its task')
            mounts.append((source, item['Destination'], '' if item['RW'] else 'readonly'))
        if {(target, mode) for _, target, mode in mounts} != {
                ('/source', 'readonly'), ('/opt/code-health/readers', 'readonly'), ('/output', '')}:
            raise ValueError('unexpected scanner container mounts')
        _validate_inspection(record, record['Image'], mounts)
        alive = boot == _boot() and (namespace != _namespace() or _start(int(pid)) == start)
        groups.setdefault((task, identity), []).append((container, alive, cleanup_allowed))
    for (task, identity), containers in groups.items():
        if any(alive for _, alive, _ in containers):
            continue
        for container, _, _ in containers:
            _remove(container, ENVIRONMENT)
        if all(allowed for _, _, allowed in containers):
            cleanup(parent, task, identity)


if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        raise SystemExit('expected runner temporary directory')
    sweep(sys.argv[1])
