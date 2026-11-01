import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from code_health import scanner_container, scanner_recovery

BOOT = '12345678-1234-1234-1234-123456789abc'


def container(task, identity, pid, ident):
    tags = {scanner_recovery.PREFIX + key: value for key, value in {
        'task': str(task), 'identity': identity, 'boot': BOOT, 'pid': str(pid), 'start': '99'}.items()}
    mounts = [{'Source': str(task / name), 'Destination': target, 'RW': writable} for name, target, writable in
              [('source', '/source', False), ('readers', '/opt/code-health/readers', False), ('output', '/output', True)]]
    return {'Id': ident, 'Image': 'sha256:' + 'b' * 64,
            'Config': {'Labels': tags, 'User': f'{os.getuid()}:{os.getgid()}'}, 'Mounts': mounts}


class ScannerRecoveryTests(unittest.TestCase):
    def test_live_owner_is_preserved_and_dead_owner_is_recovered(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            live = parent / 'code-health-task.Live1234'
            stale = parent / 'code-health-task.Dead1234'
            for task in (live, stale):
                task.mkdir(mode=0o700)
            def identity(path):
                info = path.stat()
                return f'{info.st_dev}:{info.st_ino}'
            live_record = container(live, identity(live), 100, 'a' * 64)
            stale_record = container(stale, identity(stale), 101, 'c' * 64)
            replies = [subprocess.CompletedProcess([], 0, stdout=(('a' * 64) + '\n' + ('c' * 64) + '\n').encode()),
                       subprocess.CompletedProcess([], 0, stdout=json.dumps(live_record).encode()),
                       subprocess.CompletedProcess([], 0, stdout=json.dumps(stale_record).encode())]
            with patch.object(scanner_recovery.subprocess, 'run', side_effect=replies), \
                    patch.object(scanner_recovery, '_boot', return_value=BOOT), \
                    patch.object(scanner_recovery, '_start', side_effect=lambda pid: '99' if pid == 100 else '100'), \
                    patch.object(scanner_container, '_validate_inspection'), patch.object(scanner_container, '_remove') as remove, \
                    patch.object(scanner_recovery, 'cleanup') as clean:
                scanner_recovery.sweep(parent)
            remove.assert_called_once_with('c' * 64, scanner_recovery.ENVIRONMENT)
            clean.assert_called_once_with(parent, stale, identity(stale))
            self.assertTrue(live.is_dir())

    def test_changed_task_is_preserved_while_its_dead_container_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            task = parent / 'code-health-task.Dead1234'
            task.mkdir(mode=0o700)
            (task / 'sentinel').write_text('keep')
            record = container(task, '1:2', 101, 'c' * 64)
            replies = [subprocess.CompletedProcess([], 0, stdout=('c' * 64).encode()),
                       subprocess.CompletedProcess([], 0, stdout=json.dumps(record).encode())]
            with patch.object(scanner_recovery.subprocess, 'run', side_effect=replies), \
                    patch.object(scanner_recovery, '_boot', return_value=BOOT), \
                    patch.object(scanner_recovery, '_start', return_value=None), \
                    patch.object(scanner_container, '_validate_inspection'), patch.object(scanner_container, '_remove') as remove, \
                    patch.object(scanner_recovery, 'cleanup') as clean:
                scanner_recovery.sweep(parent)
            remove.assert_called_once()
            clean.assert_not_called()
            self.assertEqual('keep', (task / 'sentinel').read_text())

    def test_input_outside_managed_task_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            task = parent / 'code-health-task.Live1234'
            task.mkdir(mode=0o700)
            info = task.stat()
            env = {'RUNNER_TEMP': str(parent), 'CODE_HEALTH_TASK_DIR': str(task),
                   'CODE_HEALTH_TASK_ID': f'{info.st_dev}:{info.st_ino}'}
            with patch.dict(os.environ, env), self.assertRaisesRegex(ValueError, 'managed task'):
                scanner_recovery.labels([parent])


if __name__ == '__main__':
    unittest.main()
