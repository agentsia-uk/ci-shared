"""Run a real sample scan with verified readers in a locked-down container."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from code_health import prepare_readers, scanner_container, scanner_recovery
from code_health.cli import scan

IMAGE = os.environ.get('CODE_HEALTH_SCANNER_IMAGE')


@unittest.skipUnless(IMAGE, 'requires a prepared scanner image and Docker')
class ScannerContainerTests(unittest.TestCase):
    def test_recovery_preserves_live_owner_and_removes_abandoned_container(self):
        image_id = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', IMAGE],
                                           text=True, timeout=30).strip()
        containers = []
        with tempfile.TemporaryDirectory(prefix='scanner-recovery-') as temporary:
            parent = Path(temporary).resolve()
            try:
                tasks = []
                for suffix, start in [('Live1234', scanner_recovery._start(os.getpid())), ('Dead1234', '0')]:
                    task = parent / ('code-health-task.' + suffix)
                    task.mkdir(mode=0o700)
                    for name in ('source', 'readers', 'output'):
                        (task / name).mkdir(mode=0o700)
                    info = task.stat()
                    labels = {'task': str(task), 'identity': f'{info.st_dev}:{info.st_ino}',
                              'boot': scanner_recovery._boot(), 'namespace': scanner_recovery._namespace(),
                              'uid': str(os.getuid()), 'gid': str(os.getgid()), 'pid': str(os.getpid()), 'start': start}
                    command = ['docker', 'create', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
                               '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                               '--security-opt', 'seccomp=builtin', '--ipc', 'none', '--user', '10001:10001']
                    for key, value in labels.items():
                        command.extend(['--label', scanner_recovery.PREFIX + key + '=' + value])
                    for name, target, mode in [('source', '/source', ',readonly'),
                                               ('readers', '/opt/code-health/readers', ',readonly'),
                                               ('output', '/output', '')]:
                        command.extend(['--mount', f'type=bind,src={task / name},dst={target}{mode}'])
                    command.extend([image_id, '--help'])
                    containers.append(subprocess.check_output(command, text=True, timeout=30).strip())
                    tasks.append(task)
                scanner_recovery.sweep(parent)
                self.assertEqual(0, subprocess.run(['docker', 'inspect', containers[0]], stdout=subprocess.DEVNULL,
                                                   stderr=subprocess.DEVNULL, timeout=30).returncode)
                self.assertTrue(tasks[0].exists())
                self.assertNotEqual(0, subprocess.run(['docker', 'inspect', containers[1]], stdout=subprocess.DEVNULL,
                                                      stderr=subprocess.DEVNULL, timeout=30).returncode)
                self.assertFalse(tasks[1].exists())
            finally:
                for container in containers:
                    subprocess.run(['docker', 'rm', '--force', container], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=30)

    def test_sample_scan_uses_read_only_source_and_no_network(self):
        with tempfile.TemporaryDirectory(prefix='scanner-container-') as temporary:
            parent = Path(temporary).resolve()
            root = parent / 'code-health-task.Abc12345'
            root.mkdir(mode=0o700)
            source, output, readers = (root / name for name in ('source', 'output', 'readers'))
            source.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            readers.mkdir(mode=0o700)
            with patch.object(sys, 'argv', ['prepare-readers', '--destination', str(readers)]):
                prepare_readers.main()
            (source / 'sample.py').write_text('def answer():\n    return 42\n')
            config = source / '.desloppify'
            config.mkdir(mode=0o700)
            (config / 'config.json').write_text(json.dumps({'generate_scorecard': False, 'trust_plugins': False,
                'hermes_enabled': False, 'hermes_models': {}, 'languages': {}, 'ignore': [], 'zone_overrides': {},
                'exclude': [], 'commit_tracking_enabled': False, 'target_strict_score': 90}))
            image_id = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', IMAGE],
                                               text=True, timeout=30).strip()
            output.rmdir()
            area = {'id': 'sample', 'language': 'python', 'path': '.', 'exclusions': []}
            metadata = root.stat()
            env = {'RUNNER_TEMP': str(parent), 'CODE_HEALTH_TASK_DIR': str(root),
                   'CODE_HEALTH_TASK_ID': f'{metadata.st_dev}:{metadata.st_ino}'}
            def diagnostic(command, environment):
                result = subprocess.run(command, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
                if result.returncode:
                    raise ValueError((result.stdout + result.stderr).decode(errors='replace')[-5000:])
                return result.stdout
            capture = diagnostic if os.environ.get('CODE_HEALTH_ROOTLESS_DIAGNOSTIC') else scanner_container._capture
            with patch.dict(os.environ, env), patch.object(scanner_container, '_capture', side_effect=capture):
                status, state = scan(source, area, output, [area], scanner_image=image_id, readers=readers)
            self.assertTrue((output / 'state.json').is_file())
            self.assertIsInstance(status, dict)
            self.assertIsInstance(state, dict)


if __name__ == '__main__':
    unittest.main()
