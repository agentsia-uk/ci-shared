from pathlib import Path
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from code_health import scanner_container


class ScannerContainerTests(unittest.TestCase):
    def test_mount_permissions_preserve_executables_and_never_follow_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.mkdir(mode=0o700)
            executable = source / 'tool'
            executable.write_text('sample')
            executable.chmod(0o700)
            outside = root / 'outside'
            outside.write_text('keep')
            outside.chmod(0o600)
            (source / 'link').symlink_to(outside)
            scanner_container._make_readable(source)
            self.assertEqual(0o755, source.stat().st_mode & 0o777)
            self.assertEqual(0o744, executable.stat().st_mode & 0o777)
            self.assertEqual(0o600, outside.stat().st_mode & 0o777)

    def test_only_the_caller_owned_rootless_docker_socket_is_accepted(self):
        from types import SimpleNamespace
        from code_health.qualification_container import docker_environment
        with patch.dict(os.environ, {'DOCKER_HOST': 'tcp://example.invalid:2375'}):
            with self.assertRaisesRegex(ValueError, 'rootless socket'):
                docker_environment()
        expected = f'unix:///run/user/{os.getuid()}/docker.sock'
        socket = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=os.getuid())
        with patch.dict(os.environ, {'DOCKER_HOST': expected, 'GH_TOKEN': 'private'}), \
                patch('code_health.qualification_container.os.stat', return_value=socket):
            env = docker_environment()
        self.assertEqual(expected, env['DOCKER_HOST'])
        self.assertNotIn('GH_TOKEN', env)

    def test_capture_cleanup_wait_is_bounded(self):
        real_popen = subprocess.Popen
        children = []
        def stalled_cleanup(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            original_wait = child.wait
            def wait(timeout=None):
                if timeout == 5:
                    raise subprocess.TimeoutExpired(args[0], timeout)
                return original_wait(timeout=timeout)
            child.wait = wait
            children.append(child)
            return child
        with patch('code_health.scanner_container.subprocess.Popen', side_effect=stalled_cleanup), self.assertRaises(subprocess.TimeoutExpired):
            scanner_container._capture([sys.executable, '-c', 'print("ok")'], {'PATH': os.defpath})
        self.assertTrue(children[0].stdout.closed)

    def test_automatic_removal_is_confirmed_before_accepting_a_missing_container(self):
        failed = subprocess.CompletedProcess([], 1)
        absent = subprocess.CompletedProcess([], 0, stdout=b'')
        with patch.object(scanner_container.subprocess, 'run', side_effect=[failed, absent]):
            scanner_container._remove('a' * 64, {})
        unavailable = subprocess.CalledProcessError(1, 'docker')
        with patch.object(scanner_container.subprocess, 'run', side_effect=[failed, unavailable]):
            with self.assertRaises(subprocess.CalledProcessError):
                scanner_container._remove('a' * 64, {})

    def test_scanner_output_keeps_standard_error_out_of_json_and_is_bounded(self):
        command = [sys.executable, '-c', 'import sys; print("{}") ; print("warning", file=sys.stderr)']
        self.assertEqual(b'{}\n', scanner_container._capture(command, {'PATH': os.defpath}))
        with patch.object(scanner_container, 'MAX_LOG_BYTES', 4), self.assertRaisesRegex(ValueError, 'exceeds'):
            scanner_container._capture(command, {'PATH': os.defpath})

    def test_inspection_rejects_network_even_when_other_settings_match(self):
        image = 'sha256:' + 'b' * 64
        mounts = [(Path('/source'), '/source', 'readonly'), (Path('/readers'), '/readers', 'readonly'),
                  (Path('/output'), '/output', '')]
        record = {'Id': 'a' * 64, 'Image': image, 'Config': {'User': scanner_container.CONTAINER_USER},
                  'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'Privileged': False, 'AutoRemove': True,
                                 'IpcMode': 'none', 'CapDrop': ['ALL'],
                                 'SecurityOpt': ['no-new-privileges', 'seccomp=builtin']},
                  'Mounts': [{'Source': str(source), 'Destination': target, 'RW': mode != 'readonly'}
                             for source, target, mode in mounts]}
        response = subprocess.CompletedProcess([], 0, stdout=json.dumps(record).encode())
        with patch.object(scanner_container.subprocess, 'run', return_value=response):
            scanner_container._inspect('a' * 64, image, mounts, {})
            record['HostConfig']['NetworkMode'] = 'bridge'
            response.stdout = json.dumps(record).encode()
            with self.assertRaisesRegex(ValueError, 'restrictions differ'):
                scanner_container._inspect('a' * 64, image, mounts, {})

    def test_rejects_mutable_images_and_overlapping_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source, readers, output = (root / name for name in ('source', 'readers', 'output'))
            for path in (source, readers, output):
                path.mkdir(mode=0o700)
            with patch.object(scanner_container.os, 'geteuid', return_value=root.stat().st_uid):
                with self.assertRaisesRegex(ValueError, 'exact image'):
                    scanner_container.run_scanner(image='latest', source=source, readers=readers, output=output,
                                                  arguments=[])
                with self.assertRaisesRegex(ValueError, 'must not overlap'):
                    scanner_container.run_scanner(image='sha256:' + 'a' * 64, source=source, readers=source,
                                                  output=output, arguments=[])

    def test_removes_container_when_scanner_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source, readers, output = (root / name for name in ('source', 'readers', 'output'))
            for path in (source, readers, output):
                path.mkdir(mode=0o700)
            created = subprocess.CompletedProcess([], 0, stdout=b'a' * 64)
            def docker(command, **_kwargs):
                if 'create' in command:
                    Path(command[command.index('--cidfile') + 1]).write_text('a' * 64)
                return created
            with patch.object(scanner_container.os, 'geteuid', return_value=root.stat().st_uid), \
                    patch.object(scanner_container, '_require_seccomp'), \
                    patch.object(scanner_container.scanner_recovery, 'labels', return_value={}), \
                    patch.object(scanner_container, '_inspect'), \
                    patch.object(scanner_container.subprocess, 'run', side_effect=docker) as run, \
                    patch.object(scanner_container, '_capture', side_effect=TimeoutError('timeout')):
                with self.assertRaises(TimeoutError):
                    scanner_container.run_scanner(image='sha256:' + 'b' * 64, source=source, readers=readers,
                                                  output=output, arguments=[])
            self.assertEqual([scanner_container.DOCKER, 'rm', '--force', 'a' * 64], run.call_args_list[-1].args[0])

    def test_termination_removes_the_created_container(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source, readers, output = (root / name for name in ('source', 'readers', 'output'))
            for path in (source, readers, output):
                path.mkdir(mode=0o700)
            def docker(command, **_kwargs):
                if 'create' in command:
                    Path(command[command.index('--cidfile') + 1]).write_text('a' * 64)
                return subprocess.CompletedProcess(command, 0, stdout=b'a' * 64)
            previous = signal.getsignal(signal.SIGTERM)
            with patch.object(scanner_container.os, 'geteuid', return_value=root.stat().st_uid), \
                    patch.object(scanner_container, '_require_seccomp'), \
                    patch.object(scanner_container.scanner_recovery, 'labels', return_value={}), \
                    patch.object(scanner_container, '_inspect'), \
                    patch.object(scanner_container.subprocess, 'run', side_effect=docker) as run, \
                    patch.object(scanner_container, '_capture', side_effect=lambda *_: os.kill(os.getpid(), signal.SIGTERM)):
                with self.assertRaisesRegex(InterruptedError, 'cancelled'):
                    scanner_container.run_scanner(image='sha256:' + 'b' * 64, source=source, readers=readers,
                                                  output=output, arguments=[])
            self.assertEqual(previous, signal.getsignal(signal.SIGTERM))
            self.assertEqual([scanner_container.DOCKER, 'rm', '--force', 'a' * 64], run.call_args_list[-1].args[0])


if __name__ == '__main__':
    unittest.main()
