import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from code_health.qualification_container import docker_capture, run_candidate


class QualificationContainerTests(unittest.TestCase):
    def test_docker_response_is_bounded_during_read_and_on_timeout(self):
        env = {'PATH': os.defpath}
        command = [sys.executable, '-c', 'import sys; sys.stdout.write("x" * 1000000); sys.stdout.flush()']
        with self.assertRaisesRegex(ValueError, 'exceeds'):
            docker_capture(command, env=env, limit=32, timeout=3)
        command = [sys.executable, '-c', 'import time; time.sleep(5)']
        with self.assertRaises(subprocess.TimeoutExpired):
            docker_capture(command, env=env, limit=32, timeout=0.1)
        command = [sys.executable, '-c', 'import sys; print("ok"); sys.exit(4)']
        self.assertEqual(4, docker_capture(command, env=env, limit=32, check=False).returncode)
        with self.assertRaises(subprocess.CalledProcessError):
            docker_capture(command, env=env, limit=32)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.candidate = root / 'candidate'
        self.candidate.mkdir()
        self.bridge = root / 'bridge.py'
        self.bridge.write_text('# synthetic bridge\n')
        self.readers = root / 'readers'
        self.readers.mkdir()
        self.log = root / 'calls.jsonl'
        self.mode = root / 'mode'
        self.mode.write_text('ok')
        self.docker = root / 'docker'
        self.docker.write_text(f'''#!{sys.executable}
import json, os, sys, time
from pathlib import Path
log = Path({str(self.log)!r})
with log.open('a') as f:
    f.write(json.dumps({{'args': sys.argv[1:], 'secret_inherited': 'TEST_SECRET' in os.environ}}) + '\\n')
mode = Path({str(self.mode)!r}).read_text()
if sys.argv[1] == 'info':
    if mode == 'no-seccomp':
        print(json.dumps(['name=apparmor']))
    elif mode == 'invalid-info':
        print('invalid')
    else:
        print(json.dumps(['name=seccomp,profile=builtin']))
elif sys.argv[1] == 'create':
    Path(sys.argv[sys.argv.index('--cidfile') + 1]).write_text('a' * 64)
    print('x' * 1000000 if mode == 'oversize-create' else 'a' * 64)
elif sys.argv[1] == 'start':
    request = json.load(sys.stdin)
    if mode == 'timeout':
        time.sleep(5)
    if mode == 'oversize':
        sys.stdout.write('x' * 70000)
    elif mode == 'invalid-json':
        print('not-json')
    elif mode == 'wrong-case':
        print(json.dumps({{'schemaVersion': 1, 'caseId': 'another', 'outcome': 'returned', 'value': 7}}))
    elif mode == 'failure':
        sys.exit(5)
    else:
        print(json.dumps({{'schemaVersion': 1, 'caseId': request['caseId'], 'outcome': 'returned', 'value': 7}}))
elif sys.argv[1] == 'rm' and mode == 'cleanup-fails':
    sys.exit(3)
''')
        self.docker.chmod(0o700)
        self.image = 'example/policy@sha256:' + 'a' * 64

    def run_case(self, timeout=3):
        with patch('code_health.qualification_container.DOCKER', str(self.docker)), \
             patch.dict(os.environ, {'TEST_SECRET': 'must-not-be-inherited'}):
            return run_candidate(image=self.image, candidate=self.candidate, bridge=self.bridge,
                                 readers=self.readers, case_id='case-one', request={'caseId': 'case-one'}, timeout=timeout)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_isolated_container_and_bounded_protocol(self):
        self.assertEqual(self.run_case()['value'], 7)
        calls = self.calls()
        self.assertEqual([entry['args'][0] for entry in calls], ['info', 'create', 'start', 'rm'])
        self.assertTrue(all(not entry['secret_inherited'] for entry in calls))
        args = calls[1]['args']
        for pair in [('--pull', 'never'), ('--network', 'none'), ('--cap-drop', 'ALL'), ('--user', '65534:65534'),
                     ('--security-opt', 'no-new-privileges'), ('--security-opt', 'seccomp=builtin')]:
            self.assertTrue(any(args[i:i+2] == list(pair) for i in range(len(args)-1)))
        self.assertIn('--read-only', args)
        self.assertEqual(sum('readonly' in arg for arg in args), 3)
        self.assertIn(self.image, args)

    def test_failure_or_timeout_removes_the_exact_container(self):
        for mode, error in [('oversize', ValueError), ('invalid-json', ValueError),
                            ('wrong-case', ValueError), ('failure', ValueError), ('timeout', TimeoutError)]:
            with self.subTest(mode=mode):
                self.mode.write_text(mode)
                self.log.unlink(missing_ok=True)
                with self.assertRaises(error):
                    self.run_case(timeout=0.2 if mode == 'timeout' else 3)
                self.assertEqual(self.calls()[-1]['args'], ['rm', '--force', 'a' * 64])

    def test_failed_cleanup_refuses_a_successful_observation(self):
        self.mode.write_text('cleanup-fails')
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_case()

    def test_oversized_create_response_removes_recorded_container(self):
        self.mode.write_text('oversize-create')
        with self.assertRaisesRegex(ValueError, 'exceeds'):
            self.run_case()
        self.assertEqual(self.calls()[-1]['args'], ['rm', '--force', 'a' * 64])

    def test_missing_or_invalid_seccomp_support_refuses_creation(self):
        for mode in ('no-seccomp', 'invalid-info'):
            with self.subTest(mode=mode):
                self.mode.write_text(mode)
                self.log.unlink(missing_ok=True)
                with self.assertRaises(ValueError):
                    self.run_case()
                self.assertEqual([entry['args'][0] for entry in self.calls()], ['info'])

    def test_mutable_images_and_large_requests_are_refused_before_creation(self):
        with patch('code_health.qualification_container.DOCKER', str(self.docker)):
            for image, request in [('example/policy:latest', {'caseId': 'case-one'}),
                                   (self.image, {'caseId': 'case-one', 'payload': 'x' * 70000})]:
                with self.subTest(image=image), self.assertRaises(ValueError):
                    run_candidate(image=image, candidate=self.candidate, bridge=self.bridge, readers=self.readers,
                                  case_id='case-one', request=request)
        self.assertFalse(self.log.exists())


if __name__ == '__main__':
    unittest.main()
