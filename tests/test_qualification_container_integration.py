"""Exercise the actual container boundary when a pinned test image is supplied."""
import os
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from code_health.qualification_container import run_candidate
from code_health.build_release_bundle import build_bundle, runtime_files
from code_health.qualification_controller import qualification_cases
from code_health.qualification_results import collect_bundle_results, validate_results

IMAGE = os.environ.get('QUALIFICATION_TEST_IMAGE')


@unittest.skipUnless(IMAGE, 'requires a pinned image and a real Docker daemon')
class ContainerBoundaryTests(unittest.TestCase):
    def test_candidate_exit_cannot_claim_a_successful_test(self):
        with tempfile.TemporaryDirectory(prefix='qualification-adversary-') as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            candidate = root / 'candidate'
            candidate.mkdir(mode=0o755)
            package = candidate / 'code_health'
            package.mkdir(mode=0o755)
            (package / 'cli.py').write_text('import sys\nsys.exit(0)\n')
            bridge = Path(__file__).resolve().parents[1] / 'code_health/qualification_bridge.py'
            request = {'schemaVersion': 1, 'caseId': 'config-valid', 'operation': 'config', 'arguments': {}}
            with self.assertRaises(ValueError):
                run_candidate(image=IMAGE, candidate=candidate, bridge=bridge,
                              case_id='config-valid', request=request)

    def test_complete_candidate_observations_are_checked_outside_the_container(self):
        root = Path(__file__).resolve().parents[1]
        import subprocess
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
        allowed = runtime_files(root, commit)
        bundle = build_bundle(root, commit, allowed, download_readers=True)
        digest = hashlib.sha256(bundle).hexdigest()
        observations = collect_bundle_results(bundle=bundle, expected_sha256=digest, policy_commit=commit,
            allowed_files=allowed, image=IMAGE, bridge=root / 'code_health/qualification_bridge.py',
            run_id=123, run_attempt=1)
        self.assertEqual(len(qualification_cases()),
                         validate_results(observations, run_id=123, run_attempt=1, candidate_sha256=digest))

    def test_effective_container_restrictions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / 'candidate'
            candidate.mkdir(mode=0o755)
            candidate.chmod(0o755)
            bridge = root / 'probe.py'
            bridge.write_text('''import json, os, socket, sys
request = json.load(sys.stdin)
status = {}
with open('/proc/self/status') as source:
    for line in source:
        key, _, value = line.partition(':')
        if key in ('CapEff', 'NoNewPrivs', 'Seccomp'):
            status[key] = value.strip()
mounts = {}
with open('/proc/self/mountinfo') as source:
    for line in source:
        fields = line.split()
        if fields[4] in ('/', '/candidate'):
            mounts[fields[4]] = fields[5].split(',')
with socket.socket() as connection:
    connection.settimeout(2)
    try:
        network_blocked = connection.connect_ex(('1.1.1.1', 443)) != 0
    except OSError:
        network_blocked = True
with open('/tmp/probe', 'w') as target:
    target.write('temporary storage works')
value = {'uid': os.getuid(), 'caps': status.get('CapEff'), 'noNewPrivileges': status.get('NoNewPrivs'),
         'seccomp': status.get('Seccomp'), 'candidateReadOnly': 'ro' in mounts.get('/candidate', []),
         'rootReadOnly': 'ro' in mounts.get('/', []), 'networkBlocked': network_blocked,
         'secretAbsent': 'QUALIFICATION_TEST_SECRET' not in os.environ}
print(json.dumps({'schemaVersion': 1, 'caseId': request['caseId'], 'outcome': 'returned', 'value': value}))
''')
            bridge.chmod(0o644)
            with patch.dict(os.environ, {'QUALIFICATION_TEST_SECRET': 'synthetic-secret'}):
                observation = run_candidate(image=IMAGE, candidate=candidate, bridge=bridge, case_id='boundary-probe',
                                            request={'caseId': 'boundary-probe'})
            self.assertEqual(observation['value'], {'uid': 65534, 'caps': '0000000000000000',
                'noNewPrivileges': '1', 'seccomp': '2', 'candidateReadOnly': True,
                'rootReadOnly': True, 'networkBlocked': True, 'secretAbsent': True})


if __name__ == '__main__':
    unittest.main()
