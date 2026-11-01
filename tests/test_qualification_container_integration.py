"""Exercise the actual container boundary when a pinned test image is supplied."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from code_health.qualification_container import run_candidate

IMAGE = os.environ.get('QUALIFICATION_TEST_IMAGE')


@unittest.skipUnless(IMAGE, 'requires a pinned image and a real Docker daemon')
class ContainerBoundaryTests(unittest.TestCase):
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
