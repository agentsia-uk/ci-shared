import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


class ComparisonCommitTests(unittest.TestCase):
    def select(self, event_name, event, candidate='a' * 40):
        workflow = yaml.load(Path('.github/workflows/shared-code-health.yml').read_text(), Loader=yaml.BaseLoader)
        steps = workflow['jobs']['code-health']['steps']
        shell = next(step['run'] for step in steps if step.get('id') == 'commits')
        program = shell.split("python - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            event_path, output_path = Path(temporary) / 'event', Path(temporary) / 'output'
            event_path.write_text(json.dumps(event))
            output_path.touch()
            env = dict(os.environ, GITHUB_EVENT_PATH=str(event_path), GITHUB_OUTPUT=str(output_path),
                       GITHUB_EVENT_NAME=event_name, CANDIDATE_SHA=candidate)
            process = subprocess.run([sys.executable, '-I', '-c', program], env=env,
                                     capture_output=True, timeout=10)
            return process.returncode, output_path.read_text()

    def test_pull_request_and_merge_group_keep_their_comparison_commits(self):
        base, head = 'b' * 40, 'a' * 40
        self.assertEqual((0, f'base={base}\nhead={head}\n'),
                         self.select('pull_request', {'pull_request': {'base': {'sha': base}}}))
        self.assertEqual((0, f'base={base}\nhead={head}\n'),
                         self.select('merge_group', {'merge_group': {'base_sha': base, 'head_sha': head}}))

    def test_only_exact_default_branch_push_is_a_history_candidate(self):
        head = 'a' * 40
        event = {'deleted': False, 'repository': {'default_branch': 'main'},
                 'ref': 'refs/heads/main', 'after': head}
        self.assertEqual((0, f'base={head}\nhead={head}\n'), self.select('push', event))
        for changed in [{'deleted': True}, {'ref': 'refs/heads/feature'}, {'ref': 'refs/tags/main'},
                        {'after': 'b' * 40}, {'repository': {'default_branch': ''}}, {'deleted': None}]:
            with self.subTest(changed=changed):
                code, output = self.select('push', {**event, **changed})
                self.assertNotEqual(0, code)
                self.assertEqual('', output)
        code, output = self.select('schedule', event)
        self.assertNotEqual(0, code)
        self.assertEqual('', output)


if __name__ == '__main__':
    unittest.main()
