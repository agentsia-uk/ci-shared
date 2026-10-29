import base64
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from code_health import cli
from code_health import dismissals as d

AREA = {'id': 'app-python', 'language': 'python', 'path': '.', 'exclusions': []}
ATTESTATION = 'I have reviewed the loader against the documentation and I am not gaming the score by suppressing a real defect.'
RATIONALE = 'BaseLoader constructs only strings, lists and dictionaries; preserving Actions scalars requires this non-constructing loader. https://pyyaml.org/wiki/PyYAMLDocumentation'


def entry(finding=None, root=None):
    value = {'area': AREA['id'], 'findingId': 'security::service.py::B506', 'findingSha256': 'a' * 64, 'sourceSha256': {'service.py': 'b' * 64}, 'status': 'false_positive', 'toolVersion': '1.0', 'rationale': RATIONALE, 'attestation': ATTESTATION, 'pullRequest': 7}
    if finding is not None:
        value.update(findingId=finding['id'], findingSha256=d.finding_hash(finding), sourceSha256=d.source_hashes(root, finding))
    return value


def proof(value):
    return {'entry': value, 'author': 'agent', 'pullRequestUrl': 'https://github.com/agentsia-uk/example/pull/7', 'headSha': 'c' * 40, 'admittedSha': 'd' * 40}


def metadata(value):
    ledger = {'schemaVersion': 1, 'entries': [value]}
    pr = {'number': 7, 'state': 'open', 'merged': False, 'user': {'login': 'agent'}, 'head': {'sha': 'c' * 40, 'repo': {'full_name': 'agentsia-uk/example'}}, 'base': {'repo': {'full_name': 'agentsia-uk/example'}}, 'body': d.audit_block(value)}
    source = {'encoding': 'base64', 'content': base64.b64encode(json.dumps(ledger).encode()).decode()}
    return {'pulls/7': pr, 'collaborators/agent/permission': {'permission': 'write'}, f'contents/{d.LEDGER}?ref=' + 'c' * 40: source}


class DismissalTrustTests(unittest.TestCase):
    def test_ledger_rejects_weak_audits_and_unknown_fields(self):
        d.validate_ledger({'schemaVersion': 1, 'entries': [entry()]}, {AREA['id']}, '1.0')
        for changes in [{'findingId': ''}, {'area': 'other'}, {'status': 'fixed'}, {'status': []}, {'toolVersion': '0.9'}, {'rationale': ''}, {'attestation': 'I assert this is fine'}, {'sourceSha256': {'../secret': 'b' * 64}}, {'sourceSha256': {}}, {'pullRequest': True}, {'findingSha256': 'a'}, {'ignore': '*'}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                d.validate_ledger({'schemaVersion': 1, 'entries': [{**entry(), **changes}]}, {AREA['id']}, '1.0')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            d.validate_ledger({'schemaVersion': 1, 'entries': [entry(), entry()]}, {AREA['id']}, '1.0')

    def test_open_pr_is_bound_to_writer_exact_record_body_and_candidate(self):
        value = entry()
        data = metadata(value)
        seen = []
        records = d.authenticate([value], 'agentsia-uk/example', api=data.__getitem__, contains=lambda sha: seen.append(sha) or True)
        self.assertEqual(['c' * 40], seen)
        self.assertEqual('agent', records[0]['author'])
        self.assertEqual(value, records[0]['entry'])
        for field, change in [('permission', 'read'), ('body', RATIONALE), ('record', {}), ('repository', 'agentsia-uk/elsewhere'), ('state', 'closed')]:
            broken = copy.deepcopy(data)
            if field == 'permission':
                broken['collaborators/agent/permission']['permission'] = change
            elif field == 'body':
                broken['pulls/7']['body'] = change
            elif field == 'record':
                broken[f'contents/{d.LEDGER}?ref=' + 'c' * 40]['content'] = base64.b64encode(json.dumps({'entries': [change]}).encode()).decode()
            elif field == 'repository':
                broken['pulls/7']['head']['repo']['full_name'] = change
            else:
                broken['pulls/7']['state'] = change
            with self.subTest(field=field), self.assertRaises(ValueError):
                d.authenticate([value], 'agentsia-uk/example', api=broken.__getitem__, contains=lambda sha: True)
        with self.assertRaisesRegex(ValueError, 'not contained'):
            d.authenticate([value], 'agentsia-uk/example', api=data.__getitem__, contains=lambda sha: False)

    def test_squash_merge_binds_merged_commit_not_unreachable_original_head(self):
        value = entry()
        data = metadata(value)
        data['pulls/7'].update(merged=True, state='closed', merge_commit_sha='d' * 40)
        records = d.authenticate([value], 'agentsia-uk/example', api=data.__getitem__, contains=lambda sha: sha == 'd' * 40)
        self.assertEqual('d' * 40, records[0]['admittedSha'])
        self.assertEqual('c' * 40, records[0]['headSha'])

    def test_trusted_git_reader_requires_metadata_and_ancestry(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            git = lambda *args: subprocess.check_output(['git', *args], cwd=repo).decode().strip()
            git('init', '-q')
            git('config', 'user.name', 'test')
            git('config', 'user.email', 'test@example.invalid')
            (repo / '.github').mkdir()
            (repo / 'service.py').write_text('pass\n')
            git('add', '.')
            git('commit', '-qm', 'before')
            base = git('rev-parse', 'HEAD')
            self.assertEqual(([], None), cli.trusted_dismissals(repo, base, 'agentsia-uk/example', [AREA]))
            value = entry()
            (repo / d.LEDGER).write_text(json.dumps({'schemaVersion': 1, 'entries': [value]}))
            git('add', '.')
            git('commit', '-qm', 'decision')
            head = git('rev-parse', 'HEAD')
            data = metadata(value)
            data['pulls/7']['head']['sha'] = head
            data[f'contents/{d.LEDGER}?ref={head}'] = data.pop(f'contents/{d.LEDGER}?ref=' + 'c' * 40)
            with patch.dict(cli.os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, 'metadata'):
                cli.trusted_dismissals(repo, head, 'agentsia-uk/example', [AREA])
            with patch.dict(cli.os.environ, {'CODE_HEALTH_GITHUB_TOKEN': 'private-read-token'}), patch.object(d, 'github_reader', return_value=data.__getitem__):
                records, ledger_hash = cli.trusted_dismissals(repo, head, 'agentsia-uk/example', [AREA])
            self.assertEqual(head, records[0]['admittedSha'])
            self.assertEqual(64, len(ledger_hash))


class NativeDismissalTests(unittest.TestCase):
    def test_native_import_recomputes_score_and_retains_plan_and_pr_audit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / 'src'
            source.mkdir()
            (source / 'service.py').write_text('import yaml\n\ndef parse(value):\n    return yaml.load(value, Loader=yaml.BaseLoader)\n')
            raw_status, raw_state = cli.scan(source, AREA, root / 'raw', [AREA])
            finding = next(f for f in raw_state['work_items'].values() if f['detector'] == 'security')
            value = entry(finding, source)
            records = [proof(value)]
            native_run = cli.run
            calls = []
            def observe(args, *, cwd, env=None):
                calls.append((args, env))
                return native_run(args, cwd=cwd, env=env)
            with patch.dict(cli.os.environ, {'CODE_HEALTH_GITHUB_TOKEN': 'private-read-token', 'GH_TOKEN': 'private-token', 'OPENAI_API_KEY': 'private-key'}), patch.object(cli, 'run', side_effect=observe):
                status, state = cli.scan(source, AREA, root / 'imported', [AREA], records)
            importer = next((args, env) for args, env in calls if any(str(arg).endswith('/dismissals.py') for arg in args))
            self.assertFalse({'CODE_HEALTH_GITHUB_TOKEN', 'GH_TOKEN', 'OPENAI_API_KEY'} & importer[1].keys())
            self.assertNotIn(RATIONALE, ' '.join(importer[0]))
            self.assertEqual('false_positive', state['work_items'][finding['id']]['status'])
            self.assertGreater(status['objective_score'], raw_status['objective_score'])
            self.assertEqual({'false_positive': 1, 'wontfix': 0, 'inactive': 0}, status['dismissals'])
            plan = json.loads((root / 'imported/plan.json').read_text())
            skip = plan['skipped'][finding['id']]
            self.assertEqual(RATIONALE, skip['reason'])
            self.assertEqual(ATTESTATION, skip['attestation'])
            self.assertIn('/pull/7', skip['note'])
            self.assertEqual('agent', plan['execution_log'][0]['actor'])
            self.assertEqual(d.digest(value), plan['execution_log'][0]['detail']['dismissalSha256'])
            wontfix = copy.deepcopy(records)
            wontfix[0]['entry']['status'] = 'wontfix'
            _, debt_state = cli.scan(source, AREA, root / 'debt', [AREA], wontfix)
            self.assertTrue(any(f['id'] == finding['id'] and f['status'] == 'wontfix' for f in cli.mechanical_findings(debt_state)))
            debt_state['work_items'][finding['id']]['tier'] = 2
            self.assertTrue(any('T2 remains' in error for error in cli.compare(raw_status, raw_state, status, debt_state, {'service.py'}, {}, 'python')['errors']))
            (source / 'service.py').write_text((source / 'service.py').read_text() + '# changed since review\n')
            _, changed = cli.scan(source, AREA, root / 'changed', [AREA], records)
            self.assertEqual('open', changed['work_items'][finding['id']]['status'])
            stale = copy.deepcopy(records)
            stale[0]['entry']['findingSha256'] = '0' * 64
            _, changed = cli.scan(source, AREA, root / 'stale', [AREA], stale)
            self.assertEqual('open', changed['work_items'][finding['id']]['status'])
            pattern = copy.deepcopy(records)
            pattern[0]['entry']['findingId'] = 'security::*'
            inactive, changed = cli.scan(source, AREA, root / 'pattern', [AREA], pattern)
            self.assertEqual('open', changed['work_items'][finding['id']]['status'])
            self.assertEqual(1, inactive['dismissals']['inactive'])

    def test_exact_id_cannot_prefix_resolve_a_second_native_finding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'service.py').write_text('pass\n')
            finding = {'id': 'smells::service.py::one', 'file': 'service.py', 'detector': 'smells', 'tier': 2, 'summary': 'one', 'status': 'open', 'work_item_kind': 'mechanical_defect'}
            another = {**finding, 'id': finding['id'] + '::extra'}
            state = {'work_items': {f['id']: f for f in [finding, another]}}
            with patch.object(d, 'load_state', return_value=state), self.assertRaisesRegex(ValueError, 'another native finding'):
                d.import_records(root / 'state.json', root, AREA['id'], [proof(entry(finding, root))])

    def test_changed_related_file_invalidates_decision(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for path in ['service.py', 'related.py']:
                (root / path).write_text('pass\n')
            f = {'file': 'service.py', 'detail': {'related_files': ['related.py']}}
            before = d.source_hashes(root, f)
            self.assertEqual(before, d.source_hashes(root, {'file': '.', 'detail': {'related_files': ['service.py', 'related.py']}}))
            (root / 'related.py').write_text('changed\n')
            self.assertNotEqual(before, d.source_hashes(root, f))
            (root / 'escape.py').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(ValueError, 'inside the snapshot'):
                d.source_hashes(root, {'file': 'escape.py'})


if __name__ == '__main__':
    unittest.main()
