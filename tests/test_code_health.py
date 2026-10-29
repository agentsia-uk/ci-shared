import copy
import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from code_health import cli as r

SCRIPT = Path(__file__).parents[1] / 'code_health/cli.py'

def config():
    return {'schemaVersion': 1, 'policyRef': 'a' * 40, 'workflowRef': 'b' * 40, 'areas': [{'id': 'app-python', 'language': 'python', 'path': '.', 'exclusions': []}]}


def finding(path='src/a.py', tier=3, detector='smells', summary='same defect', **extra):
    return {'id': f'{detector}::{path}::{summary}', 'work_item_kind': 'mechanical_defect', 'status': 'open', 'tier': tier, 'file': path, 'detector': detector, 'summary': summary, **extra}


def state(findings=()):
    return {'version': 3, 'work_items': {str(i): f for i, f in enumerate(findings)}, 'scan_coverage': {'python': {'status': 'full', 'detectors': {'smells': {'status': 'full', 'confidence': 1}}}}}


def compare(before=(), after=(), touched=('src/a.py',), renames=None, score_before=90, score_after=90):
    return r.compare({'objective_score': score_before}, state(before), {'objective_score': score_after}, state(after), set(touched), renames or {}, 'python')


class PolicyTests(unittest.TestCase):
    def test_overrides_only_tighten(self):
        for key, value in [('strictTarget', 89), ('strictTarget', True), ('strictTarget', float('nan')), ('reviewMaxAgeDays', 0), ('reviewMaxAgeDays', 31), ('reviewMaxAgeDays', False)]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                r.validate_config({**config(), key: value})
        r.validate_config({**config(), 'strictTarget': 95, 'reviewMaxAgeDays': 14})

    def test_scope_and_exclusion_trust_boundary(self):
        for path in ['../secret', '/tmp/src', 'src/../../secret', 'src\\hidden', '*.py', 'src\n']:
            c = config()
            c['areas'][0]['path'] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                r.validate_config(c)
        for exclusion in [{'pattern': '.', 'kind': 'generated', 'rationale': 'all'}, {'pattern': 'src', 'kind': 'source', 'rationale': 'bad'}, {'pattern': 'dist', 'kind': 'build', 'rationale': ''}]:
            c = config()
            c['areas'][0]['exclusions'] = [exclusion]
            with self.subTest(exclusion=exclusion), self.assertRaises(ValueError):
                r.validate_config(c)
        c = config()
        c['areas'][0]['exclusions'] = [{'pattern': 'dist', 'kind': 'build', 'rationale': 'compiler output'}]
        r.validate_config(c)

    def test_duplicate_unknown_fields_and_mutable_pin_rejected(self):
        cases = [dict(config(), policyRef='main'), dict(config(), ignore=['*']), dict(config(), areas=[])]
        c = config()
        c['areas'].append(copy.deepcopy(c['areas'][0]))
        cases.append(c)
        for c in cases:
            with self.subTest(config=c), self.assertRaises(ValueError):
                r.validate_config(c)

    def test_caller_is_sha_pinned_unconditional_and_runs_for_all_prs(self):
        shared = 'agentsia-uk/ci-shared/.github/workflows/shared-code-health.yml@'
        valid = 'on: [pull_request, merge_group]\njobs:\n  health:\n    uses: ' + shared + 'b' * 40 + '\n'
        workflow_path = '.github/workflows/ci.yml'
        with patch.object(r, 'run', return_value=valid.encode()):
            r.validate_workflow_pin(Path('.'), 'a' * 40, workflow_path, 'b' * 40)
        invalid = [valid.replace('b' * 40, 'main'), valid.replace('    uses:', '    if: false\n    uses:'), valid.replace('[pull_request, merge_group]', '[push]'), valid.replace('on: [pull_request, merge_group]', 'on:\n  pull_request:\n    paths: [src/**]\n  merge_group:')]
        for text in invalid:
            with self.subTest(text=text), patch.object(r, 'run', return_value=text.encode()), self.assertRaises(ValueError):
                r.validate_workflow_pin(Path('.'), 'a' * 40, workflow_path, 'b' * 40)

    def test_yaml_loader_preserves_actions_scalars_without_constructing_objects(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / 'must-not-exist'
            text = ('metadata: !!python/object/apply:os.system ["touch ' + str(marker) + '"]\non: [pull_request, merge_group]\njobs:\n  health:\n    continue-on-error: false\n    uses: agentsia-uk/ci-shared/.github/workflows/shared-code-health.yml@' + 'b' * 40 + '\n').encode()
            with patch.object(r, 'run', return_value=text):
                r.validate_workflow_pin(Path('.'), 'c' * 40, '.github/workflows/health.yml', 'b' * 40)
            self.assertFalse(marker.exists())

    def test_policy_provenance_is_bound_to_actual_action_and_caller(self):
        args = SimpleNamespace(action_repository='agentsia-uk/ci-shared', action_ref='a' * 40, caller_sha='c' * 40, caller_ref='agentsia-uk/example/.github/workflows/actual.yml@refs/pull/1/merge', repository='agentsia-uk/example')
        text = ('on: [pull_request, merge_group]\njobs:\n  health:\n    uses: agentsia-uk/ci-shared/.github/workflows/shared-code-health.yml@' + 'b' * 40 + '\n').encode()
        with patch.object(r, 'run', return_value=text) as command:
            provenance = r.execution_provenance(Path('.'), args, config())
            self.assertEqual('a' * 40, provenance['actionRef'])
            self.assertEqual('c' * 40, provenance['callerWorkflowSha'])
            self.assertEqual('b' * 40, provenance['callerDeclaredWorkflowRef'])
            self.assertEqual(['git', 'show', 'c' * 40 + ':.github/workflows/actual.yml'], command.call_args.args[0])
        args.action_ref = 'd' * 40
        with self.assertRaisesRegex(ValueError, 'executing action'):
            r.execution_provenance(Path('.'), args, config())
        args.action_ref = 'a' * 40
        with patch.object(r, 'run', return_value=b'on: [pull_request, merge_group]\njobs: {other: {runs-on: linux}}'), self.assertRaisesRegex(ValueError, 'actual caller'):
            r.execution_provenance(Path('.'), args, config())

    def test_policy_pin_change_requires_a_dedicated_upgrade(self):
        moved = dict(config(), policyRef='d' * 40)
        with self.assertRaisesRegex(ValueError, 'dedicated'):
            r.validate_transition(config(), moved)
        r.validate_transition(config(), moved, upgrade=True)
        pr = {'number': 1, 'user': {'login': 'github-actions[bot]'}, 'head': {'ref': 'automation/code-health-upgrade-1', 'sha': 'd' * 40, 'repo': {'full_name': 'agentsia-uk/example'}}, 'base': {'sha': 'e' * 40, 'repo': {'full_name': 'agentsia-uk/example'}}, 'labels': [{'name': 'code-health-upgrade'}]}
        self.assertTrue(r.authorized_upgrade({'pull_request': pr}, 'agentsia-uk/example', {r.CONFIG}))
        self.assertFalse(r.authorized_upgrade({'pull_request': pr}, 'agentsia-uk/example', {'src/app.py'}))
        for mutate in [lambda p: p['user'].update(login='human'), lambda p: p['labels'].clear(), lambda p: p['head']['repo'].update(full_name='outside/fork')]:
            changed = copy.deepcopy(pr)
            mutate(changed)
            self.assertFalse(r.authorized_upgrade({'pull_request': changed}, 'agentsia-uk/example', {r.CONFIG}))

    def test_queued_upgrade_uses_live_pr_metadata_and_immutable_ancestry(self):
        pr = {'number': 1, 'user': {'login': 'github-actions[bot]'}, 'head': {'ref': 'automation/code-health-upgrade-1', 'sha': 'd' * 40, 'repo': {'full_name': 'agentsia-uk/example'}}, 'base': {'sha': 'e' * 40, 'repo': {'full_name': 'agentsia-uk/example'}}, 'labels': [{'name': 'code-health-upgrade'}]}
        event = {'merge_group': {'base_ref': 'refs/heads/main'}}
        args = SimpleNamespace(repository='agentsia-uk/example', repo=Path('.'), head='f' * 40, action_ref='a' * 40)
        def response(*_args, **_kwargs):
            return contextlib.closing(io.BytesIO(json.dumps([pr]).encode()))
        with patch.dict(r.os.environ, {'CODE_HEALTH_GITHUB_TOKEN': 'private-read-token'}), patch.object(r.urllib.request, 'urlopen', side_effect=response), patch.object(r.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), patch.object(r, 'changed_paths', return_value=({r.CONFIG}, {})), patch.object(r, 'run', side_effect=[b'e' * 40, json.dumps({'policyRef': 'a' * 40}).encode()]):
            self.assertEqual({'pullRequest': 1, 'headSha': 'd' * 40}, r.upgrade_evidence(event, args, {'src/app.py', r.CONFIG}))
        with patch.dict(r.os.environ, {'CODE_HEALTH_GITHUB_TOKEN': 'private-read-token'}), patch.object(r.urllib.request, 'urlopen', side_effect=response), patch.object(r.subprocess, 'run', return_value=SimpleNamespace(returncode=1)):
            self.assertIsNone(r.upgrade_evidence(event, args, {r.CONFIG}))

    def test_every_supported_source_language_requires_an_area(self):
        r.validate_language_coverage(['src/a.py', 'README.md'], config()['areas'])
        with self.assertRaisesRegex(ValueError, 'outside declared'):
            r.validate_language_coverage(['src/a.py', 'src/a.ts'], config()['areas'])
        areas = [*config()['areas'], {'id': 'web', 'path': 'web', 'language': 'typescript', 'exclusions': []}]
        with self.assertRaisesRegex(ValueError, 'web/hidden.py'):
            r.validate_language_coverage(['web/hidden.py'], areas)

    def test_unsupported_only_repository_has_gaps_without_invented_areas(self):
        c = dict(config(), areas=[], unsupportedLanguages=[{'language': 'yaml', 'rationale': 'workflow-only repository'}])
        r.validate_config(c)
        r.validate_language_coverage(['.github/workflows/policy.yml', 'README.md'], c['areas'])
        with self.assertRaisesRegex(ValueError, 'outside declared'):
            r.validate_language_coverage(['source.py'], c['areas'])

    def test_ordinary_pr_cannot_hide_existing_area_or_relax_rule(self):
        for mutate in [lambda c: c['areas'].clear(), lambda c: c['areas'][0].update(path='subset'), lambda c: c.update(strictTarget=89), lambda c: c.update(reviewMaxAgeDays=31)]:
            c = config()
            mutate(c)
            with self.subTest(config=c), self.assertRaises(ValueError):
                r.validate_transition(config(), c)
        r.validate_transition(None, config())
        r.validate_transition(config(), config())


class RatchetTests(unittest.TestCase):
    def test_score_drop_is_global_even_when_touched_file_is_clean(self):
        self.assertTrue(compare(score_after=89.9)['errors'])
        self.assertEqual([], compare(score_after=90.1)['errors'])

    def test_unchanged_untouched_debt_does_not_block(self):
        f = finding('other.py', tier=1)
        self.assertEqual([], compare([f], [f])['errors'])

    def test_touched_tier_one_and_two_must_be_fixed(self):
        for tier in [1, 2]:
            f = finding(tier=tier)
            self.assertTrue(compare([f], [f])['errors'])
            self.assertEqual([], compare([f], [])['errors'])

    def test_no_new_findings_even_lower_priority_or_duplicate(self):
        f = finding(tier=4)
        self.assertTrue(compare([], [f])['errors'])
        self.assertTrue(compare([f], [f, copy.deepcopy(f)])['errors'])
        self.assertEqual([], compare([f], [f])['errors'])

    def test_rename_keeps_inherited_low_priority_debt_identifiable(self):
        old, new = finding('old.py'), finding('new.py')
        self.assertEqual([], compare([old], [new], ('old.py', 'new.py'), {'old.py': 'new.py'})['errors'])
        new['tier'] = 2
        self.assertTrue(compare([old], [new], ('old.py', 'new.py'), {'old.py': 'new.py'})['errors'])

    def test_cross_file_finding_counts_when_any_related_file_is_touched(self):
        f = finding('.', detail={'related_files': ['src/a.py', 'other.py']})
        self.assertTrue(compare([], [f])['errors'])

    def test_subjective_scores_do_not_gate(self):
        f = finding(work_item_kind='review_defect')
        self.assertEqual([], compare([], [f])['errors'])

    def test_invalid_scores_and_coverage_fail_closed(self):
        for score in [None, True, float('nan'), float('inf'), -1, 101]:
            with self.subTest(score=score), self.assertRaises(ValueError):
                compare(score_after=score)
        broken = state()
        broken['scan_coverage']['python']['detectors']['smells']['confidence'] = .5
        with self.assertRaises(ValueError):
            r.compare({'objective_score': 90}, state(), {'objective_score': 90}, broken, set(), {}, 'python')
        with self.assertRaises(ValueError):
            r.compare({'objective_score': 90}, state(), {'objective_score': 90}, {}, set(), {}, 'python')

    def test_snapshot_uses_exact_blobs_despite_export_attributes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo = root / 'repo'
            repo.mkdir()
            git = lambda *args: subprocess.check_output(['git', *args], cwd=repo)
            git('init', '-q')
            git('config', 'user.name', 'test')
            git('config', 'user.email', 'test@example.invalid')
            unsafe = b'def handle(value):\n    return eval(value)\n'
            substitution = b'COMMIT = "$Format:%H$"\n'
            (repo / 'unsafe.py').write_bytes(unsafe)
            (repo / 'substitution.py').write_bytes(substitution)
            (repo / '.gitattributes').write_text('unsafe.py export-ignore\nsubstitution.py export-subst\n')
            (repo / 'run.sh').write_text('#!/bin/sh\ntrue\n')
            (repo / 'run.sh').chmod(0o755)
            (repo / 'internal.py').symlink_to('unsafe.py')
            git('add', '.')
            git('commit', '-qm', 'source')
            sha = git('rev-parse', 'HEAD').decode().strip()
            destination = root / 'snapshot'
            r.snapshot(repo, sha, destination)
            self.assertEqual(git('show', f'{sha}:unsafe.py'), (destination / 'unsafe.py').read_bytes())
            self.assertEqual(substitution, (destination / 'substitution.py').read_bytes())
            self.assertEqual(0o755, (destination / 'run.sh').stat().st_mode & 0o777)
            self.assertTrue((destination / 'internal.py').is_symlink())
            self.assertEqual(unsafe, (destination / 'internal.py').read_bytes())
            (repo / 'escape').symlink_to('/etc')
            git('add', '.')
            git('commit', '-qm', 'escape')
            with self.assertRaisesRegex(ValueError, 'symlink escapes'):
                r.snapshot(repo, git('rev-parse', 'HEAD').decode().strip(), root / 'escaped')

    def test_changed_paths_include_both_rename_ends_and_deleted_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            git = lambda *args: subprocess.check_output(['git', *args], cwd=repo).decode().strip()
            git('init', '-q')
            git('config', 'user.name', 'test')
            git('config', 'user.email', 'test@example.invalid')
            (repo / 'old name.py').write_text('x = 1\n')
            (repo / 'removed.py').write_text('x = 2\n')
            git('add', '.')
            git('commit', '-qm', 'before')
            base = git('rev-parse', 'HEAD')
            (repo / 'old name.py').rename(repo / 'new name.py')
            (repo / 'removed.py').unlink()
            git('add', '.')
            git('commit', '-qm', 'after')
            touched, renames = r.changed_paths(repo, base, git('rev-parse', 'HEAD'))
            self.assertEqual({'old name.py', 'new name.py', 'removed.py'}, touched)
            self.assertEqual({'old name.py': 'new name.py'}, renames)

    def test_cli_scans_real_git_snapshots_and_ignores_committed_local_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo = root / 'repo'
            repo.mkdir()
            git = lambda *args: subprocess.check_output(['git', *args], cwd=repo).decode().strip()
            git('init', '-q')
            git('config', 'user.name', 'test')
            git('config', 'user.email', 'test@example.invalid')
            (repo / '.github/workflows').mkdir(parents=True)
            (repo / '.github/code-health.json').write_text(json.dumps(config()))
            (repo / '.github/workflows/health.yml').write_text('on: [pull_request, merge_group]\njobs:\n  health:\n    uses: agentsia-uk/ci-shared/.github/workflows/shared-code-health.yml@' + 'b' * 40 + '\n')
            (repo / '.desloppify').mkdir()
            (repo / '.desloppify/config.json').write_text('{"ignore": ["*"], "trust_plugins": true}')
            (repo / 'service.py').write_text('def handle(value):\n    return str(value)\n')
            git('add', '.')
            git('commit', '-qm', 'before')
            base = git('rev-parse', 'HEAD')
            (repo / 'service.py').write_text('def handle(value):\n    return eval(value)\n')
            git('add', '.')
            git('commit', '-qm', 'after')
            head = git('rev-parse', 'HEAD')
            output = root / 'result'
            argv = ['ratchet', '--repo', str(repo), '--base', base, '--head', head, '--output', str(output), '--repository', 'agentsia-uk/example', '--action-repository', 'agentsia-uk/ci-shared', '--action-ref', 'a' * 40, '--caller-ref', 'agentsia-uk/example/.github/workflows/health.yml@refs/pull/1/merge', '--caller-sha', head]
            with patch.object(r.sys, 'argv', argv), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(1, r.main())
            report = json.loads((output / 'result.json').read_text())
            self.assertEqual(base, report['base'])
            self.assertEqual(head, report['head'])
            self.assertTrue(report['areas'][0]['errors'])
            self.assertNotIn('eval(', json.dumps(report))
            self.assertEqual(r.POLICY['desloppifyVersion'], report['desloppifyVersion'])

    def test_new_area_has_no_fabricated_baseline_score(self):
        area = dict(config()['areas'][0], path='new-project')
        self.assertFalse(r.area_has_source(['README.md'], area, [area]))
        self.assertTrue(r.area_has_source(['new-project/service.py'], area, [area]))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'new-project').mkdir()
            (root / 'new-project/service.py').write_text('def handle(value):\n    return str(value)\n')
            status, scanned = r.scan(root, area, root / 'result', [area])
            result = r.compare(None, None, status, scanned, {'new-project/service.py'}, {}, 'python')
            self.assertIsNone(result['objectiveBefore'])
            self.assertEqual('new-area', result['baselineKind'])
            self.assertEqual([], result['errors'])
            unsafe = state([finding('new-project/service.py', tier=2)])
            self.assertTrue(r.compare(None, None, {'objective_score': 95}, unsafe, {'new-project/service.py'}, {}, 'python')['errors'])

    def test_actual_scanner_rejects_new_security_defect(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            before, after = root / 'base', root / 'head'
            before.mkdir()
            after.mkdir()
            (before / 'service.py').write_text('def handle(value):\n    return str(value)\n')
            (after / 'service.py').write_text('def handle(value):\n    return eval(value)\n')
            area = config()['areas'][0]
            base_status, base_state = r.scan(before, area, root / 'base-result', [area])
            head_status, head_state = r.scan(after, area, root / 'head-result', [area])
            result = r.compare(base_status, base_state, head_status, head_state, {'service.py'}, {}, 'python')
            self.assertTrue(result['errors'])
            self.assertTrue(any('security' in error for error in result['errors']))
            security = head_state['scan_coverage']['python']['detectors'].get('security')
            self.assertEqual('full', security['status'])

    def test_scanner_uses_pinned_config_and_drops_credential_environment(self):
        calls = []
        def fake_run(args, *, cwd, env=None):
            calls.append((args, env))
            if 'scan' in args:
                output = Path(args[args.index('--state') + 1])
                output.write_text(json.dumps(state()))
                return b'log'
            return b'{"objective_score": 90}'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'repo'
            root.mkdir()
            (root / 'training').mkdir()
            with patch.object(r, 'run', side_effect=fake_run), patch.dict(r.os.environ, {'GH_TOKEN': 'do-not-forward', 'OPENAI_API_KEY': 'do-not-forward', 'CODE_HEALTH_GITHUB_TOKEN': 'private-read-token'}):
                r.scan(root, config()['areas'][0], Path(temporary) / 'output', [*config()['areas'], {'path': 'training'}])
            scanner_config = json.loads((root / '.desloppify/config.json').read_text())
            self.assertFalse(scanner_config['trust_plugins'])
            self.assertFalse(scanner_config['hermes_enabled'])
            self.assertEqual(['training'], scanner_config['exclude'])
            self.assertIn('--profile', calls[0][0])
            for _, env in calls:
                self.assertNotIn('GH_TOKEN', env)
                self.assertNotIn('OPENAI_API_KEY', env)
                self.assertNotIn('CODE_HEALTH_GITHUB_TOKEN', env)


if __name__ == '__main__':
    unittest.main()
