"""Execute a single policy operation inside the candidate sandbox.

All output is untrusted: only the external controller evaluates it.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types

MAX_REQUEST_BYTES = 64 * 1024


def _fixture_git(repo, root):
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'LC_ALL': 'C'}

    def git(*args):
        return subprocess.run(['/usr/bin/git', *args], cwd=repo, env=env, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20).stdout.decode().strip()

    git('init', '-q')
    git('config', 'user.name', 'qualification-test')
    git('config', 'user.email', 'test@example.invalid')
    return git


def _git_fixture(policy, operation, escape):
    with tempfile.TemporaryDirectory(prefix='qualification-git-') as temporary:
        root = Path(temporary)
        repo = root / 'repo'
        repo.mkdir()
        git = _fixture_git(repo, root)
        if operation == 'git-snapshot':
            (repo / 'unsafe.py').write_text('def handle(value):\n    return eval(value)\n')
            (repo / 'substitution.py').write_text('COMMIT = "$Format:%H$"\n')
            (repo / '.gitattributes').write_text('unsafe.py export-ignore\nsubstitution.py export-subst\n')
            (repo / 'run.sh').write_text('#!/bin/sh\ntrue\n')
            (repo / 'run.sh').chmod(0o755)
            (repo / 'internal.py').symlink_to('unsafe.py')
            if escape:
                (repo / 'escape').symlink_to('/etc')
            git('add', '.')
            git('commit', '-qm', 'fixture')
            target = root / 'snapshot'
            policy.snapshot(repo, git('rev-parse', 'HEAD'), target)
            return {'source': (target / 'unsafe.py').read_text(),
                    'substitution': (target / 'substitution.py').read_text(),
                    'executable': (target / 'run.sh').stat().st_mode & 0o777,
                    'internalIsLink': (target / 'internal.py').is_symlink(),
                    'internalContent': (target / 'internal.py').read_text()}
        (repo / 'old name.py').write_text('x = 1\n')
        (repo / 'removed.py').write_text('x = 2\n')
        git('add', '.')
        git('commit', '-qm', 'before')
        base = git('rev-parse', 'HEAD')
        (repo / 'old name.py').rename(repo / 'new name.py')
        (repo / 'removed.py').unlink()
        git('add', '.')
        git('commit', '-qm', 'after')
        touched, renames = policy.changed_paths(repo, base, git('rev-parse', 'HEAD'))
        return {'touched': sorted(touched), 'renames': renames}


def _workflow_fixture(policy, mode):
    with tempfile.TemporaryDirectory(prefix='qualification-workflow-') as temporary:
        root = Path(temporary)
        repo = root / 'repo'
        repo.mkdir()
        git = _fixture_git(repo, root)
        workflow = repo / '.github/workflows/health.yml'
        workflow.parent.mkdir(parents=True)
        events = 'on: [pull_request, merge_group]\n'
        if mode == 'filtered':
            events = 'on:\n  pull_request:\n    paths: [src/**]\n  merge_group: {}\n'
        reference = 'main' if mode == 'mutable' else 'b' * 40
        condition = '    if: false\n' if mode == 'conditional' else ''
        workflow.write_text(events + 'jobs:\n  health:\n' + condition +
                            '    uses: agentsia-uk/ci-shared/.github/workflows/shared-code-health.yml@' + reference + '\n')
        git('add', '.')
        git('commit', '-qm', 'workflow fixture')
        policy.validate_workflow_pin(repo, git('rev-parse', 'HEAD'), '.github/workflows/health.yml', 'b' * 40)


def _scanner_fixture(policy, operation):
    area = {'id': 'fixture-python', 'language': 'python', 'path': '.', 'exclusions': []}
    with tempfile.TemporaryDirectory(prefix='qualification-scan-') as temporary:
        root = Path(temporary)
        before, after = root / 'before', root / 'after'
        before.mkdir()
        after.mkdir()
        (before / 'service.py').write_text('def handle(value):\n    return str(value)\n')
        (after / 'service.py').write_text('def handle(value):\n    return eval(value)\n')
        if operation == 'scanner-new-area':
            status, state = policy.scan(before, area, root / 'before-result', [area])
            result = policy.compare(None, None, status, state, {'service.py'}, {}, 'python')
            return {'baselineKind': result['baselineKind'], 'objectiveBefore': result['objectiveBefore'],
                    'errors': result['errors']}
        base_status, base_state = policy.scan(before, area, root / 'before-result', [area])
        head_status, head_state = policy.scan(after, area, root / 'after-result', [area])
        result = policy.compare(base_status, base_state, head_status, head_state, {'service.py'}, {}, 'python')
        security = head_state['scan_coverage']['python']['detectors'].get('security', {})
        return {'securityCoverage': security.get('status'),
                'hasSecurityFinding': any(f.get('detector') == 'security' for f in head_state['work_items'].values()),
                'hasSecurityError': any('security' in error for error in result['errors'])}



def _scanner_mapping_fixture(policy):
    patch = policy.scanner_patch
    sources = {}
    for name, spec in patch.COMPONENTS.items():
        source = patch.scanner_source(name).read_bytes()
        if hashlib.sha256(source).hexdigest() != spec['patched']:
            source = patch.patched_component(name, source)
        sources[name] = source
    identity = ''.join(f'{name}:{hashlib.sha256(sources[name]).hexdigest()}\n' for name in sorted(sources)).encode()
    ts = {'__name__': 'desloppify.languages.typescript.test_coverage'}
    py = {'__name__': 'desloppify.languages.python.test_coverage'}
    mapper = {'__name__': 'desloppify.engine.detectors.coverage.mapping_imports'}
    for name, namespace in [('typescript', ts), ('python', py), ('mapping', mapper)]:
        exec(compile(sources[name], '<candidate-scanner>', 'exec'), namespace)
    mapping = ts['map_test_to_source']
    parse, resolve = py['parse_test_import_specs'], py['resolve_import_spec']
    mapper['read_coverage_file'] = lambda *_args, **_kwargs: types.SimpleNamespace(ok=True, content='from . import missing\n')
    mapper['_load_lang_test_coverage_module'] = lambda _lang: types.SimpleNamespace(parse_test_import_specs=parse, resolve_import_spec=resolve)
    unrelated = mapper['_parse_test_imports']('src/pkg/tests/test_bridge.py', {'src/other/missing.py'},
                                              {'missing': 'src/other/missing.py'}, 'python')
    return {'patchSha256': hashlib.sha256(identity).hexdigest(),
            'exact': mapping('src/db/__tests__/health.test.ts', {'src/db/health.ts', 'src/api/routes/health.ts'}),
            'ambiguousName': mapping('other/__tests__/health.test.ts', {'src/db/health.ts', 'src/api/routes/health.ts'}),
            'ambiguousExact': mapping('src/db/__tests__/health.test.ts', {'src/db/health.ts', 'src/db/health.tsx'}),
            'pythonNames': sorted(parse('from code_health import cli, qualification_bridge\n')),
            'relative': resolve('..qualification_bridge', 'src/pkg/tests/test_bridge.py', {'src/pkg/qualification_bridge.py'}),
            'unrelatedRelative': sorted(unrelated)}



def _finding_move_fixture(policy, mode):
    def finding(line, tier=4):
        path = 'src/example.py'
        return {'id': f'security::{path}::security::B506::{path}::{line}', 'file': path,
                'detector': 'security', 'summary': 'possible unsafe operation', 'tier': tier,
                'confidence': 'medium', 'status': 'open', 'work_item_kind': 'mechanical_defect',
                'detail': {'source': 'bandit', 'line': line, 'kind': 'B506', 'test_name': 'yaml_load'}}
    def state(item):
        return {'version': 3, 'work_items': {'one': item},
                'scan_coverage': {'python': {'status': 'full', 'detectors': {'security': {'status': 'full', 'confidence': 1}}}}}
    with tempfile.TemporaryDirectory(prefix='qualification-finding-') as temporary:
        root = Path(temporary)
        base, head = root / 'base', root / 'head'
        (base / 'src').mkdir(parents=True)
        (head / 'src').mkdir(parents=True)
        source = 'def validate(value):\n    return unsafe(value)\n'
        (base / 'src/example.py').write_text(source)
        new = source if mode != 'changed' else 'def validate(value):\n    return unsafe(value, other=True)\n'
        (head / 'src/example.py').write_text('# inserted\n' + new)
        tier = 2 if mode == 'high-priority' else 4
        result = policy.compare({'objective_score': 90}, state(finding(2, tier)),
                                {'objective_score': 90}, state(finding(3, tier)),
                                {'src/example.py'}, {}, 'python', source_roots=(base, head))
        return {'errors': result['errors']}


def observe(request, policy):
    if (not isinstance(request, dict) or set(request) != {'schemaVersion', 'caseId', 'operation', 'arguments'} or
            type(request['schemaVersion']) is not int or request['schemaVersion'] != 1 or
            not isinstance(request['caseId'], str) or not isinstance(request['arguments'], dict)):
        raise ValueError('invalid qualification request')
    operation, args = request['operation'], request['arguments']
    try:
        if operation == 'validate-config' and set(args) == {'config'}:
            policy.validate_config(args['config'])
            value = None
        elif operation == 'validate-transition' and set(args) == {'base', 'head', 'upgrade'}:
            policy.validate_transition(args['base'], args['head'], upgrade=args['upgrade'])
            value = None
        elif operation == 'validate-language-coverage' and set(args) == {'files', 'areas'}:
            policy.validate_language_coverage(args['files'], args['areas'])
            value = None
        elif operation == 'compare' and set(args) == {'baseStatus', 'baseState', 'headStatus', 'headState', 'touched', 'renames', 'language'}:
            value = policy.compare(args['baseStatus'], args['baseState'], args['headStatus'], args['headState'],
                                   set(args['touched']), args['renames'], args['language'])
        elif operation == 'git-snapshot' and set(args) == {'escape'} and type(args['escape']) is bool:
            value = _git_fixture(policy, operation, args['escape'])
        elif operation == 'git-changed-paths' and not args:
            value = _git_fixture(policy, operation, False)
        elif (operation == 'workflow-pin' and set(args) == {'mode'} and isinstance(args['mode'], str) and
              args['mode'] in {'valid', 'mutable', 'conditional', 'filtered'}):
            _workflow_fixture(policy, args['mode'])
            value = None
        elif operation in {'scanner-new-area', 'scanner-security'} and not args:
            value = _scanner_fixture(policy, operation)
        elif operation == 'scanner-mapping' and not args:
            value = _scanner_mapping_fixture(policy)
        elif operation == 'finding-move' and set(args) == {'mode'} and args['mode'] in {'unchanged', 'changed', 'high-priority'}:
            value = _finding_move_fixture(policy, args['mode'])
        else:
            raise RuntimeError('unknown qualification operation')
    except ValueError as error:
        return {'schemaVersion': 1, 'caseId': request['caseId'], 'outcome': 'rejected', 'value': str(error)}
    return {'schemaVersion': 1, 'caseId': request['caseId'], 'outcome': 'returned', 'value': value}


def main():
    data = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(data) > MAX_REQUEST_BYTES:
        raise ValueError('qualification request exceeds size limit')
    request = json.loads(data)
    sys.path.insert(0, '/candidate')
    from code_health import cli as policy
    response = observe(request, policy)
    sys.stdout.write(json.dumps(response, allow_nan=False, separators=(',', ':')) + '\n')


if __name__ == '__main__':
    main()
