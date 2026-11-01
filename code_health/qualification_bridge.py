"""Execute a single policy operation inside the candidate sandbox.

All output is untrusted: only the external controller evaluates it.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

MAX_REQUEST_BYTES = 64 * 1024


def _git_fixture(policy, operation, escape):
    with tempfile.TemporaryDirectory(prefix='qualification-git-') as temporary:
        root = Path(temporary)
        repo = root / 'repo'
        repo.mkdir()
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_CONFIG_GLOBAL': '/dev/null', 'LC_ALL': 'C'}

        def git(*args):
            return subprocess.run(['/usr/bin/git', *args], cwd=repo, env=env, check=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20).stdout.decode().strip()

        git('init', '-q')
        git('config', 'user.name', 'qualification-test')
        git('config', 'user.email', 'test@example.invalid')
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
        else:
            raise RuntimeError('unknown qualification operation')
    except ValueError as error:
        if operation == 'git-snapshot' and args.get('escape') is True and 'symlink escapes' not in str(error):
            raise
        return {'schemaVersion': 1, 'caseId': request['caseId'], 'outcome': 'rejected', 'value': None}
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
