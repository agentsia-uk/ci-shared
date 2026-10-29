"""Build a deterministic policy bundle from exact committed Git blobs."""
import hashlib
import argparse
import io
import json
import os
import re
from pathlib import Path, PurePosixPath
import subprocess
import tarfile

from .release_bundle import COMMIT, MAX_BUNDLE_BYTES

RUNTIME_SOURCE = re.compile(r'code_health/[a-z_][a-z0-9_]*\.py\Z')


def runtime_files(repo: str | os.PathLike[str], commit: str) -> set[str]:
    """Select only top-level Python modules and the fixed policy/lock files."""
    if not COMMIT.fullmatch(commit):
        raise ValueError('release commit must be a full SHA')
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    raw = subprocess.run(['/usr/bin/git', 'ls-tree', '-r', '-z', '--name-only', f'{commit}^{{commit}}', '--', 'code_health'],
                         cwd=repo, env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120).stdout
    names = [name.decode('utf-8') for name in raw.split(b'\0') if name]
    result = {name for name in names if RUNTIME_SOURCE.fullmatch(name)}
    result.update({'code_health/policy.json', 'code_health/requirements.lock'})
    if 'code_health/cli.py' not in result:
        raise ValueError('policy entrypoint is missing')
    return result


def build_bundle(repo: str | os.PathLike[str], commit: str, allowed_files: set[str]) -> bytes:
    if not COMMIT.fullmatch(commit):
        raise ValueError('release commit must be a full SHA')
    required = {'code_health/policy.json', 'code_health/requirements.lock'}
    paths = set(allowed_files)
    if not required <= paths:
        raise ValueError('release needs the policy and dependency lock')
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}

    def git(*args):
        return subprocess.run(['/usr/bin/git', *args], cwd=repo, env=env, check=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=120).stdout

    files = {}
    total = 0
    for name in sorted(paths):
        path = PurePosixPath(name)
        if (not name.startswith('code_health/') or name != str(path) or path.is_absolute() or
                '..' in path.parts or '\\' in name or any(ord(char) < 32 for char in name)):
            raise ValueError('invalid policy source path')
        rows = git('ls-tree', '-z', '--full-tree', f'{commit}^{{commit}}', '--', name).split(b'\0')
        if len(rows) != 2 or rows[-1] != b'':
            raise ValueError('missing policy source file')
        metadata, actual = rows[0].split(b'\t', 1)
        mode, kind, oid = metadata.split()
        if actual != name.encode() or kind != b'blob' or mode not in {b'100644', b'100755'}:
            raise ValueError('policy source must be an exact regular Git blob')
        size = int(git('cat-file', '-s', oid.decode()))
        total += size
        if size < 0 or total > MAX_BUNDLE_BYTES:
            raise ValueError('policy source exceeds the size limit')
        blob = git('cat-file', 'blob', oid.decode())
        if len(blob) != size:
            raise ValueError('incomplete policy source blob')
        files[name] = blob
    policy = json.loads(files['code_health/policy.json'])
    version = policy.get('desloppifyVersion') if isinstance(policy, dict) else None
    if not isinstance(version, str) or not version:
        raise ValueError('policy is missing its scanner version')
    manifest = {'schemaVersion': 1, 'kind': 'agentsia.code-health.policy-release', 'policyCommitSha': commit,
                'desloppifyVersion': version,
                'requirementsLockSha256': hashlib.sha256(files['code_health/requirements.lock']).hexdigest(),
                'files': [{'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
                          for name, data in files.items()]}
    payload = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode() + b'\n'
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, data in [('release.json', payload), *files.items()]:
            item = tarfile.TarInfo(name)
            item.mode, item.uid, item.gid, item.mtime, item.size = 0o600, 0, 0, 0, len(data)
            archive.addfile(item, io.BytesIO(data))
    if len(output.getvalue()) > MAX_BUNDLE_BYTES:
        raise ValueError('policy bundle exceeds the size limit')
    return output.getvalue()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.write_bytes(build_bundle(args.repo, args.commit, runtime_files(args.repo, args.commit)))


if __name__ == '__main__':
    main()
