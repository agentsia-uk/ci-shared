"""Build a deterministic policy bundle from exact committed Git blobs."""
import hashlib
import argparse
from importlib.metadata import version as package_version
import io
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import urllib.error
import urllib.parse
import urllib.request

from .release_bundle import COMMIT, MAX_BUNDLE_BYTES
from .readers_lock import ASSET_NAMES, MAX_ARCHIVE_BYTES, PLATFORMS, locked_package_version, required_grammars, verify_archive, verify_manifest

RUNTIME_SOURCE = re.compile(r'code_health/[a-z_][a-z0-9_]*\.py\Z')


class ReaderRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if (target.scheme != 'https' or target.hostname not in {'github.com', 'release-assets.githubusercontent.com'}
                or target.username is not None or target.password is not None or target.port not in (None, 443)):
            raise ValueError('reader download redirect is not trusted')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_reader_archives(lock):
    """Download public archives and verify each against an authenticated lock."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ReaderRedirect())
    archives = {}
    for entry in lock.archives:
        expected = ('https://github.com/kreuzberg-dev/tree-sitter-language-pack/releases/download/v'
                    + lock.version + '/parsers-' + entry.platform + '.tar.zst')
        if entry.platform not in PLATFORMS or entry.url != expected:
            raise ValueError('reader download URL is not trusted')
        with opener.open(entry.url, timeout=60) as response:
            data = response.read(MAX_ARCHIVE_BYTES + 1)
        archives[entry.platform] = verify_archive(data, lock=lock, platform=entry.platform)
    return archives


def runtime_files(repo: str | os.PathLike[str], commit: str) -> set[str]:
    """Select only top-level Python modules and the fixed policy/lock files."""
    if not COMMIT.fullmatch(commit):
        raise ValueError('release commit must be a full SHA')
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env['GIT_NO_REPLACE_OBJECTS'] = '1'
    raw = subprocess.run(['/usr/bin/git', 'ls-tree', '-r', '-z', '--name-only', f'{commit}^{{commit}}', '--', 'code_health'],
                         cwd=repo, env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120).stdout
    names = [name.decode('utf-8') for name in raw.split(b'\0') if name]
    result = {name for name in names if RUNTIME_SOURCE.fullmatch(name)}
    result.update({'code_health/policy.json', 'code_health/requirements.lock'})
    reader_files = {'code_health/readers-lock.json', 'code_health/readers-upstream.json'}
    present = reader_files & set(names)
    if present and present != reader_files:
        raise ValueError('reader metadata is incomplete')
    result.update(present)
    if present:
        result.update(ASSET_NAMES.values())
    if 'code_health/cli.py' not in result:
        raise ValueError('policy entrypoint is missing')
    return result


def build_bundle(repo: str | os.PathLike[str], commit: str, allowed_files: set[str], *, reader_archives=None,
                 download_readers=False) -> bytes:
    if not COMMIT.fullmatch(commit):
        raise ValueError('release commit must be a full SHA')
    required = {'code_health/policy.json', 'code_health/requirements.lock'}
    paths = set(allowed_files)
    if not required <= paths:
        raise ValueError('release needs the policy and dependency lock')
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env['GIT_NO_REPLACE_OBJECTS'] = '1'

    def git(*args):
        return subprocess.run(['/usr/bin/git', *args], cwd=repo, env=env, check=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=120).stdout

    files = {}
    total = 0
    for name in sorted(paths - set(ASSET_NAMES.values())):
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
    reader_files = {'code_health/readers-lock.json', 'code_health/readers-upstream.json'}
    present = reader_files & files.keys()
    reader_version = policy.get('readerMetadataVersion') if isinstance(policy, dict) else None
    if reader_version is not None or present:
        if type(reader_version) is not int or reader_version != 1 or present != reader_files:
            raise ValueError('reader metadata is missing or undeclared')
        if package_version('desloppify') != policy.get('desloppifyVersion'):
            raise ValueError('installed scanner differs from the selected policy')
        installed_version = package_version('tree-sitter-language-pack')
        if installed_version != locked_package_version(files['code_health/requirements.lock']):
            raise ValueError('installed reader package differs from the dependency lock')
        lock = verify_manifest(files['code_health/readers-lock.json'], files['code_health/readers-upstream.json'],
                               package_version=installed_version, grammars=required_grammars())
        if download_readers:
            if reader_archives is not None:
                raise ValueError('choose one reader archive source')
            reader_archives = download_reader_archives(lock)
        if (not isinstance(reader_archives, dict) or set(reader_archives) != PLATFORMS
                or not set(ASSET_NAMES.values()) <= paths):
            raise ValueError('verified reader archives are missing')
        for platform, name in sorted(ASSET_NAMES.items()):
            data = verify_archive(reader_archives[platform], lock=lock, platform=platform)
            total += len(data)
            if total > MAX_BUNDLE_BYTES:
                raise ValueError('policy source and readers exceed the size limit')
            files[name] = data
    elif reader_archives is not None or download_readers or paths & set(ASSET_NAMES.values()):
        raise ValueError('reader archives have no declared metadata')
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


def read_reader_archives(directory: Path) -> dict[str, bytes]:
    root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    archives = {}
    try:
        for platform in sorted(PLATFORMS):
            fd = os.open('parsers-' + platform + '.tar.zst', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
            try:
                metadata = os.fstat(fd)
                if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_ARCHIVE_BYTES:
                    raise ValueError('invalid reader archive file')
                with os.fdopen(fd, 'rb') as source:
                    fd = None
                    data = source.read(MAX_ARCHIVE_BYTES + 1)
                if len(data) != metadata.st_size:
                    raise ValueError('reader archive changed while reading')
                archives[platform] = data
            finally:
                if fd is not None:
                    os.close(fd)
    finally:
        os.close(root)
    return archives


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reader-directory', type=Path)
    parser.add_argument('--download-readers', action='store_true')
    args = parser.parse_args()
    archives = read_reader_archives(args.reader_directory) if args.reader_directory is not None else None
    data = build_bundle(args.repo, args.commit, runtime_files(args.repo, args.commit), reader_archives=archives,
                        download_readers=args.download_readers)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


if __name__ == '__main__':
    main()
