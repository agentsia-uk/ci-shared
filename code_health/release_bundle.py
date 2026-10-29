"""Validate the contents of an already attested code-health policy bundle."""
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path, PurePosixPath

MAX_BUNDLE_BYTES = 64 * 1024 * 1024
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')


def read_bundle(path, *, policy_commit, allowed_files):
    """Return verified runtime bytes; the caller must verify the bundle attestation first."""
    if isinstance(path, bytes):
        data = path
    else:
        with Path(path).open('rb') as source:
            data = source.read(MAX_BUNDLE_BYTES + 1)
    if len(data) > MAX_BUNDLE_BYTES or not COMMIT.fullmatch(policy_commit):
        raise ValueError('invalid policy bundle size or commit')
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        for item in archive:
            name = item.name
            pure = PurePosixPath(name)
            if (not item.isfile() or item.pax_headers or item.sparse or name != str(pure) or pure.is_absolute() or
                    any(part in ('.', '..') for part in pure.parts) or '\\' in name or
                    any(ord(char) < 32 for char in name) or name in files or item.size > MAX_BUNDLE_BYTES):
                raise ValueError('unsafe policy bundle entry')
            total += item.size
            if total > MAX_BUNDLE_BYTES:
                raise ValueError('policy bundle contents exceed the size limit')
            stream = archive.extractfile(item)
            if stream is None:
                raise ValueError('unreadable policy bundle entry')
            files[name] = stream.read(MAX_BUNDLE_BYTES + 1)
            if len(files[name]) != item.size:
                raise ValueError('incomplete policy bundle entry')
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate manifest field')
            result[key] = value
        return result

    try:
        manifest_bytes = files.pop('release.json')
        manifest = json.loads(manifest_bytes, object_pairs_hook=unique_pairs)
    except (KeyError, ValueError, UnicodeError) as error:
        raise ValueError('invalid policy release manifest') from error
    fields = {'schemaVersion', 'kind', 'policyCommitSha', 'desloppifyVersion', 'requirementsLockSha256', 'files'}
    if (not isinstance(manifest, dict) or set(manifest) != fields or type(manifest['schemaVersion']) is not int or
            manifest['schemaVersion'] != 1 or manifest['kind'] != 'agentsia.code-health.policy-release' or
            manifest['policyCommitSha'] != policy_commit or not isinstance(manifest['desloppifyVersion'], str) or
            not manifest['desloppifyVersion'] or not isinstance(manifest['requirementsLockSha256'], str) or
            not SHA256.fullmatch(manifest['requirementsLockSha256']) or not isinstance(manifest['files'], list)):
        raise ValueError('invalid policy release manifest')
    index = {}
    for entry in manifest['files']:
        if (not isinstance(entry, dict) or set(entry) != {'path', 'sha256', 'size'} or
                not isinstance(entry['path'], str) or entry['path'] in index or
                not isinstance(entry['sha256'], str) or not SHA256.fullmatch(entry['sha256']) or
                type(entry['size']) is not int or entry['size'] < 0):
            raise ValueError('invalid policy release file index')
        index[entry['path']] = entry
    if set(files) != set(index) or set(files) != set(allowed_files):
        raise ValueError('policy bundle file set differs from trusted allowlist')
    for name, data in files.items():
        if len(data) != index[name]['size'] or hashlib.sha256(data).hexdigest() != index[name]['sha256']:
            raise ValueError('policy bundle file digest mismatch')
    if ('code_health/requirements.lock' not in files or
            hashlib.sha256(files['code_health/requirements.lock']).hexdigest() != manifest['requirementsLockSha256']):
        raise ValueError('policy dependency lock digest mismatch')
    try:
        policy = json.loads(files['code_health/policy.json'], object_pairs_hook=unique_pairs)
    except (KeyError, ValueError, UnicodeError) as error:
        raise ValueError('invalid bundled policy') from error
    if not isinstance(policy, dict) or policy.get('desloppifyVersion') != manifest['desloppifyVersion']:
        raise ValueError('bundled policy version mismatch')
    return manifest, files, hashlib.sha256(manifest_bytes).hexdigest()
