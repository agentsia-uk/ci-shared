"""Build candidate CI evidence; m3 independently admits its run and attestation."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import sys

if __package__:
    from . import cli
else:
    import cli

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_RESULT_BYTES = 8 * 1024 * 1024
MAX_EXECUTION_BYTES = 64 * 1024
MAX_ENVELOPE_BYTES = 4 * 1024 * 1024
MAX_PROJECTION_BYTES = 8 * 1024 * 1024
MAX_PROJECTIONS_BYTES = 64 * 1024 * 1024
CANONICAL_REPOSITORY = 'agentsia-uk/ci-shared'
ENVELOPE_FIELDS = {'schemaVersion', 'kind', 'collectorValidationRequired', 'repository', 'run', 'source', 'manifest', 'result', 'launcher', 'release', 'runtime', 'registry'}


def object_fields(value, fields, name) -> None:
    cli.require(isinstance(value, dict) and set(value) == set(fields), f'invalid {name} fields')


def text(value, name, limit=512) -> None:
    cli.require(isinstance(value, str) and 0 < len(value) <= limit and not any(ord(c) < 32 for c in value), f'invalid {name}')


def sha(value, name, length=40) -> None:
    cli.require(isinstance(value, str) and re.fullmatch(f'[0-9a-f]{{{length}}}', value), f'invalid {name}')


def positive_integer(value, name) -> None:
    cli.require(type(value) is int and 0 < value <= 2 ** 53 - 1, f'invalid {name}')


def unique_object(pairs) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        cli.require(key not in result, 'duplicate JSON object key')
        result[key] = value
    return result


def json_bytes(raw, maximum) -> object:
    cli.require(len(raw) <= maximum, 'artifact JSON exceeds its byte limit')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object, parse_constant=lambda value: cli.require(False, 'non-finite JSON number'))


def read_bounded(path, maximum) -> bytes:
    with path.open('rb') as source:
        raw = source.read(maximum + 1)
    cli.require(len(raw) <= maximum, 'artifact input exceeds its byte limit')
    return raw


def sha256(raw) -> str:
    return hashlib.sha256(raw).hexdigest()


def validate_repository(value) -> None:
    object_fields(value, {'id', 'fullName'}, 'repository')
    positive_integer(value['id'], 'repository ID')
    cli.require(isinstance(value['fullName'], str) and re.fullmatch(r'agentsia-uk/[A-Za-z0-9_.-]{1,100}', value['fullName']), 'repository must be an agentsia-uk slug')


def validate_run(value) -> None:
    object_fields(value, {'id', 'attempt', 'event', 'ref'}, 'run')
    positive_integer(value['id'], 'run ID')
    positive_integer(value['attempt'], 'run attempt')
    cli.require(isinstance(value['event'], str) and value['event'] in {'pull_request', 'merge_group', 'push', 'schedule', 'workflow_dispatch'}, 'unsupported producer event')
    text(value['ref'], 'run ref')
    cli.require(value['ref'].startswith('refs/'), 'run ref must be a full Git ref')


def validate_execution(value) -> None:
    """Validate shape only; the launcher must supply its private verified output."""
    object_fields(value, {'launcher', 'release'}, 'verified execution')
    launcher, release = value['launcher'], value['release']
    object_fields(launcher, {'repository', 'workflowPath', 'workflowSha', 'actionRef'}, 'launcher')
    cli.require(launcher['repository'] == CANONICAL_REPOSITORY, 'launcher repository is not canonical')
    text(launcher['workflowPath'], 'launcher workflow path')
    cli.require(re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml', launcher['workflowPath']), 'invalid launcher workflow path')
    for field in ['workflowSha', 'actionRef']:
        sha(launcher[field], 'launcher ' + field)
    object_fields(release, {'repository', 'tag', 'policyCommitSha', 'bundleSha256', 'releaseManifestSha256', 'qualificationWorkflowSha', 'requirementsLockSha256'}, 'release')
    cli.require(release['repository'] == CANONICAL_REPOSITORY, 'release repository is not canonical')
    text(release['tag'], 'release tag', 200)
    for field in ['policyCommitSha', 'qualificationWorkflowSha']:
        sha(release[field], 'release ' + field)
    for field in ['bundleSha256', 'releaseManifestSha256', 'requirementsLockSha256']:
        sha(release[field], 'release ' + field, 64)


def validate_runtime(value) -> None:
    object_fields(value, {'pythonVersion', 'sysPlatform', 'machine', 'glibcVersion'}, 'runtime')
    cli.require(isinstance(value['pythonVersion'], str) and re.fullmatch(r'3\.13\.\d+', value['pythonVersion']), 'producer requires Python 3.13')
    cli.require(value['sysPlatform'] == 'linux' and isinstance(value['machine'], str) and value['machine'] in {'x86_64', 'aarch64'}, 'producer requires supported Linux architecture')
    cli.require(isinstance(value['glibcVersion'], str) and re.fullmatch(r'\d+\.\d+(?:\.\d+)?', value['glibcVersion']), 'producer requires glibc')
    cli.require(tuple(int(part) for part in value['glibcVersion'].split('.')[:2]) >= (2, 34), 'producer requires glibc >= 2.34')


def current_runtime() -> dict[str, str]:
    libc, version = platform.libc_ver()
    cli.require(libc == 'glibc', 'producer requires glibc')
    value = {'pythonVersion': platform.python_version(), 'sysPlatform': sys.platform, 'machine': platform.machine(), 'glibcVersion': version}
    validate_runtime(value)
    return value


def project_registry(repository, commit, manifest_raw) -> dict[str, object]:
    """A manifest-derived namespace; no repository or area enum can go stale."""
    validate_repository(repository)
    sha(commit, 'registry source commit')
    definition = cli.validate_config(json_bytes(manifest_raw, MAX_MANIFEST_BYTES))
    return {'repository': copy.deepcopy(repository), 'sourceCommitSha': commit, 'manifestSha256': sha256(manifest_raw), 'areas': copy.deepcopy(definition['areas']), 'unsupportedLanguages': copy.deepcopy(definition.get('unsupportedLanguages', []))}


def validate_envelope(value) -> dict[str, object]:
    cli.require(isinstance(value, dict) and type(value.get('schemaVersion')) is int and value['schemaVersion'] in (1, 2), 'unsupported producer schema')
    object_fields(value, ENVELOPE_FIELDS | ({'projections'} if value['schemaVersion'] == 2 else set()), 'producer envelope')
    cli.require(value['kind'] == 'agentsia.code-health.ci-producer', 'unsupported producer schema')
    cli.require(value['collectorValidationRequired'] is True, 'producer evidence requires independent m3 admission')
    validate_repository(value['repository'])
    validate_run(value['run'])
    validate_runtime(value['runtime'])
    validate_execution({'launcher': value['launcher'], 'release': value['release']})
    object_fields(value['source'], {'baseCommitSha', 'commitSha', 'treeSha'}, 'source')
    for field in value['source']:
        sha(value['source'][field], field)
    manifest = value['manifest']
    object_fields(manifest, {'path', 'gitBlobSha', 'sha256', 'size', 'definition'}, 'manifest')
    cli.require(manifest['path'] == cli.CONFIG, 'unexpected producer manifest path')
    sha(manifest['gitBlobSha'], 'manifest Git blob SHA')
    sha(manifest['sha256'], 'manifest hash', 64)
    positive_integer(manifest['size'], 'manifest size')
    cli.require(manifest['size'] <= MAX_MANIFEST_BYTES, 'manifest exceeds its byte limit')
    cli.validate_config(manifest['definition'])
    cli.require(manifest['definition']['policyRef'] == value['release']['policyCommitSha'], 'manifest pin differs from the verified release')
    cli.require(manifest['definition']['workflowRef'] == value['launcher']['workflowSha'], 'manifest pin differs from the verified launcher')
    result = value['result']
    object_fields(result, {'path', 'sha256', 'size'}, 'result')
    cli.require(result['path'] == 'result.json', 'unexpected producer result path')
    sha(result['sha256'], 'result hash', 64)
    positive_integer(result['size'], 'result size')
    cli.require(result['size'] <= MAX_RESULT_BYTES, 'result exceeds its byte limit')
    registry = value['registry']
    object_fields(registry, {'repository', 'sourceCommitSha', 'manifestSha256', 'areas', 'unsupportedLanguages'}, 'registry')
    expected = {'repository': value['repository'], 'sourceCommitSha': value['source']['commitSha'], 'manifestSha256': manifest['sha256'], 'areas': manifest['definition']['areas'], 'unsupportedLanguages': manifest['definition'].get('unsupportedLanguages', [])}
    cli.require(json.dumps(registry, sort_keys=True, separators=(',', ':')) == json.dumps(expected, sort_keys=True, separators=(',', ':')), 'registry is not the exact manifest projection')
    if value['schemaVersion'] == 2:
        projections = value['projections']
        areas = {area['id'] for area in manifest['definition']['areas']}
        cli.require(isinstance(projections, list) and len(projections) == len(areas), 'projection inventory differs from manifest')
        seen, total = set(), 0
        for item in projections:
            object_fields(item, {'area', 'path', 'sha256', 'size'}, 'projection reference')
            area = item['area']
            cli.require(isinstance(area, str) and area in areas and area not in seen and item['path'] == f'projections/{area}.json', 'invalid projection reference')
            sha(item['sha256'], 'projection hash', 64)
            positive_integer(item['size'], 'projection size')
            cli.require(item['size'] <= MAX_PROJECTION_BYTES, 'projection exceeds its byte limit')
            total += item['size']
            seen.add(area)
        cli.require(total <= MAX_PROJECTIONS_BYTES and seen == areas, 'projection inventory differs from manifest')
    return value


def manifest_blob(repo, commit) -> tuple[str, bytes]:
    tree = cli.run(['git', 'ls-tree', '-z', '--full-tree', f'{commit}^{{commit}}', '--', cli.CONFIG], cwd=repo).split(b'\0')
    cli.require(len(tree) == 2 and tree[-1] == b'', 'manifest must exist at its exact Git path')
    metadata, path = tree[0].split(b'\t', 1)
    mode, kind, oid = metadata.split()
    cli.require(path == cli.CONFIG.encode() and kind == b'blob' and mode in {b'100644', b'100755'} and re.fullmatch(b'[0-9a-f]{40}', oid), 'manifest must be a regular Git blob')
    size = cli.run(['git', 'cat-file', '-s', oid.decode()], cwd=repo).strip()
    cli.require(size.isdigit() and int(size) <= MAX_MANIFEST_BYTES, 'manifest exceeds its byte limit')
    raw = cli.run(['git', 'cat-file', 'blob', oid.decode()], cwd=repo)
    cli.require(len(raw) == int(size), 'manifest blob read was incomplete')
    return oid.decode(), raw


def build_envelope(repo, base, head, result_path, execution_path, repository, run) -> dict[str, object]:
    """Only the trusted launcher calls this after verifying its private inputs."""
    sha(base, 'base commit')
    sha(head, 'head commit')
    cli.run(['git', 'rev-parse', '--verify', f'{base}^{{commit}}'], cwd=repo)
    tree = cli.run(['git', 'rev-parse', '--verify', f'{head}^{{tree}}'], cwd=repo).decode().strip()
    oid, raw = manifest_blob(repo, head)
    definition = cli.validate_config(json_bytes(raw, MAX_MANIFEST_BYTES))
    cli.require(not execution_path.resolve().is_relative_to(repo.resolve()), 'verified execution evidence must be outside the caller checkout')
    execution = json_bytes(read_bounded(execution_path, MAX_EXECUTION_BYTES), MAX_EXECUTION_BYTES)
    validate_execution(execution)
    result_raw = read_bounded(result_path, MAX_RESULT_BYTES)
    result = json_bytes(result_raw, MAX_RESULT_BYTES)
    cli.require(isinstance(result, dict) and type(result.get('schemaVersion')) is int and result['schemaVersion'] == 1 and result.get('base') == base and result.get('head') == head, 'result does not describe these exact source commits')
    cli.require(result.get('desloppifyVersion') == cli.POLICY['desloppifyVersion'], 'result tool version differs from the selected policy')
    cli.require(isinstance(cli.POLICY.get('scannerPatch'), dict) and result.get('scannerPatch') == cli.POLICY['scannerPatch'], 'result scanner correction differs from the selected policy')
    cli.require(result.get('configSha256') == sha256(json.dumps(definition, sort_keys=True).encode()), 'result config hash differs from the source manifest')
    cli.require(isinstance(result.get('areas'), list) and all(isinstance(a, dict) and isinstance(a.get('area'), str) for a in result['areas']) and sorted(a['area'] for a in result['areas']) == sorted(a['id'] for a in definition['areas']), 'result areas differ from the source manifest')
    value = {'schemaVersion': 1, 'kind': 'agentsia.code-health.ci-producer', 'collectorValidationRequired': True, 'repository': copy.deepcopy(repository), 'run': copy.deepcopy(run), 'source': {'baseCommitSha': base, 'commitSha': head, 'treeSha': tree}, 'manifest': {'path': cli.CONFIG, 'gitBlobSha': oid, 'sha256': sha256(raw), 'size': len(raw), 'definition': definition}, 'result': {'path': 'result.json', 'sha256': sha256(result_raw), 'size': len(result_raw)}, **execution, 'runtime': current_runtime(), 'registry': project_registry(repository, head, raw)}
    validate_envelope(value)
    cli.require(len(json.dumps(value).encode()) <= MAX_ENVELOPE_BYTES, 'producer envelope exceeds its byte limit')
    return value


def build_envelope_v2(repo, base, head, result_path, execution_path, repository, run, projection_bytes) -> dict[str, object]:
    """Bind projections as data; the caller and collector must authenticate their origin."""
    if __package__:
        from . import mechanical
    else:
        import mechanical
    envelope = build_envelope(repo, base, head, result_path, execution_path, repository, run)
    raw_result = read_bounded(result_path, MAX_RESULT_BYTES)
    cli.require(sha256(raw_result) == envelope['result']['sha256'], 'result changed during projection binding')
    result = json_bytes(raw_result, MAX_RESULT_BYTES)
    areas = {area['id']: area for area in envelope['manifest']['definition']['areas']}
    cli.require(isinstance(projection_bytes, dict) and set(projection_bytes) == set(areas), 'projection inventory differs from manifest')
    results = {area['area']: area for area in result['areas']}
    references, total = [], 0
    for area_id, raw in sorted(projection_bytes.items()):
        cli.require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_PROJECTION_BYTES, 'invalid projection bytes')
        total += len(raw)
        cli.require(total <= MAX_PROJECTIONS_BYTES, 'projections exceed total byte limit')
        projection = json_bytes(raw, MAX_PROJECTION_BYTES)
        fields = {'schemaVersion', 'kind', 'repositoryId', 'area', 'commitSha', 'capturedAt', 'desloppifyVersion',
                  'scannerPatch', 'language', 'scanPath', 'scanCompleteness', 'excludes', 'scores', 'subjectiveAssessment',
                  'mechanicalDimensions', 'counts', 'coverage', 'findings', 'hotspots', 'comparabilityKey'}
        object_fields(projection, fields, 'mechanical projection')
        area = areas[area_id]
        mechanical.validate_public_projection(projection)
        try:
            rendered = json.dumps(projection, ensure_ascii=False, allow_nan=False, separators=(',', ':'))
        except (TypeError, ValueError, RecursionError) as error:
            raise ValueError('invalid projection values') from error
        cli.require(not mechanical._has_secret(rendered), 'secret-bearing projection is not publishable')
        cli.require(type(projection['schemaVersion']) is int and projection['schemaVersion'] == 2 and
                    projection['kind'] == 'agentsia.code-health.mechanical-projection' and
                    type(projection['repositoryId']) is int and projection['repositoryId'] == repository['id'] and
                    projection['area'] == area_id and projection['commitSha'] == head and
                    projection['language'] == area['language'] and projection['scanPath'] == area['path'] and
                    projection['desloppifyVersion'] == result['desloppifyVersion'] and
                    projection['scannerPatch'] == result['scannerPatch'] and projection['subjectiveAssessment'] == 'absent',
                    'projection identity differs from the scan')
        root = PurePosixPath(area['path'])
        expected_excludes = [item['pattern'] for item in area['exclusions']]
        expected_excludes.extend(other['path'] for other in areas.values()
                                 if PurePosixPath(other['path']) != root and PurePosixPath(other['path']).is_relative_to(root))
        cli.require(isinstance(projection['excludes'], list) and all(isinstance(item, str) for item in projection['excludes']) and
                    sorted(projection['excludes']) == sorted(expected_excludes) and
                    projection['scanCompleteness'] in ('fast', 'full') and isinstance(projection['coverage'], dict) and
                    projection['coverage'].get('status') == results[area_id].get('coverage'), 'projection scope differs from the scan')
        object_fields(projection['scores'], {'overall', 'strict', 'objective', 'verified'}, 'projection scores')
        for name, value in projection['scores'].items():
            cli.require(value == mechanical._score(value, 'projection ' + name), 'projection score is not rounded')
        cli.require(
                    mechanical._score(projection['scores'].get('objective'), 'projection objective') ==
                    mechanical._score(results[area_id].get('objectiveAfter'), 'result objective'), 'projection score differs from the scan')
        mechanical._timestamp(projection['capturedAt'])
        cli.require(projection['comparabilityKey'] == mechanical.comparison_key(projection), 'projection comparison key differs')
        references.append({'area': area_id, 'path': f'projections/{area_id}.json', 'sha256': sha256(raw), 'size': len(raw)})
    envelope['schemaVersion'] = 2
    envelope['projections'] = references
    validate_envelope(envelope)
    cli.require(len(json.dumps(envelope).encode()) <= MAX_ENVELOPE_BYTES, 'producer envelope exceeds its byte limit')
    return envelope


def read_projection_directory(directory, repo) -> dict[str, bytes]:
    """Read bounded regular files from a private task directory, never from the caller checkout."""
    requested = directory.absolute()
    cli.require(requested.resolve(strict=True) == requested and not requested.is_relative_to(repo.resolve()), 'projection directory must be outside the checkout')
    fd = os.open(requested, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        cli.require(metadata.st_uid == os.geteuid() and metadata.st_mode & 0o077 == 0, 'projection directory is not private')
        names = os.listdir(fd)
        cli.require(len(names) <= 100 and all(re.fullmatch(r'[a-z][a-z0-9-]*\.json', name) for name in names), 'invalid projection file inventory')
        output, total = {}, 0
        for name in sorted(names):
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                before = os.fstat(file_fd)
                cli.require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1 and
                            not before.st_mode & 0o022 and 0 < before.st_size <= MAX_PROJECTION_BYTES, 'unsafe projection file')
                chunks, remaining = [], before.st_size + 1
                while remaining:
                    chunk = os.read(file_fd, min(65536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b''.join(chunks)
                after = os.fstat(file_fd)
                current = os.stat(name, dir_fd=fd, follow_symlinks=False)
                cli.require(len(raw) == before.st_size and
                            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                            (current.st_dev, current.st_ino) == (before.st_dev, before.st_ino), 'projection file changed during read')
                total += len(raw)
                cli.require(total <= MAX_PROJECTIONS_BYTES, 'projections exceed total byte limit')
                output[name[:-5]] = raw
            finally:
                os.close(file_fd)
        current = requested.lstat()
        after = os.fstat(fd)
        cli.require((current.st_dev, current.st_ino) == (metadata.st_dev, metadata.st_ino) and
                    (after.st_dev, after.st_ino, after.st_uid, after.st_mode, after.st_mtime_ns, after.st_ctime_ns) ==
                    (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_mode, metadata.st_mtime_ns, metadata.st_ctime_ns) and
                    sorted(os.listdir(fd)) == sorted(names), 'projection directory changed during read')
        return output
    finally:
        os.close(fd)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--base', required=True)
    parser.add_argument('--head', required=True)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--execution-evidence', type=Path, required=True)
    parser.add_argument('--projection-dir', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    cli.require(os.environ.get('GITHUB_ACTIONS') == 'true', 'producer must run in the trusted GitHub workflow')
    repository = {'id': int(os.environ['GITHUB_REPOSITORY_ID']), 'fullName': os.environ['GITHUB_REPOSITORY']}
    run = {'id': int(os.environ['GITHUB_RUN_ID']), 'attempt': int(os.environ['GITHUB_RUN_ATTEMPT']), 'event': os.environ['GITHUB_EVENT_NAME'], 'ref': os.environ['GITHUB_REF']}
    if args.projection_dir is None:
        value = build_envelope(args.repo, args.base, args.head, args.result, args.execution_evidence, repository, run)
    else:
        projections = read_projection_directory(args.projection_dir, args.repo)
        value = build_envelope_v2(args.repo, args.base, args.head, args.result, args.execution_evidence, repository, run, projections)
    # Private output is created once; m3 must verify its attestation and result bytes.
    with args.output.open('x', encoding='utf-8') as output:
        output.write(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n')


if __name__ == '__main__':
    main()
