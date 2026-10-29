"""Run comparable whole-area scans and enforce the shared mechanical ratchet."""
from __future__ import annotations

import argparse
from collections import Counter
import json
import hashlib
import math
from importlib.metadata import version
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile

from desloppify.languages import available_langs, get_lang

POLICY = json.loads(Path(__file__).with_name('policy.json').read_text())
CONFIG = '.github/code-health.json'
LANGUAGES = set(available_langs())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    return json.loads(path.read_text())


def relative_path(value, *, pattern=False):
    require(isinstance(value, str) and value and '\\' not in value, 'expected a relative POSIX path')
    p = PurePosixPath(value)
    require(not p.is_absolute() and '..' not in p.parts, 'path escapes the repository')
    require(not any(ord(c) < 32 for c in value), 'control characters in path')
    if pattern:
        require(value not in {'.', '*', '**', '**/*'}, 'an exclusion cannot hide the whole area')
    else:
        require(not any(c in value for c in '*?['), 'area paths must be literal')
    return value


def validate_config(config):
    require(isinstance(config, dict), 'code-health config must be an object')
    require(set(config) <= {'schemaVersion', 'policyRef', 'strictTarget', 'reviewMaxAgeDays', 'areas', 'unsupportedLanguages'}, 'unknown code-health config field')
    require(type(config.get('schemaVersion')) is int and config['schemaVersion'] == POLICY['schemaVersion'], 'unsupported policy schema')
    require(re.fullmatch('[0-9a-f]{40}', str(config.get('policyRef', ''))), 'policyRef must be an immutable 40-character SHA')
    target = config.get('strictTarget', POLICY['strictTarget'])
    age = config.get('reviewMaxAgeDays', POLICY['review']['maxAgeDays'])
    require(type(target) in {int, float} and math.isfinite(target) and POLICY['strictTarget'] <= target <= 100, 'strict target may only tighten the shared policy')
    require(type(age) is int and 1 <= age <= POLICY['review']['maxAgeDays'], 'review age may only tighten the shared policy')
    areas = config.get('areas')
    require(isinstance(areas, list) and areas, 'at least one coherent project area is required')
    ids, paths = set(), set()
    for area in areas:
        require(isinstance(area, dict) and set(area) == {'id', 'language', 'path', 'exclusions'}, 'invalid area fields')
        require(re.fullmatch('[a-z][a-z0-9-]*', str(area['id'])), 'invalid area id')
        require(area['id'] not in ids, 'duplicate area id')
        ids.add(area['id'])
        require(isinstance(area['language'], str) and area['language'] in LANGUAGES, 'unsupported scanner language')
        relative_path(area['path'])
        key = area['language'], area['path']
        require(key not in paths, 'duplicate language/project area')
        paths.add(key)
        require(isinstance(area['exclusions'], list), 'area exclusions must be a list')
        for exclusion in area['exclusions']:
            require(isinstance(exclusion, dict) and set(exclusion) == {'pattern', 'kind', 'rationale'}, 'each exclusion needs its class and rationale')
            relative_path(exclusion['pattern'], pattern=True)
            require(exclusion['kind'] in POLICY['excludedClasses'], 'exclusion class requires operator approval')
            require(isinstance(exclusion['rationale'], str) and exclusion['rationale'].strip(), 'exclusion rationale is required')
    gaps = config.get('unsupportedLanguages', [])
    require(isinstance(gaps, list), 'unsupportedLanguages must be a list')
    for gap in gaps:
        require(isinstance(gap, dict) and set(gap) == {'language', 'rationale'} and gap['language'] not in LANGUAGES and gap['rationale'], 'known language gaps must be unsupported and explained')
    return config


def validate_transition(base, head):
    if base is None:
        return
    require(head.get('strictTarget', 90) >= base.get('strictTarget', 90), 'a repository cannot lower its strict target')
    require(head.get('reviewMaxAgeDays', 30) <= base.get('reviewMaxAgeDays', 30), 'a repository cannot relax its review cadence')
    old = {a['id']: a for a in base['areas']}
    new = {a['id']: a for a in head['areas']}
    for key, area in old.items():
        require(new.get(key) == area, 'existing scan areas and exclusions cannot change in an ordinary PR')


def validate_workflow_pin(repo, sha, files, policy_ref):
    import yaml

    expected = f'agentsia-uk/ci-shared/.github/workflows/shared-code-health.yml@{policy_ref}'
    found = False
    for file in files:
        if not file.startswith('.github/workflows/') or not file.endswith(('.yml', '.yaml')):
            continue
        workflow = yaml.load(run(['git', 'show', f'{sha}:{file}'], cwd=repo), Loader=yaml.BaseLoader)
        if not isinstance(workflow, dict):
            continue
        jobs = workflow.get('jobs', {})
        if not isinstance(jobs, dict):
            continue
        for job in jobs.values():
            if not isinstance(job, dict) or not str(job.get('uses', '')).startswith('agentsia-uk/ci-shared/.github/workflows/shared-code-health.yml@'):
                continue
            require(job['uses'] == expected, 'caller workflow does not match policyRef')
            require('if' not in job and job.get('continue-on-error', 'false') == 'false', 'the code-health gate may not be conditional or advisory')
            events = workflow.get('on', {})
            require(isinstance(events, (dict, list)) and 'pull_request' in events and 'merge_group' in events, 'code-health caller must run on pull_request and merge_group')
            if isinstance(events, dict):
                for event in ['pull_request', 'merge_group']:
                    require(events[event] in ('', None) or events[event] == {}, 'code-health caller may not filter PR or merge-group events')
            found = True
    require(found, 'no unconditional SHA-pinned shared code-health workflow caller')


def validate_language_coverage(files, areas):
    extensions = {language: set(get_lang(language).extensions) for language in LANGUAGES}
    supported = set().union(*extensions.values())
    for file in files:
        suffix = PurePosixPath(file).suffix
        if suffix not in supported:
            continue
        owners = [area for area in areas if area['path'] == '.' or PurePosixPath(file).is_relative_to(area['path'])]
        depth = max((len(PurePosixPath(a['path']).parts) for a in owners), default=-1)
        covered = any(len(PurePosixPath(area['path']).parts) == depth and suffix in extensions[area['language']] for area in owners)
        require(covered, f'supported source file is outside declared language areas: {file}')


def run(args, *, cwd, env=None):
    result = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=1800)
    return result.stdout


def changed_paths(repo, base, head):
    raw = run(['git', 'diff', '--name-status', '-z', '--find-renames', base, head, '--'], cwd=repo).decode().split('\0')
    touched, renames = set(), {}
    i = 0
    while i < len(raw) and raw[i]:
        status, old = raw[i:i + 2]
        i += 2
        if status.startswith(('R', 'C')):
            new = raw[i]
            i += 1
            touched.update([old, new])
            if status.startswith('R'):
                renames[old] = new
        else:
            touched.add(old)
    return touched, renames


def mechanical_findings(state):
    require(state.get('version') == 3 and isinstance(state.get('work_items'), dict), 'unsupported desloppify state schema')
    result = []
    for finding in state['work_items'].values():
        require(isinstance(finding, dict), 'invalid scanner finding')
        if finding.get('work_item_kind') != 'mechanical_defect':
            continue
        require(type(finding.get('tier')) is int and finding['tier'] in {1, 2, 3, 4}, 'invalid mechanical tier')
        require(finding.get('status') in {'open', 'fixed', 'auto_resolved', 'wontfix', 'false_positive'}, 'unknown finding status')
        if finding['status'] in {'open', 'wontfix'}:
            require(isinstance(finding.get('id'), str) and isinstance(finding.get('file'), str) and isinstance(finding.get('detector'), str) and isinstance(finding.get('summary'), str), 'incomplete mechanical finding')
            result.append(finding)
    return result


def finding_paths(finding):
    paths = {finding['file']}
    detail = finding.get('detail', {})
    if isinstance(detail, dict):
        paths.update(p for p in detail.get('related_files', []) if isinstance(p, str))
    return paths


def fingerprint(finding, renames):
    return finding['detector'], renames.get(finding['file'], finding['file']), tuple(renames.get(part, part) for part in finding['id'].split('::'))


def compare(base_status, base_state, head_status, head_state, touched, renames, language):
    errors = []
    scores = []
    for status in [base_status, head_status]:
        score = status.get('objective_score')
        require(type(score) in {float, int} and math.isfinite(score) and 0 <= score <= 100, 'missing or invalid objective score')
        scores.append(score)
    if scores[1] < scores[0]:
        errors.append(f'objective score decreased: {scores[0]} -> {scores[1]}')
    coverage = []
    for state in [base_state, head_state]:
        record = state.get('scan_coverage', {}).get(language)
        require(isinstance(record, dict) and record.get('status') in {'full', 'reduced'} and isinstance(record.get('detectors'), dict), 'missing detector coverage')
        coverage.append({k: (v.get('status'), v.get('confidence')) for k, v in record['detectors'].items()})
    require(coverage[0] == coverage[1], 'detector coverage changed between scans; scores are not comparable')
    before = Counter(fingerprint(f, renames) for f in mechanical_findings(base_state))
    after = mechanical_findings(head_state)
    introduced = Counter()
    for finding in after:
        if finding_paths(finding) & touched:
            introduced[fingerprint(finding, {})] += 1
            if finding['tier'] in POLICY['ratchet']['touchedTiersMustBeClear']:
                errors.append(f'T{finding["tier"]} remains in touched path: {finding["file"]} ({finding["detector"]})')
    for key, count in (introduced - before).items():
        errors.append(f'{count} new finding(s) in touched path: {key[1]} ({key[0]})')
    return {'objectiveBefore': scores[0], 'objectiveAfter': scores[1], 'coverage': head_state['scan_coverage'][language]['status'], 'errors': errors}


def snapshot(repo, sha, destination):
    archive_path = destination.parent / f'{destination.name}.tar'
    with archive_path.open('wb') as archive:
        subprocess.run(['git', 'archive', '--format=tar', sha], cwd=repo, stdout=archive, check=True, timeout=1800)
    destination.mkdir()
    with tarfile.open(archive_path) as source:
        members = [m for m in source.getmembers() if '.desloppify' not in PurePosixPath(m.name).parts]
        source.extractall(destination, members=members, filter='data')
    archive_path.unlink()


def scan(snapshot_root, area, output, areas):
    snapshot_root = snapshot_root.resolve()
    root = (snapshot_root / area['path']).resolve()
    require(root.is_relative_to(snapshot_root) and root.is_dir(), 'scan area is missing or escapes its snapshot')
    config = {'generate_scorecard': False, 'trust_plugins': False, 'hermes_enabled': False, 'hermes_models': {}, 'languages': {}, 'ignore': [], 'zone_overrides': {}, 'exclude': [e['pattern'] for e in area['exclusions']], 'commit_tracking_enabled': False, 'target_strict_score': POLICY['strictTarget']}
    for other in areas:
        nested = (snapshot_root / other['path']).resolve()
        if nested != root and nested.is_relative_to(root):
            config['exclude'].append(str(nested.relative_to(snapshot_root)))
    for location in {snapshot_root, root}:
        (location / '.desloppify').mkdir(exist_ok=True)
        (location / '.desloppify/config.json').write_text(json.dumps(config))
    env = {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR', 'SYSTEMROOT', 'LANG'] if key in os.environ}
    private_home = snapshot_root.parent / 'scanner-home'
    private_home.mkdir(exist_ok=True)
    env['HOME'] = str(private_home)
    env['PATH'] = str(Path(sys.executable).parent) + os.pathsep + env.get('PATH', '')
    env.update({'DESLOPPIFY_ROOT': str(snapshot_root), 'NO_COLOR': '1', 'CI': 'true', 'npm_config_yes': 'false'})
    state = output / 'state.json'
    output.mkdir(parents=True)
    command = [str(Path(sys.executable).with_name('desloppify')), '--lang', area['language']]
    log = run(command + ['scan', '--path', area['path'], '--profile', 'ci', '--no-badge', '--state', str(state)], cwd=snapshot_root, env=env)
    (output / 'scan.log').write_bytes(log)
    status = run(command + ['status', '--state', str(state), '--json'], cwd=snapshot_root, env=env)
    (output / 'status.json').write_bytes(status)
    return json.loads(status), read_json(state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--base', required=True)
    parser.add_argument('--head', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(re.fullmatch('[0-9a-f]{40}', args.base) and re.fullmatch('[0-9a-f]{40}', args.head), 'base and head must be full commit SHAs')
    require(version('desloppify') == POLICY['desloppifyVersion'], 'installed scanner version differs from the shared pin')
    args.output = args.output.resolve()
    repo = args.repo.resolve()
    for sha in [args.base, args.head]:
        run(['git', 'rev-parse', '--verify', f'{sha}^{{commit}}'], cwd=repo)
    base_bytes = subprocess.run(['git', 'show', f'{args.base}:{CONFIG}'], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(base_bytes.returncode in {0, 128}, 'could not read base config')
    base = validate_config(json.loads(base_bytes.stdout)) if base_bytes.returncode == 0 else None
    head = validate_config(json.loads(run(['git', 'show', f'{args.head}:{CONFIG}'], cwd=repo)))
    validate_transition(base, head)
    files = run(['git', 'ls-tree', '-r', '--name-only', '-z', args.head], cwd=repo).decode().rstrip('\0').split('\0')
    validate_workflow_pin(repo, args.head, files, head['policyRef'])
    validate_language_coverage(files, head['areas'])
    touched, renames = changed_paths(repo, args.base, args.head)
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix='code-health-') as temporary:
        root = Path(temporary)
        for name, sha in [('base', args.base), ('head', args.head)]:
            snapshot(repo, sha, root / name)
        for area in head['areas']:
            before = scan(root / 'base', area, args.output / area['id'] / 'base', head['areas'])
            after = scan(root / 'head', area, args.output / area['id'] / 'head', head['areas'])
            result = compare(*before, *after, touched, renames, area['language'])
            results.append({'area': area['id'], **result})
    report = {'schemaVersion': 1, 'base': args.base, 'head': args.head, 'desloppifyVersion': POLICY['desloppifyVersion'], 'policyRef': head['policyRef'], 'configSha256': hashlib.sha256(json.dumps(head, sort_keys=True).encode()).hexdigest(), 'areas': results, 'unsupportedLanguages': head.get('unsupportedLanguages', [])}
    (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return int(any(r['errors'] for r in results))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f'code-health refused: {error}', file=sys.stderr)
        sys.exit(2)
