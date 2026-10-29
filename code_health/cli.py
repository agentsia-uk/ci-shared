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
import tempfile
import urllib.parse
import urllib.request

import yaml

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
    require(set(config) <= {'schemaVersion', 'policyRef', 'workflowRef', 'strictTarget', 'reviewMaxAgeDays', 'areas', 'unsupportedLanguages'}, 'unknown code-health config field')
    require(type(config.get('schemaVersion')) is int and config['schemaVersion'] == POLICY['schemaVersion'], 'unsupported policy schema')
    for field in ['policyRef', 'workflowRef']:
        require(isinstance(config.get(field), str) and re.fullmatch('[0-9a-f]{40}', config[field]), f'{field} must be an immutable 40-character SHA')
    target = config.get('strictTarget', POLICY['strictTarget'])
    age = config.get('reviewMaxAgeDays', POLICY['review']['maxAgeDays'])
    require(type(target) in {int, float} and math.isfinite(target) and POLICY['strictTarget'] <= target <= 100, 'strict target may only tighten the shared policy')
    require(type(age) is int and 1 <= age <= POLICY['review']['maxAgeDays'], 'review age may only tighten the shared policy')
    areas = config.get('areas')
    require(isinstance(areas, list), 'areas must list the coherent projects')
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
    require(areas or gaps, 'declare at least one supported area or an unsupported-language gap')
    return config


def validate_transition(base, head, *, upgrade=False):
    if base is None:
        return
    require(head['policyRef'] == base['policyRef'] or upgrade, 'policy changes require a dedicated authorized upgrade PR')
    require(head.get('strictTarget', 90) >= base.get('strictTarget', 90), 'a repository cannot lower its strict target')
    require(head.get('reviewMaxAgeDays', 30) <= base.get('reviewMaxAgeDays', 30), 'a repository cannot relax its review cadence')
    old = {a['id']: a for a in base['areas']}
    new = {a['id']: a for a in head['areas']}
    for key, area in old.items():
        require(new.get(key) == area, 'existing scan areas and exclusions cannot change in an ordinary PR')


def validate_workflow_pin(repo, sha, workflow_path, workflow_ref):
    relative_path(workflow_path)
    require(workflow_path.startswith('.github/workflows/') and workflow_path.endswith(('.yml', '.yaml')), 'caller workflow path is invalid')
    expected = f'agentsia-uk/ci-shared/.github/workflows/shared-code-health.yml@{workflow_ref}'
    # BaseLoader preserves Actions scalars and cannot construct tagged Python objects.
    workflow = yaml.load(run(['git', 'show', f'{sha}:{workflow_path}'], cwd=repo), Loader=yaml.BaseLoader)
    require(isinstance(workflow, dict) and isinstance(workflow.get('jobs'), dict), 'caller workflow has no jobs')
    found = False
    for job in workflow['jobs'].values():
        if not isinstance(job, dict) or not str(job.get('uses', '')).startswith('agentsia-uk/ci-shared/.github/workflows/shared-code-health.yml@'):
            continue
        require(job['uses'] == expected, 'actual caller workflow does not match workflowRef')
        require('if' not in job and job.get('continue-on-error', 'false') == 'false', 'the code-health gate may not be conditional or advisory')
        events = workflow.get('on', {})
        require(isinstance(events, (dict, list)) and 'pull_request' in events and 'merge_group' in events, 'code-health caller must run on pull_request and merge_group')
        if isinstance(events, dict):
            for event in ['pull_request', 'merge_group']:
                require(events[event] in ('', None) or events[event] == {}, 'code-health caller may not filter PR or merge-group events')
        found = True
    require(found, 'actual caller has no unconditional SHA-pinned shared code-health workflow')


def execution_provenance(repo, args, config):
    require(args.action_repository == 'agentsia-uk/ci-shared', 'policy action is not from the canonical repository')
    require(re.fullmatch('[0-9a-f]{40}', args.action_ref or ''), 'executing action must use a full SHA pin')
    require(args.action_ref == config['policyRef'], 'policyRef does not match the executing action')
    require(re.fullmatch('[0-9a-f]{40}', args.caller_sha or ''), 'caller workflow must be bound to its actual commit')
    prefix = args.repository + '/'
    require(args.caller_ref.startswith(prefix) and '@' in args.caller_ref, 'caller workflow does not belong to this repository')
    caller_path = args.caller_ref[len(prefix):].split('@', 1)[0]
    validate_workflow_pin(repo, args.caller_sha, caller_path, config['workflowRef'])
    return {
        'actionRepository': args.action_repository,
        'actionRef': args.action_ref,
        'callerWorkflow': caller_path,
        'callerWorkflowSha': args.caller_sha,
        'callerDeclaredWorkflowRef': config['workflowRef'],
        'policySha256': hashlib.sha256(Path(__file__).with_name('policy.json').read_bytes()).hexdigest(),
        'verifierSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'invocation': 'github-actions' if os.environ.get('GITHUB_ACTIONS') == 'true' else 'local',
    }


def authorized_upgrade(event, repository, touched):
    pr = event.get('pull_request', {})
    return (pr.get('user', {}).get('login') == 'github-actions[bot]'
            and pr.get('head', {}).get('ref', '').startswith('automation/code-health-upgrade-')
            and pr.get('head', {}).get('repo', {}).get('full_name') == repository
            and pr.get('base', {}).get('repo', {}).get('full_name') == repository
            and any(label.get('name') == 'code-health-upgrade' for label in pr.get('labels', []))
            and all(path == CONFIG or path.startswith('.github/workflows/') for path in touched))


def upgrade_evidence(event, args, touched):
    if authorized_upgrade(event, args.repository, touched):
        pr = event['pull_request']
        pin = json.loads(run(['git', 'show', f"{pr['head']['sha']}:{CONFIG}"], cwd=args.repo)).get('policyRef')
        if pin == args.action_ref:
            return {'pullRequest': pr['number'], 'headSha': pr['head']['sha']}
    if 'merge_group' not in event:
        return None
    token = os.environ.get('CODE_HEALTH_GITHUB_TOKEN')
    require(token, 'a queued policy upgrade requires read-only PR metadata')
    branch = event['merge_group']['base_ref'].removeprefix('refs/heads/')
    for page in range(1, 101):
        query = urllib.parse.urlencode({'state': 'open', 'base': branch, 'per_page': 100, 'page': page})
        request = urllib.request.Request(f'https://api.github.com/repos/{args.repository}/pulls?{query}', headers={'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json'})
        with urllib.request.urlopen(request, timeout=30) as response:
            prs = json.load(response)
        require(isinstance(prs, list), 'invalid upgrade PR metadata')
        for pr in prs:
            if not authorized_upgrade({'pull_request': pr}, args.repository, {CONFIG}):
                continue
            sha = pr['head']['sha']
            require(re.fullmatch('[0-9a-f]{40}', sha), 'invalid upgrade head SHA')
            contained = subprocess.run(['git', 'merge-base', '--is-ancestor', sha, args.head], cwd=args.repo, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=1800)
            require(contained.returncode in {0, 1, 128}, 'could not verify queued upgrade ancestry')
            if contained.returncode:
                continue
            ancestor = run(['git', 'merge-base', pr['base']['sha'], sha], cwd=args.repo).decode().strip()
            paths, _ = changed_paths(args.repo, ancestor, sha)
            pin = json.loads(run(['git', 'show', f'{sha}:{CONFIG}'], cwd=args.repo)).get('policyRef')
            if pin == args.action_ref and authorized_upgrade({'pull_request': pr}, args.repository, paths):
                return {'pullRequest': pr['number'], 'headSha': sha}
        if len(prs) < 100:
            return None
    raise ValueError('upgrade PR metadata exceeded the bounded page limit')


def area_has_source(files, area, areas):
    extensions = set(get_lang(area['language']).extensions)
    for file in files:
        path = PurePosixPath(file)
        if path.suffix not in extensions or not (area['path'] == '.' or path.is_relative_to(area['path'])):
            continue
        nested = any(other['path'] != area['path'] and PurePosixPath(other['path']).is_relative_to(area['path']) and path.is_relative_to(other['path']) for other in areas)
        if not nested:
            return True
    return False


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


def objective_score(status):
    score = status.get('objective_score')
    require(type(score) in {float, int} and math.isfinite(score) and 0 <= score <= 100, 'missing or invalid objective score')
    return score


def detector_coverage(state, language):
    record = state.get('scan_coverage', {}).get(language)
    require(isinstance(record, dict) and record.get('status') in {'full', 'reduced'} and isinstance(record.get('detectors'), dict), 'missing detector coverage')
    return {k: (v.get('status'), v.get('confidence')) for k, v in record['detectors'].items()}


def compare(base_status, base_state, head_status, head_state, touched, renames, language):
    errors = []
    score_after = objective_score(head_status)
    coverage_after = detector_coverage(head_state, language)
    if base_status is None and base_state is None:
        score_before, before = None, Counter()
    else:
        score_before = objective_score(base_status)
        require(detector_coverage(base_state, language) == coverage_after, 'detector coverage changed between scans; scores are not comparable')
        before = Counter(fingerprint(f, renames) for f in mechanical_findings(base_state))
        if score_after < score_before:
            errors.append(f'objective score decreased: {score_before} -> {score_after}')
    after = mechanical_findings(head_state)
    introduced = Counter()
    for finding in after:
        if finding_paths(finding) & touched:
            introduced[fingerprint(finding, {})] += 1
            if finding['tier'] in POLICY['ratchet']['touchedTiersMustBeClear']:
                errors.append(f'T{finding["tier"]} remains in touched path: {finding["file"]} ({finding["detector"]})')
    for key, count in (introduced - before).items():
        errors.append(f'{count} new finding(s) in touched path: {key[1]} ({key[0]})')
    return {'objectiveBefore': score_before, 'objectiveAfter': score_after, 'baselineKind': 'existing-area' if score_before is not None else 'new-area', 'coverage': head_state['scan_coverage'][language]['status'], 'errors': errors}


def snapshot(repo, sha, destination):
    destination.mkdir()
    root = destination.resolve()
    entries, links = [], []
    tree = run(['git', 'ls-tree', '-rz', '--full-tree', sha], cwd=repo)
    for record in tree.split(b'\0'):
        if not record:
            continue
        metadata, raw_path = record.split(b'\t', 1)
        mode, kind, oid = metadata.split()
        path = PurePosixPath(os.fsdecode(raw_path))
        require(not path.is_absolute() and '..' not in path.parts, 'Git tree path escapes its snapshot')
        if '.desloppify' in path.parts:
            continue
        if kind == b'commit' and mode == b'160000':
            (destination / path).mkdir(parents=True, exist_ok=True)
            continue
        require(kind == b'blob' and mode in {b'100644', b'100755', b'120000'}, 'unsupported Git tree entry')
        entries.append((mode, oid, path))
    batch = destination.parent / f'{destination.name}.blobs'
    with batch.open('wb') as output:
        requests = b''.join(oid + b'\n' for _, oid, _ in entries)
        subprocess.run(['git', 'cat-file', '--batch'], input=requests, cwd=repo, stdout=output, stderr=subprocess.PIPE, check=True, timeout=1800)
    with batch.open('rb') as source:
        for mode, oid, path in entries:
            header = source.readline().split()
            require(len(header) == 3 and header[:2] == [oid, b'blob'] and header[2].isdigit(), 'invalid Git blob response')
            remaining = int(header[2])
            target = destination / path
            target.parent.mkdir(parents=True, exist_ok=True)
            require(not target.exists() and not target.is_symlink(), 'colliding Git snapshot paths')
            if mode == b'120000':
                require(remaining <= 4096, 'snapshot symlink target is too long')
                data = source.read(remaining)
                require(len(data) == remaining, 'truncated Git symlink blob')
                links.append((target, os.fsdecode(data)))
            else:
                with target.open('wb') as output:
                    while remaining:
                        data = source.read(min(remaining, 1024 * 1024))
                        require(data, 'truncated Git blob')
                        output.write(data)
                        remaining -= len(data)
                target.chmod(0o755 if mode == b'100755' else 0o644)
            require(source.read(1) == b'\n', 'invalid Git blob delimiter')
        require(not source.read(1), 'unexpected extra Git blob data')
    batch.unlink()
    # Create links last so blob writes never follow candidate-controlled links.
    for target, link in links:
        require(not Path(link).is_absolute() and (target.parent / link).resolve().is_relative_to(root), 'snapshot symlink escapes its root')
        require(not target.exists() and not target.is_symlink(), 'colliding Git symlink path')
        target.symlink_to(link)


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
    parser.add_argument('--repository', required=True)
    parser.add_argument('--action-repository', required=True)
    parser.add_argument('--action-ref', required=True)
    parser.add_argument('--caller-ref', required=True)
    parser.add_argument('--caller-sha', required=True)
    args = parser.parse_args()
    require(re.fullmatch('[0-9a-f]{40}', args.base) and re.fullmatch('[0-9a-f]{40}', args.head), 'base and head must be full commit SHAs')
    require(version('desloppify') == POLICY['desloppifyVersion'], 'installed scanner version differs from the shared pin')
    args.output = args.output.resolve()
    require(re.fullmatch(r'agentsia-uk/[A-Za-z0-9_.-]+', args.repository), 'repository must be an agentsia-uk slug')
    repo = args.repo.resolve()
    args.repo = repo
    for sha in [args.base, args.head]:
        run(['git', 'rev-parse', '--verify', f'{sha}^{{commit}}'], cwd=repo)
    base_bytes = subprocess.run(['git', 'show', f'{args.base}:{CONFIG}'], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1800)
    require(base_bytes.returncode in {0, 128}, 'could not read base config')
    base = validate_config(json.loads(base_bytes.stdout)) if base_bytes.returncode == 0 else None
    head = validate_config(json.loads(run(['git', 'show', f'{args.head}:{CONFIG}'], cwd=repo)))
    touched, renames = changed_paths(repo, args.base, args.head)
    event_path = os.environ.get('GITHUB_EVENT_PATH')
    event = read_json(Path(event_path)) if event_path else {}
    evidence = upgrade_evidence(event, args, touched) if base is not None and base['policyRef'] != head['policyRef'] else None
    validate_transition(base, head, upgrade=evidence is not None)
    provenance = execution_provenance(repo, args, head)
    files = run(['git', 'ls-tree', '-r', '--name-only', '-z', args.head], cwd=repo).decode().rstrip('\0').split('\0')
    base_files = run(['git', 'ls-tree', '-r', '--name-only', '-z', args.base], cwd=repo).decode().rstrip('\0').split('\0')
    validate_language_coverage(files, head['areas'])
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix='code-health-') as temporary:
        root = Path(temporary)
        for name, sha in [('base', args.base), ('head', args.head)]:
            snapshot(repo, sha, root / name)
        for area in head['areas']:
            before = scan(root / 'base', area, args.output / area['id'] / 'base', head['areas']) if area_has_source(base_files, area, head['areas']) else (None, None)
            after = scan(root / 'head', area, args.output / area['id'] / 'head', head['areas'])
            result = compare(*before, *after, touched, renames, area['language'])
            results.append({'area': area['id'], **result})
    report = {
        'schemaVersion': 1,
        'base': args.base,
        'head': args.head,
        'desloppifyVersion': POLICY['desloppifyVersion'],
        'provenance': provenance,
        'policyChanged': base is not None and base['policyRef'] != head['policyRef'],
        'upgradeEvidence': evidence,
        'configSha256': hashlib.sha256(json.dumps(head, sort_keys=True).encode()).hexdigest(),
        'areas': results,
        'unsupportedLanguages': head.get('unsupportedLanguages', []),
    }
    (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return int(any(r['errors'] for r in results))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f'code-health refused: {error}', file=sys.stderr)
        sys.exit(2)
