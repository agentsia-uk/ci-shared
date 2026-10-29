"""Authenticate exact finding decisions and import them through native plan APIs."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import urllib.parse
import urllib.request

from desloppify.engine.plan_ops import append_log_entry, skip_items
from desloppify.engine.plan_state import empty_plan, plan_path_for_state, save_plan
from desloppify.state_compat import load_state, match_issues, resolve_issues, save_state

LEDGER = '.github/code-health-dismissals.json'
MAX_LEDGER_BYTES = 1024 * 1024
FIELDS = {'area', 'findingId', 'findingSha256', 'sourceSha256', 'status', 'toolVersion', 'rationale', 'attestation', 'pullRequest'}


def check(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_ledger(value, areas, tool_version):
    check(isinstance(value, dict) and set(value) == {'schemaVersion', 'entries'} and type(value['schemaVersion']) is int and value['schemaVersion'] == 1, 'invalid dismissal ledger schema')
    check(isinstance(value['entries'], list), 'dismissal entries must be a list')
    seen = set()
    for entry in value['entries']:
        check(isinstance(entry, dict) and set(entry) == FIELDS, 'invalid dismissal fields')
        check(isinstance(entry['area'], str) and entry['area'] in areas, 'dismissal area is not declared')
        check(isinstance(entry['findingId'], str) and entry['findingId'].strip() and not any(ord(c) < 32 for c in entry['findingId']), 'dismissal needs a complete finding ID')
        key = entry['area'], entry['findingId']
        check(key not in seen, 'duplicate dismissal finding')
        seen.add(key)
        check(isinstance(entry['status'], str) and entry['status'] in {'false_positive', 'wontfix'}, 'only false_positive and wontfix decisions are allowed')
        check(entry['toolVersion'] == tool_version, 'dismissal tool version differs from the shared pin')
        check(type(entry['pullRequest']) is int and entry['pullRequest'] > 0, 'dismissal needs its same-repository PR number')
        for field in ['rationale', 'attestation']:
            check(isinstance(entry[field], str) and entry[field].strip(), f'dismissal {field} is required')
        text = ' '.join(entry['attestation'].lower().split())
        check('not gaming' in text and ('reviewed' in text or 'i have actually' in text), 'dismissal needs the original native review attestation')
        check(isinstance(entry['findingSha256'], str) and re.fullmatch('[0-9a-f]{64}', entry['findingSha256']), 'dismissal needs its finding evidence hash')
        check(isinstance(entry['sourceSha256'], dict) and entry['sourceSha256'], 'dismissal needs source hashes')
        for path, sha in entry['sourceSha256'].items():
            p = PurePosixPath(path)
            check(path and not p.is_absolute() and '..' not in p.parts and '\\' not in path and not any(ord(c) < 32 for c in path), 'dismissal source path escapes the repository')
            check(isinstance(sha, str) and re.fullmatch('[0-9a-f]{64}', sha), 'invalid dismissal source hash')
    return value['entries']


def audit_block(entry):
    """The exact block the deciding agent must include in the referenced PR body."""
    return 'Code health dismissal:\n```json\n' + json.dumps(entry, sort_keys=True, indent=2) + '\n```'


def github_reader(repository, token):
    cache = {}

    def read(path):
        if path not in cache:
            request = urllib.request.Request(f'https://api.github.com/repos/{repository}/{path}', headers={'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json'})
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(4 * MAX_LEDGER_BYTES + 1)
            check(len(raw) <= 4 * MAX_LEDGER_BYTES, 'dismissal metadata exceeds the bounded response size')
            cache[path] = json.loads(raw)
        return cache[path]
    return read


def authenticate(entries, repository, *, api, contains):
    """Bind every decision to a repository writer's PR, including squash merges."""
    trusted = []
    for entry in entries:
        pr = api(f'pulls/{entry["pullRequest"]}')
        check(pr.get('number') == entry['pullRequest'] and pr.get('head', {}).get('repo', {}).get('full_name') == repository and pr.get('base', {}).get('repo', {}).get('full_name') == repository, 'dismissal PR must belong to this repository')
        author = pr.get('user', {}).get('login', '')
        check(re.fullmatch(r'[A-Za-z0-9_-]+(?:\[bot\])?', author), 'invalid dismissal PR author')
        permission = api('collaborators/' + urllib.parse.quote(author, safe='') + '/permission')
        check(permission.get('permission') in {'write', 'admin'}, 'dismissal PR author needs repository write permission')
        check(audit_block(entry) in (pr.get('body') or ''), 'dismissal rationale and attestation are missing from the referenced PR body')
        sha = pr.get('head', {}).get('sha', '')
        check(re.fullmatch('[0-9a-f]{40}', sha), 'invalid dismissal PR head')
        admitted = pr.get('merge_commit_sha') if pr.get('merged') is True else sha if pr.get('state') == 'open' else None
        check(isinstance(admitted, str) and re.fullmatch('[0-9a-f]{40}', admitted) and contains(admitted), 'dismissal PR is not contained in this candidate')
        source = api(f'contents/{LEDGER}?ref={sha}')
        check(source.get('encoding') == 'base64' and isinstance(source.get('content'), str), 'dismissal PR ledger is unavailable')
        raw = base64.b64decode(source['content'].replace('\n', ''), validate=True)
        check(len(raw) <= MAX_LEDGER_BYTES, 'dismissal PR ledger exceeds the size limit')
        ledger = json.loads(raw)
        check(isinstance(ledger, dict) and isinstance(ledger.get('entries'), list) and entry in ledger['entries'], 'dismissal record is absent from its authenticated PR head')
        trusted.append({'entry': entry, 'author': author, 'pullRequestUrl': f'https://github.com/{repository}/pull/{entry["pullRequest"]}', 'headSha': sha, 'admittedSha': admitted})
    return trusted


def finding_hash(finding):
    return digest({key: finding.get(key) for key in ['id', 'file', 'detector', 'tier', 'confidence', 'summary', 'detail']})


def source_hashes(root, finding):
    paths = {finding['file']}
    detail = finding.get('detail', {})
    if isinstance(detail, dict):
        paths.update(p for p in detail.get('related_files', []) if isinstance(p, str))
    if len(paths) > 1:
        paths.discard('.')  # Native cross-file findings use the repository as their primary path.
    result = {}
    for path in paths:
        p = PurePosixPath(path)
        check(not p.is_absolute() and '..' not in p.parts and '\\' not in path, 'finding source path escapes the snapshot')
        source = (root / path).resolve()
        check(source.is_relative_to(root.resolve()) and source.is_file(), 'dismissal requires all finding source files inside the snapshot')
        result[path] = hashlib.sha256(source.read_bytes()).hexdigest()
    return result


def import_records(state_path, root, area, records):
    """Runs only in the scanner's credential-free environment on trusted inputs."""
    state = load_state(state_path)
    plan = empty_plan()
    summary = {'false_positive': 0, 'wontfix': 0, 'inactive': 0}
    for record in records:
        entry = record['entry']
        if entry['area'] != area:
            continue
        issue = state['work_items'].get(entry['findingId'])
        if issue is None or issue.get('work_item_kind') != 'mechanical_defect' or issue.get('status') != 'open' or finding_hash(issue) != entry['findingSha256'] or source_hashes(root, issue) != entry['sourceSha256']:
            summary['inactive'] += 1
            continue
        # Native IDs also support prefix/glob matching: preflight the complete set.
        check({f['id'] for f in match_issues(state, entry['findingId'])} == {entry['findingId']}, 'dismissal ID also matches another native finding')
        note = entry['rationale'] + '\n' + record['pullRequestUrl']
        affected = resolve_issues(state, entry['findingId'], entry['status'], note=note, attestation=entry['attestation'])
        check(affected == [entry['findingId']], 'native dismissal changed an unexpected finding')
        skip_items(plan, affected, kind='false_positive' if entry['status'] == 'false_positive' else 'permanent', reason=entry['rationale'], note=note, attestation=entry['attestation'], scan_count=state.get('scan_count', 0))
        append_log_entry(plan, 'skip', issue_ids=affected, actor=record['author'], note=note, detail={'dismissalSha256': digest(entry), 'pullRequest': record['pullRequestUrl'], 'headSha': record['headSha'], 'admittedSha': record['admittedSha']})
        summary[entry['status']] += 1
    save_state(state, state_path)
    save_plan(plan, plan_path_for_state(state_path))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--area', required=True)
    parser.add_argument('--records', type=Path, required=True)
    args = parser.parse_args()
    summary = import_records(args.state, args.root, args.area, json.loads(args.records.read_text()))
    (args.state.parent / 'dismissals.json').write_text(json.dumps(summary) + '\n')


if __name__ == '__main__':
    main()
