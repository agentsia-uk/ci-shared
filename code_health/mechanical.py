"""Project native mechanical scan data without raw evidence or review claims."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
import math
from pathlib import Path, PurePosixPath
import re

if __package__:
    from . import artifacts as a
else:
    import artifacts as a

MAX_STATE_BYTES = 64 * 1024 * 1024
MAX_PROJECTION_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 20_000
MAX_DETECTORS = 64
SUMMARY_CHARS = 400
WITHHELD_SUMMARY = '[summary withheld: matched secret pattern]'
# Same base patterns used by Modelsmith's approved code-health normaliser.
# ASCII boundaries match JavaScript regular-expression word boundaries.
SECRET_PATTERNS = tuple(re.compile(pattern, flags | re.ASCII) for pattern, flags in [
    (r'-----BEGIN [A-Z ]*PRIVATE KEY-----', 0),
    (r'\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b', 0),
    (r'sk-ant-api03-[A-Za-z0-9_-]{50,}', 0),
    (r'AIza[A-Za-z0-9_-]{30,}', 0),
    (r'sk-or-v1-[A-Za-z0-9_-]{32,}', 0),
    (r'\bsk-(?!ant-api03-|or-v1-)[A-Za-z0-9_-]{32,}\b', 0),
    (r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b', 0),
    (r'\b(?:TOKEN|SECRET|PASSWORD|PASS|TURSO_AUTH_TOKEN|OPENAI_API_KEY|OPENROUTER_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY)\s*=\s*["\']?[^"\'\s]+["\']?', re.IGNORECASE),
])


def _object(value, name) -> dict[str, object]:
    a.cli.require(isinstance(value, dict), f'{name} must be an object')
    return value


def _array(value, name, maximum) -> list[object]:
    a.cli.require(isinstance(value, list) and len(value) <= maximum, f'invalid {name}')
    return value


def _text(value, name, maximum=512) -> str:
    a.cli.require(isinstance(value, str) and value and len(value.encode('utf-16-le')) // 2 <= maximum and not any(ord(c) < 32 for c in value), f'invalid {name}')
    return value


def _count(value, name) -> int:
    a.cli.require(type(value) is int and 0 <= value <= 2 ** 53 - 1, f'invalid {name}')
    return value


def _score(value, name) -> float:
    a.cli.require(type(value) in {int, float} and math.isfinite(value) and 0 <= value <= 100, f'invalid {name}')
    # Dashboard scores have one decimal place; retain the scanner's meaning.
    return math.floor(value * 10 + .5) / 10


def _tier(value) -> int:
    a.cli.require(type(value) is int and value in {1, 2, 3, 4}, 'invalid native tier')
    return value


def _timestamp(value) -> str:
    a.cli.require(isinstance(value, str), 'native scan timestamp is missing')
    stamp = datetime.fromisoformat(value)
    a.cli.require(stamp.tzinfo is not None, 'native scan timestamp needs its timezone')
    return stamp.astimezone(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def _has_secret(value) -> bool:
    return any(pattern.search(value) for pattern in SECRET_PATTERNS)


def _summary(value) -> str:
    a.cli.require(isinstance(value, str) and value, 'native summary is missing')
    if _has_secret(value):
        return WITHHELD_SUMMARY
    raw = value.encode('utf-16-le')
    if len(raw) > SUMMARY_CHARS * 2:
        return raw[:(SUMMARY_CHARS - 1) * 2].decode('utf-16-le', errors='ignore') + '…'
    return value


def _path(value) -> str:
    path = _text(value, 'finding path')
    pure = PurePosixPath(path)
    a.cli.require(not pure.is_absolute() and '..' not in pure.parts and '\\' not in path, 'finding path escapes the repository')
    return path


def _tally(counter) -> list[dict[str, object]]:
    return [{'path': path, 'open': count} for path, count in sorted(counter.items(), key=lambda row: (-row[1], row[0]))]


def _inventory(state) -> list[dict[str, object]]:
    items = _object(state.get('work_items'), 'native work_items')
    result = []
    for key, value in items.items():
        item = _object(value, 'native work item')
        a.cli.require(item.get('id') == key, 'native finding ID differs from its inventory key')
        a.cli.require(isinstance(item.get('status'), str) and item['status'] in {'open', 'fixed', 'auto_resolved', 'wontfix', 'false_positive'}, 'unsupported native finding status')
        _text(key, 'native finding ID')
        _text(item.get('detector'), 'native detector', 128)
        result.append(item)
    return result


def _dimensions(status, state, opened) -> tuple[list[dict[str, object]], dict[str, str]]:
    native = _object(state.get('dimension_scores'), 'native dimension_scores')
    dimensions, detector_dimensions = [], {}
    for value in _array(status.get('scorecard_dimensions'), 'native scorecard_dimensions', 64):
        row = _object(value, 'native scorecard dimension')
        a.cli.require(type(row.get('subjective')) is bool, 'native dimension needs its subjective flag')
        if row['subjective']:
            continue
        name = _text(row.get('name'), 'native dimension name', 128)
        a.cli.require(not any(d['name'] == name for d in dimensions), 'duplicate native dimension')
        detectors = sorted(_object(_object(native.get(name), 'native dimension').get('detectors'), 'native dimension detectors'))
        a.cli.require(len(detectors) <= MAX_DETECTORS, 'too many native dimension detectors')
        for detector in detectors:
            _text(detector, 'native dimension detector', 128)
            detector_dimensions[detector] = re.sub('[^a-z0-9]+', '_', name.lower()).strip('_')
        dimensions.append({'name': name, 'health': _score(row.get('score'), 'dimension health'), 'strict': _score(row.get('strict'), 'dimension strict'), 'openIssueCount': sum(item['detector'] in detectors for item in opened), 'tier': _tier(row.get('tier')), 'detectors': detectors})
    return dimensions, detector_dimensions


def _counts(state, items) -> dict[str, object]:
    native = _object(state.get('stats'), 'native stats')
    counts = {name: _count(native.get(name), 'native count ' + name) for name in ['total', 'open', 'fixed', 'wontfix']}
    per_detector = {}
    for item in items:
        row = per_detector.setdefault(item['detector'], {'detector': item['detector'], 'open': 0, 'fixed': 0, 'wontfix': 0})
        if item['status'] in {'open', 'fixed', 'wontfix'}:
            row[item['status']] += 1
    a.cli.require(len(per_detector) <= MAX_DETECTORS, 'too many native detectors')
    counts['byDetector'] = [per_detector[key] for key in sorted(per_detector)]
    return counts


def _coverage(state, language) -> dict[str, object]:
    native = _object(_object(state.get('scan_coverage'), 'native scan_coverage').get(language), 'native language coverage')
    a.cli.require(isinstance(native.get('status'), str) and native['status'] in {'full', 'reduced'}, 'unsupported native coverage status')
    confidence = native.get('confidence')
    a.cli.require(type(confidence) in {int, float} and math.isfinite(confidence) and 0 <= confidence <= 1, 'invalid native coverage confidence')
    notes = []
    for value in _array(native.get('warnings'), 'native coverage warnings', 32):
        row = _object(value, 'native coverage warning')
        notes.append({'detector': _text(row.get('detector'), 'coverage detector', 128), 'status': _text(row.get('status'), 'coverage status', 128), 'reason': _text(row.get('reason'), 'coverage reason', 400), 'summary': _summary(row.get('summary'))})
    potentials = _object(_object(state.get('potentials'), 'native potentials').get(language), 'native language potentials')
    a.cli.require(len(potentials) <= MAX_DETECTORS, 'too many native potential detectors')
    detectors = sorted(_text(key, 'potential detector', 128) for key in potentials)
    _, checked = a.cli.detector_coverage(state, language)
    a.cli.require(len(checked) <= MAX_DETECTORS, 'too many coverage detectors')
    coverage_detectors = []
    for name, (detector_status, detector_confidence, details) in sorted(checked.items()):
        _text(name, 'coverage detector', 128)
        a.cli.require(all(len(value.encode('utf-8')) <= 400 for value in details), 'coverage detail exceeds limit')
        coverage_detectors.append({'detector': name, 'status': detector_status, 'confidence': detector_confidence,
                                   'details': dict(zip(('tool', 'reason', 'summary', 'impact'), details))})
    return {'status': native['status'], 'confidence': confidence, 'detectorSet': detectors, 'detectors': coverage_detectors, 'notes': notes}


def comparison_key(projection) -> str:
    comparison = {name: projection[name] for name in ('repositoryId', 'area', 'desloppifyVersion', 'scannerPatch',
                  'language', 'scanPath', 'scanCompleteness', 'coverage')}
    comparison['excludes'] = sorted(projection['excludes'])
    return 'sha256:' + hashlib.sha256(json.dumps(comparison, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def validate_public_projection(value) -> None:
    """Validate publishable fields only; this does not authenticate the scan."""
    coverage = value['coverage']
    a.object_fields(coverage, {'status', 'confidence', 'detectorSet', 'detectors', 'notes'}, 'projection coverage')
    a.cli.require(coverage['status'] in {'full', 'reduced'} and type(coverage['confidence']) in {int, float} and
                  math.isfinite(coverage['confidence']) and 0 <= coverage['confidence'] <= 1, 'invalid projection coverage')
    for detector in _array(coverage['detectorSet'], 'projection detector set', MAX_DETECTORS):
        _text(detector, 'projection detector', 128)
    for item in _array(coverage['detectors'], 'projection coverage detectors', MAX_DETECTORS):
        a.object_fields(item, {'detector', 'status', 'confidence', 'details'}, 'projection coverage detector')
        _text(item['detector'], 'projection coverage detector', 128)
        a.cli.require(item['status'] in {'full', 'reduced'} and type(item['confidence']) in {int, float} and
                      math.isfinite(item['confidence']) and 0 <= item['confidence'] <= 1, 'invalid projection detector coverage')
        a.object_fields(item['details'], {'tool', 'reason', 'summary', 'impact'} if item['status'] == 'reduced' else set(), 'projection coverage details')
        a.cli.require(all(isinstance(detail, str) and len(detail.encode('utf-8')) <= 400 for detail in item['details'].values()), 'invalid projection coverage details')
    for note in _array(coverage['notes'], 'projection coverage notes', 32):
        a.object_fields(note, {'detector', 'status', 'reason', 'summary'}, 'projection coverage note')
        for name in note:
            _text(note[name], 'projection coverage note ' + name, 400 if name in {'reason', 'summary'} else 128)
    for dimension in _array(value['mechanicalDimensions'], 'projection dimensions', 64):
        a.object_fields(dimension, {'name', 'health', 'strict', 'openIssueCount', 'tier', 'detectors'}, 'projection dimension')
        _text(dimension['name'], 'projection dimension name', 128)
        _score(dimension['health'], 'projection dimension health')
        _score(dimension['strict'], 'projection dimension strict')
        _count(dimension['openIssueCount'], 'projection dimension open count')
        _tier(dimension['tier'])
        for detector in _array(dimension['detectors'], 'projection dimension detectors', MAX_DETECTORS):
            _text(detector, 'projection dimension detector', 128)
    counts = value['counts']
    a.object_fields(counts, {'total', 'open', 'fixed', 'wontfix', 'byDetector'}, 'projection counts')
    for name in ('total', 'open', 'fixed', 'wontfix'):
        _count(counts[name], 'projection count')
    for row in _array(counts['byDetector'], 'projection counts by detector', MAX_DETECTORS):
        a.object_fields(row, {'detector', 'open', 'fixed', 'wontfix'}, 'projection detector count')
        _text(row['detector'], 'projection count detector', 128)
        for name in ('open', 'fixed', 'wontfix'):
            _count(row[name], 'projection detector count')
    for finding in _array(value['findings'], 'projection findings', MAX_FINDINGS):
        a.object_fields(finding, {'id', 'detector', 'dimension', 'tier', 'confidence', 'summary', 'file', 'line', 'redacted'}, 'projection finding')
        _text(finding['id'], 'projection finding ID')
        _text(finding['detector'], 'projection finding detector', 128)
        if finding['dimension'] is not None:
            _text(finding['dimension'], 'projection finding dimension', 128)
        _tier(finding['tier'])
        a.cli.require(finding['confidence'] in {'low', 'medium', 'high'} and finding['redacted'] is True, 'invalid projection finding')
        _text(finding['summary'], 'projection finding summary', SUMMARY_CHARS)
        _path(finding['file'])
        a.cli.require(finding['line'] is None or (type(finding['line']) is int and 0 < finding['line'] <= 2 ** 53 - 1), 'invalid projection finding line')
    a.object_fields(value['hotspots'], {'files', 'directories'}, 'projection hotspots')
    for kind, maximum in [('files', 10_000), ('directories', 2_000)]:
        for row in _array(value['hotspots'][kind], 'projection hotspots', maximum):
            a.object_fields(row, {'path', 'open'}, 'projection hotspot')
            _path(row['path'])
            _count(row['open'], 'projection hotspot count')


def project_mechanical(status, state, area, scan_config, *, repository_id, commit_sha, tool_version, scanner_patch) -> dict[str, object]:
    """Use native values only; publication and subjective joins belong to m3."""
    status, state = _object(status, 'native status'), _object(state, 'native state')
    a.object_fields(area, {'id', 'language', 'path', 'exclusions'}, 'manifest area')
    a.cli.require(isinstance(area['id'], str) and re.fullmatch('[a-z][a-z0-9-]*', area['id']), 'invalid manifest area ID')
    a.cli.require(isinstance(area['language'], str) and area['language'] in a.cli.LANGUAGES, 'unsupported manifest language')
    a.cli.relative_path(area['path'])
    a.positive_integer(repository_id, 'repository ID')
    a.sha(commit_sha, 'source commit')
    a.cli.require(state.get('version') == 3 and type(state['version']) is int, 'unsupported native state schema')
    a.cli.require(state.get('subjective_assessments') == {}, 'mechanical projection cannot assert unattributed subjective assessments')
    a.cli.require(tool_version == a.cli.POLICY['desloppifyVersion'], 'projection tool differs from the policy pin')
    a.cli.require(scanner_patch == a.cli.POLICY.get('scannerPatch') and isinstance(scanner_patch, dict)
                  and set(scanner_patch) == {'id', 'sha256'}, 'projection scanner correction differs from the policy pin')
    scan_config = _object(scan_config, 'actual scan config')
    a.cli.require(scan_config.get('ignore') == [] and scan_config.get('trust_plugins') is False and scan_config.get('hermes_enabled') is False, 'mechanical projection requires the reconstructed scan config')
    excludes = [_text(value, 'actual scan exclusion') for value in _array(scan_config.get('exclude'), 'actual scan exclusions', 1000)]
    captured = _timestamp(state.get('last_scan'))
    a.cli.require(_timestamp(status.get('last_scan')) == captured, 'native state/status timestamps differ')
    a.cli.require(str(PurePosixPath(_text(state.get('scan_path'), 'native scan path'))) == str(PurePosixPath(area['path'])), 'native scan path differs from the manifest area')
    completeness = _object(state.get('scan_completeness'), 'native scan completeness').get(area['language'])
    a.cli.require(isinstance(completeness, str) and completeness in {'fast', 'full'}, 'unsupported native scan completeness')
    score_names = {'overall': 'overall_score', 'strict': 'strict_score', 'objective': 'objective_score', 'verified': 'verified_strict_score'}
    scores = {name: _score(status.get(native), native) for name, native in score_names.items()}
    a.cli.require(all(scores[name] == _score(state.get(native), 'state ' + native) for name, native in score_names.items()), 'native state/status scores differ')
    items = _inventory(state)
    opened = [item for item in items if item['status'] == 'open' and item.get('work_item_kind') == 'mechanical_defect']
    a.cli.require(len(opened) <= MAX_FINDINGS, 'too many open mechanical findings')
    dimensions, detector_dimensions = _dimensions(status, state, opened)
    findings, files, directories = [], Counter(), Counter()
    for item in opened:
        detail = _object(item.get('detail'), 'native finding detail')
        raw_line = detail.get('line', detail.get('lines', [None])[0] if isinstance(detail.get('lines'), list) and detail['lines'] else None)
        line = raw_line if type(raw_line) is int and raw_line >= 1 else None
        path = _path(item.get('file'))
        confidence = item.get('confidence')
        a.cli.require(isinstance(confidence, str) and confidence in {'low', 'medium', 'high'}, 'invalid native finding confidence')
        findings.append({'id': item['id'], 'detector': item['detector'], 'dimension': detector_dimensions.get(item['detector']), 'tier': _tier(item.get('tier')), 'confidence': confidence, 'summary': _summary(item.get('summary')), 'file': path, 'line': line, 'redacted': True})
        if path != '.':
            files[path] += 1
        directory = str(PurePosixPath(path).parent)
        directories['.' if directory == '.' else '/'.join(directory.split('/')[:3])] += 1
    a.cli.require(len(files) <= 10_000 and len(directories) <= 2_000, 'mechanical hotspot limit exceeded')
    result = {'schemaVersion': 2, 'kind': 'agentsia.code-health.mechanical-projection', 'repositoryId': repository_id, 'area': area['id'], 'commitSha': commit_sha, 'capturedAt': captured, 'desloppifyVersion': tool_version, 'scannerPatch': dict(scanner_patch), 'language': area['language'], 'scanPath': area['path'], 'scanCompleteness': completeness, 'excludes': excludes, 'scores': scores, 'subjectiveAssessment': 'absent', 'mechanicalDimensions': dimensions, 'counts': _counts(state, items), 'coverage': _coverage(state, area['language']), 'findings': sorted(findings, key=lambda finding: finding['id']), 'hotspots': {'files': _tally(files), 'directories': _tally(directories)}}
    result['comparabilityKey'] = comparison_key(result)
    validate_public_projection(result)
    encoded = json.dumps(result, ensure_ascii=False, separators=(',', ':'))
    a.cli.require(len(encoded.encode()) <= MAX_PROJECTION_BYTES, 'mechanical projection exceeds its byte limit')
    # Never change identities to hide a secret: refuse publication instead.
    a.cli.require(not _has_secret(encoded), 'secret-bearing metadata remains at the projection output boundary')
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['state', 'status', 'manifest', 'scan-config', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--area', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--repository-id', type=int, required=True)
    args = parser.parse_args()
    a.cli.require(version('desloppify') == a.cli.POLICY['desloppifyVersion'], 'installed scanner differs from the policy pin')
    read = lambda path, maximum: a.json_bytes(a.read_bounded(path, maximum), maximum)
    manifest = a.cli.validate_config(read(args.manifest, a.MAX_MANIFEST_BYTES))
    areas = [area for area in manifest['areas'] if area['id'] == args.area]
    a.cli.require(len(areas) == 1, 'projection area is not in the manifest')
    result = project_mechanical(read(args.status, a.MAX_RESULT_BYTES), read(args.state, MAX_STATE_BYTES), areas[0], read(args.scan_config, a.MAX_MANIFEST_BYTES), repository_id=args.repository_id, commit_sha=args.commit, tool_version=a.cli.POLICY['desloppifyVersion'], scanner_patch=a.cli.POLICY.get('scannerPatch'))
    with args.output.open('x', encoding='utf-8') as output:
        output.write(json.dumps(result, ensure_ascii=False, separators=(',', ':')) + '\n')


if __name__ == '__main__':
    main()
