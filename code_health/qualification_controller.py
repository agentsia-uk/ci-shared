"""Trusted, independently defined assertions for candidate policy observations.

The current inventory covers configuration, ratchet, Git and selected scanner operations only.
It deliberately cannot issue a release qualification receipt.
"""
import copy

from .qualification_container import run_candidate

REJECTION_REASONS = {
    'config-traversal': 'path escapes the repository',
    'config-lower-target': 'strict target may only tighten the shared policy',
    'config-mutable-pin': 'policyRef must be an immutable 40-character SHA',
    'config-unknown-field': 'unknown code-health config field',
    'config-duplicate-area': 'duplicate area id',
    'config-exclude-all': 'an exclusion cannot hide the whole area',
    'transition-unauthorised': 'policy changes require a dedicated authorized upgrade PR',
    'transition-narrowed-area': 'existing scan areas and exclusions cannot change in an ordinary PR',
    'language-uncovered': 'supported source file is outside declared language areas: src/a.ts',
    'invalid-score': 'missing or invalid objective score',
    'invalid-coverage': 'detector coverage changed between scans; scores are not comparable',
    'git-snapshot-escape': 'symlink escapes',
    'workflow-mutable': 'does not match workflowRef',
    'workflow-conditional': 'may not be conditional or advisory',
    'workflow-filtered': 'may not filter PR or merge-group events',
}


def _config():
    return {'schemaVersion': 1, 'policyRef': 'a' * 40, 'workflowRef': 'b' * 40,
            'areas': [{'id': 'app-python', 'language': 'python', 'path': '.', 'exclusions': []}]}


def _state(findings=()):
    return {'version': 3, 'work_items': {str(index): item for index, item in enumerate(findings)},
            'scan_coverage': {'python': {'status': 'full', 'detectors': {'smells': {'status': 'full', 'confidence': 1}}}}}


def _compare(score_before=90, score_after=90, before=(), after=(), touched=('src/a.py',)):
    return {'baseStatus': {'objective_score': score_before}, 'baseState': _state(before),
            'headStatus': {'objective_score': score_after}, 'headState': _state(after),
            'touched': list(touched), 'renames': {}, 'language': 'python'}


def _expected_comparison(score_after=90, errors=()):
    return {'objectiveBefore': 90, 'objectiveAfter': score_after, 'baselineKind': 'existing-area',
            'coverage': 'full', 'errors': list(errors)}


def qualification_cases():
    """Return independent test inputs and expected observations, never candidate code."""
    valid = _config()
    traversal = copy.deepcopy(valid)
    traversal['areas'][0]['path'] = '../outside'
    lowered = copy.deepcopy(valid)
    lowered['strictTarget'] = 89
    mutable = copy.deepcopy(valid)
    mutable['policyRef'] = 'main'
    changed = copy.deepcopy(valid)
    changed['policyRef'] = 'c' * 40
    narrowed = copy.deepcopy(valid)
    narrowed['areas'][0]['path'] = 'subset'
    unknown = copy.deepcopy(valid)
    unknown['ignore'] = ['*']
    duplicate = copy.deepcopy(valid)
    duplicate['areas'].append(copy.deepcopy(duplicate['areas'][0]))
    excluded = copy.deepcopy(valid)
    excluded['areas'][0]['exclusions'] = [{'pattern': '.', 'kind': 'generated', 'rationale': 'all'}]
    finding = {'id': 'smells::src/a.py::unsafe', 'work_item_kind': 'mechanical_defect',
               'status': 'open', 'tier': 2, 'file': 'src/a.py', 'detector': 'smells', 'summary': 'unsafe'}
    minor = {**finding, 'tier': 4}
    subjective = {**finding, 'work_item_kind': 'review_defect'}
    bad_coverage = _compare()
    bad_coverage['headState']['scan_coverage']['python']['detectors']['smells']['confidence'] = .5
    return [
        ('config-valid', 'validate-config', {'config': valid}, 'returned'),
        ('config-traversal', 'validate-config', {'config': traversal}, 'rejected'),
        ('config-lower-target', 'validate-config', {'config': lowered}, 'rejected'),
        ('config-mutable-pin', 'validate-config', {'config': mutable}, 'rejected'),
        ('config-unknown-field', 'validate-config', {'config': unknown}, 'rejected'),
        ('config-duplicate-area', 'validate-config', {'config': duplicate}, 'rejected'),
        ('config-exclude-all', 'validate-config', {'config': excluded}, 'rejected'),
        ('transition-unauthorised', 'validate-transition', {'base': valid, 'head': changed, 'upgrade': False}, 'rejected'),
        ('transition-authorised', 'validate-transition', {'base': valid, 'head': changed, 'upgrade': True}, 'returned'),
        ('transition-narrowed-area', 'validate-transition', {'base': valid, 'head': narrowed, 'upgrade': False}, 'rejected'),
        ('language-covered', 'validate-language-coverage', {'files': ['src/a.py'], 'areas': valid['areas']}, 'returned'),
        ('language-uncovered', 'validate-language-coverage', {'files': ['src/a.ts'], 'areas': valid['areas']}, 'rejected'),
        ('score-unchanged', 'compare', _compare(), _expected_comparison()),
        ('score-decreased', 'compare', _compare(score_after=89.9),
         _expected_comparison(89.9, ['objective score decreased: 90 -> 89.9'])),
        ('touched-tier-two', 'compare', _compare(before=[finding], after=[finding]),
         _expected_comparison(errors=['T2 remains in touched path: src/a.py (smells)'])),
        ('fixed-tier-two', 'compare', _compare(before=[finding]), _expected_comparison()),
        ('new-low-priority', 'compare', _compare(after=[minor]),
         _expected_comparison(errors=['1 new finding(s) in touched path: src/a.py (smells)'])),
        ('existing-low-priority', 'compare', _compare(before=[minor], after=[minor]), _expected_comparison()),
        ('subjective-not-gated', 'compare', _compare(after=[subjective]), _expected_comparison()),
        ('invalid-score', 'compare', _compare(score_after=True), 'rejected'),
        ('invalid-coverage', 'compare', bad_coverage, 'rejected'),
        ('git-snapshot-exact', 'git-snapshot', {'escape': False},
         {'source': 'def handle(value):\n    return eval(value)\n', 'substitution': 'COMMIT = "$Format:%H$"\n',
          'executable': 0o755, 'internalIsLink': True, 'internalContent': 'def handle(value):\n    return eval(value)\n'}),
        ('git-snapshot-escape', 'git-snapshot', {'escape': True}, 'rejected'),
        ('git-identity', 'git-identity', {}, {'content': 'original = True\n'}),
        ('git-renames-deletions', 'git-changed-paths', {},
         {'touched': ['new name.py', 'old name.py', 'removed.py'], 'renames': {'old name.py': 'new name.py'}}),
        ('workflow-valid', 'workflow-pin', {'mode': 'valid'}, 'returned'),
        ('workflow-mutable', 'workflow-pin', {'mode': 'mutable'}, 'rejected'),
        ('workflow-conditional', 'workflow-pin', {'mode': 'conditional'}, 'rejected'),
        ('workflow-filtered', 'workflow-pin', {'mode': 'filtered'}, 'rejected'),
        ('scanner-mapping', 'scanner-mapping', {},
         {'namespaceImport': True, 'patchSha256': '8e9385c2901a8c2ca6dc919a652a9a2b5c97c23d6c2c316beef98a752415c0d6',
          'exact': 'src/db/health.ts', 'ambiguousName': None, 'ambiguousExact': None,
          'pythonNames': ['code_health', 'code_health.cli', 'code_health.qualification_bridge'],
          'relative': 'src/pkg/qualification_bridge.py', 'unrelatedRelative': []}),
        ('finding-move-typescript', 'finding-move', {'mode': 'typescript'}, {'errors': []}),
        ('finding-move-tsx', 'finding-move', {'mode': 'typescript-tsx'}, {'errors': []}),
        ('finding-move-typescript-changed', 'finding-move', {'mode': 'typescript-changed'},
         {'errors': ['1 new finding(s) in touched path: src/example.ts (security)']}),
        ('finding-move-unchanged', 'finding-move', {'mode': 'unchanged'}, {'errors': []}),
        ('finding-move-native', 'finding-move', {'mode': 'native'}, {'errors': []}),
        ('finding-move-top-level', 'finding-move', {'mode': 'top-level'}, {'errors': []}),
        ('finding-move-severity', 'finding-move', {'mode': 'severity'},
         {'errors': ['1 new finding(s) in touched path: src/example.py (security)']}),
        ('finding-move-changed', 'finding-move', {'mode': 'changed'},
         {'errors': ['1 new finding(s) in touched path: src/example.py (security)']}),
        ('finding-move-priority', 'finding-move', {'mode': 'high-priority'},
         {'errors': ['T2 remains in touched path: src/example.py (security)']}),
        ('scanner-new-area', 'scanner-new-area', {},
         {'baselineKind': 'new-area', 'objectiveBefore': None, 'errors': []}),
        ('scanner-security', 'scanner-security', {},
         {'securityCoverage': 'full', 'hasSecurityFinding': True, 'hasSecurityError': True}),
    ]


def evaluate_observation(observation, expected_case, expected):
    if (not isinstance(observation, dict) or
            set(observation) != {'schemaVersion', 'caseId', 'outcome', 'value'} or
            type(observation['schemaVersion']) is not int or observation['schemaVersion'] != 1 or
            observation['caseId'] != expected_case):
        raise ValueError('candidate observation is not bound to the expected case')
    if isinstance(expected, str) and expected in {'returned', 'rejected'}:
        value = observation.get('value')
        if (observation.get('outcome') != expected or
                (expected == 'returned' and value is not None) or
                (expected == 'rejected' and
                 (expected_case not in REJECTION_REASONS or not isinstance(value, str) or
                  REJECTION_REASONS[expected_case] not in value))):
            raise ValueError('candidate disagrees with the trusted qualification case')
        return
    value = observation.get('value')
    if observation.get('outcome') != 'returned' or not isinstance(value, dict) or not isinstance(expected, dict):
        raise ValueError('candidate returned an invalid structured observation')
    if value != expected:
        raise ValueError('candidate disagrees with the trusted qualification case')


def run_qualification_cases(*, image, candidate, bridge, readers, runner=run_candidate):
    """Exercise the current cases; this is not a complete qualification."""
    completed = 0
    for case_id, operation, arguments, expected in qualification_cases():
        request = {'schemaVersion': 1, 'caseId': case_id, 'operation': operation, 'arguments': arguments}
        observation = runner(image=image, candidate=candidate, bridge=bridge, readers=readers, case_id=case_id, request=request)
        evaluate_observation(observation, case_id, expected)
        completed += 1
    return completed
