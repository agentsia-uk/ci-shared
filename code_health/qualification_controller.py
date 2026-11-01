"""Trusted, independently defined assertions for candidate policy observations.

The current inventory covers configuration, ratchet, Git and selected scanner operations only.
It deliberately cannot issue a release qualification receipt.
"""
import copy

from .qualification_container import run_candidate


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
        ('transition-unauthorised', 'validate-transition', {'base': valid, 'head': changed, 'upgrade': False}, 'rejected'),
        ('transition-authorised', 'validate-transition', {'base': valid, 'head': changed, 'upgrade': True}, 'returned'),
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
        ('git-renames-deletions', 'git-changed-paths', {},
         {'touched': ['new name.py', 'old name.py', 'removed.py'], 'renames': {'old name.py': 'new name.py'}}),
        ('workflow-valid', 'workflow-pin', {'mode': 'valid'}, 'returned'),
        ('workflow-mutable', 'workflow-pin', {'mode': 'mutable'}, 'rejected'),
        ('workflow-conditional', 'workflow-pin', {'mode': 'conditional'}, 'rejected'),
        ('workflow-filtered', 'workflow-pin', {'mode': 'filtered'}, 'rejected'),
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
        if observation.get('outcome') != expected or observation.get('value') is not None:
            raise ValueError('candidate disagrees with the trusted qualification case')
        return
    value = observation.get('value')
    if observation.get('outcome') != 'returned' or not isinstance(value, dict) or not isinstance(expected, dict):
        raise ValueError('candidate returned an invalid structured observation')
    if value != expected:
        raise ValueError('candidate disagrees with the trusted qualification case')


def run_qualification_cases(*, image, candidate, bridge, runner=run_candidate):
    """Exercise the current cases; this is not a complete qualification."""
    completed = 0
    for case_id, operation, arguments, expected in qualification_cases():
        request = {'schemaVersion': 1, 'caseId': case_id, 'operation': operation, 'arguments': arguments}
        observation = runner(image=image, candidate=candidate, bridge=bridge, case_id=case_id, request=request)
        evaluate_observation(observation, case_id, expected)
        completed += 1
    return completed
