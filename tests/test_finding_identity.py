import tempfile
import unittest
from pathlib import Path

from code_health import cli


def finding(line, *, path='src/example.py', rule='B506', tier=4):
    return {'id': f'security::{path}::security::{rule}::{path}::{line}', 'file': path,
            'detector': 'security', 'summary': 'possible unsafe operation', 'tier': tier,
            'confidence': 'medium', 'status': 'open', 'work_item_kind': 'mechanical_defect',
            'detail': {'source': 'bandit', 'line': line, 'kind': rule, 'test_name': 'yaml_load'}}


def state(items):
    return {'version': 3, 'work_items': {str(index): item for index, item in enumerate(items)},
            'scan_coverage': {'python': {'status': 'full', 'detectors': {'security': {'status': 'full', 'confidence': 1}}}}}


class FindingIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / 'base'
        self.head = Path(self.temp.name) / 'head'
        (self.base / 'src').mkdir(parents=True)
        (self.head / 'src').mkdir(parents=True)

    def compare(self, old_source, new_source, old, new, renames=None):
        (self.base / old['file']).write_text(old_source)
        (self.head / new['file']).write_text(new_source)
        return cli.compare({'objective_score': 90}, state([old]), {'objective_score': 90}, state([new]),
                           {old['file'], new['file']}, renames or {}, 'python', source_roots=(self.base, self.head))['errors']

    def test_uniquely_unchanged_function_moved_by_inserted_lines_is_inherited(self):
        source = 'def validate(value):\n    return unsafe(value)\n'
        self.assertEqual([], self.compare(source, '# inserted\n\n' + source, finding(2), finding(4)))

    def test_native_python_security_finding_also_tracks_a_proven_move(self):
        source = 'def validate(value):\n    return unsafe(value)\n'
        old, new = finding(2), finding(3)
        for item in (old, new):
            item['detail'].pop('source')
            item['detail'].pop('test_name')
        self.assertEqual([], self.compare(source, '# inserted\n' + source, old, new))

    def test_unique_top_level_statement_can_move_without_becoming_new(self):
        source = 'dangerous = unsafe(value)\n'
        self.assertEqual([], self.compare(source, '# inserted\n' + source, finding(1), finding(2)))
        self.assertTrue(self.compare(source, '# inserted\ndangerous = unsafe(other)\n', finding(1), finding(2)))

    def test_changed_or_duplicated_function_is_new(self):
        source = 'def validate(value):\n    return unsafe(value)\n'
        for changed in ['# inserted\ndef validate(value):\n    return unsafe(value, other=True)\n',
                        '# inserted\n' + source + source]:
            with self.subTest(changed=changed):
                self.assertTrue(self.compare(source, changed, finding(2), finding(3)))

    def test_changed_detector_rule_and_invalid_source_are_new(self):
        source = 'def validate(value):\n    return unsafe(value)\n'
        self.assertTrue(self.compare(source, '# inserted\n' + source, finding(2), finding(3, rule='B603')))
        self.assertTrue(self.compare(source, 'invalid (\n', finding(2), finding(2)))

    def test_same_line_changed_or_ambiguous_source_is_new(self):
        source = 'def validate(value):\n    return unsafe(value)\n'
        changed = 'def validate(value):\n    return unsafe(value, other=True)\n'
        self.assertTrue(self.compare(source, changed, finding(2), finding(2)))
        decorated = '@policy\ndef validate(value):\n    return unsafe(value)\n'
        self.assertTrue(self.compare(decorated, decorated, finding(3), finding(3)))

    def test_relocated_high_priority_finding_still_blocks(self):
        source = 'def validate(value):\n    return unsafe(value)\n'
        errors = self.compare(source, '# inserted\n' + source, finding(2, tier=2), finding(3, tier=2))
        self.assertTrue(any('T2 remains' in error for error in errors))

    def test_duplicate_findings_are_counted_and_links_are_not_followed(self):
        source = 'def validate(value):\n    return unsafe(value)\n'
        old, new = finding(2), finding(3)
        (self.base / old['file']).write_text(source)
        (self.head / new['file']).write_text('# inserted\n' + source)
        errors = cli.compare({'objective_score': 90}, state([old]), {'objective_score': 90}, state([new, new]),
                             {new['file']}, {}, 'python', source_roots=(self.base, self.head))['errors']
        self.assertTrue(any('1 new finding' in error for error in errors))
        (self.head / new['file']).unlink()
        (self.head / new['file']).symlink_to(self.base / old['file'])
        errors = cli.compare({'objective_score': 90}, state([old]), {'objective_score': 90}, state([new]),
                             {new['file']}, {}, 'python', source_roots=(self.base, self.head))['errors']
        self.assertTrue(any('new finding' in error for error in errors))

    def test_renamed_file_with_unchanged_function_is_inherited(self):
        source = 'def validate(value):\n    return unsafe(value)\n'
        self.assertEqual([], self.compare(source, '# inserted\n' + source, finding(2),
                                          finding(3, path='src/renamed.py'), {'src/example.py': 'src/renamed.py'}))


if __name__ == '__main__':
    unittest.main()
