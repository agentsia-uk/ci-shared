import tempfile
import unittest
from pathlib import Path

from code_health import cli


def finding(line, *, path='src/example.py', rule='B506', tier=4):
    return {'id': f'security::{path}::security::{rule}::{path}::{line}', 'file': path,
            'detector': 'security', 'summary': 'possible unsafe operation', 'tier': tier,
            'confidence': 'medium', 'status': 'open', 'work_item_kind': 'mechanical_defect',
            'detail': {'source': 'bandit', 'line': line, 'kind': rule, 'test_name': 'yaml_load'}}


def state(items, language='python'):
    return {'version': 3, 'work_items': {str(index): item for index, item in enumerate(items)},
            'scan_coverage': {language: {'status': 'full', 'detectors': {'security': {'status': 'full', 'confidence': 1}}}}}


class FindingIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / 'base'
        self.head = Path(self.temp.name) / 'head'
        (self.base / 'src').mkdir(parents=True)
        (self.head / 'src').mkdir(parents=True)

    def compare(self, old_source, new_source, old, new, renames=None, language='python'):
        (self.base / old['file']).write_text(old_source)
        (self.head / new['file']).write_text(new_source)
        return cli.compare({'objective_score': 90}, state([old], language), {'objective_score': 90}, state([new], language),
                           {old['file'], new['file']}, renames or {}, language, source_roots=(self.base, self.head))['errors']

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

    def test_typescript_and_tsx_unique_unchanged_statements_can_move(self):
        examples = [('src/example.ts', 'export function validate(value: string) {\n  return eval(value);\n}\n'),
                    ('src/example.tsx', 'export const View = () => (\n  <div dangerouslySetInnerHTML={{__html: value}} />\n);\n'),
                    ('src/example.js', 'export function validate(value) {\n  return eval(value);\n}\n'),
                    ('src/example.jsx', 'export const View = () => (\n  <div dangerouslySetInnerHTML={{__html: value}} />\n);\n'),
                    ('src/example.mts', 'export function validate(value: string) {\n  return eval(value);\n}\n'),
                    ('src/example.cts', 'export function validate(value: string) {\n  return eval(value);\n}\n'),
                    ('src/example.mjs', 'export function validate(value) {\n  return eval(value);\n}\n'),
                    ('src/example.cjs', 'function validate(value) {\n  return eval(value);\n}\n')]
        for path, source in examples:
            with self.subTest(path=path):
                old, new = finding(2, path=path), finding(3, path=path)
                for item in (old, new):
                    item['detail'].pop('source')
                    item['detail'].pop('test_name')
                self.assertEqual([], self.compare(source, '// inserted\n' + source, old, new, language='typescript'))
                changed = source.replace('value', 'other')
                self.assertTrue(self.compare(source, '// inserted\n' + changed, old, new, language='typescript'))
                self.assertTrue(self.compare(source, '// inserted\n' + source + source, old, new, language='typescript'))
                self.assertTrue(self.compare(source, 'invalid {\n', old, new, language='typescript'))

    def test_real_typescript_security_entries_match_when_unchanged(self):
        from desloppify.engine.detectors.security.rules import SecurityRule, make_security_entry
        path = 'src/example.ts'
        rule = SecurityRule('eval_usage', 'eval risk', 'high', 'medium', 'avoid eval')
        def actual(line):
            entry = make_security_entry(path, line, 'return eval(value);', rule)
            return {**entry, 'id': f"security::{path}::{entry['name']}", 'status': 'open',
                    'work_item_kind': 'mechanical_defect', 'tier': 4, 'detector': 'security'}
        source = 'export function validate(value: string) {\n  return eval(value);\n}\n'
        self.assertEqual([], self.compare(source, '// inserted\n' + source, actual(2), actual(3), language='typescript'))

    def test_typescript_priority_and_severity_changes_still_block(self):
        source = 'export function validate(value: string) {\n  return eval(value);\n}\n'
        old, new = finding(2, path='src/example.ts', tier=2), finding(3, path='src/example.ts', tier=2)
        for item in (old, new):
            item['detail'].pop('source')
            item['detail'].pop('test_name')
        self.assertTrue(any('T2 remains' in error for error in
                            self.compare(source, '// inserted\n' + source, old, new, language='typescript')))
        old['tier'] = new['tier'] = 4
        old['detail']['severity'], new['detail']['severity'] = 'low', 'high'
        self.assertTrue(self.compare(source, '// inserted\n' + source, old, new, language='typescript'))

    def test_two_statements_on_same_line_cannot_be_uniquely_matched(self):
        source = 'const a = eval(x); const b = eval(y);\n'
        old, new = finding(1, path='src/example.ts'), finding(2, path='src/example.ts')
        for item in (old, new):
            item['detail'].pop('source')
            item['detail'].pop('test_name')
        self.assertTrue(self.compare(source, '// inserted\n' + source, old, new, language='typescript'))

    def test_changed_finding_severity_is_new(self):
        source = 'def validate(value):\n    return unsafe(value)\n'
        old, new = finding(2), finding(3)
        old['detail']['severity'] = 'low'
        new['detail']['severity'] = 'high'
        self.assertTrue(self.compare(source, '# inserted\n' + source, old, new))

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
