import types
import unittest

from code_health import scanner_patch


class PythonCoveragePatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original = scanner_patch.scanner_source('python').read_bytes()
        if scanner_patch.component_digest(original) == scanner_patch.COMPONENTS['python']['patched']:
            cls.source = original
        else:
            cls.source = scanner_patch.patched_component('python', original)
        namespace = {'__name__': 'desloppify.languages.python.test_coverage'}
        exec(compile(cls.source, '<patched Python scanner>', 'exec'), namespace)
        cls.parse = staticmethod(namespace['parse_test_import_specs'])
        cls.resolve = staticmethod(namespace['resolve_import_spec'])

    def test_multiple_imports_aliases_and_parenthesised_imports(self):
        content = '''from code_health import cli as policy, qualification_bridge
from code_health import (
    qualification_controller as controller,
    qualification_results,
)
import alpha.beta as alias, gamma.delta
text = "from fake import ignored"
'''
        result = set(self.parse(content))
        self.assertTrue({'code_health.cli', 'code_health.qualification_bridge',
                         'code_health.qualification_controller', 'code_health.qualification_results',
                         'alpha.beta', 'gamma.delta'} <= result)
        self.assertNotIn('fake.ignored', result)

    def test_relative_imports_resolve_against_the_test_package(self):
        self.assertIn('..qualification_bridge', self.parse('from .. import qualification_bridge\n'))
        files = {'src/pkg/qualification_bridge.py', 'src/other/qualification_bridge.py'}
        self.assertEqual('src/pkg/qualification_bridge.py',
                         self.resolve('..qualification_bridge', 'src/pkg/tests/test_bridge.py', files))
        self.assertIsNone(self.resolve('.missing', 'src/pkg/tests/test_bridge.py', files))

    def test_unresolved_relative_import_does_not_match_an_unrelated_global_module(self):
        original = scanner_patch.scanner_source('mapping').read_bytes()
        if scanner_patch.component_digest(original) == scanner_patch.COMPONENTS['mapping']['patched']:
            corrected = original
        else:
            corrected = scanner_patch.patched_component('mapping', original)
        namespace = {'__name__': 'desloppify.engine.detectors.coverage.mapping_imports'}
        exec(compile(corrected, '<patched coverage mapper>', 'exec'), namespace)
        namespace['read_coverage_file'] = lambda *_args, **_kwargs: types.SimpleNamespace(ok=True, content='from . import missing\n')
        namespace['_load_lang_test_coverage_module'] = lambda _lang: types.SimpleNamespace(
            parse_test_import_specs=self.parse, resolve_import_spec=self.resolve)
        found = namespace['_parse_test_imports']('src/pkg/tests/test_bridge.py', {'src/other/missing.py'},
                                                  {'missing': 'src/other/missing.py'}, 'python')
        self.assertEqual(set(), found)

    def test_syntax_errors_cannot_silently_create_a_partial_mapping(self):
        with self.assertRaises((SyntaxError, ValueError)):
            self.parse('from x import a,\n')


if __name__ == '__main__':
    unittest.main()
