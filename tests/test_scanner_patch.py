import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import ast

from code_health import scanner_patch


def original_typescript():
    source = scanner_patch.scanner_source('typescript').read_bytes()
    if hashlib.sha256(source).hexdigest() == scanner_patch.COMPONENTS['typescript']['patched']:
        source = source.replace(scanner_patch.NEW.encode(), scanner_patch.OLD.encode())
    return source


class ScannerPatchTests(unittest.TestCase):
    def test_batch_review_contract_uses_the_selected_language(self):
        source = scanner_patch.scanner_source('review_orchestrator').read_bytes()
        if scanner_patch.component_digest(source) != scanner_patch.COMPONENTS['review_orchestrator']['patched']:
            source = scanner_patch.patched_component('review_orchestrator', source)
        module = ast.parse(source)
        function = next(node for node in module.body
                        if isinstance(node, ast.FunctionDef) and node.name == '_build_prepared_packet_contract')
        namespace = {
            'prepared_packet_contract': lambda context, **kwargs: kwargs,
            'resolve_review_packet_context': lambda args: args,
        }
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<review packet orchestrator>', 'exec'), namespace)
        result = namespace['_build_prepared_packet_contract'](
            'review context', config={}, lang=SimpleNamespace(name='typescript'))
        self.assertEqual('typescript', result['language'])

    def test_dynamic_writes_make_phantom_read_uncertain(self):
        from desloppify.languages.python.detectors.dict_keys import (
            TrackedDict, _CONFIG_NAMES, _is_singular_plural, _levenshtein,
        )
        source = scanner_patch.scanner_source('python_dict_helpers').read_bytes()
        if scanner_patch.component_digest(source) != scanner_patch.COMPONENTS['python_dict_helpers']['patched']:
            source = scanner_patch.patched_component('python_dict_helpers', source)
        module = ast.parse(source)
        function = next(node for node in module.body
                        if isinstance(node, ast.FunctionDef) and node.name == 'analyze_scope_issues')
        namespace = {'TrackedDict': TrackedDict, '_CONFIG_NAMES': _CONFIG_NAMES,
                     '_is_singular_plural': _is_singular_plural, '_levenshtein': _levenshtein}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<patched dict-key analysis>', 'exec'), namespace)
        tracked = TrackedDict('files', 1, True)
        tracked.reads['policy.json'].append(2)
        tracked.has_dynamic_write = True
        visitor = SimpleNamespace(filepath='sample.py')
        self.assertEqual([], namespace['analyze_scope_issues'](visitor, {'files': tracked}, 'build'))
        tracked.has_dynamic_write = False
        self.assertEqual(['phantom_read'], [issue['kind'] for issue in
                         namespace['analyze_scope_issues'](visitor, {'files': tracked}, 'build')])

    def test_review_source_identity_binds_a_clean_commit_to_its_scan_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            area = root / 'sdk'
            area.mkdir()
            (area / 'module.py').write_text('value = 1\n')
            subprocess.run(['git', 'init', '-q', '-b', 'main'], cwd=root, check=True)
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            subprocess.run(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                            'commit', '-q', '-m', 'fixture'], cwd=root, check=True)
            commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=root, check=True,
                                    capture_output=True, text=True).stdout.strip()
            self.assertEqual({'commit_sha': commit, 'path': str(area.resolve()), 'language': 'python'},
                             scanner_patch.review_source_identity(area, 'python'))
            (root / '.desloppify').mkdir()
            (root / '.desloppify' / 'review.json').write_text('{}')
            self.assertEqual({'commit_sha': commit, 'path': str(area.resolve()), 'language': 'python'},
                             scanner_patch.review_source_identity(area, 'python'))
            (area / 'untracked.py').write_text('value = 2\n')
            self.assertIsNone(scanner_patch.review_source_identity(area, 'python'))

    def test_python_nesting_counts_blocks_not_continuation_alignment(self):
        source = scanner_patch.scanner_source('python_complexity').read_bytes()
        if hashlib.sha256(source).hexdigest() != scanner_patch.COMPONENTS['python_complexity']['patched']:
            source = scanner_patch.patched_component('python_complexity', source)
        namespace = {'__name__': 'desloppify.languages.python.detectors.complexity'}
        exec(compile(source, '<patched scanner>', 'exec'), namespace)
        nesting = namespace['compute_nesting_depth']
        aligned = 'def f():\n    if True:\n        return (1 +\n             2 +\n' + ' ' * 47 + '3)\n'
        deep = 'def f():\n    if True:\n        if True:\n            if True:\n                if True:\n                    pass\n'
        self.assertIsNone(nesting(aligned, aligned.splitlines()))
        self.assertEqual((5, 'nesting depth 5'), nesting(deep, deep.splitlines()))
        string = 'def f():\n    return """text\n' + ' ' * 47 + 'text\n"""\n'
        self.assertIsNone(nesting(string, string.splitlines()))
        tabs = 'def f():\n\tif True:\n\t\tif True:\n\t\t\tif True:\n\t\t\t\tif True:\n\t\t\t\t\tpass\n'
        self.assertEqual((5, 'nesting depth 5'), nesting(tabs, tabs.splitlines()))

    def test_exact_paths_win_and_ambiguous_fallback_is_refused(self):
        corrected = scanner_patch.patched_component('typescript', original_typescript())
        namespace = {'__name__': 'desloppify.languages.typescript.test_coverage'}
        exec(compile(corrected, '<patched scanner>', 'exec'), namespace)
        mapping = namespace['map_test_to_source']
        production = {'src/db/health.ts', 'src/api/routes/health.ts'}
        self.assertEqual('src/db/health.ts', mapping('src/db/__tests__/health.test.ts', production))
        self.assertIsNone(mapping('unrelated/__tests__/health.test.ts', production))
        self.assertEqual('src/db/health.ts', mapping('unrelated/__tests__/health.test.ts', {'src/db/health.ts'}))
        self.assertIsNone(mapping('src/db/__tests__/health.test.ts', {'src/db/health.ts', 'src/db/health.tsx'}))

    def test_install_is_idempotent_and_refuses_unknown_source(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = {}
            for name in scanner_patch.COMPONENTS:
                paths[name] = Path(directory) / (name + '.py')
                paths[name].write_bytes(original_typescript() if name == 'typescript'
                                        else scanner_patch.scanner_source(name).read_bytes())
            with patch.object(scanner_patch, 'scanner_source', side_effect=lambda name: paths[name]):
                scanner_patch.install()
                scanner_patch.verify()
                scanner_patch.install()
                paths['python'].write_text('unexpected scanner source')
                with self.assertRaises(ValueError):
                    scanner_patch.install()
                with self.assertRaises(ValueError):
                    scanner_patch.verify()

    def test_unknown_component_is_rejected_before_any_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = {}
            for name in scanner_patch.COMPONENTS:
                paths[name] = Path(directory) / (name + '.py')
                paths[name].write_bytes(original_typescript() if name == 'typescript'
                                        else scanner_patch.scanner_source(name).read_bytes())
            original = paths['typescript'].read_bytes()
            paths['python'].write_text('unexpected scanner source')
            with patch.object(scanner_patch, 'scanner_source', side_effect=lambda name: paths[name]):
                with self.assertRaises(ValueError):
                    scanner_patch.install()
            self.assertEqual(original, paths['typescript'].read_bytes())
            self.assertEqual(set(paths.values()), set(Path(directory).iterdir()))

    def test_partial_publication_is_rejected_and_retry_repairs_it(self):
        original = {'a': b'old-a', 'b': b'old-b'}
        updated = {'a': b'new-a', 'b': b'new-b'}
        components = {name: {'original': hashlib.sha256(original[name]).hexdigest(),
                             'patched': hashlib.sha256(updated[name]).hexdigest()} for name in original}
        identity = ''.join(f"{name}:{components[name]['patched']}\n" for name in sorted(components)).encode()
        with tempfile.TemporaryDirectory() as directory:
            paths = {name: Path(directory) / name for name in components}
            for name in paths:
                paths[name].write_bytes(original[name])
            replace = scanner_patch.os.replace
            count = 0
            def fail_second(source, target):
                nonlocal count
                count += 1
                if count == 2:
                    raise OSError('interrupted publication')
                replace(source, target)
            def candidate(name, data):
                if data != original[name]:
                    raise ValueError('unexpected source')
                return updated[name]
            with patch.object(scanner_patch, 'COMPONENTS', components), \
                    patch.object(scanner_patch, 'PATCHED_SHA256', hashlib.sha256(identity).hexdigest()), \
                    patch.object(scanner_patch, 'scanner_source', side_effect=lambda name: paths[name]), \
                    patch.object(scanner_patch, 'patched_component', side_effect=candidate):
                with patch.object(scanner_patch.os, 'replace', side_effect=fail_second):
                    with self.assertRaises(OSError):
                        scanner_patch.install()
                with self.assertRaises(ValueError):
                    scanner_patch.verify()
                scanner_patch.install()
                scanner_patch.verify()
                self.assertEqual(updated, {name: paths[name].read_bytes() for name in paths})

    def test_direct_scan_refuses_an_unverified_scanner(self):
        from code_health import cli
        with patch.object(cli.sys, 'platform', 'linux'), \
                patch.object(scanner_patch, 'verify', side_effect=ValueError('scanner changed')):
            with self.assertRaisesRegex(ValueError, 'scanner changed'):
                cli.scan(Path('/unused'), {}, Path('/unused'), [])

    def test_direct_scan_refuses_macos_before_touching_source(self):
        from code_health import cli
        with patch.object(cli, 'verify_scanner'), patch.object(cli.sys, 'platform', 'darwin'):
            with self.assertRaisesRegex(ValueError, 'scanning requires Linux'):
                cli.scan(Path('/unused'), {}, Path('/unused'), [])

    def test_policy_must_bind_the_exact_scanner_patch(self):
        from code_health import cli
        with patch.object(cli.sys, 'platform', 'linux'), \
                patch.dict(cli.POLICY, {'scannerPatch': {'id': scanner_patch.PATCH_ID, 'sha256': '0' * 64}}), \
                patch.object(scanner_patch, 'verify') as verify:
            with self.assertRaisesRegex(ValueError, 'scanner patch differs from policy'):
                cli.scan(Path('/unused'), {}, Path('/unused'), [])
            verify.assert_not_called()

    def test_failed_publication_preserves_the_original_scanner(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = {}
            for name in scanner_patch.COMPONENTS:
                paths[name] = Path(directory) / (name + '.py')
                paths[name].write_bytes(original_typescript() if name == 'typescript'
                                        else scanner_patch.scanner_source(name).read_bytes())
            original = paths['typescript'].read_bytes()
            with patch.object(scanner_patch, 'scanner_source', side_effect=lambda name: paths[name]), \
                    patch.object(scanner_patch.os, 'replace', side_effect=OSError('write failed')):
                with self.assertRaises(OSError):
                    scanner_patch.install()
            self.assertEqual(original, paths['typescript'].read_bytes())
            self.assertEqual(set(paths.values()), set(Path(directory).iterdir()))


if __name__ == '__main__':
    unittest.main()
