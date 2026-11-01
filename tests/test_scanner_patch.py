import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from code_health import scanner_patch


def original_typescript():
    source = scanner_patch.scanner_source('typescript').read_bytes()
    if hashlib.sha256(source).hexdigest() == scanner_patch.COMPONENTS['typescript']['patched']:
        source = source.replace(scanner_patch.NEW.encode(), scanner_patch.OLD.encode())
    return source


class ScannerPatchTests(unittest.TestCase):
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
        with patch.object(scanner_patch, 'verify', side_effect=ValueError('scanner changed')):
            with self.assertRaisesRegex(ValueError, 'scanner changed'):
                cli.scan(Path('/unused'), {}, Path('/unused'), [])

    def test_policy_must_bind_the_exact_scanner_patch(self):
        from code_health import cli
        with patch.dict(cli.POLICY, {'scannerPatch': {'id': scanner_patch.PATCH_ID, 'sha256': '0' * 64}}), \
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
