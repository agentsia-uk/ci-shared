import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from code_health import scanner_patch


class ScannerPatchTests(unittest.TestCase):
    def test_exact_paths_win_and_ambiguous_fallback_is_refused(self):
        original = scanner_patch.scanner_source().read_bytes()
        if hashlib.sha256(original).hexdigest() == scanner_patch.PATCHED_SHA256:
            original = original.replace(scanner_patch.NEW.encode(), scanner_patch.OLD.encode())
        corrected = scanner_patch.patched_bytes(original)
        namespace = {'__name__': 'desloppify.languages.typescript.test_coverage'}
        exec(compile(corrected, '<patched scanner>', 'exec'), namespace)
        mapping = namespace['map_test_to_source']
        production = {'src/db/health.ts', 'src/api/routes/health.ts'}
        self.assertEqual('src/db/health.ts', mapping('src/db/__tests__/health.test.ts', production))
        self.assertIsNone(mapping('unrelated/__tests__/health.test.ts', production))
        self.assertEqual('src/db/health.ts', mapping('unrelated/__tests__/health.test.ts', {'src/db/health.ts'}))

    def test_install_is_idempotent_and_refuses_unknown_source(self):
        original = scanner_patch.scanner_source().read_bytes()
        if hashlib.sha256(original).hexdigest() == scanner_patch.PATCHED_SHA256:
            original = original.replace(scanner_patch.NEW.encode(), scanner_patch.OLD.encode())
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'test_coverage.py'
            source.write_bytes(original)
            with patch.object(scanner_patch, 'scanner_source', return_value=source):
                scanner_patch.install()
                scanner_patch.verify()
                scanner_patch.install()
                source.write_text('unexpected scanner source')
                with self.assertRaises(ValueError):
                    scanner_patch.install()
                with self.assertRaises(ValueError):
                    scanner_patch.verify()


    def test_failed_publication_preserves_the_original_scanner(self):
        original = scanner_patch.scanner_source().read_bytes()
        if hashlib.sha256(original).hexdigest() == scanner_patch.PATCHED_SHA256:
            original = original.replace(scanner_patch.NEW.encode(), scanner_patch.OLD.encode())
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'test_coverage.py'
            source.write_bytes(original)
            with patch.object(scanner_patch, 'scanner_source', return_value=source), \
                    patch.object(scanner_patch.os, 'replace', side_effect=OSError('write failed')):
                with self.assertRaises(OSError):
                    scanner_patch.install()
            self.assertEqual(original, source.read_bytes())
            self.assertEqual([source], list(source.parent.iterdir()))


if __name__ == '__main__':
    unittest.main()
