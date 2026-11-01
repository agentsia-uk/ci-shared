import unittest
from pathlib import Path
import tempfile
from unittest.mock import MagicMock, patch

from code_health import scanner_entrypoint


class ScannerEntrypointTests(unittest.TestCase):
    def test_output_handoff_preserves_links_without_following_them(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'output'
            output.mkdir(mode=0o700)
            result = output / 'state.json'
            result.write_text('private')
            result.chmod(0o600)
            outside = root / 'outside'
            outside.write_text('keep')
            outside.chmod(0o600)
            (output / 'link').symlink_to(outside)
            scanner_entrypoint.make_output_accessible(output)
            self.assertEqual(0o666, result.stat().st_mode & 0o777)
            self.assertEqual(0o600, outside.stat().st_mode & 0o777)

    def test_missing_reader_refuses_to_start_scanner(self):
        with patch.object(scanner_entrypoint.sys, 'platform', 'linux'), \
                patch.object(scanner_entrypoint.scanner_patch, 'verify'), \
                patch.object(scanner_entrypoint.ctypes, 'CDLL'), \
                patch.object(scanner_entrypoint, 'required_grammars', return_value={'nim'}), \
                patch.object(scanner_entrypoint.readers, 'configure'), \
                patch.object(scanner_entrypoint.readers, 'downloaded_languages', return_value=[]), \
                patch('desloppify.cli.main') as scanner:
            with self.assertRaisesRegex(ValueError, 'readers are missing'):
                scanner_entrypoint.main()
            scanner.assert_not_called()

    def test_validated_reader_loads_before_scanner_starts(self):
        parser = MagicMock()
        with patch.object(scanner_entrypoint.sys, 'platform', 'linux'), \
                patch.object(scanner_entrypoint.scanner_patch, 'verify') as verify, \
                patch.object(scanner_entrypoint.ctypes, 'CDLL') as runtime, \
                patch.object(scanner_entrypoint.os, 'umask') as umask, \
                patch.object(scanner_entrypoint, 'OUTPUT_DIR', '/nonexistent-qualification-output'), \
                patch.object(scanner_entrypoint, 'required_grammars', return_value={'nim'}), \
                patch.object(scanner_entrypoint.readers, 'configure') as configure, \
                patch.object(scanner_entrypoint.readers, 'downloaded_languages', return_value=['nim']), \
                patch.object(scanner_entrypoint.readers, 'get_parser', return_value=parser), \
                patch('desloppify.cli.main', return_value=0) as scanner:
            self.assertEqual(0, scanner_entrypoint.main())
            verify.assert_called_once()
            runtime.assert_called_once_with('libstdc++.so.6', mode=scanner_entrypoint.ctypes.RTLD_GLOBAL)
            configure.assert_called_once_with(cache_dir=scanner_entrypoint.READER_DIR)
            parser.parse.assert_called_once_with(b'')
            umask.assert_called_once_with(0)
            scanner.assert_called_once()


if __name__ == '__main__':
    unittest.main()
