import unittest
from unittest.mock import MagicMock, patch

from code_health import scanner_entrypoint


class ScannerEntrypointTests(unittest.TestCase):
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
            scanner.assert_called_once()


if __name__ == '__main__':
    unittest.main()
