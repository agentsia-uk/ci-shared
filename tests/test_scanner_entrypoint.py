import unittest
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
import tempfile
from unittest.mock import MagicMock, patch

from code_health import scanner_entrypoint


class ScannerEntrypointTests(unittest.TestCase):
    def test_cancellation_reaps_unresponsive_worker_without_publishing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready = root / 'ready'
            worker = ('import os,signal,sys,time; '
                      'signal.signal(signal.SIGTERM, signal.SIG_IGN); '
                      'open(sys.argv[1], "w").write(str(os.getpid())); '
                      'time.sleep(60)')
            parent = ('import sys; from code_health.scanner_entrypoint import capture_to_file; '
                      'capture_to_file([sys.executable, "-c", sys.argv[2], sys.argv[3]], sys.argv[1])')
            process = subprocess.Popen([sys.executable, '-c', parent, directory, worker, str(ready)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            worker_pid = None
            try:
                deadline = time.monotonic() + 10
                while process.poll() is None and time.monotonic() < deadline:
                    if ready.exists() and ready.read_text().isdigit():
                        worker_pid = int(ready.read_text())
                        break
                    time.sleep(0.05)
                self.assertIsNotNone(worker_pid, 'worker did not start')
                process.send_signal(signal.SIGTERM)
                self.assertNotEqual(process.wait(timeout=12), 0)
                with self.assertRaises(ProcessLookupError):
                    os.kill(worker_pid, 0)
                worker_pid = None
                self.assertFalse((root / scanner_entrypoint.OUTPUT_NAME).exists())
                self.assertFalse((root / (scanner_entrypoint.OUTPUT_NAME + '.tmp')).exists())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                if worker_pid is not None:
                    try:
                        os.kill(worker_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_capture_writes_complete_output_and_refuses_partial_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = lambda script: scanner_entrypoint.capture_to_file([sys.executable, '-c', script], directory)
            run('print("complete")')
            output = root / scanner_entrypoint.OUTPUT_NAME
            self.assertEqual(output.read_bytes(), b'complete\n')
            with self.assertRaises(FileExistsError):
                run('print("overwrite")')
            self.assertEqual(output.read_bytes(), b'complete\n')
            output.unlink()
            with self.assertRaisesRegex(ValueError, 'worker failed'):
                run('import sys; print("partial"); sys.exit(1)')
            self.assertFalse(output.exists())
            with patch.object(scanner_entrypoint, 'MAX_OUTPUT_BYTES', 4), self.assertRaisesRegex(ValueError, 'exceeds'):
                run('print("too long")')
            self.assertEqual(list(root.iterdir()), [])

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
