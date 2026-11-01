from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from code_health import scanner_container


class ScannerContainerTests(unittest.TestCase):
    def test_rejects_mutable_images_and_overlapping_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source, readers, output = (root / name for name in ('source', 'readers', 'output'))
            for path in (source, readers, output):
                path.mkdir(mode=0o700)
            with patch.object(scanner_container.os, 'geteuid', return_value=root.stat().st_uid):
                with self.assertRaisesRegex(ValueError, 'exact image'):
                    scanner_container.run_scanner(image='latest', source=source, readers=readers, output=output,
                                                  arguments=[])
                with self.assertRaisesRegex(ValueError, 'must not overlap'):
                    scanner_container.run_scanner(image='sha256:' + 'a' * 64, source=source, readers=source,
                                                  output=output, arguments=[])

    def test_removes_container_when_scanner_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source, readers, output = (root / name for name in ('source', 'readers', 'output'))
            for path in (source, readers, output):
                path.mkdir(mode=0o700)
            created = subprocess.CompletedProcess([], 0, stdout=b'a' * 64)
            with patch.object(scanner_container.os, 'geteuid', return_value=root.stat().st_uid), \
                    patch.object(scanner_container, '_require_seccomp'), \
                    patch.object(scanner_container.subprocess, 'run', return_value=created) as run, \
                    patch.object(scanner_container, '_capture', side_effect=TimeoutError('timeout')):
                with self.assertRaises(TimeoutError):
                    scanner_container.run_scanner(image='sha256:' + 'b' * 64, source=source, readers=readers,
                                                  output=output, arguments=[])
            self.assertEqual([scanner_container.DOCKER, 'rm', '--force', 'a' * 64], run.call_args_list[-1].args[0])


if __name__ == '__main__':
    unittest.main()
