import hashlib
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from code_health import prepare_release_gh, release_attestation


class ReleaseGhTests(unittest.TestCase):
    def test_release_pins_are_full_sha256_values(self):
        self.assertRegex(prepare_release_gh.ARCHIVE_SHA256, r'^[0-9a-f]{64}$')
        self.assertRegex(prepare_release_gh.BINARY_SHA256, r'^[0-9a-f]{64}$')

    def test_verified_archive_produces_only_the_expected_binary(self):
        binary = b'approved synthetic executable'
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:gz') as archive:
            info = tarfile.TarInfo(prepare_release_gh.MEMBER)
            info.size = len(binary)
            archive.addfile(info, io.BytesIO(binary))
        archive_bytes = data.getvalue()
        opener = unittest.mock.Mock()
        opener.open.side_effect = lambda *_args, **_kwargs: io.BytesIO(archive_bytes)
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(prepare_release_gh.urllib.request, 'build_opener', return_value=opener), \
             patch.object(prepare_release_gh, 'ARCHIVE_SIZE', len(archive_bytes)), \
             patch.object(prepare_release_gh, 'ARCHIVE_SHA256', hashlib.sha256(archive_bytes).hexdigest()), \
             patch.object(prepare_release_gh, 'BINARY_SIZE', len(binary)), \
             patch.object(prepare_release_gh, 'BINARY_SHA256', hashlib.sha256(binary).hexdigest()):
            output = Path(directory) / 'gh'
            prepare_release_gh.prepare(output)
            self.assertEqual(binary, output.read_bytes())
            self.assertEqual(0o700, output.stat().st_mode & 0o777)
            with self.assertRaises(FileExistsError):
                prepare_release_gh.prepare(output)
            output.unlink()
            with patch.object(prepare_release_gh, 'ARCHIVE_SHA256', '0' * 64), self.assertRaises(ValueError):
                prepare_release_gh.prepare(output)
            self.assertFalse(output.exists())
            with patch.object(prepare_release_gh, 'BINARY_SHA256', '0' * 64), self.assertRaises(ValueError):
                prepare_release_gh.prepare(output)
            self.assertFalse(output.exists())

    def test_untrusted_or_symlinked_binary_is_refused(self):
        binary = b'approved synthetic executable'
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(release_attestation.os.path, 'isdir', return_value=True), \
             patch.object(prepare_release_gh, 'BINARY_SIZE', len(binary)), \
             patch.object(prepare_release_gh, 'BINARY_SHA256', hashlib.sha256(binary).hexdigest()):
            target = Path(directory) / 'gh'
            target.write_bytes(binary)
            target.chmod(0o700)
            fd = release_attestation._verified_gh_fd(str(target))
            os.close(fd)
            target.chmod(0o722)
            with self.assertRaisesRegex(ValueError, 'metadata'):
                release_attestation._verified_gh_fd(str(target))
            target.chmod(0o700)
            target.write_bytes(b'changed synthetic executable!')
            with self.assertRaises(ValueError):
                release_attestation._verified_gh_fd(str(target))
            link = Path(directory) / 'link'
            link.symlink_to(target)
            with self.assertRaises(OSError):
                release_attestation._verified_gh_fd(str(link))

    @unittest.skipUnless(sys.platform == 'linux', 'requires Linux descriptor execution')
    def test_executes_the_checked_descriptor_on_linux(self):
        binary = b'#!/bin/sh\nprintf "verified\\n"\n'
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(prepare_release_gh, 'BINARY_SIZE', len(binary)), \
             patch.object(prepare_release_gh, 'BINARY_SHA256', hashlib.sha256(binary).hexdigest()):
            target = Path(directory) / 'gh'
            target.write_bytes(binary)
            target.chmod(0o700)
            with patch.dict(os.environ, {'CODE_HEALTH_GH_EXECUTABLE': str(target)}):
                self.assertEqual(b'verified\n', release_attestation.read_command([release_attestation.GH_EXECUTABLE, '--version']))


if __name__ == '__main__':
    unittest.main()
