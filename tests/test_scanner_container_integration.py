"""Run a real sample scan with verified readers in a locked-down container."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from code_health import readers_lock
from code_health.build_release_bundle import download_reader_archives
from code_health.scanner_container import run_scanner

IMAGE = os.environ.get('CODE_HEALTH_SCANNER_IMAGE')


@unittest.skipUnless(IMAGE, 'requires a prepared scanner image and Docker')
class ScannerContainerTests(unittest.TestCase):
    def test_sample_scan_uses_read_only_source_and_no_network(self):
        policy = Path(__file__).resolve().parents[1] / 'code_health'
        lock = readers_lock.verify_selected_manifest((policy / 'readers-lock.json').read_bytes(),
                                                     (policy / 'readers-upstream.json').read_bytes())
        archives = download_reader_archives(lock)
        with tempfile.TemporaryDirectory(prefix='scanner-container-') as temporary:
            root = Path(temporary)
            source, output, readers = (root / name for name in ('source', 'output', 'readers'))
            source.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            readers.mkdir(mode=0o700)
            fd = os.open(readers, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                readers_lock.unpack_archive(archives['linux-x86_64'], lock=lock,
                                            platform='linux-x86_64', destination_fd=fd)
            finally:
                os.close(fd)
            (source / 'sample.py').write_text('def answer():\n    return 42\n')
            config = source / '.desloppify'
            config.mkdir(mode=0o700)
            (config / 'config.json').write_text(json.dumps({'generate_scorecard': False, 'trust_plugins': False,
                'hermes_enabled': False, 'hermes_models': {}, 'languages': {}, 'ignore': [], 'zone_overrides': {},
                'exclude': [], 'commit_tracking_enabled': False, 'target_strict_score': 90}))
            image_id = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', IMAGE],
                                               text=True, timeout=30).strip()
            run_scanner(image=image_id, source=source, readers=readers, output=output,
                        arguments=['--lang', 'python', 'scan', '--path', '.', '--profile', 'ci', '--no-badge',
                                   '--state', '/output/state.json'])
            self.assertTrue((output / 'state.json').is_file())


if __name__ == '__main__':
    unittest.main()
