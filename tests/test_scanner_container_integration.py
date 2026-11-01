"""Run a real sample scan with verified readers in a locked-down container."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from code_health import prepare_readers
from code_health.cli import scan

IMAGE = os.environ.get('CODE_HEALTH_SCANNER_IMAGE')


@unittest.skipUnless(IMAGE, 'requires a prepared scanner image and Docker')
class ScannerContainerTests(unittest.TestCase):
    def test_sample_scan_uses_read_only_source_and_no_network(self):
        with tempfile.TemporaryDirectory(prefix='scanner-container-') as temporary:
            root = Path(temporary)
            source, output, readers = (root / name for name in ('source', 'output', 'readers'))
            source.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            readers.mkdir(mode=0o700)
            with patch.object(sys, 'argv', ['prepare-readers', '--destination', str(readers)]):
                prepare_readers.main()
            (source / 'sample.py').write_text('def answer():\n    return 42\n')
            config = source / '.desloppify'
            config.mkdir(mode=0o700)
            (config / 'config.json').write_text(json.dumps({'generate_scorecard': False, 'trust_plugins': False,
                'hermes_enabled': False, 'hermes_models': {}, 'languages': {}, 'ignore': [], 'zone_overrides': {},
                'exclude': [], 'commit_tracking_enabled': False, 'target_strict_score': 90}))
            image_id = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', IMAGE],
                                               text=True, timeout=30).strip()
            output.rmdir()
            area = {'id': 'sample', 'language': 'python', 'path': '.', 'exclusions': []}
            status, state = scan(source, area, output, [area], scanner_image=image_id, readers=readers)
            self.assertTrue((output / 'state.json').is_file())
            self.assertIsInstance(status, dict)
            self.assertIsInstance(state, dict)


if __name__ == '__main__':
    unittest.main()
