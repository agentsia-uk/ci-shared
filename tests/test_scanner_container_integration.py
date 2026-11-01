"""Run a real sample scan with verified readers in a locked-down container."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from code_health import readers_lock
from code_health.build_release_bundle import download_reader_archives

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
            root.chmod(0o755)
            source, output, readers = (root / name for name in ('source', 'output', 'readers'))
            source.mkdir(mode=0o755)
            output.mkdir(mode=0o777)
            output.chmod(0o777)
            readers.mkdir(mode=0o700)
            fd = os.open(readers, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                files = readers_lock.unpack_archive(archives['linux-x86_64'], lock=lock,
                                                    platform='linux-x86_64', destination_fd=fd)
            finally:
                os.close(fd)
            for name in files:
                (readers / name).chmod(0o444)
            readers.chmod(0o755)
            (source / 'sample.py').write_text('def answer():\n    return 42\n')
            config = source / '.desloppify'
            config.mkdir(mode=0o755)
            (config / 'config.json').write_text(json.dumps({'generate_scorecard': False, 'trust_plugins': False,
                'hermes_enabled': False, 'hermes_models': {}, 'languages': {}, 'ignore': [], 'zone_overrides': {},
                'exclude': [], 'commit_tracking_enabled': False, 'target_strict_score': 90}))
            mounts = [(source, '/source', 'readonly'), (readers, '/opt/code-health/readers', 'readonly'),
                      (output, '/output', '')]
            args = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
                    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '256',
                    '--memory', '2g', '--memory-swap', '2g', '--cpus', '2', '--user', '10001:10001',
                    '--tmpfs', '/tmp:rw,nosuid,nodev,size=1g', '-e', 'HOME=/tmp', '-e', 'DESLOPPIFY_ROOT=/source',
                    '-e', 'CI=true', '-e', 'NO_COLOR=1']
            for host, target, mode in mounts:
                args.extend(['--mount', f'type=bind,src={host},dst={target}' + (',' + mode if mode else '')])
            args.extend([IMAGE, '--lang', 'python', 'scan', '--path', '.', '--profile', 'ci', '--no-badge',
                         '--state', '/output/state.json'])
            result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
            self.assertEqual(0, result.returncode, result.stderr.decode(errors='replace')[-4000:])
            self.assertTrue((output / 'state.json').is_file())


if __name__ == '__main__':
    unittest.main()
