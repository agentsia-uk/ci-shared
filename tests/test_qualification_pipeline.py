import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from code_health import qualification_pipeline


class QualificationPipelineTests(unittest.TestCase):
    def test_validation_uses_independently_rebuilt_candidate_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / 'result.json'
            result.write_bytes(b'observations')
            argv = ['qualification', 'validate', '--repo', directory, '--commit', 'a' * 40,
                    '--result', str(result), '--run-id', '17', '--run-attempt', '2']
            with patch.object(sys, 'argv', argv), \
                    patch.object(qualification_pipeline, 'candidate_bundle', return_value=(b'bundle', set(), 'b' * 64)), \
                    patch.object(qualification_pipeline, 'validate_results') as validate:
                qualification_pipeline.main()
            validate.assert_called_once_with(b'observations', run_id=17, run_attempt=2, candidate_sha256='b' * 64)

    def test_validation_refuses_a_link_to_another_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'target'
            target.write_bytes(b'keep')
            link = root / 'result.json'
            link.symlink_to(target)
            argv = ['qualification', 'validate', '--repo', directory, '--commit', 'a' * 40,
                    '--result', str(link), '--run-id', '17', '--run-attempt', '2']
            with patch.object(sys, 'argv', argv), \
                    patch.object(qualification_pipeline, 'candidate_bundle', return_value=(b'bundle', set(), 'b' * 64)):
                with self.assertRaises(OSError):
                    qualification_pipeline.main()


if __name__ == '__main__':
    unittest.main()
