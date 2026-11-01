import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from code_health.cleanup_task import cleanup


class CleanupTaskTests(unittest.TestCase):
    def test_removes_only_the_original_private_task(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            task = root / 'code-health-task.Abc12345'
            task.mkdir(mode=0o700)
            (task / 'data').write_text('private')
            metadata = task.stat()
            identity = f'{metadata.st_dev}:{metadata.st_ino}'
            with self.assertRaisesRegex(ValueError, 'identity'):
                cleanup(root, task, '0:0')
            self.assertTrue((task / 'data').is_file())
            cleanup(root, task, identity)
            self.assertFalse(task.exists())
            cleanup(root, task, identity)

    def test_preserves_an_object_swapped_during_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            task = root / 'code-health-task.Abc12345'
            task.mkdir(mode=0o700)
            other = root / 'other'
            other.mkdir(mode=0o700)
            (other / 'sentinel').write_text('keep')
            metadata = task.stat()
            identity = f'{metadata.st_dev}:{metadata.st_ino}'
            real_rename = os.rename
            def swap(source, target):
                real_rename(task, root / 'original')
                real_rename(other, source)
                real_rename(source, target)
            with patch('code_health.cleanup_task.os.rename', side_effect=swap):
                with self.assertRaisesRegex(ValueError, 'preserved'):
                    cleanup(root, task, identity)
            self.assertEqual('keep', next(root.glob('.code-health-cleanup-*/owned/sentinel')).read_text())
            self.assertTrue((root / 'original').is_dir())

    def test_recovery_accepts_the_same_task_names_as_cleanup(self):
        from code_health.scanner_recovery import _task
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            task = root / 'code-health-task.Ab_12345'
            task.mkdir(mode=0o700)
            metadata = task.stat()
            identity = f'{metadata.st_dev}:{metadata.st_ino}'
            self.assertEqual(task, _task(root, task, identity))
            cleanup(root, task, identity)
            self.assertFalse(task.exists())


if __name__ == '__main__':
    unittest.main()
