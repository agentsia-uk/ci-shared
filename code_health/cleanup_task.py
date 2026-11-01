"""Remove only the private temporary directory created by this action."""
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile


def cleanup(parent, task, identity):
    parent = Path(parent).resolve(strict=True)
    task = Path(task).absolute()
    if task.parent != parent or not re.fullmatch(r'code-health-task\.[A-Za-z0-9]{8}', task.name):
        raise ValueError('invalid scanner task directory')
    try:
        metadata = task.lstat()
    except FileNotFoundError:
        return
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
            or identity != f'{metadata.st_dev}:{metadata.st_ino}' or not shutil.rmtree.avoids_symlink_attacks):
        raise ValueError('scanner task identity or permissions changed')
    quarantine = Path(tempfile.mkdtemp(prefix='.code-health-cleanup-', dir=parent))
    moved = quarantine / 'owned'
    try:
        os.rename(task, moved)
    except OSError:
        quarantine.rmdir()
        raise
    metadata = moved.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
            or identity != f'{metadata.st_dev}:{metadata.st_ino}'):
        raise ValueError('scanner task changed during cleanup; preserved in private quarantine')
    shutil.rmtree(quarantine)


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('expected runner temporary directory, task directory and identity')
    cleanup(*sys.argv[1:])
