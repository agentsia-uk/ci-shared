"""Start the scanner inside a caller-verified, network-disabled container."""
import ctypes
import os
import signal
import stat
import sys

import tree_sitter_language_pack as readers

from . import scanner_patch
from .readers_lock import required_grammars

READER_DIR = '/opt/code-health/readers'
OUTPUT_DIR = '/output'


def make_output_accessible(root):
    for _, _, files, directory_fd in os.fwalk(root, follow_symlinks=False):
        directory = os.fstat(directory_fd)
        if directory.st_uid == os.geteuid():
            os.fchmod(directory_fd, stat.S_IMODE(directory.st_mode) | 0o777)
        elif stat.S_IMODE(directory.st_mode) & 0o777 != 0o777:
            raise ValueError('scanner output directory is not accessible to its host')
        for name in files:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
                raise ValueError('scanner output contains an unsafe file')
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
            try:
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise ValueError('scanner output changed during hand-off')
                os.fchmod(fd, stat.S_IMODE(opened.st_mode) | 0o666)
            finally:
                os.close(fd)


def main():
    if sys.platform != 'linux':
        raise ValueError('trusted code-health scanning requires Linux')
    scanner_patch.verify()
    ctypes.CDLL('libstdc++.so.6', mode=ctypes.RTLD_GLOBAL)
    readers.configure(cache_dir=READER_DIR)
    required = required_grammars()
    if not required <= set(readers.downloaded_languages()):
        raise ValueError('verified scanner readers are missing')
    for language in sorted(required):
        readers.get_parser(language).parse(b'')
    # The private task parent protects output; permissive modes permit rootless-host cleanup.
    os.umask(0)
    from desloppify.cli import main as scanner_main
    def interrupted(_signum, _frame):
        raise InterruptedError('scanner cancelled')
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        return scanner_main()
    finally:
        signal.signal(signal.SIGTERM, previous)
        if os.path.isdir(OUTPUT_DIR):
            make_output_accessible(OUTPUT_DIR)


if __name__ == '__main__':
    sys.exit(main())
