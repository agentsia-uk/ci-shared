"""Start the scanner inside a caller-verified, network-disabled container."""
import ctypes
import os
import signal
import stat
import subprocess
import sys

import tree_sitter_language_pack as readers

from . import scanner_patch
from .readers_lock import required_grammars

READER_DIR = '/opt/code-health/readers'
OUTPUT_DIR = '/output'
OUTPUT_NAME = '.scanner-stdout'
MAX_OUTPUT_BYTES = 64 * 1024 * 1024


def capture_to_file(command, directory):
    temporary = os.path.join(directory, OUTPUT_NAME + '.tmp')
    final = os.path.join(directory, OUTPUT_NAME)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    identity = os.fstat(fd)
    child = None
    previous = signal.getsignal(signal.SIGTERM)
    def interrupted(_signum, _frame):
        raise InterruptedError('scanner cancelled')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        child = subprocess.Popen(command, stdout=subprocess.PIPE)
        total = 0
        while True:
            chunk = os.read(child.stdout.fileno(), min(65536, MAX_OUTPUT_BYTES - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_OUTPUT_BYTES:
                raise ValueError('scanner output exceeds its size limit')
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise ValueError('scanner output made no progress')
                remaining = remaining[written:]
        if child.wait() != 0:
            raise ValueError('scanner worker failed')
        os.fsync(fd)
        current = os.lstat(temporary)
        if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
            raise ValueError('scanner output identity changed')
        os.link(temporary, final, follow_symlinks=False)
        linked = os.lstat(final)
        if (linked.st_dev, linked.st_ino) != (identity.st_dev, identity.st_ino):
            raise ValueError('scanner output publication changed')
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            if child is not None:
                try:
                    if child.poll() is None:
                        try:
                            child.terminate()
                        except ProcessLookupError:
                            pass
                        try:
                            child.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            try:
                                child.kill()
                            except ProcessLookupError:
                                pass
                    child.wait(timeout=5)
                finally:
                    child.stdout.close()
        finally:
            signal.signal(signal.SIGTERM, previous)
            os.close(fd)
            try:
                current = os.lstat(temporary)
                if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                    os.unlink(temporary)
            except FileNotFoundError:
                pass


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
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError('scanner output contains an unsafe file')
            if metadata.st_uid != os.geteuid():
                continue
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
    program = "import sys; sys.path.insert(0, '/opt/code-health'); from code_health.scanner_entrypoint import main; sys.exit(main())"
    capture_to_file([sys.executable, '-I', '-B', '-c', program, *sys.argv[1:]], OUTPUT_DIR)
