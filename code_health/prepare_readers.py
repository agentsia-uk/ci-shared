"""Prepare the exact pinned readers in an empty private directory."""
import argparse
from importlib.metadata import version
import os
from pathlib import Path
import platform
import sys

from .build_release_bundle import download_reader_archives
from .readers_lock import PLATFORMS, locked_package_version, unpack_archive, verify_selected_manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != 'linux':
        raise ValueError('trusted code-health scanning requires Linux')
    root = Path(__file__).resolve().parent
    requirements = (root / 'requirements.lock').read_bytes()
    if version('tree-sitter-language-pack') != locked_package_version(requirements):
        raise ValueError('installed reader package differs from the dependency lock')
    lock = verify_selected_manifest((root / 'readers-lock.json').read_bytes(),
                                    (root / 'readers-upstream.json').read_bytes())
    selected = 'linux-' + platform.machine()
    if selected not in PLATFORMS:
        raise ValueError('scanner architecture is not supported')
    archives = download_reader_archives(lock)
    fd = os.open(args.destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        unpack_archive(archives[selected], lock=lock, platform=selected, destination_fd=fd)
    finally:
        os.close(fd)


if __name__ == '__main__':
    main()
