"""Start the scanner inside a caller-verified, network-disabled container."""
import ctypes
import os
import sys

import tree_sitter_language_pack as readers

from . import scanner_patch
from .readers_lock import required_grammars

READER_DIR = '/opt/code-health/readers'


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
    return scanner_main()


if __name__ == '__main__':
    sys.exit(main())
