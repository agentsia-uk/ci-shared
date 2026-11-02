"""Prepare the pinned Linux GitHub CLI without modifying the host installation."""
import argparse
import hashlib
import io
import os
from pathlib import Path
import tarfile
import urllib.request

from .build_release_bundle import ReaderRedirect

VERSION = '2.102.0'
ARCHIVE_SIZE = 15319960
ARCHIVE_SHA256 = 'bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386'
BINARY_SIZE = 42086560
BINARY_SHA256 = '7469124f706944133d6a169691dd1c6c3511b12e85878d255e044e2948df4c9b'
URL = f'https://github.com/cli/cli/releases/download/v{VERSION}/gh_{VERSION}_linux_amd64.tar.gz'
MEMBER = f'gh_{VERSION}_linux_amd64/bin/gh'


def prepare(destination: Path) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ReaderRedirect())
    with opener.open(URL, timeout=60) as response:
        archive = response.read(ARCHIVE_SIZE + 1)
    if len(archive) != ARCHIVE_SIZE or hashlib.sha256(archive).hexdigest() != ARCHIVE_SHA256:
        raise ValueError('GitHub CLI archive does not match the approved pin')
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as data:
        matches = [item for item in data if item.name == MEMBER]
        if len(matches) != 1 or not matches[0].isfile() or matches[0].size != BINARY_SIZE:
            raise ValueError('GitHub CLI archive lacks the expected binary')
        source = data.extractfile(matches[0])
        binary = source.read(BINARY_SIZE + 1) if source else b''
    if len(binary) != BINARY_SIZE or hashlib.sha256(binary).hexdigest() != BINARY_SHA256:
        raise ValueError('GitHub CLI binary does not match the approved pin')
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), 0o700)
        output.write(binary)
        output.flush()
        os.fsync(output.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', required=True, type=Path)
    args = parser.parse_args()
    prepare(args.destination)


if __name__ == '__main__':
    main()
