"""Run the independently pinned qualification inventory and record completion."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

EXPECTED_COUNT = 25
EXPECTED_IDS_SHA256 = 'eeb060fbd9b785ee97c900237d18465e88c3e46a5f897edf21166dbbd68325d5'
EXPECTED_TEST_FILE_SHA256 = 'a900552cb873240812228b5057a013bdb3fd1a76dd4bbf5c75c4cd6a91bcd311'


def test_ids(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from test_ids(item)
        else:
            yield item.id()


def run_qualification(test_dir: str, receipt: Path, expected_count: int, expected_ids_sha256: str,
                      expected_file_sha256: str) -> None:
    test_file = Path(test_dir) / 'test_code_health.py'
    if hashlib.sha256(test_file.read_bytes()).hexdigest() != expected_file_sha256:
        raise ValueError('qualification test bytes differ from their trusted pin')
    sys.path.insert(0, str(Path.cwd()))
    suite = unittest.defaultTestLoader.discover(test_dir, pattern='test_code_health.py')
    ids = sorted(test_ids(suite))
    digest = hashlib.sha256(('\n'.join(ids) + '\n').encode()).hexdigest()
    if len(ids) != expected_count or digest != expected_ids_sha256:
        raise ValueError('qualification test inventory differs from its trusted pin')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if (not result.wasSuccessful() or result.testsRun != expected_count or result.skipped or result.expectedFailures or
            hashlib.sha256(test_file.read_bytes()).hexdigest() != expected_file_sha256):
        raise ValueError('qualification tests did not all complete successfully')
    payload = json.dumps({'testsRun': result.testsRun, 'testIdsSha256': digest}, sort_keys=True).encode() + b'\n'
    fd = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        receipt.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test-directory', required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    run_qualification(args.test_directory, args.receipt, EXPECTED_COUNT, EXPECTED_IDS_SHA256, EXPECTED_TEST_FILE_SHA256)


if __name__ == '__main__':
    main()
