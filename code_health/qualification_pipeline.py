"""Collect or independently validate bounded qualification observations."""
import argparse
import hashlib
import os
from pathlib import Path
import stat

from .build_release_bundle import build_bundle, runtime_files
from .qualification_results import MAX_RESULTS_BYTES, collect_bundle_results, validate_results


def candidate_bundle(repo, commit):
    allowed = runtime_files(repo, commit)
    data = build_bundle(repo, commit, allowed, download_readers=True)
    return data, allowed, hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('collect', 'validate'))
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--result', required=True, type=Path)
    parser.add_argument('--run-id', required=True, type=int)
    parser.add_argument('--run-attempt', required=True, type=int)
    parser.add_argument('--image')
    args = parser.parse_args()
    if args.run_id < 1 or args.run_attempt < 1:
        raise ValueError('invalid qualification run identity')
    bundle, allowed, digest = candidate_bundle(args.repo, args.commit)
    if args.mode == 'collect':
        if not args.image:
            raise ValueError('qualification image is required')
        data = collect_bundle_results(bundle=bundle, expected_sha256=digest, policy_commit=args.commit,
                                      allowed_files=allowed, image=args.image,
                                      bridge=Path(__file__).with_name('qualification_bridge.py'),
                                      run_id=args.run_id, run_attempt=args.run_attempt)
        fd = os.open(args.result, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    else:
        if args.image:
            raise ValueError('validation does not accept an image')
        fd = os.open(args.result, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_RESULTS_BYTES:
                raise ValueError('invalid qualification result file')
            data = source.read(MAX_RESULTS_BYTES + 1)
        validate_results(data, run_id=args.run_id, run_attempt=args.run_attempt, candidate_sha256=digest)


if __name__ == '__main__':
    main()
