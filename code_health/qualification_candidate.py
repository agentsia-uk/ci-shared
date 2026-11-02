"""Prepare isolated candidate bytes from an independently checked release bundle.

The caller must establish the bundle digest and allowlist independently. This
module does not prove CI provenance or issue a qualification receipt.
"""
from contextlib import contextmanager
import hashlib
from pathlib import Path
import tempfile

from .release_bundle import read_bundle


@contextmanager
def candidate_snapshot(bundle: bytes, *, expected_sha256: str, policy_commit: str, allowed_files: set[str]):
    if not isinstance(bundle, bytes) or hashlib.sha256(bundle).hexdigest() != expected_sha256:
        raise ValueError('candidate bundle digest mismatch')
    _, files, _ = read_bundle(bundle, policy_commit=policy_commit, allowed_files=allowed_files)
    if any(len(Path(name).parts) != 2 or Path(name).parts[0] != 'code_health' for name in files):
        raise ValueError('candidate file is outside the supported runtime layout')
    with tempfile.TemporaryDirectory(prefix='code-health-candidate-') as temporary:
        root = Path(temporary) / 'candidate'
        root.mkdir(mode=0o755)
        root.chmod(0o755)
        for name, data in files.items():
            target = root / name
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            target.parent.chmod(0o755)
            with target.open('xb') as output:
                output.write(data)
            target.chmod(0o644)
        yield root
