"""Freeze an asset, verify its origin, then validate its exact runtime bytes."""
import hashlib
import tempfile
from pathlib import Path

from .release_attestation import verify_release
from .release_bundle import MAX_BUNDLE_BYTES, read_bundle


def load_verified_release(asset, *, policy_commit, signer_commit, allowed_files):
    with open(asset, 'rb') as source:
        data = source.read(MAX_BUNDLE_BYTES + 1)
    if len(data) > MAX_BUNDLE_BYTES:
        raise ValueError('policy bundle exceeds the size limit')
    bundle_sha = hashlib.sha256(data).hexdigest()
    with tempfile.TemporaryDirectory(prefix='code-health-release-') as temporary:
        frozen = Path(temporary) / 'policy-bundle.tar'
        frozen.write_bytes(data)
        tag = verify_release(frozen, policy_commit=policy_commit, signer_commit=signer_commit)
        if hashlib.sha256(frozen.read_bytes()).hexdigest() != bundle_sha:
            raise ValueError('policy bundle changed during verification')
        manifest, files, manifest_sha = read_bundle(data, policy_commit=policy_commit, allowed_files=allowed_files)
        if hashlib.sha256(frozen.read_bytes()).hexdigest() != bundle_sha:
            raise ValueError('policy bundle changed during validation')
    return files, {'repository': 'agentsia-uk/ci-shared', 'tag': tag, 'policyCommitSha': policy_commit,
                   'bundleSha256': bundle_sha, 'releaseManifestSha256': manifest_sha,
                   'qualificationWorkflowSha': signer_commit, 'requirementsLockSha256': manifest['requirementsLockSha256']}
