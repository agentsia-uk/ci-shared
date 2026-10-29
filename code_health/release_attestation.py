"""Verify an immutable policy asset and its pinned qualification workflow."""
import json
import re
import subprocess

REPOSITORY = 'agentsia-uk/ci-shared'
REPOSITORY_ID = '1259100960'
SIGNER = REPOSITORY + '/.github/workflows/code-health-release.yml'
SHA = re.compile(r'[0-9a-f]{40}\Z')


def verify_release(asset, *, policy_commit, signer_commit):
    if not SHA.fullmatch(policy_commit) or not SHA.fullmatch(signer_commit):
        raise ValueError('policy and signer commits must be full SHAs')
    tag = 'code-health-' + policy_commit

    def gh(*args):
        result = subprocess.run(['gh', *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=True)
        if len(result.stdout) > 8 * 1024 * 1024:
            raise ValueError('verification response exceeds limit')
        return result.stdout

    release = json.loads(gh('api', f'repos/{REPOSITORY}/releases/tags/{tag}'))
    if release.get('immutable') is not True or release.get('draft') is not False or release.get('tag_name') != tag:
        raise ValueError('policy release is not an immutable published release')
    commit = json.loads(gh('api', f'repos/{REPOSITORY}/commits/{tag}'))
    if commit.get('sha') != policy_commit:
        raise ValueError('release tag does not identify the selected policy commit')
    gh('release', 'verify', tag, '-R', REPOSITORY)
    gh('release', 'verify-asset', tag, str(asset), '-R', REPOSITORY)
    verified = json.loads(gh('attestation', 'verify', str(asset), '--repo', REPOSITORY,
                             '--signer-workflow', SIGNER, '--signer-digest', signer_commit,
                             '--source-ref', 'refs/heads/main', '--source-digest', policy_commit,
                             '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com',
                             '--predicate-type', 'https://slsa.dev/provenance/v1', '--format', 'json'))
    if not isinstance(verified, list) or not verified:
        raise ValueError('no verified policy attestations')
    for item in verified:
        try:
            repo_id = item['verificationResult']['signature']['certificate']['sourceRepositoryIdentifier']
        except (KeyError, TypeError) as error:
            raise ValueError('verified certificate lacks repository identity') from error
        if repo_id != REPOSITORY_ID:
            raise ValueError('verified certificate has the wrong repository identity')
    return tag
