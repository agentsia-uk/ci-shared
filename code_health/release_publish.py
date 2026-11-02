"""Resume only an exact bot-owned draft before publishing an immutable release."""
import argparse
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
import urllib.error
import urllib.request
import uuid

from .release_attestation import GH_EXECUTABLE, REPOSITORY, SHA, ensure_gh_version, read_command, verify_local_attestation
from .qualification_pipeline import candidate_bundle
from .qualification_results import MAX_RESULTS_BYTES, validate_results
from .release_bundle import MAX_BUNDLE_BYTES

BOT_ID = 41898282


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, 'release API redirect refused', headers, fp)


def open_api(request, *, timeout):
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect()).open(request, timeout=timeout)


def validate_tag_protection(ruleset: object, ruleset_id: str) -> None:
    if not isinstance(ruleset, dict):
        raise ValueError('tag protection ruleset is missing')
    conditions = ruleset.get('conditions')
    refs = conditions.get('ref_name') if isinstance(conditions, dict) else None
    rules = ruleset.get('rules')
    types = {rule.get('type') for rule in rules if isinstance(rule, dict)} if isinstance(rules, list) else set()
    if (ruleset.get('id') != int(ruleset_id) or ruleset.get('source_type') != 'Repository' or
            ruleset.get('source') != REPOSITORY or ruleset.get('target') != 'tag' or
            ruleset.get('enforcement') != 'active' or ruleset.get('bypass_actors') != [] or
            not isinstance(refs, dict) or refs.get('include') != ['refs/tags/code-health-*'] or
            refs.get('exclude') != [] or not {'update', 'deletion'}.issubset(types)):
        raise ValueError('tag protection ruleset is not the approved active no-bypass policy')


def find_release(api, tag: str):
    match = None
    for page in range(1, 101):
        releases = api(f'releases?per_page=100&page={page}')
        if not isinstance(releases, list) or len(releases) > 100:
            raise ValueError('invalid release listing')
        for item in releases:
            if isinstance(item, dict) and item.get('tag_name') == tag:
                if match is not None:
                    raise ValueError('multiple releases share the tag')
                match = item
        if len(releases) < 100:
            return match
    raise ValueError('release listing exceeds its page limit')


def _publish_verified(asset: Path, policy_commit: str) -> None:
    if not SHA.fullmatch(policy_commit) or asset.name != 'policy-bundle.tar':
        raise ValueError('invalid release commit or asset name')
    with asset.open('rb') as source:
        data = source.read(MAX_BUNDLE_BYTES + 1)
    if len(data) > MAX_BUNDLE_BYTES:
        raise ValueError('release asset exceeds its size limit')
    digest = 'sha256:' + hashlib.sha256(data).hexdigest()
    tag = 'code-health-' + policy_commit
    token = os.environ.get('GH_TOKEN')
    admin_read_token = os.environ.get('RELEASE_ADMIN_READ_TOKEN')
    if not token or not admin_read_token:
        raise ValueError('release and administration-read tokens are required')
    ruleset_id = os.environ.get('CODE_HEALTH_TAG_RULESET_ID', '')
    if not ruleset_id.isascii() or not ruleset_id.isdecimal() or int(ruleset_id) < 1:
        raise ValueError('valid tag protection ruleset ID is required')
    ensure_gh_version()

    def api(path: str, *, body=None, admin=False, method=None, upload=None):
        host = 'uploads.github.com' if upload is not None else 'api.github.com'
        request_method = method or ('POST' if body is not None or upload is not None else 'GET')
        headers = {'Authorization': 'Bearer ' + (admin_read_token if admin else token), 'Accept': 'application/vnd.github+json'}
        if request_method == 'GET':
            headers['Cache-Control'] = 'no-cache'
            path += ('&' if '?' in path else '?') + 'code_health_read=' + uuid.uuid4().hex
        if upload is not None:
            headers['Content-Type'] = 'application/octet-stream'
        elif body is not None:
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(f'https://{host}/repos/{REPOSITORY}/{path}', headers=headers,
            data=upload if upload is not None else json.dumps(body).encode() if body is not None else None,
            method=request_method)
        try:
            with open_api(request, timeout=30) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            if error.code == 404 and request_method == 'GET':
                return None
            raise
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError('release API response exceeds its size limit')
        return json.loads(raw)

    def gh(*args: str) -> None:
        read_command([GH_EXECUTABLE, *args])

    def tag_exists_and_matches() -> bool:
        ref = api('git/ref/tags/' + tag)
        if ref is None:
            return False
        if not isinstance(ref, dict) or ref.get('ref') != 'refs/tags/' + tag:
            raise ValueError('invalid release tag reference')
        obj = ref.get('object')
        for _ in range(6):
            if not isinstance(obj, dict) or not isinstance(obj.get('sha'), str) or not SHA.fullmatch(obj['sha']):
                raise ValueError('invalid release tag target')
            if obj.get('type') == 'commit':
                if obj['sha'] != policy_commit:
                    raise ValueError('existing release tag points to a different commit')
                return True
            if obj.get('type') != 'tag':
                break
            annotated = api('git/tags/' + obj['sha'])
            obj = annotated.get('object') if isinstance(annotated, dict) else None
        raise ValueError('release tag does not resolve to a commit')

    def inspect_release(value, *, allow_missing_asset: bool):
        if (not isinstance(value, dict) or value.get('tag_name') != tag or
                type(value.get('id')) is not int or value['id'] < 1 or
                not isinstance(value.get('author'), dict) or value['author'].get('id') != BOT_ID or
                type(value.get('draft')) is not bool):
            raise ValueError('release is not the expected bot-owned release')
        assets = api(f"releases/{value['id']}/assets?per_page=2&page=1")
        if not isinstance(assets, list):
            raise ValueError('invalid release asset listing')
        if len(assets) == 0 and allow_missing_asset:
            return False
        if len(assets) != 1 or not isinstance(assets[0], dict):
            raise ValueError('release contains unexpected assets')
        item = assets[0]
        if (item.get('name') != asset.name or item.get('state') != 'uploaded' or
                item.get('size') != len(data) or item.get('digest') != digest):
            raise ValueError('release asset does not match the qualified bundle')
        return True

    def require_immutable_setting() -> None:
        settings = api('immutable-releases', admin=True)
        if not isinstance(settings, dict) or settings.get('enabled') is not True:
            raise ValueError('immutable releases are not enabled')

    def require_current_main() -> None:
        branch = api('branches/main')
        commit = branch.get('commit') if isinstance(branch, dict) else None
        if not isinstance(commit, dict) or commit.get('sha') != policy_commit:
            raise ValueError('protected main moved before release publication')

    require_immutable_setting()
    validate_tag_protection(api('rulesets/' + ruleset_id, admin=True), ruleset_id)
    exists = tag_exists_and_matches()
    release = find_release(api, tag)
    if release is not None:
        inspect_release(release, allow_missing_asset=release.get('draft') is True)
        if not exists and release.get('draft') is not True:
            raise ValueError('published release exists without its tag')
    if release is None or release.get('draft') is True:
        require_current_main()
    if not exists:
        try:
            api('git/refs', body={'ref': 'refs/tags/' + tag, 'sha': policy_commit})
        except urllib.error.HTTPError as error:
            if error.code != 422 or not tag_exists_and_matches():
                raise
        if not tag_exists_and_matches():
            raise ValueError('new release tag is missing')
    if release is None:
        require_current_main()
        gh('release', 'create', tag, '-R', REPOSITORY, '--target', policy_commit,
           '--verify-tag', '--draft', '--title', tag, '--notes', 'Qualified code-health policy bundle.')
        release = find_release(api, tag)
        if not isinstance(release, dict):
            raise ValueError('new release could not be read')
        if not tag_exists_and_matches():
            raise ValueError('new release tag is missing')

    has_asset = inspect_release(release, allow_missing_asset=release.get('draft') is True)
    current_id = release['id']
    if release['draft']:
        if not has_asset:
            require_current_main()
            api(f"releases/{release['id']}/assets?name=policy-bundle.tar", upload=data)
        current = find_release(api, tag)
        if (not isinstance(current, dict) or not tag_exists_and_matches() or
                current.get('id') != release.get('id') or current.get('draft') is not True):
            raise ValueError('release changed before publication')
        inspect_release(current, allow_missing_asset=False)
        require_immutable_setting()
        validate_tag_protection(api('rulesets/' + ruleset_id, admin=True), ruleset_id)
        require_current_main()
        api(f"releases/{release['id']}", method='PATCH', body={'draft': False})
        release = find_release(api, tag)
    if (not isinstance(release, dict) or not tag_exists_and_matches() or
            release.get('id') != current_id or release.get('draft') is not False or release.get('immutable') is not True):
        raise ValueError('published release is not immutable or points to the wrong commit')
    inspect_release(release, allow_missing_asset=False)
    gh('release', 'verify', tag, '-R', REPOSITORY)
    gh('release', 'verify-asset', tag, str(asset), '-R', REPOSITORY)



def _read_regular(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ValueError('invalid or oversized input file')
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError('input file exceeds its size limit')
    return data


def publish(asset: Path, policy_commit: str, *, repo: Path, qualification: Path,
            run_id: int, run_attempt: int, signer_commit: str) -> None:
    if not SHA.fullmatch(policy_commit) or not SHA.fullmatch(signer_commit) or asset.name != 'policy-bundle.tar':
        raise ValueError('invalid release identity or asset name')
    bundle, _, digest = candidate_bundle(repo, policy_commit)
    if _read_regular(asset, MAX_BUNDLE_BYTES) != bundle:
        raise ValueError('release asset differs from the rebuilt candidate')
    observations = _read_regular(qualification, MAX_RESULTS_BYTES)
    validate_results(observations, run_id=run_id, run_attempt=run_attempt, candidate_sha256=digest)
    with tempfile.TemporaryDirectory(prefix='code-health-publish-') as directory:
        frozen = Path(directory) / 'policy-bundle.tar'
        frozen.write_bytes(bundle)
        verify_local_attestation(frozen, policy_commit=policy_commit, signer_commit=signer_commit,
                                 run_id=run_id, run_attempt=run_attempt)
        _publish_verified(frozen, policy_commit)

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--asset', required=True, type=Path)
    parser.add_argument('--policy-commit', required=True)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--qualification', required=True, type=Path)
    parser.add_argument('--run-id', required=True, type=int)
    parser.add_argument('--run-attempt', required=True, type=int)
    parser.add_argument('--signer-commit', required=True)
    args = parser.parse_args()
    publish(args.asset, args.policy_commit, repo=args.repo, qualification=args.qualification,
            run_id=args.run_id, run_attempt=args.run_attempt, signer_commit=args.signer_commit)


if __name__ == '__main__':
    main()
