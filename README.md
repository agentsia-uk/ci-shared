# agentsia-uk/ci-shared

Public, reusable CI workflows for the `agentsia-uk` organisation. This repo is the **single source of truth** for cross-repo CI quality-baseline workflows (designed in [`agentsia-uk/Modelsmith#3237`](https://github.com/agentsia-uk/Modelsmith/issues/3237), council run-id `cross-repo-cicd-3237`).

It is deliberately **public** so that public org repos (e.g. [`assay-harness`](https://github.com/agentsia-uk/assay-harness)) can consume these workflows — GitHub does not allow a public repo to call a reusable workflow hosted in a private repo, and `internal` visibility is not available on the Team plan. Keeping the shared workflows here (rather than in the private `.github` repo) means **no agent-instruction or operational content is ever exposed**: this repo holds reusable workflows and their public policy contracts, verifiers and tests.

## Workflows

### `shared-secrets-scan.yml` — gitleaks secrets scan

Platform- and arch-aware, version-pinned `gitleaks detect` (Linux or macOS on arm64 or x64). The single source of truth for the org secrets-scan gate; runs with `permissions: contents: read` only (no secrets, fork-PR safe).

Consume it with a **40-char commit SHA pin** (never a branch or mutable tag):

```yaml
jobs:
  secrets-scan:
    uses: agentsia-uk/ci-shared/.github/workflows/shared-secrets-scan.yml@<40-char-sha>
    with:
      gitleaks-version: "8.21.2"      # MUST equal Modelsmith config/cross-repo-release-contract.json :: qualityBaseline.secretsScan.version
      runs-on: '["ubuntu-latest"]'    # JSON array; override for self-hosted/ARC pools
    permissions:
      contents: read
```

### `pr-label-policy.yml` — mutually exclusive strategy attribution

Reads the pull request's live labels and fails closed unless there is exactly
one change type (`bug`, `enhancement`, `documentation`, or `type:tech-debt`)
and exactly one canonical strategy pillar (`pillar-1` through `pillar-9`). It
also rejects retired, case-variant, or otherwise pillar-like labels so one PR
cannot be attributed to two pillars. The workflow checks out no contributor
code and needs only `contents: read` plus `pull-requests: read`.

The organisation ruleset should require the SHA-pinned
`org-required-pr-label-policy.yml` workflow on the
default branch of every repository. That makes the policy fail closed for
current and future repositories without copying a caller into each one.
Repository-local SHA-pinned callers and required-status rules remain the
compatible fallback where an organisation required-workflow rule is not
available.

Reusable callers may pass `runs-on` as a JSON array or runner-group object. It
defaults to `["ubuntu-latest"]`, preserving GitHub-hosted execution unless a
consumer explicitly supplies an attested self-hosted selector:

```yaml
jobs:
  pr-label-policy:
    uses: agentsia-uk/ci-shared/.github/workflows/pr-label-policy.yml@<40-char-sha>
    with:
      runs-on: '{"group":"modelsmith-pr-jit","labels":"modelsmith-pr-jit"}'
    permissions:
      contents: read
      pull-requests: read
```

For the organisation-required workflow path, authors can make the strategy
choice before the PR opens by including two explicit body fields:

```markdown
Pillar: P4
Change type: enhancement
```

That workflow's `pull_request_target` job reads only GitHub's PR metadata, never checks out
contributor code, provisions the complete 12-label canonical catalogue when a
new repository receives its first PR, and applies the declared pair before the
read-only validation job runs. The catalogue reconciliation is idempotent, so
deleted canonical labels are restored on later PR events. Existing labels and
body declarations must agree; conflicts fail closed.

## Rules

1. **SHA-pin every consumer** (council S2). Bumping a workflow is a deliberate re-pin in each consumer, never a silent mutable-ref drift.
2. **Single source of truth** (council U-series). Do not re-fork shared policy logic into a consumer repo. Need different behaviour? Add a typed `workflow_call` input here — no copy-paste variants.
3. **Version is contract-governed.** `shared-secrets-scan.yml`'s `gitleaks-version` default must equal `Modelsmith/config/cross-repo-release-contract.json :: qualityBaseline.secretsScan.version`. Modelsmith's `npm run cross-repo:contract` fails closed on drift.
4. **No secrets, no agent-instruction files in git.** This repo is public; it holds reusable workflows and their public policy contracts, verifiers and tests. No `CLAUDE.md`/`AGENTS.md`/`.env`/credentials.

## Consumers

- `agentsia-uk/Modelsmith` (private)
- `agentsia-uk/agentsia-web` (private)
- `agentsia-uk/assay-harness` (public)
- every other current and future `agentsia-uk` repository through the organisation PR-label bootstrap/audit

Licensed under Apache-2.0.


### Shared code-health policy and mechanical ratchet

`code_health/policy.json` is the shared policy contract. The strict-score target
is at least 90 in each coherent project/language area. Subjective reviews use
`claude-opus-5-5` at high effort every 30 days, with a calibration break when
the reviewer changes. Subjective scores do not gate merges.

The reusable `shared-code-health.yml` workflow runs full base and candidate
scans with the same pinned scanner. It refuses an objective-score decrease,
new mechanical findings in touched files, and remaining T1/T2 findings in
those files. A cross-file finding counts when any related file is touched.
Git renames preserve the identity of inherited lower-priority findings.
Changed detector coverage fails closed. A genuinely new project/language area
records `objectiveBefore: null` and `baselineKind: new-area`; the candidate is
scanned and its new touched findings still fail, without inventing a previous
score. Existing reduced coverage is reported
explicitly and never described as a complete detector run.

A consumer commits `.github/code-health.json`:

```json
{
  "schemaVersion": 1,
  "policyRef": "<40-character shared action commit SHA>",
  "workflowRef": "<40-character shared workflow commit SHA>",
  "areas": [
    {"id": "app-typescript", "language": "typescript", "path": ".", "exclusions": []},
    {"id": "training-python", "language": "python", "path": "training", "exclusions": []}
  ],
  "unsupportedLanguages": []
}
```

Each path must be one coherent project. A nested project's path is excluded
from its parent's scan automatically. Every tracked file with a supported
language extension must belong to a matching language area. Unsupported
language gaps may be listed as `{"language": "...", "rationale": "..."}`.
Repositories containing only unsupported languages declare `areas: []` and
their known gaps; they receive no invented score or source-language area.
Each explicit exclusion requires `pattern`, `kind` and `rationale`; allowed
classes are generated, vendored, fixtures, snapshots and build output.
Arbitrary source exclusions are refused. Optional `strictTarget` and
`reviewMaxAgeDays` may only tighten the shared policy and the repository's
previous values. Existing area definitions and exclusions are immutable in
ordinary PRs so a scope change cannot quietly reset a comparison.

`policyRef` is checked against the action repository and SHA actually executing.
`workflowRef` is checked in the actual caller workflow at GitHub's bound
workflow commit, so a decoy candidate workflow cannot supply the pin. Results
record the executing action identity, the caller identity, the caller's
declared shared-workflow ref and hashes of the policy, verifier and repository
configuration. A caller declaration does not establish that branch protection
requires the gate; adoption must verify live required contexts and their
producer identities separately.

The corresponding caller is unconditional and has no path or branch filters:

```yaml
on: [pull_request, merge_group]
permissions:
  contents: read
  pull-requests: read
jobs:
  code-health:
    uses: agentsia-uk/ci-shared/.github/workflows/shared-code-health.yml@<workflowRef>
    with:
      runs-on: '<JSON selector for the repository-approved isolated CI pool>'
    permissions:
      contents: read
      pull-requests: read
```

The shared workflow requires the consumer's existing approved isolated Linux CI
pool, with no hosted fallback. It does not install application dependencies or
explicitly launch application entrypoints. Detector tools may invoke compilers
or load project tool configuration, so the caller's existing CI isolation is
still the execution boundary. Application secrets are never passed to scans. The verifier and policy come from the frozen
shared action rather than the candidate checkout. Snapshots materialise raw Git blobs directly, so export-ignore/export-subst
attributes cannot omit or rewrite source. Escaping symlinks are refused.
Scanner configuration is reconstructed with plugins and model runners disabled; checked-in local
Desloppify state is ignored. Only the sanitised `result.json` is uploaded.
Raw state and logs can contain source excerpts and must stay private.

This first release provides the contract and executable mechanical gate.
It does **not** activate an organisation ruleset, onboard other repositories,
schedule monthly reviews, create weekly upgrade PRs, publish points to the
Code Health dashboard, or import recorded finding dismissals. Those consumers
and automation must be delivered separately. Weekly tool upgrades, deliberate
scope migrations and their calibration records still need a dedicated
reviewed migration path. Scanner-policy pin changes already require a
same-repository PR authored by `github-actions[bot]`, with an
`automation/code-health-upgrade-` branch and `code-health-upgrade` label,
changing only the manifest/workflows. Queued upgrades are independently
matched to live PR metadata, exact ancestry and the pin carried by that PR.
This release does not create those upgrade PRs or alter live required checks.

Run the verifier's tests with the pinned scanner installed:

```sh
python -m pip install 'desloppify[full]==1.0'
python -m unittest discover -s tests -v
```

#### Versioned CI producer evidence

The stable trusted launcher may generate `producer.json` after it has verified
the immutable policy bundle and completed the scan:

```sh
python -m code_health.artifacts \
  --repo /caller/checkout --base "$BASE_SHA" --head "$HEAD_SHA" \
  --result /private/output/result.json \
  --execution-evidence /private/verified-execution.json \
  --output /private/output/producer.json
```

The execution-evidence file must live outside the caller checkout and contain
the launcher's private, already verified `launcher` and `release` objects. The
launcher object identifies the actual stable workflow and action. The release
object separately identifies the selected immutable policy commit, bundle,
release manifest, qualification workflow and fully hashed dependency lock.
Those hashes must come from the trusted launcher's actual verification of the
downloaded bytes; merely passing this module's shape checks does not authenticate
an untrusted JSON file. The lock's bundle path is `code_health/requirements.lock`.

Schema version 1, kind `agentsia.code-health.ci-producer`, binds the exact source
commits/tree, regular Git manifest blob, raw manifest bytes, result bytes and
GitHub run identity. Its registry is generated from every declared manifest area
and unsupported-language gap, namespaced by repository ID/name. There is no fixed
repository list or area enum. Source/result/config mismatches, unknown envelope
fields, duplicate JSON keys, oversized inputs and candidate-checkout execution
evidence are refused. Existing output files cannot be overwritten.

The actual runtime is recorded as `runtime` with `pythonVersion`, `sysPlatform`,
`machine` and `glibcVersion`. Generation requires Python 3.13 on Linux x86_64 or
aarch64 with glibc >= 2.34, matching the dependency lock's supported platform
resolution. Resolution and shape tests do not establish successful installation
or end-to-end operation on a real Linux runner; that qualification remains
required before activation.

The trusted workflow attests the exact `producer.json` bytes, then uploads it
with the exact `result.json` it references. Artifact ID and archive digest are
obtained after upload, so they are not embedded in their own content. Every
envelope has `collectorValidationRequired: true`: m3-max independently verifies
the live run/attempt, artifact bytes/digests, certificate repository IDs, trusted
signer workflow and immutable policy release before signing or publishing a
point. A matching check display name, caller assertion or envelope alone never
establishes that authority. The publishing signing key stays off CI.

This producer slice binds the mechanical ratchet report and manifest projection.
It does not invent the additional native scores/dimensions/findings needed for
the richer dashboard, upload raw scanner state or activate a workflow. A later
sanitised native projection and the versioned feed consumer must preserve the
existing history while admitting new repository/area series.
