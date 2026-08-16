# agentsia-uk/ci-shared

Public, reusable CI workflows for the `agentsia-uk` organisation. This repo is the **single source of truth** for cross-repo CI quality-baseline workflows (designed in [`agentsia-uk/Modelsmith#3237`](https://github.com/agentsia-uk/Modelsmith/issues/3237), council run-id `cross-repo-cicd-3237`).

It is deliberately **public** so that public org repos (e.g. [`assay-harness`](https://github.com/agentsia-uk/assay-harness)) can consume these workflows — GitHub does not allow a public repo to call a reusable workflow hosted in a private repo, and `internal` visibility is not available on the Team plan. Keeping the shared workflows here (rather than in the private `.github` repo) means **no agent-instruction or operational content is ever exposed**: this repo holds workflows only.

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
and exactly one canonical strategy pillar (`pillar-1` through `pillar-8`). It
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

For the organisation-required workflow path, authors can make the strategy
choice before the PR opens by including two explicit body fields:

```markdown
Pillar: P4
Change type: enhancement
```

That workflow's `pull_request_target` job reads only GitHub's PR metadata, never checks out
contributor code, creates the fixed canonical labels when a new repository does
not have them yet, and applies the declared pair before the read-only validation
job runs. Existing labels and body declarations must agree; conflicts fail
closed.

## Rules

1. **SHA-pin every consumer** (council S2). Bumping a workflow is a deliberate re-pin in each consumer, never a silent mutable-ref drift.
2. **Single source of truth** (council U-series). Do not re-fork shared policy logic into a consumer repo. Need different behaviour? Add a typed `workflow_call` input here — no copy-paste variants.
3. **Version is contract-governed.** `shared-secrets-scan.yml`'s `gitleaks-version` default must equal `Modelsmith/config/cross-repo-release-contract.json :: qualityBaseline.secretsScan.version`. Modelsmith's `npm run cross-repo:contract` fails closed on drift.
4. **No secrets, no agent-instruction files in git.** This repo is public; it holds reusable workflows only. No `CLAUDE.md`/`AGENTS.md`/`.env`/credentials.

## Consumers

- `agentsia-uk/Modelsmith` (private)
- `agentsia-uk/agentsia-web` (private)
- `agentsia-uk/assay-harness` (public)
- every other current and future `agentsia-uk` repository through the organisation PR-label bootstrap/audit

Licensed under Apache-2.0.
