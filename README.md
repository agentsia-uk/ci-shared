# agentsia-uk/ci-shared

Public, reusable CI workflows for the `agentsia-uk` organisation. This repo is the **single source of truth** for cross-repo CI quality-baseline workflows (designed in [`agentsia-uk/Modelsmith#3237`](https://github.com/agentsia-uk/Modelsmith/issues/3237), council run-id `cross-repo-cicd-3237`).

It is deliberately **public** so that public org repos (e.g. [`assay-harness`](https://github.com/agentsia-uk/assay-harness)) can consume these workflows — GitHub does not allow a public repo to call a reusable workflow hosted in a private repo, and `internal` visibility is not available on the Team plan. Keeping the shared workflows here (rather than in the private `.github` repo) means **no agent-instruction or operational content is ever exposed**: this repo holds workflows only.

## Workflows

### `shared-secrets-scan.yml` — gitleaks secrets scan

Arch-aware, version-pinned `gitleaks detect`. The single source of truth for the org secrets-scan gate; runs with `permissions: contents: read` only (no secrets, fork-PR safe).

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

## Rules

1. **SHA-pin every consumer** (council S2). Bumping a workflow is a deliberate re-pin in each consumer, never a silent mutable-ref drift.
2. **Single source of truth** (council U-series). Do not re-fork the gitleaks (or any shared) logic into a consumer repo. Need different behaviour? Add a typed `workflow_call` input here — no copy-paste variants.
3. **Version is contract-governed.** `shared-secrets-scan.yml`'s `gitleaks-version` default must equal `Modelsmith/config/cross-repo-release-contract.json :: qualityBaseline.secretsScan.version`. Modelsmith's `npm run cross-repo:contract` fails closed on drift.
4. **No secrets, no agent-instruction files in git.** This repo is public; it holds reusable workflows only. No `CLAUDE.md`/`AGENTS.md`/`.env`/credentials.

## Consumers

- `agentsia-uk/Modelsmith` (private)
- `agentsia-uk/agentsia-web` (private)
- `agentsia-uk/assay-harness` (public)

Licensed under Apache-2.0.
