# Arconath Release Control

`release-control` is a public, protected, centralized release contract and
evidence surface for Arconath products whose source repositories cannot yet
enforce private branch or environment protection. The private
`Arconath/.github` control plane is the only release executor. It may consume
this repository as inert, pinned policy data, but it must never execute public
release-control or fork code on the private runner fleet.

The release authority is permanently machine-only: no human release signer,
environment reviewer, or manual override is accepted. Machine authority is
valid only when the exact control-plane workflow, source commit/tree, immutable
artifact digest, completed successful checks, evidence, canary, rollback, and
replay/expiry guards all pass. GHCR is an optional mirror, never the canonical
deployment source.

This repository does **not** deploy workloads. `Arconath/platform-apps` remains
the owner of environment state and must consume the signed promotion manifest
through its machine/CI admission process. Any human review applies only to
source-governance changes, never to runtime publication or promotion.

## Trust flow

```text
protected private Arconath/.github workflow
            |
            v
exact source/tree verification (source GitHub App, contents:read only)
            |
            v
rootless build/test (no release credential or deployment authority)
            |
            v
publish/sign (canonical Distribution robot + OIDC)
            |
            v
machine attestation + canary/observability/rollback gates
            |
            v
platform-apps digest admission
```

The public `release-control` repository contributes only pinned policy,
validator contracts, and read-only evidence. Its old workflow is retained only
as a legacy compatibility surface; runner-group policy excludes public
repositories from `arconath-jit`, so it is not an executor. Every
private-executor transfer is bound to the source repository, full commit SHA,
Git tree SHA, OCI manifest digest, and SHA-256 of the transported OCI archive.
Mutable tags are never accepted as source or deployment identity.

## Machine-only release authority

The canonical policy is
[`policies/automated-release-policy.json`](policies/automated-release-policy.json).
The private control plane must emit a canonical machine attestation and validate
it with the same strict contract before publication or promotion. The
attestation binds:

- `Arconath/.github` at the protected `main` ref and the exact workflow run;
- `Arconath/release-control` commit/tree, product source commit/tree, and the
  immutable registry digest;
- every required CI context as `completed`/`success` on the exact control SHA;
- private ephemeral runner identity, verified provenance/SBOM/signatures,
  canary health and metrics/logs/traces, and explicit abort thresholds;
- automatic GitOps rollback to a different verified digest, append-only audit,
  single-use nonce, cooldown, and short expiry.

Missing, skipped, neutral, forged, replayed, expired, or manually overridden
attestations are rejected. Source changes remain pull-request/CI, signed-commit,
linear-history, and administrator-enforcement governed; that source policy is
distinct from runtime release authorization and has no release-time approval
gate.

Use `admit-machine-release` from the private control plane. Admission hashes
the evidence bytes, verifies machine signatures, rechecks all three exact Git
trees and the published registry digest, then atomically consumes a single-use
replay-ledger entry. The command does not deploy workloads or mutate GitOps;
`Arconath/platform-apps` remains the owner of environment state. The lighter
`validate-machine-attestation` command is for structural contract checks only.

## Legacy signed intent

The SSH-signed intent flow under `intents/` is retained as historical evidence
and compatibility material only. It is not a runtime authorization path under
the permanent machine-only policy, and no new release may rely on it.

```sh
python3 scripts/release_control.py canonicalize \
  --input intent.draft.json --output intents/2026-08-31-example.json
ssh-keygen -Y sign -f /secure/path/release-key \
  -n arconath-release-intent intents/2026-08-31-example.json
python3 scripts/release_control.py validate-intent \
  --intent intents/2026-08-31-example.json \
  --signature intents/2026-08-31-example.json.sig \
  --allowed-signers policies/release-signers \
  --policy-dir policies/products
```

The legacy schemas remain documented in
[`contracts/release-intent.schema.json`](contracts/release-intent.schema.json)
and [`contracts/product-policy.schema.json`](contracts/product-policy.schema.json).
The active machine contracts are
[`contracts/automated-release-policy.schema.json`](contracts/automated-release-policy.schema.json)
and [`contracts/machine-release-attestation.schema.json`](contracts/machine-release-attestation.schema.json).

## Repository configuration

The public repository is fail-closed and non-authoritative by design. Its
workflow is not permitted to use the private runner group. The protected
private `Arconath/.github` control plane must be configured with:

- A protected `main` for the private workflow: pull request required, no
  human approval/code-owner/last-push gate, required
  `contracts and workflow policy`, linear history, force-push and
  deletion disabled, administrators enforced.
- Protected `publication` and `promotion` environments restricted to `main`,
  with an empty reviewer set (`required_reviewers: 0`) and administrator
  bypass disabled.
- `SOURCE_READER_APP_ID` repository variable.
- `SOURCE_READER_PRIVATE_KEY` repository secret for a GitHub App installed only
  on approved source repositories with `contents:read` and `metadata:read`.
- `ARCONATH_REGISTRY_HOST` private-control-plane repository variable matching the reviewed policy,
  normally `ghcr.io` on the private service network.
- `ARCONATH_REGISTRY_USERNAME` and `ARCONATH_REGISTRY_PASSWORD` secrets on the
  protected `publication` environment for a robot account restricted to
  allowlisted repositories. The job fails before login if any value is absent.
- Source-governance changes remain subject to pull-request/CI checks, signed
  commits, linear history, and enforced administrator protection. Release-time
  SSH keys and human environment reviewers are not used by the active
  machine-only path.

Do not add a personal access token. The source GitHub App token is short-lived
and repository scoped. Registry robot credentials stay only in the publication
environment and are never exposed to source-fetch, build-test, or promotion.

## Adding a product artifact

Copy `policies/products/example.json.disabled`, assign one OCI image per policy,
use argv arrays for deterministic verification commands, then enable it through
the protected source-governance pull-request/CI process. The central policy—not product-controlled input—owns
the repository, canonical registry host, build context, Dockerfile, platform,
and package destination. An optional mirror must copy from the already signed
canonical digest, verify digest equality, and must never become a GitOps input.

## Verification

```sh
./scripts/verify.sh
```

The suite covers canonical source identity, signed and expiring intents, strict
policy matching, source archive integrity, job credential separation, exact OCI
digest propagation, promotion identity, and rollback manifests.

The current rollout authority admits production only. A canary is a bounded
rollout inside production, with the existing health thresholds, cooldown,
backup/domain guards and tested rollback evidence. No staging deployment or
staging prerequisite is authorized by the current candidate policy. The first
BoringKit artifact may be published without a prior digest only in explicit
publication-only mode; that evidence cannot authorize a deployment or pretend
a rollback baseline exists. BoringKit production targets namespace
`boringkit-production` and retains all six workload bindings.
