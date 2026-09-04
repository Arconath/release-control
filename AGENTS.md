# Release Control Working Agreement

This public repository is the pinned release contract and evidence surface for
Arconath product artifacts. The protected private `Arconath/.github` control
plane is the only release executor. Treat every product checkout, release
intent, archive, OCI layout, and uploaded artifact as untrusted until its
identity and digest have been verified.

## Boundaries

- Product repositories own business code and read-only validation workflows.
- The private `Arconath/.github` control plane owns source attestation, isolated
  candidate builds, artifact publication, signing, release evidence, and
  promotion/rollback manifests, using this repository only as pinned policy
  data and a read-only evidence surface.
- Platform GitOps remains the only deployment owner. This repository may emit a
  promotion proposal, but it must not mutate a cluster or production manifest.
- Public `release-control` and fork code must never execute on the private
  runner fleet. Never add a GitHub-hosted runner fallback, Docker socket,
  long-lived registry credential, plaintext secret, or public-repository path
  to release credentials.

## Change rules

- All actions must be pinned to an immutable commit.
- The private executor uses the `arconath-jit` runner group and canonical
  rootless labels. The public workflow surface is legacy and excluded from
  that runner group.
- Private source-fetch, build-test, publish-sign, and promotion credentials
  remain separate. Publish jobs must never execute product source.
- Machine release contracts are strict and fail on unknown fields, mutable
  references, expired/replayed attestations, mismatched source/tree/artifact
  digests, incomplete checks, and missing rollback.
- Run `./scripts/verify.sh` and review the workflow permission map before push.
