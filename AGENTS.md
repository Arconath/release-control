# Release Control Working Agreement

This repository is the trusted release authority for Arconath product artifacts.
Treat every product checkout, release intent, archive, OCI layout, and uploaded
artifact as untrusted until its identity and digest have been verified.

## Boundaries

- Product repositories own business code and read-only validation workflows.
- This repository owns source attestation, isolated candidate builds, artifact
  publication, signing, release evidence, and promotion/rollback manifests.
- Platform GitOps remains the only deployment owner. This repository may emit a
  promotion proposal, but it must not mutate a cluster or production manifest.
- Never add a GitHub-hosted runner fallback, Docker socket, long-lived registry
  credential, plaintext secret, or workflow that executes public-fork code.

## Change rules

- All actions must be pinned to an immutable commit.
- All jobs use the `arconath-jit` runner group and canonical rootless labels.
- Keep source-fetch, build-test, publish-sign, and promotion credentials in
  separate jobs. Publish jobs must never execute product source.
- Public Actions artifacts must never contain private product source or a
  plaintext OCI candidate. Cross-job source/candidate transports use the
  reviewed age handoff envelope, exact run/source binding, and a bounded
  decrypt step with its dedicated protected environment identity.
- Release contracts are strict and fail on unknown fields, mutable references,
  expired intents, mismatched tree or artifact digests, and missing rollback.
- Run `./scripts/verify.sh` and review the workflow permission map before push.
