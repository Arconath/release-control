# Trust model and failure behavior

## Trusted inputs

- The workflow and product policy at the protected `release-control/main` SHA.
- A canonical release intent whose exact bytes verify against an allowlisted SSH
  public key and whose lifetime has not expired.
- GitHub's OIDC identity for this exact workflow on `refs/heads/main`.
- The configured private Distribution endpoint and its TLS trust chain.

Production activation requires two distinct named GitHub reviewers and two
distinct allowlisted intent-signing keys. The bootstrap repository contains
only `@hermawan22`; a second real operator must replace this documented gap.
The two-approval branch rule deliberately blocks policy changes until then.

Product source and every artifact it creates remain untrusted data. Product
source runs only in `build-test`, which has no source-reader secret, registry
secret, OIDC token, package permission, or deployment credential.

## Credential compartments

| Job | Credential | Authority |
|---|---|---|
| validate-intent | read-only job token | protected release-control source |
| source-fetch | short-lived GitHub App token | one approved source repository, contents read |
| build-test | none | artifact transport only |
| publish-sign | protected registry robot + GitHub OIDC | one policy-bound registry repository and signatures |
| promote | GitHub contents write + GitHub OIDC | release-control evidence release only |

The publication job never extracts or executes product source. The promotion
job has no source or registry credential and cannot deploy.

## Fail-closed cases

The release stops before publication when the intent is absent, non-canonical,
expired, signed by an unknown key, or mismatched with policy; the source commit
or tree differs; registry host or robot credentials are absent; tests or the
vulnerability gate fail; or the OCI archive changes in transit.

Validation, publication, and promotion each re-read the remote protected
`main` SHA. A rerun of an old workflow or a release whose control policy was
superseded is revoked before the next privileged boundary.

If an exact immutable tag exists because a prior run published but failed
before signing, the workflow resumes only when its registry digest is identical
to the transported OCI manifest. A different digest is rejected. Consumers
must require valid Cosign signature and attestation, so an unsigned interrupted
candidate is never admissible.

## Promotion and rollback

Promotion emits a digest-only manifest and the exact protected
`release_control_sha` that generated it. Rollback is generated in the same run
and identifies both the digest being replaced and the previously verified
digest to restore. Neither document changes platform desired state. GitOps must
verify the Sigstore bundle, release-control workflow identity and SHA,
source/tree identity, artifact digest, and rollback digest before opening a
deployment PR.

GHCR mirroring, if later enabled, copies from the signed canonical Distribution
digest and proves digest equality. A mirror tag or digest is never accepted as
the canonical promotion identity.
