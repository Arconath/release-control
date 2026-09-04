# Trust model and failure behavior

## Trusted inputs

- The machine-only policy and evidence contracts at the exact public
  `Arconath/release-control` commit/tree.
- The protected private `Arconath/.github` workflow at `refs/heads/main`, with
  an exact run ID and private ephemeral runner attestation.
- GitHub's OIDC identity for that exact private workflow run.
- The configured private Distribution endpoint and its TLS trust chain.
- Machine signatures over every evidence file, verified against the pinned
  machine-signers file.
- The append-only replay ledger and exact Git checkout identities used by the
  admission command.

Runtime release authorization is permanently machine-only. Human release
signers, environment reviewers, and manual override are all forbidden. The
repository's pull-request/CI, signed-commit, linear-history, and administrator
rules remain source governance; they are not a release-time gate.

Product source and every artifact it creates remain untrusted data. Product
source runs only in `build-test`, which has no source-reader secret, registry
secret, OIDC token, package permission, or deployment credential.

## Credential compartments

| Boundary | Credential | Authority |
|---|---|---|
| public release-control | none | read-only policy/evidence surface; legacy workflow excluded from private runner |
| private `.github` control plane | short-lived source/registry credentials | one exact release workflow run |
| product validation | none | untrusted artifact transport only |
| publication | protected registry robot + GitHub OIDC | one policy-bound registry repository and signatures |
| promotion | GitHub contents write + GitHub OIDC | evidence publication only |
| admission | machine-signers file + replay ledger | one exact attestation, once |

The private runner group must exclude the public `release-control` repository;
the checked-in public workflow is therefore non-runnable on the private fleet
and remains legacy compatibility material, not a release executor.
The control plane may parse pinned public policy data, but it must not execute
public release-control or fork source there. Publication never retains source
credentials in promotion, and promotion cannot deploy.

## Fail-closed cases

The release stops before publication when the machine attestation is absent,
non-canonical, expired, replayed, manually overridden, or mismatched with the
policy; any evidence file is missing, hash-mismatched, unsigned, or bound to a
different artifact; the release-control/source/control-plane checkout commit
or tree differs; the registry lookup returns a different digest; any required
CI context is missing, incomplete, skipped, neutral, or unsuccessful; the
runner is not private/ephemeral; routes are outside the canonical allowlist;
canary health/observability or policy thresholds fail; rollback is not
automatic and tested; backup/domain guard statements fail; or the OCI archive
changes in transit.

Validation, publication, and promotion each re-read the remote protected
`main` SHA. A rerun of an old workflow or a release whose control policy was
superseded is revoked before the next privileged boundary.

If an exact immutable tag exists because a prior run published but failed
before signing, the workflow resumes only when its registry digest is identical
to the transported OCI manifest. A different digest is rejected. Consumers
must require valid Cosign signature and attestation, so an unsigned interrupted
candidate is never admissible. The machine attestation nonce is single-use and
expires quickly. Admission atomically appends the nonce and sequence to the
replay ledger under an exclusive lock; a second admission or a promotion inside
the cooldown window is rejected. No manual override can revive it.

## Promotion and rollback

Promotion emits a digest-only manifest. Rollback is generated in the same run
and identifies both the digest being replaced and the previously verified
digest to restore. Canary gates, abort thresholds, and automatic GitOps revert
are mandatory. Neither document changes platform desired state. GitOps must
verify the machine attestation, Sigstore bundles, private workflow identity,
source/tree identity, artifact digest, production-domain guard, external-backup
guard, and rollback digest before opening a deployment PR.

GHCR mirroring, if later enabled, copies from the signed canonical Distribution
digest and proves digest equality. A mirror tag or digest is never accepted as
the canonical promotion identity.
