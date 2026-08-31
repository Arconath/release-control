# Trust model and failure behavior

## Trusted inputs

- The workflow and product policy at the protected `release-control/main` SHA.
- A canonical release intent whose exact bytes verify against an allowlisted SSH
  public key and whose lifetime has not expired.
- GitHub's OIDC identity for this exact workflow on `refs/heads/main`.
- The configured private Distribution endpoint and its TLS trust chain.

Production activation uses one named operator, `@hermawan22`, and one
allowlisted intent-signing key. This is an explicit bootstrap policy, not a
claim of two-person separation. GitHub Free requires the pull request and
strict status/signed-commit controls but does not enforce a reviewer count;
manual review must be recorded before the operator merges and signs an intent.
The repository is intentionally keyless until the offline procedure in
`docs/operator-key-bootstrap.md` installs the real public key. An SSH-agent
identity on a workstation is not a substitute for that reviewed policy line,
and no private key is ever stored in this repository or on a runner.
Every privileged job revalidates the exact protected control SHA before
crossing its credential boundary.

Product source and every artifact it creates remain untrusted data. Product
source runs only in `build-test`. The source archive and OCI candidate cross
job boundaries only as age-encrypted ciphertext with a canonical envelope bound
to the intent, exact source identity, and GitHub run ID. A dedicated handoff
identity is injected for one bounded decrypt step and is unset before any
product verification or build command; it is not a source-reader, registry,
OIDC, package, or deployment credential.

## Credential compartments

| Job | Credential | Authority |
|---|---|---|
| validate-intent | read-only job token | protected release-control source |
| source-fetch | short-lived GitHub App token + public age recipient | one approved source repository, contents read; encrypted transport only |
| build-test | protected source-handoff age identity for one decrypt step | encrypted source transport; no source-reader, registry, OIDC, package, or deployment authority |
| publish-sign | protected registry robot + candidate-handoff age identity + GitHub OIDC | one policy-bound registry repository and signatures; candidate decrypt only after identity revalidation |
| promote | GitHub contents write + GitHub OIDC | release-control evidence release only |

The publication job never extracts or executes product source. It decrypts only
the OCI candidate after the signed identity boundary has been revalidated; the
candidate handoff identity is removed before registry login. The promotion job
has no source, handoff, or registry credential and cannot deploy.

## Fail-closed cases

The release stops before publication when the intent is absent, non-canonical,
expired, signed by an unknown key, or mismatched with policy; the source commit
or tree differs; a handoff recipient, run ID, ciphertext hash, decrypted hash,
or canonical filename differs; age is unavailable; registry host or robot
credentials are absent; tests, SPDX license evidence, SLSA provenance, or the
vulnerability gate fail; or the OCI archive changes in transit. A missing
handoff identity fails closed before source or candidate use.

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

GitHub Actions artifacts contain only age ciphertext for private source and
OCI candidates; release, promotion, and SBOM evidence is digest metadata and
does not carry the source archive. Artifact retention is intentionally short
for transport, and runner cleanup removes plaintext before the job exits.

GHCR mirroring, if later enabled, copies from the signed canonical Distribution
digest and proves digest equality. A mirror tag or digest is never accepted as
the canonical promotion identity.
