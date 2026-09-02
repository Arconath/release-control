# Trust model and failure behavior

## Trusted inputs

- The workflow and product policy at the protected `release-control/main` SHA.
- A canonical release intent whose exact bytes verify against an allowlisted SSH
  public key and whose lifetime has not expired.
- GitHub's OIDC identity for this exact workflow on `refs/heads/main`.
- The configured private Distribution endpoint and its TLS trust chain.

Production activation requires two distinct named GitHub reviewers and two
distinct allowlisted intent-signing keys. The bootstrap repository currently
contains only `@hermawan22` and no real signer key; a second real operator and
second key must be added through reviewed changes. Every release-sensitive
CODEOWNERS path must list both direct named accounts; a second owner on an
unrelated path or a one-member team does not satisfy the gate. The two-approval
branch rule and three protected environments deliberately fail closed until
then. Every privileged job revalidates the exact protected control SHA before
crossing its credential boundary.

Product source and every artifact it creates remain untrusted data. Direct
product verification commands run only in `product-validate`; candidate build
runs in the subsequent `build-test` job. Those jobs require distinct JIT
one-job runners so an untrusted validation process cannot persist into the
builder. The source archive and OCI candidate cross
job boundaries only as age-encrypted ciphertext with a canonical envelope bound
to the intent, exact source identity, and GitHub run ID. A dedicated handoff
identity is injected for one bounded decrypt step and is unset before any
product verification or build command; it is not a source-reader, registry,
OIDC, package, or deployment credential.

The checked-in governance diagnostic is not a live GitHub check. With
`--allow-incomplete`, it reports observed signer/CODEOWNER counts, explicit
blocking reason codes, `checked_in_contract_ready`, and
`live_github_configuration: "unverified"`. The `merge-readiness` command adds
the closed-world schema, policy, action-pinning, permissions, and private-runner
gates, while keeping the live GitHub configuration as a separate external hold.
The trusted release workflow omits that flag and aborts before source access
when the two-person contract is incomplete. Actual branch protection,
environment reviewers, and organization settings must still be verified in
GitHub before production activation.

## Credential compartments

| Job | Credential | Authority |
|---|---|---|
| validate-intent | read-only job token | protected release-control source |
| source-fetch | short-lived GitHub App token + public age recipient | one approved source repository, contents read; encrypted transport only |
| product-validate | protected source-handoff age identity for one decrypt step | encrypted source transport and untrusted checks; no builder, source-reader, registry, OIDC, package, or deployment authority |
| build-test | protected source-handoff age identity for one decrypt step + rootless BuildKit | separately decrypted validated source and candidate build; no source-reader, registry, OIDC, package, or deployment authority |
| publish-sign | protected registry robot + candidate-handoff age identity + GitHub OIDC | one policy-bound registry repository and signatures; candidate decrypt only after identity revalidation |
| promote | read-only registry verifier + GitHub contents write + GitHub OIDC | release-control evidence release only |

The publication job never extracts or executes product source. It decrypts only
the OCI candidate after the signed identity boundary has been revalidated; the
candidate handoff identity is removed before registry login. The promotion job
has no source, handoff, or registry publication credential. It receives a
separate read-only registry verifier only to prove that a non-zero rollback
digest exists in the canonical repository and is signed by the exact trusted
release workflow; the verifier is removed when the job exits. It cannot deploy.

## Fail-closed cases

The release stops before publication when the governance contract is incomplete,
the intent is absent, non-canonical, expired, signed by an unknown key, or
mismatched with policy; the source commit or tree differs; a handoff recipient,
run ID, ciphertext hash, decrypted hash, or canonical filename differs; age is
unavailable; registry host or robot credentials are absent; tests, SBOM,
license evidence, provenance, vulnerability evidence, or attestation
verification fails; a non-zero rollback digest is absent, belongs to another
repository, is unsigned, or lacks exact-workflow provenance; or the OCI archive
changes in transit. A zero rollback digest is the explicit first-release
baseline and is not looked up. A missing handoff identity fails closed before
source or candidate use. The offline diagnostic never changes this gate.

Validation, publication, and promotion each re-read the remote protected
`main` SHA. A rerun of an old workflow or a release whose control policy was
superseded is revoked before the next privileged boundary.

If an exact immutable tag exists because a prior run published but failed
before signing, the workflow resumes only when its registry digest is identical
to the transported OCI manifest. A different digest is rejected. Consumers
must require valid Cosign signature and attestation, so an unsigned interrupted
candidate is never admissible.

## Promotion and rollback

Promotion emits a digest-only manifest, rollback, and proposal with the exact
protected `release_control_sha` that generated them and the complete evidence
map. Rollback identifies both the digest being replaced and the previously
verified digest to restore. The artifact-lock proposal is always
`proposal_only: true` and deployment-ineligible; neither it nor the other
documents changes platform desired state. Immediately before these manifests
are emitted, release-control cryptographically re-verifies the artifact bundle,
all five evidence-attestation bundles, and their exact local predicates. It
also verifies every non-zero rollback digest against the canonical registry,
Cosign signature, and two-pass provenance proof bound to the exact artifact,
source/tree, workflow identity, workflow SHA, and OIDC issuer. GitOps must still
verify all signed bundles, the release-control workflow identity and SHA,
source/tree identity, artifact digest, evidence-lock hashes, and rollback
digest before opening a deployment PR.

GitHub Actions artifacts contain only age ciphertext for private source and
OCI candidates; release, promotion, SBOM, license, provenance, and
vulnerability evidence is digest metadata and does not carry the source
archive. Artifact retention is intentionally short
for transport, and runner cleanup removes plaintext before the job exits.

GHCR mirroring, if later enabled, copies from the signed canonical Distribution
digest and proves digest equality. A mirror tag or digest is never accepted as
the canonical promotion identity.
