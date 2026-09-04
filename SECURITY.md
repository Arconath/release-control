# Security policy

Do not open a public issue for a suspected release-control vulnerability,
credential exposure, signature bypass, digest mismatch, or runner isolation
failure. Use GitHub private vulnerability reporting for this repository.

If release integrity may be affected, disable the `publication` and `promotion`
environments, revoke the source-reader GitHub App key, suspend the affected
canonical registry robot account, and preserve workflow logs and machine
attestations. Do not delete or overwrite a released digest. Recovery must
create a new machine attestation whose rollback manifest points at the last
verified production digest; human or manual override must not be used.
