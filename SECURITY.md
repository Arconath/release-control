# Security policy

Do not open a public issue for a suspected release-control vulnerability,
credential exposure, signature bypass, digest mismatch, or runner isolation
failure. Use GitHub private vulnerability reporting for this repository.

If release integrity may be affected, disable the `publication` and `promotion`
environments, revoke the source-reader GitHub App key, suspend the affected
canonical registry robot account, and preserve workflow logs and signed evidence. Do not delete or
overwrite a released digest. Recovery must create a new signed intent whose
rollback manifest points at the last verified production digest.
