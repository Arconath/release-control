# Bootstrap the release-intent signing key

The public repository starts with an intentionally empty
`policies/release-signers` file. This is a fail-closed state: validation may run,
but no release intent can verify until the one approved `hermawan22` public key
is installed through a reviewed pull request.

## Generate or select the key offline

Use a dedicated Ed25519 key on the operator workstation or an
hardware-backed/OpenSSH-compatible keystore. Do not generate it on a runner,
in a repository checkout, or in a workflow. Keep the private key outside this
repository with mode `0600` (or inside the keystore), and record its fingerprint
in the operator's offline key inventory.

```sh
umask 077
install -d -m 0700 /secure/arconath/release-signing
ssh-keygen -t ed25519 -f /secure/arconath/release-signing/hermawan22-release \
  -C hermawan22@arconath-release-intent
ssh-keygen -lf /secure/arconath/release-signing/hermawan22-release.pub \
  -E sha256
```

If an existing hardware-backed key is used, export only its public key and
verify the fingerprint out of band. Never export or paste the private key.

## Install the public key by review

Create the one allowed-signers line from the verified public key. The identity
must be exactly `hermawan22`; do not add aliases, a second key, a wildcard, or a
team identity. Preserve the comment only as operator metadata.

```sh
public_key_line="$(cat /secure/arconath/release-signing/hermawan22-release.pub)"
printf '%s\n' "hermawan22 namespaces=\"arconath-release-intent\" ${public_key_line}" \
  > policies/release-signers
chmod 0644 policies/release-signers
python3 scripts/release_control.py validate-signers \
  --allowed-signers policies/release-signers
```

Open a pull request containing only the reviewed public policy line and its
fingerprint in the operator's change record. The private key, passphrase,
agent socket, and key comments containing sensitive information must not enter
the diff, workflow environment, or Actions artifacts. The single operator
performs the documented manual review and merges the protected PR; GitHub Free
does not provide a second-reviewer gate.

## Sign and verify an intent

After the public key change is on protected `main`, sign canonical intent bytes
offline and verify them before submitting a release-control PR:

```sh
ssh-keygen -Y sign -f /secure/arconath/release-signing/hermawan22-release \
  -n arconath-release-intent intents/2026-08-31-example.json
python3 scripts/release_control.py validate-intent \
  --intent intents/2026-08-31-example.json \
  --signature intents/2026-08-31-example.json.sig \
  --allowed-signers policies/release-signers \
  --policy-dir policies/products
```

Rotate by adding the replacement key in a reviewed PR, verifying it, then
removing the old key in a second reviewed change. The verifier must observe
exactly one active `hermawan22` key at every protected revision; there is no
overlap window in the single-key bootstrap policy.
