# Bootstrap the release-intent signing keys

The public repository starts with an intentionally empty
`policies/release-signers` file. This is a fail-closed state: validation may run,
but no release intent can verify until two independent named operator public
keys are installed through reviewed pull requests. Two names on one key do not
count as two operators.

## Generate or select the key offline

Each operator uses a dedicated Ed25519 key on the operator workstation or an
hardware-backed/OpenSSH-compatible keystore. Do not generate keys on a runner,
in a repository checkout, or in a workflow. Keep private keys outside this
repository with mode `0600` (or inside the keystore), and record each
fingerprint in the offline key inventory. The two private keys must be
independent; never copy one private key or alias it under two identities.

```sh
umask 077
install -d -m 0700 /secure/arconath/release-signing
ssh-keygen -t ed25519 -f /secure/arconath/release-signing/hermawan22-release \
  -C hermawan22@arconath-release-intent
ssh-keygen -t ed25519 -f /secure/arconath/release-signing/second-operator-release \
  -C second-operator@arconath-release-intent
ssh-keygen -lf /secure/arconath/release-signing/hermawan22-release.pub -E sha256
ssh-keygen -lf /secure/arconath/release-signing/second-operator-release.pub -E sha256
```

If an existing hardware-backed key is used, export only its public key and
verify the fingerprint out of band. Never export or paste the private key.

## Install the public key by review

Create one allowed-signers line per verified public key. The principals must be
the exact two named GitHub accounts; do not add aliases, wildcard principals,
or a team identity. Replace `second-operator` below with the actual second
GitHub handle; it is only a placeholder and must not be committed as-is.
Preserve comments only as operator metadata.

```sh
first_public_key="$(cat /secure/arconath/release-signing/hermawan22-release.pub)"
second_public_key="$(cat /secure/arconath/release-signing/second-operator-release.pub)"
printf '%s\n' \
  "hermawan22 namespaces=\"arconath-release-intent\" ${first_public_key}" \
  "second-operator namespaces=\"arconath-release-intent\" ${second_public_key}" \
  > policies/release-signers
chmod 0644 policies/release-signers
python3 scripts/release_control.py validate-governance \
  --codeowners .github/CODEOWNERS \
  --allowed-signers policies/release-signers \
  --settings bootstrap/repository-settings.json
```

Open a pull request containing only the reviewed public policy lines and their
fingerprints in the operators' change record. The private keys, passphrases,
agent sockets, and key comments containing sensitive information must not enter
the diff, workflow environment, or Actions artifacts. The protected branch and
all release environments must have two distinct named reviewers with
self-review disabled before an intent can be released.

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

Rotate by adding a replacement key in a reviewed PR, verifying it, then
removing the old key in a second reviewed change. The verifier must observe at
least two distinct named keys at every protected revision; never create a
one-key overlap window during rotation.
