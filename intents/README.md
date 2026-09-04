# Legacy release intents

The SSH-signed intent format is retained as historical compatibility material.
It is not a runtime authorization path: the active release authority is the
machine-only attestation emitted by the private `Arconath/.github` control
plane. New releases must not rely on a human signer or detached signature.

Do not add new intents here unless a migration or forensic record explicitly
requires one. The default ignore rule remains in place to prevent accidental
release input from entering this public repository.
