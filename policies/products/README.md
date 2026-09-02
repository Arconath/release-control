# Canonical product image policies

This directory contains a closed-world inventory of 27 OCI image policies for
the eleven canonical Arconath products. Every product policy is intentionally
named `*.json.disabled` and has `enabled: false`; renaming/enabling one requires
a protected review and real release prerequisites.

Each policy binds exactly one registry repository to:

- one canonical `product_id` and GitHub source repository;
- a repository-relative build context and Dockerfile;
- centrally approved validation commands;
- universal source identity arguments plus any Dockerfile-specific identity
  aliases, whose values come only from the signed intent, source SHA, and
  intent timestamp;
- an exact `Arconath/platform-apps` desired-state path and workload list.

The release workflow emits a signed `artifact-lock-proposal.json` for that
binding. It is evidence for later GitOps review, never a direct desired-state
mutation, and always remains deployment-ineligible by itself.
The proposal contract is closed-world and product-only: `platform-*` policies,
non-canonical product IDs, and any artifact-lock target outside these eleven
product mappings are rejected before evidence generation.

The inventory covers OCI images only. Aeliqo's `aeliqo-agent.ipk` and
AgentDeck's mobile-store bundle require separate signed package/mobile release
contracts. They must not be represented by a fabricated OCI digest.

Run the complete local contract suite with:

```sh
./scripts/verify.sh
```
