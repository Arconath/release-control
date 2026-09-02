# GitOps admission-envelope handoff

Release-control ends at an evidence-backed proposal. Its promotion job emits
`artifact-lock-proposal.json` as the admission envelope for
`platform/gitops`; the document remains `proposal_only: true` and
`deployment_eligibility: false`.

The envelope carries the exact product and policy identity, source repository
and commit/tree identity, canonical desired-state path, workload identities,
published image repository and digest, the immutable evidence map, and the
rollback digest. GitOps treats every field as input to independent admission
checks rather than as an instruction to mutate cluster state.

The GitOps admission boundary should:

1. verify the release-control workflow identity and protected control commit;
2. verify the source/tree identity, canonical registry host, image digest,
   evidence-lock hashes, signed evidence bundles, and rollback binding;
3. resolve the exact desired-state path and workload identities in the reviewed
   `platform-apps` tree;
4. add platform-owned rollout, backup/restore, secret, and staging/production
   acceptance evidence; and
5. open the reviewed GitOps change using the exact digest, without accepting a
   mutable tag or granting deployment eligibility from release-control alone.

This handoff does not define credentials, operators, signing keys, cluster
access, or live environment settings. Those remain external platform-owned
configuration and must be verified at admission. Release-control does not
write the GitOps desired state, reconcile a cluster, or declare live readiness.
