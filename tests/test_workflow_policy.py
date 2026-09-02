#!/usr/bin/env python3

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
RUNNER_GROUP = "group: arconath-jit"
RUNNER_LABELS = "labels: [self-hosted, linux, x64, arconath-jit, rootless-buildkit]"


def job_block(text: str, name: str) -> str:
    match = re.search(
        rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise AssertionError(f"job not found: {name}")
    return match.group("body")


def step_block(text: str, name: str) -> str:
    match = re.search(
        rf"^      - name: {re.escape(name)}\n(?P<body>.*?)(?=^      - name:|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise AssertionError(f"step not found: {name}")
    return match.group("body")


class WorkflowPolicyTests(unittest.TestCase):
    def test_workflows_do_not_contain_duplicate_job_keys(self) -> None:
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("    runs-on:\n    runs-on:\n", text, path)

    def test_every_job_uses_only_canonical_self_hosted_runner(self) -> None:
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            runs = list(re.finditer(r"^    runs-on:\n(?P<body>(?:      .+\n){2})", text, re.MULTILINE))
            self.assertTrue(runs, path)
            for run in runs:
                body = run.group("body")
                self.assertIn(RUNNER_GROUP, body, path)
                self.assertIn(RUNNER_LABELS, body, path)
            self.assertNotRegex(text, r"runs-on:\s+(?:ubuntu|macos|windows)-")

    def test_all_external_actions_are_commit_pinned(self) -> None:
        for path in sorted(WORKFLOWS.glob("*.yml")):
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                match = re.match(r"\s*-?\s*uses:\s*([^\s#]+)", line)
                if not match or match.group(1).startswith("./"):
                    continue
                self.assertRegex(
                    match.group(1),
                    r"^[^@]+@[0-9a-f]{40}$",
                    f"{path}:{line_number}",
                )

    def test_public_pull_requests_cannot_reach_private_runner(self) -> None:
        text = (WORKFLOWS / "validate.yml").read_text(encoding="utf-8")
        self.assertIn(
            "github.repository == 'Arconath/release-control'",
            text,
        )
        self.assertIn(
            "github.event.pull_request.head.repo.full_name == 'Arconath/release-control'",
            text,
        )

    def test_same_repository_stacked_pull_requests_are_validated(self) -> None:
        text = (WORKFLOWS / "validate.yml").read_text(encoding="utf-8")
        self.assertNotIn("github.event.pull_request.base.ref", text)

    def test_validation_uses_trusted_base_and_inert_candidate_checkout(self) -> None:
        text = (WORKFLOWS / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("pull_request_target:", text)
        self.assertNotRegex(text, r"(?m)^\s+pull_request:\s*$")
        self.assertIn("github.event.pull_request.base.sha", text)
        self.assertIn("github.event.pull_request.head.sha", text)
        self.assertIn("path: trusted", text)
        self.assertIn("path: candidate", text)
        self.assertIn("python3 trusted/scripts/verify_candidate.py", text)
        self.assertIn('--trusted-sha "$EXPECTED_TRUSTED_SHA"', text)
        self.assertIn('--candidate-sha "$EXPECTED_CANDIDATE_SHA"', text)
        self.assertNotIn("./scripts/verify.sh", text)
        self.assertNotIn("python3 candidate/", text)

    def test_trusted_workflows_require_the_canonical_repository_event_and_ref(self) -> None:
        release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        for name in (
            "validate-intent",
            "source-fetch",
            "product-validate",
            "build-test",
            "publish-sign",
            "promote",
        ):
            block = job_block(release, name)
            self.assertIn("github.repository == 'Arconath/release-control'", block, name)
            self.assertIn("github.event_name == 'workflow_dispatch'", block, name)
            self.assertIn("github.ref == 'refs/heads/main'", block, name)
        validation = (WORKFLOWS / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("github.repository == 'Arconath/release-control'", validation)

    def test_runner_and_container_socket_guards_fail_closed(self) -> None:
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            self.assertIn('RUNNER_ENVIRONMENT:-', text, path)
            self.assertIn("/run/user/$(id -u)/docker.sock", text, path)
            self.assertIn("PODMAN_HOST", text, path)
            self.assertIn("test ! -e /var/run/docker.sock", text, path)
        release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        build = job_block(release, "build-test")
        self.assertEqual(
            build.count('"/run/user/$(id -u)/buildkit/buildkitd.sock"'),
            2,
        )
        self.assertNotIn("*/run/buildkit/buildkitd.sock", build)

    def test_release_credentials_are_separated_by_job(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        validate = job_block(text, "validate-intent")
        fetch = job_block(text, "source-fetch")
        build = job_block(text, "build-test")
        publish = job_block(text, "publish-sign")
        promote = job_block(text, "promote")

        self.assertIn("SOURCE_READER_PRIVATE_KEY", fetch)
        self.assertNotIn("id-token: write", fetch)

        for block in (validate, build):
            self.assertNotIn("SOURCE_READER_PRIVATE_KEY", block)
            self.assertNotIn("id-token: write", block)
            self.assertNotIn("contents: write", block)

        self.assertIn("id-token: write", publish)
        self.assertIn("ARCONATH_REGISTRY_PASSWORD", publish)
        self.assertIn("ARCONATH_REGISTRY_USERNAME", publish)
        self.assertNotIn("SOURCE_READER_PRIVATE_KEY", publish)
        self.assertNotIn("source/", publish)

        self.assertIn("contents: write", promote)
        self.assertIn("id-token: write", promote)
        self.assertIn("ARCONATH_REGISTRY_READ_USERNAME", promote)
        self.assertIn("ARCONATH_REGISTRY_READ_PASSWORD", promote)
        self.assertNotIn("ARCONATH_REGISTRY_PASSWORD", promote)
        self.assertNotIn("SOURCE_READER_PRIVATE_KEY", promote)
        self.assertNotIn("packages: write", text)

    def test_release_runs_only_from_protected_default_branch(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        self.assertIn("github.ref == 'refs/heads/main'", text)
        self.assertIn("ref: ${{ github.sha }}", text)
        self.assertGreaterEqual(text.count('[[ "$current_main" == "$GITHUB_SHA" ]]'), 11)
        for step_name in (
            "Publish or resume the exact immutable OCI digest",
            "Sign and attest exact digest",
            "Emit immutable promotion and rollback manifests",
            "Sign promotion, rollback, and artifact-lock proposal",
            "Publish immutable release evidence",
        ):
            with self.subTest(step=step_name):
                self.assertIn(
                    '[[ "$current_main" == "$GITHUB_SHA" ]]',
                    step_block(text, step_name),
                )

    def test_release_requires_two_person_governance_before_source_access(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        validate = job_block(text, "validate-intent")
        self.assertIn("validate-governance", validate)
        self.assertIn("--codeowners .github/CODEOWNERS", validate)
        self.assertIn("--allowed-signers policies/release-signers", validate)
        self.assertNotIn("--allow-incomplete", validate)
        self.assertLess(
            validate.index("validate-governance"),
            validate.index("validate-intent"),
        )

    def test_release_requires_two_intent_signatures_at_every_validation_boundary(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        for name in ("validate-intent", "publish-sign", "promote"):
            block = job_block(text, name)
            self.assertIn("--signature", block, name)
            self.assertIn(".sig.1", block, name)
            self.assertIn(".sig.2", block, name)
        self.assertNotIn("release-intent.json.sig\n", text)

    def test_build_arguments_are_central_policy_outputs(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        self.assertIn("build-args-json:", text)
        self.assertIn("identity-build-args-json:", text)
        self.assertIn("BUILD_ARGS_JSON:", text)
        self.assertIn("IDENTITY_BUILD_ARGS_JSON:", text)
        self.assertIn('build-arg:SOURCE_REVISION=$SOURCE_SHA', text)
        self.assertIn('build-arg:VCS_REF=$SOURCE_SHA', text)
        self.assertIn("static build arguments override signed identity", text)
        self.assertIn("sorted(value.items())", text)

    def test_untrusted_product_checks_are_separate_from_candidate_build(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        source = job_block(text, "source-fetch")
        validation = job_block(text, "product-validate")
        build = job_block(text, "build-test")
        self.assertIn("environment: source-handoff", source)
        self.assertIn("run-policy", validation)
        self.assertNotIn("run-policy", build)
        self.assertNotIn("buildctl", validation)
        self.assertIn("needs: [validate-intent, source-fetch, product-validate]", build)
        self.assertIn("environment: source-handoff", validation)
        self.assertIn("environment: source-handoff", build)

    def test_candidate_build_forwards_no_host_credentials_or_insecure_entitlements(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        build_step = step_block(text, "Build one non-published OCI archive")
        for forbidden in ("--allow", "--secret", "--ssh", "--network=host"):
            self.assertNotIn(forbidden, build_step)

    def test_publisher_refuses_to_overwrite_an_existing_digest_tag(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        publish = job_block(text, "publish-sign")
        self.assertIn("expected_digest=\"$(jq -er '.artifact.digest' candidate/build-evidence.json)\"", publish)
        self.assertIn('existing_digest="$(skopeo inspect', publish)
        self.assertIn(
            '[[ "$existing_digest" == "$expected_digest" ]]',
            publish,
        )
        self.assertIn("refusing overwrite", publish)
        self.assertIn("immutable-tag-inspect.error", publish)
        self.assertIn("Unable to prove immutable source tag is absent", publish)

    def test_publication_serializes_same_policy_and_source(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        publish = job_block(text, "publish-sign")
        self.assertIn(
            "concurrency:\n"
            "      group: trusted-publish-${{ needs.validate-intent.outputs.policy-id }}-"
            "${{ needs.validate-intent.outputs.source-sha }}\n"
            "      cancel-in-progress: false",
            publish,
        )

    def test_signed_evidence_verification_binds_workflow_claims(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        for claim in (
            "--certificate-github-workflow-trigger workflow_dispatch",
            "--certificate-github-workflow-sha",
            "--certificate-github-workflow-name \"Trusted product release\"",
            "--certificate-github-workflow-repository \"Arconath/release-control\"",
            "--certificate-github-workflow-ref refs/heads/main",
        ):
            self.assertIn(claim, text)
        identity_regex = (
            r"^https://github\.com/Arconath/release-control/\.github/workflows/"
            r"release\.yml@refs/heads/main$"
        )
        self.assertEqual(job_block(text, "publish-sign").count(identity_regex), 2)
        self.assertNotIn(r"^https://github\\.com/Arconath/release-control", job_block(text, "publish-sign"))

    def test_public_artifacts_never_transport_plaintext_source_or_oci(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        source = job_block(text, "source-fetch")
        build = job_block(text, "build-test")
        publish = job_block(text, "publish-sign")

        source_upload = step_block(text, "Upload immutable source transport")
        candidate_upload = step_block(text, "Upload non-published release candidate")
        self.assertIn("age --encrypt", source)
        self.assertIn("product.tar.age", source_upload)
        self.assertNotRegex(source_upload, r"(?m)^\s+product\.tar$")
        self.assertNotIn("product.tar.sha256", source_upload)
        self.assertIn("age --encrypt", build)
        self.assertIn("candidate.oci.tar.age", candidate_upload)
        self.assertNotRegex(candidate_upload, r"(?m)^\s+candidate\.oci\.tar$")
        self.assertNotIn("path: candidate/", text)
        self.assertIn("age --decrypt", publish)
        self.assertIn("candidate.oci.tar.age", publish)

    def test_handoff_keys_are_scoped_to_bounded_decrypt_steps(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        source = job_block(text, "source-fetch")
        build = job_block(text, "build-test")
        publish = job_block(text, "publish-sign")
        promote = job_block(text, "promote")

        self.assertIn("environment: source-handoff", build)
        self.assertIn("SOURCE_HANDOFF_AGE_IDENTITY", build)
        self.assertNotIn("SOURCE_HANDOFF_AGE_IDENTITY", step_block(text, "Fail closed when source-reader prerequisites are absent"))
        self.assertNotIn("SOURCE_HANDOFF_AGE_IDENTITY", publish)
        self.assertNotIn("SOURCE_HANDOFF_AGE_IDENTITY", promote)
        self.assertIn("CANDIDATE_HANDOFF_AGE_IDENTITY", publish)
        self.assertNotIn("CANDIDATE_HANDOFF_AGE_IDENTITY", source)
        self.assertNotIn("CANDIDATE_HANDOFF_AGE_IDENTITY", build)
        self.assertNotIn("CANDIDATE_HANDOFF_AGE_IDENTITY", promote)
        self.assertNotIn(
            "SOURCE_HANDOFF_AGE_IDENTITY",
            step_block(text, "Fail closed when build runner prerequisites are absent"),
        )
        self.assertIn(
            "SOURCE_HANDOFF_AGE_IDENTITY",
            step_block(text, "Decrypt source only in the bounded handoff step"),
        )
        self.assertNotIn(
            "CANDIDATE_HANDOFF_AGE_IDENTITY",
            step_block(text, "Fail closed when publication prerequisites are absent"),
        )
        self.assertIn(
            "CANDIDATE_HANDOFF_AGE_IDENTITY",
            step_block(text, "Decrypt candidate only after identity revalidation"),
        )
        self.assertIn("--run-id", source)
        self.assertIn("--run-id", build)
        self.assertIn("--run-id", publish)

    def test_build_and_publish_require_the_immutable_evidence_lock(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        build = job_block(text, "build-test")
        publish = job_block(text, "publish-sign")
        self.assertIn("build-provenance", build)
        self.assertIn("create-evidence-lock", build)
        self.assertIn("--release-control-sha \"$GITHUB_SHA\"", build)
        self.assertIn("check-license-policy.py", build)
        self.assertIn("candidate/licenses.json", build)
        self.assertIn("--licenses candidate/licenses.json", build)
        self.assertIn("evidence-lock.json", build)
        self.assertIn("verify-evidence-lock", publish)
        self.assertIn("Verify exact evidence lock before registry mutation", publish)
        self.assertLess(
            publish.index("Verify exact evidence lock before registry mutation"),
            publish.index("Publish or resume the exact immutable OCI digest"),
        )

    def test_missing_runner_or_registry_prerequisites_fail_closed(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        fetch = job_block(text, "source-fetch")
        build = job_block(text, "build-test")
        publish = job_block(text, "publish-sign")
        self.assertIn("Fail closed when source-reader prerequisites are absent", fetch)
        for value in ("SOURCE_READER_APP_ID", "SOURCE_READER_PRIVATE_KEY", "SOURCE_HANDOFF_AGE_RECIPIENT"):
            self.assertIn(f'[[ -n "${value}" ]]', fetch)
        self.assertIn("Fail closed when build runner prerequisites are absent", build)
        self.assertIn('[[ -n "$SOURCE_HANDOFF_AGE_IDENTITY" ]]', build)
        self.assertIn("Fail closed when publication prerequisites are absent", publish)
        self.assertIn('[[ -n "$CONFIGURED_REGISTRY_HOST"', publish)
        self.assertIn(
            '[[ -n "$ARCONATH_REGISTRY_USERNAME" && -n "$ARCONATH_REGISTRY_PASSWORD" ]]',
            publish,
        )
        self.assertIn('[[ -n "$CANDIDATE_HANDOFF_AGE_RECIPIENT" ]]', publish)
        self.assertIn('[[ -n "$CANDIDATE_HANDOFF_AGE_IDENTITY" ]]', publish)

    def test_normal_verifier_requires_strict_merge_readiness(self) -> None:
        text = (ROOT / "scripts/verify.sh").read_text(encoding="utf-8")
        self.assertIn("merge-readiness", text)
        self.assertIn("--require-ready", text)

    def test_publication_produces_and_verifies_all_signed_evidence_types(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        publish = job_block(text, "publish-sign")
        for name in (
            "artifact.sigstore.json",
            "build-evidence.attestation.sigstore.json",
            "license.attestation.sigstore.json",
            "sbom.attestation.sigstore.json",
            "provenance.attestation.sigstore.json",
            "vulnerability.attestation.sigstore.json",
        ):
            self.assertIn(name, publish)
        self.assertIn("cosign verify --bundle candidate/artifact.sigstore.json", publish)
        self.assertIn('cosign verify-attestation --bundle "$bundle"', publish)
        self.assertIn("verify-attestation-payload", publish)
        for predicate_type in (
            "https://arconath.com/BuildEvidence/v1",
            "https://arconath.com/LicenseEvidence/v1",
            "https://spdx.dev/Document",
            "https://slsa.dev/provenance/v1",
            "https://arconath.com/VulnerabilityScan/v1",
        ):
            self.assertIn(predicate_type, publish)
        self.assertEqual(publish.count(".verified-attestation.json"), 5)
        self.assertIn("finalize-release", publish)
        self.assertLess(
            publish.index("Install Cosign before any registry mutation"),
            publish.index("Publish or resume the exact immutable OCI digest"),
        )

    def test_promotion_revalidates_downloaded_evidence_before_emitting_manifests(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        promote = job_block(text, "promote")
        self.assertIn("--evidence-dir evidence", promote)
        self.assertIn("evidence/promotion-manifest.json", promote)
        self.assertIn("evidence/rollback-manifest.json", promote)
        self.assertIn("evidence/artifact-lock-proposal.json", promote)
        self.assertIn("evidence/licenses.json", promote)
        self.assertIn("evidence/license.attestation.sigstore.json", promote)
        self.assertIn("evidence/artifact-lock-proposal.sigstore.json", promote)
        self.assertIn("verify-promotion-inputs", promote)
        self.assertIn("skopeo login", promote)
        self.assertIn("DOCKER_CONFIG", promote)
        self.assertIn("cosign verify-blob --bundle", promote)
        self.assertIn("certificate-oidc-issuer https://token.actions.githubusercontent.com", promote)
        self.assertIn("evidence-release-view.error", promote)
        self.assertIn("Unable to prove the evidence release tag is absent", promote)
        self.assertNotIn("evidence/*", promote)
        self.assertNotIn("path: evidence/", promote)
        self.assertLess(
            promote.index("verify-promotion-inputs"),
            promote.index("emit-manifests"),
        )

    def test_promotion_signature_verification_uses_exact_workflow_identity(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        promote = job_block(text, "promote")
        identity_regex = (
            r"^https://github\.com/Arconath/release-control/\.github/workflows/"
            r"release\.yml@refs/heads/main$"
        )
        self.assertEqual(promote.count(identity_regex), 2)
        self.assertNotIn(r"^https://github\\.com/Arconath/release-control", promote)

    def test_publish_boundary_is_rootless_and_cannot_execute_product_source(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        build = job_block(text, "build-test")
        publish = job_block(text, "publish-sign")
        self.assertIn('[[ "$(id -u)" != 0 ]]', build)
        self.assertIn('[[ "$(id -u)" != 0 ]]', publish)
        self.assertIn("test ! -S /var/run/docker.sock", publish)
        self.assertIn('test ! -e product', publish)
        self.assertNotIn("git -C product", publish)


if __name__ == "__main__":
    unittest.main(verbosity=2)
