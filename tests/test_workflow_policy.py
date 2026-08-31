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
            "github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository",
            text,
        )

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
        self.assertNotIn("ARCONATH_REGISTRY_PASSWORD", promote)
        self.assertNotIn("SOURCE_READER_PRIVATE_KEY", promote)
        self.assertNotIn("packages: write", text)

    def test_release_runs_only_from_protected_default_branch(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        self.assertIn("github.ref == 'refs/heads/main'", text)
        self.assertIn("ref: ${{ github.sha }}", text)
        self.assertEqual(text.count('[[ "$current_main" == "$GITHUB_SHA" ]]'), 3)

    def test_build_arguments_are_central_policy_outputs(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        self.assertIn("build-args-json:", text)
        self.assertIn("BUILD_ARGS_JSON:", text)
        self.assertIn('build-arg:SOURCE_REVISION=$SOURCE_SHA', text)
        self.assertIn('build-arg:VCS_REF=$SOURCE_SHA', text)
        self.assertIn("sorted(value.items())", text)

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
        self.assertNotIn("SOURCE_HANDOFF_AGE_IDENTITY", source)
        self.assertNotIn("SOURCE_HANDOFF_AGE_IDENTITY", publish)
        self.assertNotIn("SOURCE_HANDOFF_AGE_IDENTITY", promote)
        self.assertIn("CANDIDATE_HANDOFF_AGE_IDENTITY", publish)
        self.assertNotIn("CANDIDATE_HANDOFF_AGE_IDENTITY", source)
        self.assertNotIn("CANDIDATE_HANDOFF_AGE_IDENTITY", build)
        self.assertNotIn("CANDIDATE_HANDOFF_AGE_IDENTITY", promote)
        self.assertIn("--run-id", source)
        self.assertIn("--run-id", build)
        self.assertIn("--run-id", publish)


if __name__ == "__main__":
    unittest.main(verbosity=2)
