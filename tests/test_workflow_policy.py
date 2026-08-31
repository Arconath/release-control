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


if __name__ == "__main__":
    unittest.main(verbosity=2)
