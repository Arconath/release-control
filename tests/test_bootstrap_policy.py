#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class BootstrapPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.settings = json.loads(
            (ROOT / "bootstrap/repository-settings.json").read_text(encoding="utf-8")
        )

    def test_repository_is_public_and_uses_free_protection_controls(self) -> None:
        repository = self.settings["repository"]
        protection = self.settings["main_protection"]
        self.assertEqual(repository["visibility"], "public")
        self.assertTrue(protection["enforce_admins"])
        self.assertTrue(protection["strict_checks"])
        self.assertTrue(protection["require_signed_commits"])
        self.assertFalse(protection["require_code_owner_review"])
        self.assertFalse(protection["require_last_push_approval"])
        self.assertEqual(protection["required_approvals"], 0)
        self.assertFalse(protection["linear_history"])
        self.assertEqual(protection["allowed_merge_methods"], ["merge"])
        self.assertFalse(protection["allow_force_pushes"])
        self.assertFalse(protection["allow_deletions"])
        self.assertEqual(protection["required_checks"], ["contracts and workflow policy"])

    def test_release_environments_are_branch_restricted_and_credential_scoped(self) -> None:
        environments = self.settings["environments"]
        self.assertEqual(
            set(environments), {"source-handoff", "publication", "promotion"}
        )
        for name, environment in environments.items():
            with self.subTest(environment=name):
                self.assertTrue(environment["protected_branches_only"])
                self.assertEqual(environment["wait_timer_minutes"], 0)

        self.assertEqual(
            environments["source-handoff"]["required_secrets"],
            ["SOURCE_HANDOFF_AGE_IDENTITY"],
        )
        self.assertEqual(
            environments["publication"]["required_secrets"],
            [
                "ARCONATH_REGISTRY_USERNAME",
                "ARCONATH_REGISTRY_PASSWORD",
                "CANDIDATE_HANDOFF_AGE_IDENTITY",
            ],
        )
        self.assertEqual(environments["promotion"]["required_secrets"], [])

    def test_bootstrap_does_not_introduce_a_github_team_or_hosted_runner(self) -> None:
        serialized = json.dumps(self.settings, sort_keys=True)
        self.assertNotIn("GitHub Actions", serialized)
        self.assertNotIn("@Arconath/", serialized)
        self.assertNotIn("ubuntu-", serialized)
        self.assertNotIn("macos-", serialized)
        self.assertNotIn("windows-", serialized)

    def test_platform_component_policies_are_present_but_fail_closed(self) -> None:
        policy_dir = ROOT / "policies" / "products"
        expected = {
            "platform-keycloak",
            "platform-traefik",
            "platform-registry-jwks",
            "platform-observability",
            "platform-pgadmin",
        }
        actual = {
            path.name.removesuffix(".json.disabled")
            for path in policy_dir.glob("platform-*.json.disabled")
        }
        self.assertEqual(actual, expected)
        for policy_id in sorted(expected):
            path = policy_dir / f"{policy_id}.json.disabled"
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse(value["enabled"])
            self.assertEqual(value["source_repository"], "Arconath/platform-components")
            self.assertEqual(value["registry_host"], "registry.arconath.internal")
            self.assertTrue(value["build"]["build_args"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
