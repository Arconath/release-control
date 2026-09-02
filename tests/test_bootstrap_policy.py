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
        self.assertTrue(protection["require_code_owner_review"])
        self.assertTrue(protection["require_last_push_approval"])
        self.assertEqual(protection["required_approvals"], 2)
        self.assertFalse(protection["allow_force_pushes"])
        self.assertFalse(protection["allow_deletions"])
        self.assertEqual(protection["required_checks"], ["contracts and workflow policy"])
        governance = self.settings["release_governance"]
        self.assertEqual(governance["minimum_named_codeowners"], 2)
        self.assertEqual(governance["minimum_distinct_release_signers"], 2)
        self.assertEqual(governance["minimum_environment_reviewers"], 2)
        self.assertEqual(
            governance["required_codeowner_patterns"],
            [
                "*",
                "/.github/CODEOWNERS",
                "/.github/workflows/",
                "/bootstrap/",
                "/contracts/",
                "/policies/",
                "/scripts/",
                "/tests/",
            ],
        )
        self.assertTrue(governance["enforce_on_release"])

    def test_release_environments_are_branch_restricted_and_credential_scoped(self) -> None:
        environments = self.settings["environments"]
        self.assertEqual(
            set(environments), {"source-handoff", "publication", "promotion"}
        )
        for name, environment in environments.items():
            with self.subTest(environment=name):
                self.assertTrue(environment["protected_branches_only"])
                self.assertEqual(environment["wait_timer_minutes"], 0)
                self.assertEqual(environment["required_reviewers"], 2)
                self.assertTrue(environment["prevent_self_review"])

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
        self.assertEqual(
            environments["promotion"]["required_secrets"],
            [
                "ARCONATH_REGISTRY_READ_USERNAME",
                "ARCONATH_REGISTRY_READ_PASSWORD",
            ],
        )

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

    def test_all_canonical_product_artifact_policies_are_present_but_disabled(self) -> None:
        policy_dir = ROOT / "policies" / "products"
        policies = []
        for path in sorted(policy_dir.glob("*.json.disabled")):
            value = json.loads(path.read_text(encoding="utf-8"))
            if "product_id" in value:
                policies.append(value)
        self.assertEqual(len(policies), 27)
        self.assertEqual(
            {value["product_id"] for value in policies},
            {
                "release-passport",
                "foundiqo",
                "opportunity-radar",
                "boringkit",
                "abra",
                "aeliqo",
                "spatial-studio",
                "efficient-ai-compute",
                "people-passport",
                "agentdeck",
                "syviora",
            },
        )
        self.assertTrue(all(value["enabled"] is False for value in policies))
        self.assertTrue(all(value["artifact_lock"]["proposal_only"] is True for value in policies))

    def test_release_contract_schemas_are_strict_json_documents(self) -> None:
        expected = {
            "artifact-lock-proposal.schema.json",
            "build-evidence.schema.json",
            "evidence-lock.schema.json",
            "license-evidence.schema.json",
            "product-policy.schema.json",
            "promotion-manifest.schema.json",
            "provenance.schema.json",
            "release-intent.schema.json",
            "release-record.schema.json",
            "rollback-manifest.schema.json",
            "source-handoff.schema.json",
        }
        contract_dir = ROOT / "contracts"
        self.assertEqual({path.name for path in contract_dir.glob("*.json")}, expected)
        for path in sorted(contract_dir.glob("*.json")):
            with self.subTest(schema=path.name):
                value = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(value["type"], "object")
                self.assertFalse(value["additionalProperties"])
                self.assertTrue(value["required"])
                self.assertEqual(
                    value.get("$id"),
                    f"https://release-control.arconath.com/contracts/{path.name}",
                )

    def test_source_handoff_schema_binds_kind_to_ciphertext_filename(self) -> None:
        schema = json.loads(
            (ROOT / "contracts/source-handoff.schema.json").read_text(encoding="utf-8")
        )
        bindings = {}
        for condition in schema["allOf"]:
            kind = condition["if"]["properties"]["handoff_type"]["const"]
            filename = condition["then"]["properties"]["ciphertext"]["properties"][
                "filename"
            ]["const"]
            bindings[kind] = filename
        self.assertEqual(
            bindings,
            {
                "source": "product.tar.age",
                "candidate": "candidate.oci.tar.age",
            },
        )

    def test_schema_object_keywords_are_strictly_typed_and_self_contained(self) -> None:
        """Keep every object sub-schema compatible with strict Draft 2020-12 tools."""

        def visit(value: object, location: str) -> None:
            if isinstance(value, dict):
                if "properties" in value:
                    self.assertEqual(value.get("type"), "object", location)
                if "required" in value:
                    self.assertEqual(value.get("type"), "object", location)
                    properties = value.get("properties", {})
                    self.assertIsInstance(properties, dict, location)
                    self.assertTrue(
                        set(value["required"]).issubset(properties),
                        f"{location}: required keys must be declared locally",
                    )
                for key, child in value.items():
                    visit(child, f"{location}/{key}")
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    visit(child, f"{location}/{index}")

        for path in sorted((ROOT / "contracts").glob("*.json")):
            with self.subTest(schema=path.name):
                visit(json.loads(path.read_text(encoding="utf-8")), path.name)

    def test_release_evidence_schemas_require_every_signed_bundle(self) -> None:
        expected = {
            "lock",
            "sbom",
            "licenses",
            "provenance",
            "vulnerabilities",
            "artifact_signature",
            "build_evidence_attestation",
            "license_attestation",
            "sbom_attestation",
            "provenance_attestation",
            "vulnerability_attestation",
        }
        for filename in (
            "release-record.schema.json",
            "promotion-manifest.schema.json",
            "rollback-manifest.schema.json",
        ):
            value = json.loads((ROOT / "contracts" / filename).read_text(encoding="utf-8"))
            evidence = value["$defs"]["evidence"]
            self.assertEqual(set(evidence["required"]), expected, filename)
            self.assertEqual(set(evidence["properties"]), expected, filename)

    def test_release_intent_schema_requires_exactly_two_distinct_signers(self) -> None:
        schema = json.loads(
            (ROOT / "contracts/release-intent.schema.json").read_text(encoding="utf-8")
        )
        self.assertIn("signer_identities", schema["required"])
        self.assertNotIn("signer_identity", schema["required"])
        signers = schema["properties"]["signer_identities"]
        self.assertEqual(signers["minItems"], 2)
        self.assertEqual(signers["maxItems"], 2)
        self.assertTrue(signers["uniqueItems"])

    def test_artifact_lock_proposal_schema_pins_canonical_evidence_filenames(self) -> None:
        expected = {
            "lock": "evidence-lock.json",
            "sbom": "sbom.spdx.json",
            "licenses": "licenses.json",
            "provenance": "provenance.intoto.json",
            "vulnerabilities": "vulnerabilities.json",
            "artifact_signature": "artifact.sigstore.json",
            "build_evidence_attestation": "build-evidence.attestation.sigstore.json",
            "license_attestation": "license.attestation.sigstore.json",
            "sbom_attestation": "sbom.attestation.sigstore.json",
            "provenance_attestation": "provenance.attestation.sigstore.json",
            "vulnerability_attestation": "vulnerability.attestation.sigstore.json",
        }
        schema = json.loads(
            (ROOT / "contracts/artifact-lock-proposal.schema.json").read_text(
                encoding="utf-8"
            )
        )
        properties = schema["$defs"]["evidence"]["properties"]
        for key, filename in expected.items():
            with self.subTest(evidence=key):
                self.assertEqual(
                    properties[key]["allOf"][1]["properties"]["filename"]["const"],
                    filename,
                )

    def test_license_evidence_schema_is_nonempty_and_strict(self) -> None:
        schema = json.loads(
            (ROOT / "contracts/license-evidence.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            schema["required"], ["schema_version", "spdx_version", "package_count", "packages"]
        )
        self.assertEqual(schema["properties"]["package_count"]["minimum"], 1)
        packages = schema["properties"]["packages"]
        self.assertEqual(packages["minItems"], 1)
        self.assertEqual(packages["items"]["required"], ["name", "licenses"])
        self.assertEqual(packages["items"]["properties"]["licenses"]["minItems"], 1)
        self.assertEqual(packages["items"]["properties"]["licenses"]["maxItems"], 1)

    def test_artifact_lock_proposal_schema_is_closed_world_and_product_only(self) -> None:
        schema = json.loads(
            (ROOT / "contracts/artifact-lock-proposal.schema.json").read_text(
                encoding="utf-8"
            )
        )
        product_policies = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted((ROOT / "policies/products").glob("*.json.disabled"))
            if "product_id" in json.loads(path.read_text(encoding="utf-8"))
        ]
        target = schema["properties"]["target"]["properties"]
        self.assertEqual(
            set(schema["properties"]["policy_id"]["enum"]),
            {value["policy_id"] for value in product_policies},
        )
        self.assertEqual(
            set(target["product_id"]["enum"]),
            {value["product_id"] for value in product_policies},
        )
        self.assertEqual(
            set(target["artifact_lock_key"]["enum"]),
            {value["artifact_lock"]["key"] for value in product_policies},
        )
        self.assertEqual(
            set(target["desired_state_path"]["enum"]),
            {value["artifact_lock"]["desired_state_path"] for value in product_policies},
        )
        self.assertEqual(
            set(schema["$defs"]["source"]["properties"]["repository"]["enum"]),
            {value["source_repository"] for value in product_policies},
        )
        self.assertEqual(
            set(schema["$defs"]["artifact"]["properties"]["repository"]["enum"]),
            {value["artifact_repository"] for value in product_policies},
        )
        self.assertNotIn("platform-keycloak", schema["properties"]["policy_id"]["enum"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
