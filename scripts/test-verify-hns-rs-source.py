#!/usr/bin/env python3
"""Focused, no-write tests for hns-rs lock source verification."""

from __future__ import annotations

import runpy
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = runpy.run_path(str(ROOT / "scripts/verify-hns-rs-source.py"))
REGISTRY_SOURCE = VALIDATOR["REGISTRY_SOURCE"]
VERIFY_LOCK = VALIDATOR["verify_lock"]
VERIFY_MANIFEST_SOURCE_POLICY = VALIDATOR["verify_manifest_source_policy"]
CHECKSUM = "a" * 64


def canonical_package() -> dict[str, str]:
    return {
        "name": "hns-covenants",
        "version": "0.3.0",
        "source": REGISTRY_SOURCE,
        "checksum": CHECKSUM,
    }


class VerifyLockTests(unittest.TestCase):
    def verify(
        self,
        packages: list[dict[str, str]],
        *,
        expected: set[str] | None = None,
        checksums: dict[str, str] | None = None,
        expected_local_name_collisions: dict[str, str] | None = None,
    ) -> None:
        with patch.dict(VERIFY_LOCK.__globals__, {"load_toml": lambda _path: {"package": packages}}):
            VERIFY_LOCK(
                ROOT / "Cargo.lock",
                expected or {"hns-covenants"},
                checksums or {"hns-covenants": CHECKSUM},
                expected_local_name_collisions or {},
            )

    def test_accepts_one_canonical_registry_package(self) -> None:
        self.verify([canonical_package()])

    def test_rejects_canonical_and_path_duplicates(self) -> None:
        path_package = {
            "name": "hns-covenants",
            "version": "0.3.0",
        }
        with self.assertRaisesRegex(SystemExit, "duplicate hns-rs packages"):
            self.verify([canonical_package(), path_package])

    def test_rejects_canonical_and_alternate_registry_duplicates(self) -> None:
        alternate_package = {
            **canonical_package(),
            "source": "registry+https://example.invalid/index",
        }
        with self.assertRaisesRegex(SystemExit, "duplicate hns-rs packages"):
            self.verify([canonical_package(), alternate_package])

    def test_rejects_noncanonical_release_name_version(self) -> None:
        path_package = {
            "name": "hns-covenants",
            "version": "0.3.1",
        }
        with self.assertRaisesRegex(SystemExit, "unexpected hns-rs package"):
            self.verify([canonical_package(), path_package])

    def test_rejects_build_metadata_version(self) -> None:
        build_metadata_package = {
            **canonical_package(),
            "version": "0.3.0+local",
        }
        with self.assertRaisesRegex(SystemExit, "unexpected hns-rs package"):
            self.verify([build_metadata_package])

    def test_rejects_protected_underscore_lock_package(self) -> None:
        underscore_package = {
            "name": "hns_covenants",
            "version": "0.3.0",
        }
        with self.assertRaisesRegex(SystemExit, "protected package spelling"):
            self.verify([canonical_package(), underscore_package])

    def test_accepts_explicit_workspace_local_name_collision(self) -> None:
        primitive_checksum = "b" * 64
        primitive_registry = {
            "name": "hns-primitives",
            "version": "0.3.0",
            "source": REGISTRY_SOURCE,
            "checksum": primitive_checksum,
        }
        primitive_local = {
            "name": "hns-primitives",
            "version": "0.3.5",
        }
        self.verify(
            [canonical_package(), primitive_registry, primitive_local],
            expected={"hns-covenants", "hns-primitives"},
            checksums={
                "hns-covenants": CHECKSUM,
                "hns-primitives": primitive_checksum,
            },
            expected_local_name_collisions={"hns-primitives": "0.3.5"},
        )


class VerifyManifestSourcePolicyTests(unittest.TestCase):
    MANIFEST = ROOT / "crates/example/Cargo.toml"

    def verify(
        self,
        dependency: str,
        specification: dict[str, str],
        *,
        release_names: set[str] | None = None,
    ) -> None:
        self.verify_document(
            {"dependencies": {dependency: specification}},
            release_names=release_names,
        )

    def verify_document(
        self,
        document: dict[str, object],
        *,
        release_names: set[str] | None = None,
    ) -> None:
        with (
            patch.dict(
                VERIFY_MANIFEST_SOURCE_POLICY.__globals__,
                {
                    "tracked_manifests": lambda: [self.MANIFEST],
                    "load_toml": lambda _path: document,
                },
            )
        ):
            VERIFY_MANIFEST_SOURCE_POLICY(release_names or {"hns-covenants"})

    def test_accepts_canonical_workspace_inheritance(self) -> None:
        self.verify("hns-covenants", {"workspace": True})

    def test_rejects_release_name_redirected_to_path_alias(self) -> None:
        with self.assertRaisesRegex(SystemExit, "dependency aliases are forbidden"):
            self.verify(
                "hns-covenants",
                {
                    "package": "evil-covenants",
                    "path": "../evil",
                    "version": "9.9.9",
                },
            )

    def test_rejects_rust_identifier_spelling_redirected_to_path_alias(self) -> None:
        with self.assertRaisesRegex(SystemExit, "dependency aliases are forbidden"):
            self.verify(
                "hns_covenants",
                {
                    "package": "evil-covenants",
                    "path": "../evil",
                    "version": "9.9.9",
                },
            )

    def test_rejects_rust_identifier_spelling_without_package_field(self) -> None:
        with self.assertRaisesRegex(SystemExit, "dependency aliases are forbidden"):
            self.verify(
                "hns_covenants",
                {
                    "path": "../evil",
                    "version": "9.9.9",
                },
            )

    def test_rejects_inverse_underscore_package_alias(self) -> None:
        with self.assertRaisesRegex(SystemExit, "dependency aliases are forbidden"):
            self.verify(
                "evil-covenants",
                {
                    "package": "hns_covenants",
                    "path": "../evil",
                    "version": "9.9.9",
                },
            )

    def test_rejects_aliases_in_every_dependency_table_shape(self) -> None:
        alias = {
            "hns-covenants": {
                "package": "evil-covenants",
                "path": "../evil",
                "version": "9.9.9",
            }
        }
        documents = {
            "normal": {"dependencies": alias},
            "dev": {"dev-dependencies": alias},
            "build": {"build-dependencies": alias},
            "workspace": {"workspace": {"dependencies": alias}},
            "target": {"target": {"cfg(unix)": {"dependencies": alias}}},
        }
        for shape, document in documents.items():
            with (
                self.subTest(shape=shape),
                self.assertRaisesRegex(SystemExit, "dependency aliases are forbidden"),
            ):
                self.verify_document(document)

    def test_rejects_alias_redirected_to_release_name(self) -> None:
        with self.assertRaisesRegex(SystemExit, "dependency aliases are forbidden"):
            self.verify(
                "evil-covenants",
                {
                    "package": "hns-covenants",
                    "registry": "alternate",
                    "version": "=0.3.0",
                },
            )

    def test_rejects_local_collision_names_redirected_to_aliases(self) -> None:
        for dependency in ["hns-primitives", "hns-mining"]:
            with (
                self.subTest(dependency=dependency),
                self.assertRaisesRegex(SystemExit, "dependency aliases are forbidden"),
            ):
                self.verify(
                    dependency,
                    {
                        "package": f"evil-{dependency}",
                        "path": "../evil",
                        "version": "0.3.5",
                    },
                    release_names={dependency},
                )


if __name__ == "__main__":
    unittest.main()
