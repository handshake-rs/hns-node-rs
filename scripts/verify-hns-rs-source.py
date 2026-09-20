#!/usr/bin/env python3
"""Fail closed unless every hns-rs package resolves to a reviewed crates.io release."""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
MANIFEST_SHA256 = "69f2115f090e3bdeafaea3db8a65db33b42524434d44bdd3f9f80e9f601dea6a"
DIRECT = {
    "hns-covenants": "0.3.1",
    "hns-dns-relay-protocol": "0.3.0",
    "hns-hnsr-protocol": "0.3.0",
    "hns-odoh-protocol": "0.3.0",
    "hns-p2p-experimental": "0.4.1",
    "hns-rollback-journal": "0.3.0",
}
ROOT_CLOSURE = {
    ("hns-chat-protocol", "0.3.0"),
    ("hns-covenants", "0.3.1"),
    ("hns-covenants", "0.4.1"),
    ("hns-dns-relay-protocol", "0.3.0"),
    ("hns-encoding", "0.3.1"),
    ("hns-encoding", "0.4.1"),
    ("hns-hnsr-protocol", "0.3.0"),
    ("hns-hrm", "0.3.0"),
    ("hns-marketplace-protocol", "0.4.1"),
    ("hns-odoh-protocol", "0.3.0"),
    ("hns-p2p-experimental", "0.4.1"),
    ("hns-primitives", "0.3.1"),
    ("hns-primitives", "0.4.1"),
    ("hns-rollback-journal", "0.3.0"),
    ("hns-script", "0.4.1"),
    ("hns-service-authority", "0.3.0"),
    ("hns-swap", "0.4.1"),
    ("hns-transaction", "0.3.1"),
    ("hns-transaction", "0.4.1"),
}
FUZZ_CLOSURE = {
    ("hns-chat-protocol", "0.3.0"),
    ("hns-covenants", "0.3.0"),
    ("hns-covenants", "0.4.1"),
    ("hns-dns-relay-protocol", "0.3.0"),
    ("hns-encoding", "0.3.0"),
    ("hns-encoding", "0.4.1"),
    ("hns-hnsr-protocol", "0.3.0"),
    ("hns-hrm", "0.3.0"),
    ("hns-marketplace-protocol", "0.4.1"),
    ("hns-odoh-protocol", "0.3.0"),
    ("hns-p2p-experimental", "0.4.1"),
    ("hns-primitives", "0.3.0"),
    ("hns-primitives", "0.4.1"),
    ("hns-script", "0.4.1"),
    ("hns-service-authority", "0.3.0"),
    ("hns-swap", "0.4.1"),
    ("hns-transaction", "0.3.0"),
    ("hns-transaction", "0.4.1"),
}
ROOT_LOCAL_NAME_COLLISIONS = {
    "hns-primitives": "0.3.5",
}
FUZZ_LOCAL_NAME_COLLISIONS = {
    "hns-primitives": "0.3.5",
}
DEPENDENCY_TABLES = {"dependencies", "dev-dependencies", "build-dependencies"}
ALLOWED_PACKAGE_ALIASES = {
    (
        "Cargo.toml",
        ("workspace", "dependencies", "hns-protocol-primitives"),
    ): {
        "package": "hns-primitives",
        "version": "=0.4.1",
    },
}


def fail(message: str) -> None:
    raise SystemExit(f"hns-rs source verification failed: {message}")


def load_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot parse {path.relative_to(ROOT)}: {error}")


def contains_git_key(value: Any) -> bool:
    if isinstance(value, dict):
        return "git" in value or any(contains_git_key(child) for child in value.values())
    if isinstance(value, list):
        return any(contains_git_key(child) for child in value)
    return False


def dependency_specifications(
    value: Any,
    path: tuple[str, ...] = (),
) -> list[tuple[tuple[str, ...], str, dict[str, Any]]]:
    specifications: list[tuple[tuple[str, ...], str, dict[str, Any]]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = (*path, str(key))
            if key in DEPENDENCY_TABLES and isinstance(child, dict):
                for dependency, specification in child.items():
                    if isinstance(specification, dict):
                        specifications.append(
                            ((*child_path, str(dependency)), str(dependency), specification)
                        )
            specifications.extend(dependency_specifications(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            specifications.extend(dependency_specifications(child, (*path, str(index))))
    return specifications


def tracked_manifests() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--", "Cargo.toml", "**/Cargo.toml"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    paths = [ROOT / line for line in result.stdout.splitlines() if line]
    if ROOT / "Cargo.toml" not in paths:
        fail("root Cargo.toml is not tracked")
    return paths


def published_checksums() -> dict[tuple[str, str], str]:
    path = ROOT / "release/hns-rs-reviewed-crates.sha256"
    try:
        raw = path.read_bytes()
    except OSError as error:
        fail(f"cannot read {path.relative_to(ROOT)}: {error}")
    actual_digest = hashlib.sha256(raw).hexdigest()
    if actual_digest != MANIFEST_SHA256:
        fail(
            "release manifest digest mismatch "
            f"(expected {MANIFEST_SHA256}, got {actual_digest})"
        )

    checksums: dict[tuple[str, str], str] = {}
    for line in raw.decode("ascii").splitlines():
        parts = line.split("  ")
        if len(parts) != 2:
            fail(f"malformed release manifest line: {line!r}")
        checksum, filename = parts
        if len(checksum) != 64 or any(character not in "0123456789abcdef" for character in checksum):
            fail(f"malformed checksum for {filename}")
        match = re.fullmatch(r"(hns-[a-z0-9-]+)-(\d+\.\d+\.\d+)\.crate", filename)
        if match is None:
            fail(f"unexpected release archive name: {filename}")
        key = (match.group(1), match.group(2))
        if key in checksums:
            fail(f"duplicate release archive: {filename}")
        checksums[key] = checksum
    if len(checksums) != 24:
        fail(f"expected 24 reviewed hns-rs archives, found {len(checksums)}")
    return checksums


def verify_direct_dependencies() -> None:
    dependencies = load_toml(ROOT / "Cargo.toml").get("workspace", {}).get("dependencies", {})
    for name, version in sorted(DIRECT.items()):
        specification = dependencies.get(name)
        if specification != {"version": f"={version}"}:
            fail(
                f"workspace dependency {name} must be exactly "
                f'{{ version = "={version}" }}'
            )


def verify_manifest_source_policy(release_names: set[str]) -> None:
    for path in tracked_manifests():
        document = load_toml(path)
        if contains_git_key(document):
            fail(f"Git dependency is forbidden in {path.relative_to(ROOT)}")
        for location, dependency, specification in dependency_specifications(document):
            normalized_dependency = dependency.replace("_", "-")
            package = specification.get("package")
            if package is None:
                if dependency != normalized_dependency and normalized_dependency in release_names:
                    fail(
                        f"hns-rs dependency aliases are forbidden at "
                        f"{path.relative_to(ROOT)}:{'.'.join(location)}"
                    )
                continue
            if not isinstance(package, str):
                fail(
                    f"malformed dependency package alias at "
                    f"{path.relative_to(ROOT)}:{'.'.join(location)}"
                )
            normalized_package = package.replace("_", "-")
            if (
                normalized_dependency in release_names
                or normalized_package in release_names
            ):
                allowed = ALLOWED_PACKAGE_ALIASES.get(
                    (str(path.relative_to(ROOT)), location)
                )
                if allowed == specification:
                    continue
                fail(
                    f"hns-rs dependency aliases are forbidden at "
                    f"{path.relative_to(ROOT)}:{'.'.join(location)}"
                )


def verify_lock(
    path: Path,
    expected: set[tuple[str, str]],
    checksums: dict[tuple[str, str], str],
    expected_local_name_collisions: dict[str, str],
) -> None:
    data = load_toml(path)
    packages = data.get("package")
    if not isinstance(packages, list):
        fail(f"{path.relative_to(ROOT)} has no package array")

    selected: dict[tuple[str, str], dict[str, Any]] = {}
    selected_local: dict[str, dict[str, Any]] = {}
    protected_names = {name for name, _version in checksums}
    for package in packages:
        if not isinstance(package, dict):
            fail(f"{path.relative_to(ROOT)} has a malformed package entry")
        source = package.get("source")
        if isinstance(source, str) and source.startswith("git+"):
            fail(f"Git source remains in {path.relative_to(ROOT)}: {source}")
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str):
            normalized_name = name.replace("_", "-")
            if name != normalized_name and normalized_name in protected_names:
                fail(
                    f"{path.relative_to(ROOT)} resolves protected package spelling "
                    f"{name}"
                )
        if name not in protected_names:
            continue
        if not isinstance(version, str):
            fail(f"{path.relative_to(ROOT)} has a malformed version for {name}")

        expected_local_version = expected_local_name_collisions.get(name)
        if expected_local_version == version:
            if name in selected_local:
                fail(
                    f"{path.relative_to(ROOT)} resolves duplicate local packages "
                    f"for {name} {version}"
                )
            if package.get("source") is not None or package.get("checksum") is not None:
                fail(
                    f"{path.relative_to(ROOT)} local package collision {name} "
                    f"{version} must be source-less and checksum-less"
                )
            selected_local[name] = package
            continue

        key = (name, version)
        if key not in expected:
            fail(
                f"{path.relative_to(ROOT)} resolves unexpected hns-rs package "
                f"{name} {version}"
            )
        if key in selected:
            fail(
                f"{path.relative_to(ROOT)} resolves duplicate hns-rs packages "
                f"for {name} {version}"
            )
        selected[key] = package
        if package.get("source") != REGISTRY_SOURCE:
            fail(
                f"{path.relative_to(ROOT)} resolves {name} from "
                f"{package.get('source', 'a local path')}"
            )
        if package.get("checksum") != checksums[key]:
            fail(f"{path.relative_to(ROOT)} checksum mismatch for {name} {version}")
    if set(selected) != expected:
        fail(
            f"{path.relative_to(ROOT)} hns-rs closure mismatch "
            f"(expected {sorted(expected)}, got {sorted(selected)})"
        )
    if set(selected_local) != set(expected_local_name_collisions):
        fail(
            f"{path.relative_to(ROOT)} local release-name collision mismatch "
            f"(expected {sorted(expected_local_name_collisions)}, "
            f"got {sorted(selected_local)})"
        )


def main() -> None:
    checksums = published_checksums()
    verify_direct_dependencies()
    verify_manifest_source_policy({name for name, _version in checksums})
    verify_lock(
        ROOT / "Cargo.lock",
        ROOT_CLOSURE,
        checksums,
        ROOT_LOCAL_NAME_COLLISIONS,
    )
    verify_lock(
        ROOT / "fuzz/Cargo.lock",
        FUZZ_CLOSURE,
        checksums,
        FUZZ_LOCAL_NAME_COLLISIONS,
    )
    print(
        "verified reviewed hns-rs crates.io closures for the node and fuzz workspaces"
    )


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        fail(f"git manifest inventory failed: {error}")
