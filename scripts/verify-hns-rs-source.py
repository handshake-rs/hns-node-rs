#!/usr/bin/env python3
"""Fail closed unless hns-rs 0.3.0 resolves to the reviewed crates.io release."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.3.0"
REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
SOURCE_REVISION = "d0cde9ded6f8f93f96f16daafc094849c6d484bf"
MANIFEST_SHA256 = "afd271a38264ba1fb8728f264758805f11decc1ad42935c41b04f12363cd2bc0"
DIRECT = {
    "hns-covenants",
    "hns-dns-relay-protocol",
    "hns-hnsr-protocol",
    "hns-odoh-protocol",
    "hns-p2p-experimental",
    "hns-rollback-journal",
}
ROOT_CLOSURE = {
    "hns-chat-protocol",
    "hns-covenants",
    "hns-dns-relay-protocol",
    "hns-encoding",
    "hns-hnsr-protocol",
    "hns-hrm",
    "hns-odoh-protocol",
    "hns-p2p-experimental",
    "hns-primitives",
    "hns-rollback-journal",
    "hns-service-authority",
    "hns-transaction",
}
FUZZ_CLOSURE = ROOT_CLOSURE - {"hns-rollback-journal"}
ROOT_LOCAL_NAME_COLLISIONS = {
    "hns-mining": "0.3.5",
    "hns-primitives": "0.3.5",
}
FUZZ_LOCAL_NAME_COLLISIONS = {
    "hns-primitives": "0.3.5",
}
DEPENDENCY_TABLES = {"dependencies", "dev-dependencies", "build-dependencies"}


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


def published_checksums() -> dict[str, str]:
    path = ROOT / "release/hns-rs-0.3.0-crates.sha256"
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

    checksums: dict[str, str] = {}
    for line in raw.decode("ascii").splitlines():
        parts = line.split("  ")
        if len(parts) != 2:
            fail(f"malformed release manifest line: {line!r}")
        checksum, filename = parts
        suffix = f"-{VERSION}.crate"
        if len(checksum) != 64 or any(character not in "0123456789abcdef" for character in checksum):
            fail(f"malformed checksum for {filename}")
        if not filename.endswith(suffix):
            fail(f"unexpected release archive name: {filename}")
        name = filename[: -len(suffix)]
        if name in checksums:
            fail(f"duplicate release archive: {filename}")
        checksums[name] = checksum
    if len(checksums) != 19:
        fail(f"expected 19 published hns-rs archives, found {len(checksums)}")
    return checksums


def verify_direct_dependencies() -> None:
    dependencies = load_toml(ROOT / "Cargo.toml").get("workspace", {}).get("dependencies", {})
    for name in sorted(DIRECT):
        specification = dependencies.get(name)
        if specification != {"version": f"={VERSION}"}:
            fail(
                f"workspace dependency {name} must be exactly "
                f'{{ version = "={VERSION}" }}'
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
                fail(
                    f"hns-rs dependency aliases are forbidden at "
                    f"{path.relative_to(ROOT)}:{'.'.join(location)}"
                )


def verify_lock(
    path: Path,
    expected: set[str],
    checksums: dict[str, str],
    expected_local_name_collisions: dict[str, str],
) -> None:
    data = load_toml(path)
    packages = data.get("package")
    if not isinstance(packages, list):
        fail(f"{path.relative_to(ROOT)} has no package array")

    selected: dict[str, dict[str, Any]] = {}
    selected_local: dict[str, dict[str, Any]] = {}
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
            if name != normalized_name and normalized_name in checksums:
                fail(
                    f"{path.relative_to(ROOT)} resolves protected package spelling "
                    f"{name}"
                )
        if name not in checksums:
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

        if version != VERSION:
            fail(
                f"{path.relative_to(ROOT)} resolves unexpected hns-rs package "
                f"{name} {version}"
            )
        if name in selected:
            fail(f"{path.relative_to(ROOT)} resolves duplicate hns-rs packages for {name}")
        selected[name] = package
        if package.get("source") != REGISTRY_SOURCE:
            fail(
                f"{path.relative_to(ROOT)} resolves {name} from "
                f"{package.get('source', 'a local path')}"
            )
        if package.get("checksum") != checksums[name]:
            fail(f"{path.relative_to(ROOT)} checksum mismatch for {name}")
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
    verify_manifest_source_policy(set(checksums))
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
        "verified hns-rs 0.3.0 crates.io closure "
        f"from source revision {SOURCE_REVISION}"
    )


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        fail(f"git manifest inventory failed: {error}")
