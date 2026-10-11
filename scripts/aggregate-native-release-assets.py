#!/usr/bin/env python3
"""Validate selected native review artifacts and prepare release sidecars.

The caller must independently verify that each selected GitHub Actions matrix
job succeeded. This script verifies the downloaded files and their exact source
identity; it does not treat an artifact's presence as proof of CI success.

Each --artifact-dir may be a downloaded review-artifact root (containing
native-artifact/) or the native-artifact/ directory itself. A nonempty subset of
the supported targets is allowed, matching container.yml release preflight.
"""

import argparse
import hashlib
import json
import re
import stat
import tarfile
import zipfile
from pathlib import Path


REPOSITORY = "https://github.com/handshake-rs/hns-node-rs"
TARGETS = {
    "x86_64-unknown-linux-gnu": ("hsrd", ".tar.gz"),
    "aarch64-apple-darwin": ("hsrd", ".tar.gz"),
    "x86_64-apple-darwin": ("hsrd", ".tar.gz"),
    "x86_64-pc-windows-msvc": ("hsrd.exe", ".zip"),
}
NOTICE_PATHS = (
    "LICENSE-ISC",
    "THIRD_PARTY_NOTICES.md",
    "LICENSES/Apache-2.0.txt",
    "LICENSES/GPL-3.0-or-later.txt",
    "LICENSES/LGPL-3.0-or-later.txt",
    "vendor/goosig/LICENSE",
    "vendor/secp256k1/COPYING",
)
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
HEX_GIT_ID = re.compile(r"[0-9a-f]{40}\Z")


def fail(message: str) -> None:
    raise ValueError(message)


def require_keys(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} must have exactly these keys: {', '.join(sorted(keys))}")
    return value


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not HEX_SHA256.fullmatch(value):
        fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def unique_json_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def member_digest(stream, size: int, name: str) -> tuple[str, bytes | None]:
    limit = 1024 * 1024 * 1024 if name in ("hsrd", "hsrd.exe") else 16 * 1024 * 1024
    if size < 1 or size > limit:
        fail(f"invalid uncompressed size for {name}: {size}")
    digest = hashlib.sha256()
    content = bytearray() if name == "README.md" else None
    count = 0
    while chunk := stream.read(min(1024 * 1024, size - count)):
        count += len(chunk)
        digest.update(chunk)
        if content is not None:
            content.extend(chunk)
        if count > size:
            fail(f"archive member exceeds declared size: {name}")
    if count != size:
        fail(f"truncated archive member: {name}")
    return digest.hexdigest(), bytes(content) if content is not None else None


def validate_archive(archive_path: Path, root: str, executable: str, suffix: str,
                     version: str, target: str, commit: str) -> str:
    required = {executable, "README.md", *NOTICE_PATHS}
    observed = {}
    if suffix == ".zip":
        with zipfile.ZipFile(archive_path) as archive:
            entries = archive.infolist()
            if len(entries) != len(required):
                fail(f"{archive_path.name} has an unexpected number of entries")
            for info in entries:
                prefix = f"{root}/"
                if not info.filename.startswith(prefix):
                    fail(f"unexpected archive path: {info.filename}")
                name = info.filename[len(prefix):]
                if name not in required or name in observed or info.is_dir():
                    fail(f"unexpected or duplicate archive member: {info.filename}")
                if info.flag_bits & 1 or stat.S_IFMT(info.external_attr >> 16) not in (0, stat.S_IFREG):
                    fail(f"encrypted or non-regular archive member: {info.filename}")
                if name == executable and not (info.external_attr >> 16) & 0o111:
                    fail(f"executable has no execute bit: {info.filename}")
                with archive.open(info) as stream:
                    observed[name] = member_digest(stream, info.file_size, name)
    else:
        with tarfile.open(archive_path, "r:gz") as archive:
            entries = archive.getmembers()
            if len(entries) != len(required):
                fail(f"{archive_path.name} has an unexpected number of entries")
            for info in entries:
                prefix = f"{root}/"
                if not info.name.startswith(prefix):
                    fail(f"unexpected archive path: {info.name}")
                name = info.name[len(prefix):]
                if name not in required or name in observed or not info.isfile():
                    fail(f"unexpected or non-regular archive member: {info.name}")
                if name == executable and not info.mode & 0o111:
                    fail(f"executable has no execute bit: {info.name}")
                stream = archive.extractfile(info)
                if stream is None:
                    fail(f"unreadable archive member: {info.name}")
                with stream:
                    observed[name] = member_digest(stream, info.size, name)
    if set(observed) != required:
        fail(f"{archive_path.name} is missing required archive members")
    try:
        readme = observed["README.md"][1].decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"{archive_path.name} has a non-UTF-8 README: {error}")
    if not readme.startswith(f"# hsrd v{version} for {target}\n") or \
            f"Source: {REPOSITORY}/tree/{commit}\n" not in readme:
        fail(f"{archive_path.name} README does not identify the exact target and source")
    return observed[executable][0]


def artifact_files(directory: Path) -> Path:
    if not directory.is_dir() or directory.is_symlink():
        fail(f"artifact directory is missing or is a symlink: {directory}")
    children = {path.name: path for path in directory.iterdir()}
    if "native-artifact" in children:
        if set(children) - {"native-artifact", "native-logs"}:
            fail(f"unexpected files in downloaded artifact root: {directory}")
        if "native-logs" in children and not children["native-logs"].is_dir():
            fail(f"native-logs is not a directory: {directory}")
        directory = children["native-artifact"]
        if not directory.is_dir() or directory.is_symlink():
            fail(f"native-artifact is not a regular directory: {directory}")
    return directory


def inspect_artifact(directory: Path, tag: str, version: str,
                     commit: str, tree: str) -> dict:
    files_dir = artifact_files(directory)
    files = {path.name: path for path in files_dir.iterdir()}
    provenance_names = [name for name in files if name.endswith(".provenance.json")]
    if len(provenance_names) != 1:
        fail(f"expected one per-target provenance file in {files_dir}")
    match = re.fullmatch(
        rf"hsrd-v{re.escape(version)}-(.+)\.provenance\.json",
        provenance_names[0],
    )
    if not match or match.group(1) not in TARGETS:
        fail(f"unknown target or version in {provenance_names[0]}")
    target = match.group(1)
    executable, suffix = TARGETS[target]
    stem = f"hsrd-v{version}-{target}"
    archive_name = stem + suffix
    expected_files = {archive_name, f"{stem}.provenance.json", f"{stem}.sha256"}
    if set(files) != expected_files:
        fail(f"{files_dir} must contain exactly {', '.join(sorted(expected_files))}")
    for path in files.values():
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            fail(f"missing, empty, or non-regular artifact: {path}")

    provenance = json.loads(files[f"{stem}.provenance.json"].read_text("utf-8"),
                            object_pairs_hook=unique_json_pairs)
    require_keys(provenance,
                 {"schema_version", "project", "program", "version", "source", "binaries"},
                 f"{stem} provenance")
    if type(provenance["schema_version"]) is not int or provenance["schema_version"] != 1 or \
            provenance["project"] != "hns-node-rs" or provenance["program"] != "hsrd" or \
            provenance["version"] != version:
        fail(f"{stem} provenance has incorrect project or version metadata")
    expected_source = {"repository": REPOSITORY, "tag": tag, "commit": commit, "tree": tree}
    if provenance["source"] != expected_source:
        fail(f"{stem} provenance does not match exact release source")
    binaries = provenance["binaries"]
    if not isinstance(binaries, list) or len(binaries) != 1:
        fail(f"{stem} provenance must contain exactly one binary")
    entry = require_keys(binaries[0], {"target", "archive", "binary"}, f"{stem} binary entry")
    archive = require_keys(entry["archive"], {"name", "sha256"}, f"{stem} archive")
    binary = require_keys(entry["binary"], {"sha256", "version_output"}, f"{stem} executable")
    if entry["target"] != target or archive["name"] != archive_name or \
            binary["version_output"] != f"hsrd {version}":
        fail(f"{stem} provenance does not match target archive or executable version")
    archive_hash = require_sha256(archive["sha256"], f"{stem} archive hash")
    binary_hash = require_sha256(binary["sha256"], f"{stem} executable hash")
    if sha256(files[archive_name]) != archive_hash:
        fail(f"{archive_name} does not match provenance checksum")
    checksum_text = files[f"{stem}.sha256"].read_text("ascii")
    if checksum_text != f"{archive_hash}  {archive_name}\n":
        fail(f"{stem}.sha256 does not match the archive")
    actual_binary_hash = validate_archive(files[archive_name], stem, executable, suffix,
                                          version, target, commit)
    if actual_binary_hash != binary_hash:
        fail(f"{archive_name} executable does not match provenance checksum")
    return entry


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", action="append", type=Path, required=True,
                        help="repeat for each selected successful per-target review artifact")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tree", required=True)
    args = parser.parse_args()
    tag_match = re.fullmatch(r"v([0-9]+\.[0-9]+\.[0-9]+)", args.tag)
    if not tag_match:
        parser.error("tag must be a stable v-prefixed three-component version")
    if not HEX_GIT_ID.fullmatch(args.commit) or not HEX_GIT_ID.fullmatch(args.tree):
        parser.error("commit and tree must be full lowercase SHA-1 object IDs")
    version = tag_match.group(1)
    try:
        seen_paths = set()
        entries = {}
        for directory in args.artifact_dir:
            resolved = directory.resolve(strict=True)
            if resolved in seen_paths:
                fail(f"duplicate review artifact directory: {resolved}")
            seen_paths.add(resolved)
            entry = inspect_artifact(resolved, args.tag, version, args.commit, args.tree)
            target = entry["target"]
            if target in entries:
                fail(f"duplicate review artifact target: {target}")
            entries[target] = entry
        if not entries:
            fail("at least one native review artifact is required")

        ordered = [entries[target] for target in TARGETS if target in entries]
        output = args.output_dir.resolve()
        output.mkdir(parents=True, exist_ok=True)
        provenance_path = output / "NATIVE-BUILD-PROVENANCE.json"
        checksum_path = output / "NATIVE-SHA256SUMS"
        aggregate = {
            "schema_version": 1,
            "project": "hns-node-rs",
            "program": "hsrd",
            "version": version,
            "source": {"repository": REPOSITORY, "tag": args.tag,
                       "commit": args.commit, "tree": args.tree},
            "binaries": ordered,
        }
        provenance_path.write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n",
                                   encoding="utf-8")
        lines = [f'{entry["archive"]["sha256"]}  {entry["archive"]["name"]}\n'
                 for entry in ordered]
        lines.append(f"{sha256(provenance_path)}  {provenance_path.name}\n")
        checksum_path.write_text("".join(lines), encoding="ascii")
        print(f"Validated {len(ordered)} native archive(s); wrote {provenance_path} and {checksum_path}")
    except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile, UnicodeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
