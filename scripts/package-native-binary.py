#!/usr/bin/env python3
"""Package one verified hsrd binary for review in a GitHub Actions artifact."""

import argparse
import gzip
import hashlib
import io
import json
import re
import subprocess
import tarfile
import tomllib
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


def git(repo: Path, revision: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "--verify", revision],
        text=True,
    ).strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tar_member(archive: tarfile.TarFile, name: str, data: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = 0
    info.mode = mode
    info.uid = 0
    info.gid = 0
    archive.addfile(info, io.BytesIO(data))


def zip_member(archive: zipfile.ZipFile, name: str, data: bytes, mode: int) -> None:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = mode << 16
    archive.writestr(info, data)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tree", required=True)
    args = parser.parse_args()

    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.version):
        parser.error("version must be a three-component numeric version")
    if args.tag != f"v{args.version}":
        parser.error("tag and version do not match")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        parser.error("commit must be a full SHA-1 object ID")
    if not re.fullmatch(r"[0-9a-f]{40}", args.tree):
        parser.error("tree must be a full SHA-1 object ID")

    repo = args.repo_root.resolve(strict=True)
    binary = args.binary.resolve(strict=True)
    if not binary.is_file():
        parser.error("binary is not a regular file")
    with (repo / "Cargo.toml").open("rb") as stream:
        version = tomllib.load(stream)["workspace"]["package"]["version"]
    if version != args.version:
        parser.error("source workspace version does not match requested version")
    if git(repo, "HEAD") != args.commit or git(repo, "HEAD^{tree}") != args.tree:
        parser.error("source checkout does not match requested commit and tree")
    if git(repo, f"refs/tags/{args.tag}^{{commit}}") != args.commit:
        parser.error("tag does not peel to the requested commit")

    version_output = subprocess.check_output([str(binary), "--version"], text=True).strip()
    if version_output != f"hsrd {args.version}":
        parser.error(f"unexpected binary version: {version_output!r}")

    executable_name, suffix = TARGETS[args.target]
    stem = f"hsrd-v{args.version}-{args.target}"
    archive_name = stem + suffix
    root_name = stem
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    archive_path = output / archive_name

    readme = (
        f"# hsrd v{args.version} for {args.target}\n\n"
        f"Source: {REPOSITORY}/tree/{args.commit}\n"
        f"Run `{executable_name} --version` and `{executable_name} --check-config` "
        "before configuring a node. This binary was built and tested on the "
        "target platform in GitHub Actions.\n\n"
        "The matching relinkable source archive is available in the GitHub "
        f"release at {REPOSITORY}/releases/tag/{args.tag}. "
        "See THIRD_PARTY_NOTICES.md and the included licenses.\n\n"
        "Linux GNU builds use the Debian Bookworm glibc generation and link "
        "against system OpenSSL 3, libstdc++, zlib, and zstd. macOS builds "
        "target macOS 13 or newer and link only Apple system libraries. "
        "Windows builds use the native MSVC toolchain.\n"
    ).encode("utf-8")
    members = [(executable_name, binary.read_bytes(), 0o755), ("README.md", readme, 0o644)]
    for relative in NOTICE_PATHS:
        members.append((relative, (repo / relative).read_bytes(), 0o644))

    if suffix == ".zip":
        with zipfile.ZipFile(archive_path, "w") as archive:
            for name, data, mode in members:
                zip_member(archive, f"{root_name}/{name}", data, mode)
    else:
        with archive_path.open("wb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                    for name, data, mode in members:
                        tar_member(archive, f"{root_name}/{name}", data, mode)

    archive_hash = sha256(archive_path)
    provenance = {
        "schema_version": 1,
        "project": "hns-node-rs",
        "program": "hsrd",
        "version": args.version,
        "source": {
            "repository": REPOSITORY,
            "tag": args.tag,
            "commit": args.commit,
            "tree": args.tree,
        },
        "binaries": [
            {
                "target": args.target,
                "archive": {"name": archive_name, "sha256": archive_hash},
                "binary": {"sha256": sha256(binary), "version_output": version_output},
            }
        ],
    }
    (output / f"{stem}.provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / f"{stem}.sha256").write_text(
        f"{archive_hash}  {archive_name}\n", encoding="ascii"
    )
    print(f"Created {archive_path} ({archive_hash})")


if __name__ == "__main__":
    main()
