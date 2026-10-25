#!/usr/bin/env python3
"""Validate generated reprepro package indexes against their pool files."""

import hashlib
import pathlib
import sys


def parse_stanzas(text):
    stanzas = []
    for raw in text.strip().split("\n\n"):
        fields = {}
        current = None
        for line in raw.splitlines():
            if line[:1] in (" ", "\t") and current:
                fields[current] += "\n" + line[1:]
                continue
            if ":" not in line:
                raise ValueError(f"malformed Packages line: {line!r}")
            current, value = line.split(":", 1)
            fields[current] = value.strip()
        if fields:
            stanzas.append(fields)
    return stanzas


def verify(root, version):
    root = pathlib.Path(root).resolve()
    expected = {"amd64", "arm64"}
    found = set()
    for arch in sorted(expected):
        index = root / "dists/stable/main" / f"binary-{arch}/Packages"
        if not index.is_file():
            raise ValueError(f"missing package index: {index}")
        for package in parse_stanzas(index.read_text(encoding="utf-8")):
            if package.get("Package") != "lnta":
                continue
            if package.get("Version") != version:
                continue
            if package.get("Architecture") != arch:
                continue
            rel = pathlib.PurePosixPath(package.get("Filename", ""))
            if rel.is_absolute() or ".." in rel.parts:
                raise ValueError(f"unsafe package filename: {rel}")
            artifact = (root / pathlib.Path(*rel.parts)).resolve()
            if root not in artifact.parents or not artifact.is_file():
                raise ValueError(f"missing or escaping package file: {rel}")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            if digest.lower() != package.get("SHA256", "").lower():
                raise ValueError(f"SHA256 mismatch for {rel}")
            if artifact.stat().st_size != int(package.get("Size", "-1")):
                raise ValueError(f"size mismatch for {rel}")
            found.add(arch)
    missing = expected - found
    if missing:
        raise ValueError(f"repository is missing lnta {version} for: {', '.join(sorted(missing))}")
    if not (root / "dists/stable/InRelease").is_file():
        raise ValueError("missing signed dists/stable/InRelease")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: verify-repository.py REPOSITORY_ROOT VERSION")
    try:
        verify(sys.argv[1], sys.argv[2])
    except (OSError, ValueError) as exc:
        sys.exit(f"APT repository validation failed: {exc}")
