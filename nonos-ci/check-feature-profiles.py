#!/usr/bin/env python3
# Reject Cargo.toml profiles that pull in legacy gates.
#
# Forbidden gates: nonos-legacy-tree, nonos-syscall-keyring.
# Profiles checked: default, microkernel-core, microkernel-capsules,
# microkernel-keyring-smoketest, microkernel.
#
# Parses through `cargo metadata` so the script does not need tomllib
# and runs anywhere cargo runs.

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FORBIDDEN = frozenset({"nonos-legacy-tree", "nonos-syscall-keyring"})
PROFILES = (
    "default",
    "microkernel-core",
    "microkernel-capsules",
    "microkernel-keyring-smoketest",
    "microkernel",
)


def cargo_metadata(manifest: Path) -> dict:
    cmd = ["cargo", "metadata", "--format-version", "1", "--no-deps",
           "--manifest-path", str(manifest)]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit(f"::error::cargo metadata failed for {manifest}")
    return json.loads(result.stdout)


def kernel_features(meta: dict) -> dict[str, list[str]]:
    for pkg in meta.get("packages", []):
        if pkg.get("name") == "nonos_kernel":
            return pkg.get("features", {})
    raise SystemExit("::error::package 'nonos_kernel' not found in cargo metadata")


def closure(features: dict[str, list[str]], root: str) -> set[str]:
    seen: set[str] = set()
    stack = [root]
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        for entry in features.get(name, []):
            if "/" in entry or entry.startswith("dep:"):
                continue
            stack.append(entry)
    return seen


def main(argv: list[str]) -> int:
    manifest = Path(argv[1]) if len(argv) > 1 else Path("Cargo.toml")
    if not manifest.is_file():
        print(f"::error::Cargo.toml not found at {manifest}", file=sys.stderr)
        return 1

    features = kernel_features(cargo_metadata(manifest))

    missing = [p for p in PROFILES if p not in features]
    if missing:
        for name in missing:
            print(f"::error file={manifest}::profile '{name}' is not declared",
                  file=sys.stderr)
        return 1

    failed = False
    for name in PROFILES:
        members = closure(features, name)
        hits = sorted(members & FORBIDDEN)
        if hits:
            print(f"::error file={manifest}::profile '{name}' transitively pulls in {hits}",
                  file=sys.stderr)
            failed = True
        else:
            print(f"[ok] {name}: {len(members) - 1} downstream features, no forbidden gates")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
