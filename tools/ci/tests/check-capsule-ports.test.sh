#!/usr/bin/env bash
# Negative proof for tools/ci/check-capsule-ports.sh.
# Builds a synthetic capsule tree, asserts the helper detects a
# duplicate port, then asserts it accepts the same tree once the
# duplicate is removed.

set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../../.." && pwd)
helper="${repo_root}/tools/ci/check-capsule-ports.sh"

if [ ! -x "$helper" ]; then
    echo "missing helper: ${helper}" >&2
    exit 2
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "${work}/cap_a" "${work}/cap_b"
cat >"${work}/cap_a/spawn.rs" <<'RS'
const SERVICE_PORT: u32 = 9100;
const REPLY_PORT: u32 = 9101;
RS
cat >"${work}/cap_b/spawn.rs" <<'RS'
const SERVICE_PORT: u32 = 9100;
const REPLY_PORT: u32 = 9103;
RS

if "$helper" "$work" >/dev/null 2>&1; then
    echo "FAIL: helper accepted a duplicate-port tree" >&2
    exit 1
fi

cat >"${work}/cap_b/spawn.rs" <<'RS'
const SERVICE_PORT: u32 = 9102;
const REPLY_PORT: u32 = 9103;
RS

if ! "$helper" "$work" >/dev/null 2>&1; then
    echo "FAIL: helper rejected a unique-port tree" >&2
    exit 1
fi

empty=$(mktemp -d)
trap 'rm -rf "$work" "$empty"' EXIT
if "$helper" "$empty" >/dev/null 2>&1; then
    echo "FAIL: helper accepted an empty tree" >&2
    exit 1
fi

echo "check-capsule-ports.test: PASS"
