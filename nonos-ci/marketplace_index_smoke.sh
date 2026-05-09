#!/usr/bin/env bash
# NONOS Operating System
# Copyright (C) 2026 NONOS Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Marketplace-index CLI smoke. Exercises the full host-side
# pipeline end-to-end: keygen, sign empty index, verify with
# right pubkey, refuse wrong pubkey, refuse mutated body, refuse
# serial rollback. Produces no persistent artifacts.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST_TARGET="$(rustc -vV | awk '/^host:/{print $2}')"
TOOL="${ROOT}/nonos-mk/target/${HOST_TARGET}/release/marketplace-index"

if [ ! -x "${TOOL}" ]; then
    (cd "${ROOT}" && make nonos-mk-marketplace-index-tool >/dev/null)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
cd "${WORK}"

cat > index.json <<'JSON'
{
  "schema_version": 1,
  "operator_id": "smoke.marketplace.v1",
  "published_at_ms": 1700000000000,
  "serial": 1,
  "entries": []
}
JSON

"${TOOL}" keygen --out seed >/dev/null
PUB="$("${TOOL}" sign --in index.json --key-file seed --out empty.bin 2>/dev/null \
    | awk '/operator_pubkey/{print $2}')"

# Wire-format truth: first u32 must be schema_version=1 LE.
head -c 4 empty.bin | xxd -p | grep -q '^01000000$' \
    || { echo "FAIL: empty.bin does not start with 01 00 00 00"; exit 1; }

# Right pubkey verifies clean.
"${TOOL}" verify --in empty.bin --pubkey "${PUB}" >/dev/null \
    || { echo "FAIL: verify with correct pubkey rejected"; exit 1; }

# Wrong pubkey is rejected with the operator-mismatch exit code.
set +e
"${TOOL}" verify --in empty.bin \
    --pubkey 0000000000000000000000000000000000000000000000000000000000000000 \
    >/dev/null 2>&1
RC=$?
set -e
[ "${RC}" -eq 7 ] || { echo "FAIL: wrong-pubkey rc=${RC}, expected 7"; exit 1; }

# A flipped body byte breaks the signature (rc=6). Pick a byte
# inside the `serial` field so the operator_pubkey crosscheck
# still passes and we exercise the signature-verify branch.
cp empty.bin mutated.bin
printf '\xff' | dd of=mutated.bin bs=1 seek=70 count=1 conv=notrunc 2>/dev/null
set +e
"${TOOL}" verify --in mutated.bin --pubkey "${PUB}" >/dev/null 2>&1
RC=$?
set -e
[ "${RC}" -eq 6 ] || { echo "FAIL: mutated rc=${RC}, expected 6"; exit 1; }

# Serial rollback (--previous-serial >= current) is refused with rc=8.
set +e
"${TOOL}" verify --in empty.bin --pubkey "${PUB}" --previous-serial 1 \
    >/dev/null 2>&1
RC=$?
set -e
[ "${RC}" -eq 8 ] || { echo "FAIL: rollback rc=${RC}, expected 8"; exit 1; }

# Serial rollback at sign time as well.
set +e
"${TOOL}" sign --in index.json --key-file seed --out /dev/null \
    --previous-serial 1 >/dev/null 2>&1
RC=$?
set -e
[ "${RC}" -eq 8 ] || { echo "FAIL: sign rollback rc=${RC}, expected 8"; exit 1; }

# Pubkey crosscheck mismatch at sign time.
set +e
"${TOOL}" sign --in index.json --key-file seed --out /dev/null \
    --pubkey 0000000000000000000000000000000000000000000000000000000000000000 \
    >/dev/null 2>&1
RC=$?
set -e
[ "${RC}" -eq 7 ] || { echo "FAIL: sign crosscheck rc=${RC}, expected 7"; exit 1; }

echo "marketplace-index smoke: PASS"
