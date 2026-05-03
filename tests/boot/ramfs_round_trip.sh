#!/usr/bin/env bash
# NONOS Operating System
# Copyright (C) 2026 NONOS Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Boot-test harness for the ramfs capsule path. Builds the kernel with
# the capsule and the smoketest features on, boots it under QEMU with
# serial captured to a log file, and grades the run by greping for
# deterministic markers in the log. No manual inspection.

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
readonly LOG="${REPO_ROOT}/target/boot-test-ramfs.log"
readonly TIMEOUT_SECS="${BOOT_TEST_TIMEOUT:-180}"

cd "${REPO_ROOT}"

echo "[harness] building capsule + kernel with smoketest feature"
make kernel-with-ramfs-smoketest >/dev/null

echo "[harness] packaging ESP and booting under QEMU (timeout ${TIMEOUT_SECS}s)"
make esp >/dev/null
mkdir -p "$(dirname "${LOG}")"
: > "${LOG}"

set +e
timeout "${TIMEOUT_SECS}" qemu-system-x86_64 \
    -m 2G -cpu max -smp 2 -machine q35 \
    -drive "format=raw,file=fat:rw:${REPO_ROOT}/target/esp" \
    -drive if=pflash,format=raw,readonly=on,file="${OVMF:-/usr/share/OVMF/OVMF_CODE.fd}" \
    -serial "file:${LOG}" -display none -no-reboot &
QEMU_PID=$!

EXPECTED=(
    "[INIT] Starting"
    "[RAMFS] capsule spawned"
    "[RAMFS-TEST] open ok"
    "[RAMFS-TEST] write ok"
    "[RAMFS-TEST] read ok"
    "[RAMFS-TEST] truncate ok"
    "[RAMFS-TEST] close ok"
    "[RAMFS-TEST] PASS"
)

DEADLINE=$(( $(date +%s) + TIMEOUT_SECS ))
while [ $(date +%s) -lt ${DEADLINE} ]; do
    if grep -q '\[RAMFS-TEST\] PASS' "${LOG}" 2>/dev/null; then
        break
    fi
    if grep -q '\[RAMFS-TEST\] FAIL' "${LOG}" 2>/dev/null; then
        break
    fi
    if grep -q '\[FATAL\]' "${LOG}" 2>/dev/null; then
        break
    fi
    sleep 1
done

kill "${QEMU_PID}" 2>/dev/null || true
wait "${QEMU_PID}" 2>/dev/null || true
set -e

echo "[harness] verifying serial markers in ${LOG}"
MISSING=0
for marker in "${EXPECTED[@]}"; do
    if ! grep -qF "${marker}" "${LOG}"; then
        echo "  MISSING: ${marker}"
        MISSING=$((MISSING + 1))
    fi
done

if grep -qF '[RAMFS-TEST] FAIL' "${LOG}"; then
    echo "[harness] FAIL: smoketest reported failure"
    grep -F '[RAMFS-TEST] FAIL' "${LOG}"
    exit 1
fi

if [ ${MISSING} -ne 0 ]; then
    echo "[harness] FAIL: ${MISSING} expected markers missing"
    exit 1
fi

echo "[harness] PASS: all markers seen, ramfs capsule round trip verified"
exit 0
