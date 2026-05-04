#!/usr/bin/env bash
# NONOS Operating System
# Copyright (C) 2026 NONOS Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Boot-test harness for the keyring capsule path. Builds the kernel with
# the keyring capsule + smoketest features on, boots it under QEMU with
# serial captured to a log file, and grades the run by greping for
# deterministic markers in the log. No manual inspection.
#
# Not yet wired into CI; the boot-test workflow lane is contested. Run
# locally with `tests/boot/keyring_round_trip.sh`.

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
readonly LOG="${REPO_ROOT}/target/boot-test-keyring.log"
readonly TIMEOUT_SECS="${BOOT_TEST_TIMEOUT:-180}"

cd "${REPO_ROOT}"

# Resolve OVMF the same way ramfs_round_trip.sh does. Honours $OVMF if
# readable, otherwise walks the same ordered candidate list.
resolve_ovmf() {
    if [ -n "${OVMF:-}" ] && [ -r "${OVMF}" ]; then
        echo "${OVMF}"
        return 0
    fi
    for candidate in \
        /usr/share/OVMF/OVMF_CODE_4M.fd \
        /usr/share/OVMF/OVMF_CODE.fd \
        /usr/share/qemu/OVMF.fd \
        /usr/share/ovmf/OVMF.fd \
        /usr/share/edk2-ovmf/x64/OVMF_CODE.fd \
        /usr/share/edk2/ovmf/OVMF_CODE.fd \
        /opt/homebrew/share/qemu/edk2-x86_64-code.fd \
        /usr/local/share/qemu/edk2-x86_64-code.fd ; do
        if [ -r "${candidate}" ]; then
            echo "${candidate}"
            return 0
        fi
    done
    return 1
}

OVMF_PATH="$(resolve_ovmf)" || {
    echo "[harness] FAIL: no readable OVMF firmware found" >&2
    echo "[harness] looked under /usr/share/{OVMF,qemu,ovmf,edk2,edk2-ovmf} and homebrew/local prefixes" >&2
    echo "[harness] either install ovmf/edk2-ovmf or set OVMF=/path/to/OVMF_CODE.fd" >&2
    exit 1
}
echo "[harness] firmware: ${OVMF_PATH}"

echo "[harness] building brutal-minimum microkernel + capsules with keyring smoketest"
make nonos-mk-keyring-test >/dev/null

echo "[harness] packaging ESP and booting under QEMU (timeout ${TIMEOUT_SECS}s)"
make nonos-mk-esp >/dev/null
mkdir -p "$(dirname "${LOG}")"
: > "${LOG}"

# Pick the timeout tool. Linux ships `timeout` in coreutils; macOS does
# not. Fall back to `gtimeout` (homebrew coreutils) or perl `alarm`.
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD=(timeout "${TIMEOUT_SECS}")
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD=(gtimeout "${TIMEOUT_SECS}")
else
    TIMEOUT_CMD=(perl -e 'alarm shift; exec @ARGV or die "exec failed: $!"' "${TIMEOUT_SECS}")
fi

set +e
"${TIMEOUT_CMD[@]}" qemu-system-x86_64 \
    -m 2G -cpu max -smp 2 -machine q35 \
    -drive "format=raw,file=fat:rw:${REPO_ROOT}/target/esp" \
    -drive if=pflash,format=raw,readonly=on,file="${OVMF_PATH}" \
    -serial "file:${LOG}" -display none -no-reboot &
QEMU_PID=$!

EXPECTED=(
    "[INIT] Starting"
    "[KEYRING] capsule spawned"
    "[KEYRING-TEST] capsule alive"
    "[KEYRING-TEST] store ok"
    "[KEYRING-TEST] retrieve ok"
    "[KEYRING-TEST] lock ok"
    "[KEYRING-TEST] retrieve-locked denied"
    "[KEYRING-TEST] unlock ok"
    "[KEYRING-TEST] retrieve-unlocked ok"
    "[KEYRING-TEST] metadata ok"
    "[KEYRING-TEST] count ok"
    "[KEYRING-TEST] delete ok"
    "[KEYRING-TEST] retrieve-after-delete denied"
    "[KEYRING-TEST] PASS"
)

DEADLINE=$(( $(date +%s) + TIMEOUT_SECS ))
while [ $(date +%s) -lt ${DEADLINE} ]; do
    if grep -q '\[KEYRING-TEST\] PASS' "${LOG}" 2>/dev/null; then
        break
    fi
    if grep -q '\[KEYRING-TEST\] FAIL' "${LOG}" 2>/dev/null; then
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

if grep -qF '[KEYRING-TEST] FAIL' "${LOG}"; then
    echo "[harness] FAIL: smoketest reported failure"
    grep -F '[KEYRING-TEST] FAIL' "${LOG}"
    exit 1
fi

if [ ${MISSING} -ne 0 ]; then
    echo "[harness] FAIL: ${MISSING} expected markers missing"
    exit 1
fi

echo "[harness] PASS: all markers seen, keyring capsule round trip verified"
exit 0
