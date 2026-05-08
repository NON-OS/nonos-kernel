#!/usr/bin/env bash
# NONOS Operating System
# Copyright (C) 2026 NONOS Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Boot-test harness for the xHCI controller-bring-up capsule (P0).
# Builds the kernel with the driver capsule + smoketest features
# on, attaches `-device qemu-xhci` to QEMU, captures serial, and
# greps for the deterministic marker set the userland capsule and
# kernel-side smoketest emit.
#
# This proves the broker model can bring an xHCI host up and
# complete one controller command (No-op). It does NOT prove USB
# enumeration, transfers, or any device class.

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
readonly LOG="${REPO_ROOT}/target/boot-test-driver-xhci.log"
readonly TIMEOUT_SECS="${BOOT_TEST_TIMEOUT:-240}"

cd "${REPO_ROOT}"

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
    echo "[harness] either install ovmf/edk2-ovmf or set OVMF=/path/to/OVMF_CODE.fd" >&2
    exit 1
}
echo "[harness] firmware: ${OVMF_PATH}"

echo "[harness] building kernel with xhci smoketest"
make nonos-mk-driver-xhci-test >/dev/null

echo "[harness] packaging ESP and booting under QEMU (timeout ${TIMEOUT_SECS}s)"
make nonos-mk-esp >/dev/null
mkdir -p "$(dirname "${LOG}")"
: > "${LOG}"

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
    -device qemu-xhci,id=xhci0 \
    -serial "file:${LOG}" -display none -no-reboot &
QEMU_PID=$!

EXPECTED=(
    "[INIT] Starting"
    "[driver_xhci] discover ok"
    "[driver_xhci] claim ok"
    "[driver_xhci] mmio ok"
    "[driver_xhci] irq ok"
    "[driver_xhci] controller supported"
    "[driver_xhci] halt ok"
    "[driver_xhci] reset ok"
    "[driver_xhci] cnr cleared"
    "[driver_xhci] scratchpads ok"
    "[driver_xhci] dcbaa ok"
    "[driver_xhci] cmd ring ok"
    "[driver_xhci] evt ring ok"
    "[driver_xhci] running"
    "[driver_xhci] noop ok"
    "[driver_xhci] endpoint driver.xhci0 ready"
    "[DRIVER-XHCI-TEST] capsule alive"
    "[DRIVER-XHCI-TEST] healthcheck ok"
    "[DRIVER-XHCI-TEST] controller_status ok"
    "[DRIVER-XHCI-TEST] port_status ok"
    "[DRIVER-XHCI-TEST] PASS"
)

DEADLINE=$(( $(date +%s) + TIMEOUT_SECS ))
while [ $(date +%s) -lt ${DEADLINE} ]; do
    if grep -q '\[DRIVER-XHCI-TEST\] PASS' "${LOG}" 2>/dev/null; then
        break
    fi
    if grep -q '\[DRIVER-XHCI-TEST\] FAIL' "${LOG}" 2>/dev/null; then
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

if grep -qF '[DRIVER-XHCI-TEST] FAIL' "${LOG}"; then
    echo "[harness] FAIL: smoketest reported failure"
    grep -F '[DRIVER-XHCI-TEST] FAIL' "${LOG}"
    exit 1
fi

if [ ${MISSING} -ne 0 ]; then
    echo "[harness] FAIL: ${MISSING} expected markers missing"
    exit 1
fi

echo "[harness] PASS: controller-up smoke proven (P0). USB enumeration and class drivers remain out of scope."
exit 0
