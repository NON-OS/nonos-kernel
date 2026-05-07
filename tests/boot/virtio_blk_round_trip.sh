#!/usr/bin/env bash
# NONOS Operating System
# Copyright (C) 2026 NONOS Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Boot-test harness for the virtio-blk driver capsule. Builds the
# kernel with the driver capsule + smoketest features on,
# attaches a scratch raw disk to QEMU as a `virtio-blk-pci`
# device, captures serial to a log, and greps for the
# deterministic marker set the kernel-side smoketest emits.

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
readonly LOG="${REPO_ROOT}/target/boot-test-driver-virtio-blk.log"
readonly DISK="${REPO_ROOT}/target/test-virtio-blk.img"
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

echo "[harness] building kernel with virtio-blk smoketest"
make nonos-mk-driver-virtio-blk-test >/dev/null

echo "[harness] preparing scratch disk image at ${DISK}"
make nonos-mk-virtio-blk-test-image >/dev/null

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

# `-drive file=...,if=none` plus `-device virtio-blk-pci,drive=`
# is the canonical attach pattern. The userland driver discovery
# walk picks the device up by vendor 0x1AF4 / device 0x1001 or
# 0x1042. The disk is sparse and writable; the smoke pattern
# lives at LBA 64.
set +e
"${TIMEOUT_CMD[@]}" qemu-system-x86_64 \
    -m 2G -cpu max -smp 2 -machine q35 \
    -drive "format=raw,file=fat:rw:${REPO_ROOT}/target/esp" \
    -drive if=pflash,format=raw,readonly=on,file="${OVMF_PATH}" \
    -drive "file=${DISK},if=none,id=vd0,format=raw" \
    -device virtio-blk-pci,drive=vd0 \
    -serial "file:${LOG}" -display none -no-reboot &
QEMU_PID=$!

EXPECTED=(
    "[INIT] Starting"
    "[driver_blk] discover ok"
    "[driver_blk] claim ok"
    "[driver_blk] mmio ok"
    "[driver_blk] irq ok"
    "[driver_blk] dma ok"
    "[driver_blk] virtqueue ok"
    "[driver_blk] capacity ok"
    "[driver_blk] endpoint driver.virtio_blk0 ready"
    "[DRIVER-BLK-TEST] capsule alive"
    "[DRIVER-BLK-TEST] healthcheck ok"
    "[DRIVER-BLK-TEST] capacity ok"
    "[DRIVER-BLK-TEST] read block 0 ok"
    "[DRIVER-BLK-TEST] write/read round trip ok"
    "[DRIVER-BLK-TEST] PASS"
)

DEADLINE=$(( $(date +%s) + TIMEOUT_SECS ))
while [ $(date +%s) -lt ${DEADLINE} ]; do
    if grep -q '\[DRIVER-BLK-TEST\] PASS' "${LOG}" 2>/dev/null; then
        break
    fi
    if grep -q '\[DRIVER-BLK-TEST\] FAIL' "${LOG}" 2>/dev/null; then
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

if grep -qF '[DRIVER-BLK-TEST] FAIL' "${LOG}"; then
    echo "[harness] FAIL: smoketest reported failure"
    grep -F '[DRIVER-BLK-TEST] FAIL' "${LOG}"
    exit 1
fi

if [ ${MISSING} -ne 0 ]; then
    echo "[harness] FAIL: ${MISSING} expected markers missing"
    exit 1
fi

echo "[harness] PASS: all markers seen, virtio-blk driver capsule round trip verified"
exit 0
