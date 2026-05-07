#!/usr/bin/env bash
# NONOS Operating System
# Copyright (C) 2026 NONOS Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Boot-test harness for the virtio-net driver capsule. Builds
# the kernel with the driver capsule + smoketest features on,
# attaches a `virtio-net-pci` device to QEMU backed by
# `-netdev user`, captures serial to a log, and greps for the
# deterministic marker set the kernel-side smoketest emits.

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
readonly LOG="${REPO_ROOT}/target/boot-test-driver-virtio-net.log"
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

echo "[harness] building kernel with virtio-net smoketest"
make nonos-mk-driver-virtio-net-test >/dev/null

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

# `-netdev user` gives the guest a SLIRP-backed NAT interface;
# `-device virtio-net-pci` exposes the device the capsule's
# discovery walk picks up by vendor 0x1AF4 / device 0x1000 or
# 0x1041. The smoke does not assert reachability of any host
# service — it only proves the queue plumbing and frame round
# trip — so the network back-end choice is cosmetic.
set +e
"${TIMEOUT_CMD[@]}" qemu-system-x86_64 \
    -m 2G -cpu max -smp 2 -machine q35 \
    -drive "format=raw,file=fat:rw:${REPO_ROOT}/target/esp" \
    -drive if=pflash,format=raw,readonly=on,file="${OVMF_PATH}" \
    -netdev user,id=net0 \
    -device virtio-net-pci,netdev=net0 \
    -serial "file:${LOG}" -display none -no-reboot &
QEMU_PID=$!

EXPECTED=(
    "[INIT] Starting"
    "[driver_net] discover ok"
    "[driver_net] claim ok"
    "[driver_net] mmio ok"
    "[driver_net] irq ok"
    "[driver_net] dma ok"
    "[driver_net] virtqueue ok"
    "[driver_net] driver ok"
    "[driver_net] endpoint driver.virtio_net0 ready"
    "[DRIVER-NET-TEST] capsule alive"
    "[DRIVER-NET-TEST] healthcheck ok"
    "[DRIVER-NET-TEST] mac ok"
    "[DRIVER-NET-TEST] link_status ok"
    "[DRIVER-NET-TEST] tx_packet ok"
    "[DRIVER-NET-TEST] oversized denied"
    "[DRIVER-NET-TEST] PASS"
)

DEADLINE=$(( $(date +%s) + TIMEOUT_SECS ))
while [ $(date +%s) -lt ${DEADLINE} ]; do
    if grep -q '\[DRIVER-NET-TEST\] PASS' "${LOG}" 2>/dev/null; then
        break
    fi
    if grep -q '\[DRIVER-NET-TEST\] FAIL' "${LOG}" 2>/dev/null; then
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

if grep -qF '[DRIVER-NET-TEST] FAIL' "${LOG}"; then
    echo "[harness] FAIL: smoketest reported failure"
    grep -F '[DRIVER-NET-TEST] FAIL' "${LOG}"
    exit 1
fi

if [ ${MISSING} -ne 0 ]; then
    echo "[harness] FAIL: ${MISSING} expected markers missing"
    exit 1
fi

echo "[harness] PASS: all markers seen, virtio-net driver capsule round trip verified"
exit 0
