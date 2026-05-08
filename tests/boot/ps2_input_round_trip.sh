#!/usr/bin/env bash
# NONOS Operating System
# Copyright (C) 2026 NONOS Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Boot-test harness for the PS/2 input driver capsule. Builds
# the kernel with the driver capsule + smoketest features on,
# boots under QEMU with the legacy i8042 controller available
# (q35 + `-machine pcspk-audiodev` is irrelevant here; q35 keeps
# the i8042 by default). A QEMU monitor TCP socket is opened so
# the harness can inject a scancode pair via `sendkey` while the
# smoketest is polling. The kernel-side test counts events and
# the userland capsule's diagnostic counters.

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
readonly LOG="${REPO_ROOT}/target/boot-test-driver-ps2-input.log"
readonly MON_PORT="${PS2_TEST_MON_PORT:-45623}"
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

echo "[harness] building kernel with ps2-input smoketest"
make nonos-mk-driver-ps2-input-test >/dev/null

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

# q35 + the SeaBIOS/OVMF firmware leaves the legacy i8042 (PS/2)
# in place, so the capsule's discovery walk finds the synthetic
# platform device the kernel registers in
# `register_legacy_platform_devices`. The monitor on TCP gives
# the harness a handle for `sendkey`.
set +e
"${TIMEOUT_CMD[@]}" qemu-system-x86_64 \
    -m 2G -cpu max -smp 2 -machine q35 \
    -drive "format=raw,file=fat:rw:${REPO_ROOT}/target/esp" \
    -drive if=pflash,format=raw,readonly=on,file="${OVMF_PATH}" \
    -monitor "tcp:127.0.0.1:${MON_PORT},server,nowait" \
    -serial "file:${LOG}" -display none -no-reboot &
QEMU_PID=$!

# Inject a scancode pair once the capsule has had a chance to
# bind its IRQ and the kernel-side smoketest has reached its
# poll loop. The smoke retries the poll for a bounded number of
# attempts, so a brief delay before the keystroke is the right
# shape — we are not racing against a tight window.
inject_keys() {
    local deadline=$(( $(date +%s) + 60 ))
    while [ $(date +%s) -lt ${deadline} ]; do
        if grep -qF "[driver_ps2] endpoint driver.ps2_kbd0 ready" "${LOG}" 2>/dev/null; then
            break
        fi
        sleep 1
    done
    if command -v nc >/dev/null 2>&1; then
        printf 'sendkey a\nsendkey b\nsendkey c\n' | nc -w 2 127.0.0.1 "${MON_PORT}" >/dev/null 2>&1 || true
    fi
}
inject_keys &
INJECT_PID=$!

EXPECTED=(
    "[INIT] Starting"
    "[driver_ps2] endpoint driver.ps2_kbd0 ready"
    "[DRIVER-PS2-TEST] capsule alive"
    "[DRIVER-PS2-TEST] healthcheck ok"
    "[DRIVER-PS2-TEST] get_state ok"
    "[DRIVER-PS2-TEST] poll_events ok"
    "[DRIVER-PS2-TEST] counters advanced"
    "[DRIVER-PS2-TEST] PASS"
)

DEADLINE=$(( $(date +%s) + TIMEOUT_SECS ))
while [ $(date +%s) -lt ${DEADLINE} ]; do
    if grep -q '\[DRIVER-PS2-TEST\] PASS' "${LOG}" 2>/dev/null; then
        break
    fi
    if grep -q '\[DRIVER-PS2-TEST\] FAIL' "${LOG}" 2>/dev/null; then
        break
    fi
    if grep -q '\[FATAL\]' "${LOG}" 2>/dev/null; then
        break
    fi
    sleep 1
done

kill "${INJECT_PID}" 2>/dev/null || true
wait "${INJECT_PID}" 2>/dev/null || true
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

if grep -qF '[DRIVER-PS2-TEST] FAIL' "${LOG}"; then
    echo "[harness] FAIL: smoketest reported failure"
    grep -F '[DRIVER-PS2-TEST] FAIL' "${LOG}"
    exit 1
fi

if [ ${MISSING} -ne 0 ]; then
    echo "[harness] FAIL: ${MISSING} expected markers missing"
    exit 1
fi

echo "[harness] PASS: all markers seen, ps2 input driver capsule round trip verified"
exit 0
