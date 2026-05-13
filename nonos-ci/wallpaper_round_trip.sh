#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "${repo_root}"

serial_log="/tmp/nonos-wallpaper-smoke-$$.log"
rm -f "${serial_log}"
gui_mode="${WALLPAPER_SMOKE_GUI:-0}"
hold_on_pass="${WALLPAPER_SMOKE_HOLD_ON_PASS:-0}"

run_with_timeout() {
    local seconds="$1"
    shift
    if command -v gtimeout >/dev/null 2>&1; then
        gtimeout "${seconds}" "$@"
    elif command -v timeout >/dev/null 2>&1; then
        timeout "${seconds}" "$@"
    else
        perl -e 'alarm shift; exec @ARGV' "${seconds}" "$@"
    fi
}

find_ovmf_code() {
    for f in \
        firmware/OVMF.fd \
        /opt/homebrew/share/qemu/edk2-x86_64-code.fd \
        /usr/local/share/qemu/edk2-x86_64-code.fd \
        /usr/share/OVMF/OVMF_CODE_4M.fd \
        /usr/share/OVMF/OVMF_CODE.fd \
        /usr/share/qemu/OVMF.fd \
        /usr/share/ovmf/OVMF.fd; do
        if [ -r "${f}" ]; then
            printf '%s\n' "${f}"
            return 0
        fi
    done
    return 1
}

find_ovmf_vars() {
    for f in \
        firmware/OVMF_VARS.fd \
        /opt/homebrew/share/qemu/edk2-i386-vars.fd \
        /usr/local/share/qemu/edk2-i386-vars.fd \
        /usr/share/OVMF/OVMF_VARS_4M.fd \
        /usr/share/OVMF/OVMF_VARS.fd \
        /usr/share/qemu/OVMF_VARS.fd \
        /usr/share/ovmf/OVMF_VARS.fd; do
        if [ -r "${f}" ]; then
            printf '%s\n' "${f}"
            return 0
        fi
    done
    return 1
}

echo "[wallpaper-smoke] build profile: microkernel-wallpaper-smoketest"
make nonos-mk-wallpaper-test
echo "[wallpaper-smoke] build bootloader: dev-qemu"
(cd nonos-bootloader && cargo build --target x86_64-unknown-uefi --release --features "zk-groth16,dev-qemu")
echo "[wallpaper-smoke] prepare esp"
make nonos-mk-esp
cp nonos-bootloader/target/x86_64-unknown-uefi/release/nonos_boot.efi target/esp/EFI/Boot/BOOTX64.EFI

qemu_bin="qemu-system-x86_64"
ovmf_code="$(find_ovmf_code || true)"
ovmf_vars="$(find_ovmf_vars || true)"
if [ -z "${ovmf_code}" ] || [ -z "${ovmf_vars}" ]; then
    echo "[wallpaper-smoke] FAIL: OVMF firmware files not found"
    exit 1
fi

echo "[wallpaper-smoke] booting serial profile"
echo "[wallpaper-smoke] waiting up to 240s for boot markers..."
echo "[wallpaper-smoke] serial log: ${serial_log}"
if [ "${gui_mode}" = "1" ]; then
    echo "[wallpaper-smoke] GUI mode enabled"
fi
if [ "${hold_on_pass}" = "1" ]; then
    echo "[wallpaper-smoke] hold-on-pass enabled (Ctrl+A then X to quit QEMU)"
fi
boot_started="$(date +%s)"
touch "${serial_log}"
if [ "${gui_mode}" = "1" ]; then
    "${qemu_bin}" -m 2G -cpu max -smp 2 -machine q35 \
        -drive "format=raw,file=fat:rw:target/esp" \
        -drive if=pflash,format=raw,readonly=on,file="${ovmf_code}" \
        -drive if=pflash,format=raw,unit=1,readonly=on,file="${ovmf_vars}" \
        -device virtio-rng-pci \
    -serial "file:${serial_log}" -monitor none -vga std -no-reboot >/dev/null 2>&1 &
else
    "${qemu_bin}" -m 2G -cpu max -smp 2 -machine q35 \
        -drive "format=raw,file=fat:rw:target/esp" \
        -drive if=pflash,format=raw,readonly=on,file="${ovmf_code}" \
        -drive if=pflash,format=raw,unit=1,readonly=on,file="${ovmf_vars}" \
        -device virtio-rng-pci \
        -serial "file:${serial_log}" -monitor none -display none -no-reboot >/dev/null 2>&1 &
fi
qemu_pid=$!
boot_rc=124

for _ in $(seq 1 240); do
    if ! kill -0 "${qemu_pid}" >/dev/null 2>&1; then
        wait "${qemu_pid}" || true
        boot_rc=$?
        break
    fi

    if grep -qF "[wallpaper] PASS" "${serial_log}"; then
        boot_rc=0
        if [ "${hold_on_pass}" != "1" ]; then
            kill "${qemu_pid}" >/dev/null 2>&1 || true
            wait "${qemu_pid}" || true
        fi
        break
    fi
    if grep -qF "[NONOS] wallpaper: exec failed" "${serial_log}" || grep -qF "[wallpaper] FAIL" "${serial_log}"; then
        boot_rc=1
        kill "${qemu_pid}" >/dev/null 2>&1 || true
        wait "${qemu_pid}" || true
        break
    fi
    sleep 1
done

if kill -0 "${qemu_pid}" >/dev/null 2>&1; then
    kill "${qemu_pid}" >/dev/null 2>&1 || true
    wait "${qemu_pid}" || true
fi

boot_ended="$(date +%s)"
echo "[wallpaper-smoke] boot rc: ${boot_rc}"
echo "[wallpaper-smoke] boot seconds: $((boot_ended - boot_started))"
if [ "${boot_rc}" -ne 0 ] && [ "${boot_rc}" -ne 124 ] && [ "${boot_rc}" -ne 143 ]; then
    echo "[wallpaper-smoke] FAIL: boot command exited ${boot_rc}"
    cat "${serial_log}"
    exit 1
fi

if ! grep -qF "[NONOS] wallpaper: launching from /capsules/wallpaper" "${serial_log}"; then
    echo "[wallpaper-smoke] FAIL: wallpaper launch path not reached"
    cat "${serial_log}"
    exit 1
fi

if grep -qF "[NONOS] wallpaper: exec failed" "${serial_log}"; then
    echo "[wallpaper-smoke] FAIL: wallpaper exec_process failed"
    cat "${serial_log}"
    exit 1
fi

line_prev=0
for marker in \
    "[wallpaper] display ok" \
    "[wallpaper] surface created" \
    "[wallpaper] surface filled" \
    "[wallpaper] present ok" \
    "[wallpaper] PASS"; do
    line_now="$(grep -nF "${marker}" "${serial_log}" | head -n1 | cut -d: -f1 || true)"
    if [ -z "${line_now}" ]; then
        echo "[wallpaper-smoke] FAIL: missing marker: ${marker}"
        cat "${serial_log}"
        exit 1
    fi
    if [ "${line_now}" -le "${line_prev}" ]; then
        echo "[wallpaper-smoke] FAIL: marker out of order: ${marker}"
        cat "${serial_log}"
        exit 1
    fi
    line_prev="${line_now}"
done

echo "[wallpaper-smoke] PASS"
