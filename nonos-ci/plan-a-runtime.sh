#!/bin/zsh
# Deterministic Plan-A runtime lane.
# Boots the already-built ESP under TCG with a writable OVMF NVRAM store,
# a virtio-gpu + virtio-rng device, no host port forwarding, and a
# graceful shutdown so the synthetic FAT / NVRAM are never corrupted
# mid-write. Captures serial and reports the substrate marker chain.
set -u
cd "$(dirname "$0")/.."

TIMEOUT="${PLAN_A_TIMEOUT:-900}"
WORK="$(mktemp -d /tmp/plan_a_runtime.XXXXXX)"
SER="${PLAN_A_SERIAL:-/tmp/plan_a_serial.log}"
RES="${PLAN_A_RESULT:-/tmp/plan_a_result.log}"
QEMU_BIN="${QEMU:-qemu-system-x86_64}"
OVMF_CODE="${OVMF:-/usr/local/share/qemu/edk2-x86_64-code.fd}"
OVMF_VARS_TEMPLATE="${OVMF_VARS:-}"
OVMF_VARS_RW="${QEMU_OVMF_VARS_RW:-$WORK/OVMF_VARS.fd}"
QEMU_BLK_IMG="${QEMU_BLK_IMG:-$WORK/qemu-virtio-blk.img}"
ESP_DIR="${ESP_DIR:-target/esp}"

: > "$SER"

if [ ! -f "$ESP_DIR/EFI/nonos/kernel.bin" ]; then
  echo "FATAL: $ESP_DIR not packaged; run 'make nonos-mk-esp' first" | tee "$RES"
  exit 2
fi

if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
  echo "FATAL: QEMU binary not found: $QEMU_BIN" | tee "$RES"
  exit 2
fi

if [ ! -f "$OVMF_CODE" ]; then
  echo "FATAL: OVMF code image not found: $OVMF_CODE" | tee "$RES"
  exit 2
fi

if [ ! -f "$OVMF_VARS_RW" ]; then
  if [ -n "$OVMF_VARS_TEMPLATE" ] && [ -f "$OVMF_VARS_TEMPLATE" ]; then
    cp "$OVMF_VARS_TEMPLATE" "$OVMF_VARS_RW"
  else
    echo "FATAL: writable OVMF vars image not found: $OVMF_VARS_RW" | tee "$RES"
    exit 2
  fi
fi

if [ ! -f "$QEMU_BLK_IMG" ]; then
  truncate -s 64M "$QEMU_BLK_IMG"
fi

"$QEMU_BIN" \
  -accel tcg -machine q35 -cpu max -m 4G -smp 2 \
  -drive "if=pflash,format=raw,unit=0,readonly=on,file=$OVMF_CODE" \
  -drive "if=pflash,format=raw,unit=1,file=$OVMF_VARS_RW" \
  -drive "format=raw,file=fat:rw:$ESP_DIR" \
  -drive "file=$QEMU_BLK_IMG,if=none,id=vd0,format=raw" \
  -device virtio-blk-pci,drive=vd0 \
  -device virtio-gpu-pci,disable-modern=on,vectors=0 \
  -device qemu-xhci,id=xhci \
  -device usb-tablet,bus=xhci.0 \
  -device virtio-rng-pci \
  -serial "file:$SER" -display none -monitor none -no-reboot &
QPID=$!

DECISIVE='Hardware requirements not met|\[NONOS\] Handoff (OK|FAIL)|\[gfx\.virtio_gpu0\]|\[INIT\] Capsules spawned|KERNEL PANIC|PANIC'
hit=""
for i in $(seq 1 "$TIMEOUT"); do
  kill -0 "$QPID" 2>/dev/null || { hit="qemu-exited"; break; }
  if grep -qE "$DECISIVE" "$SER" 2>/dev/null; then hit="marker"; sleep 15; break; fi
  sleep 1
done

kill -TERM "$QPID" 2>/dev/null
for _ in $(seq 1 10); do kill -0 "$QPID" 2>/dev/null || break; sleep 1; done
kill -KILL "$QPID" 2>/dev/null
rm -rf "$WORK"

{
  echo "stop-reason: ${hit:-timeout}   serial-lines: $(wc -l <"$SER")"
  echo "=== chain markers ==="
  grep -nE "Handoff (OK|FAIL)|Hardware requirements|\[gfx\.virtio_gpu0\]|stage:|setup failed|DRIVER-VIRTIO-GPU|\[compositor\]|\[wm\] boot|\[desktop_shell\]|Capsules spawned|PANIC" "$SER" || echo "(none)"
  echo "=== last 20 serial lines ==="
  tail -20 "$SER"
} > "$RES" 2>&1
cat "$RES"
