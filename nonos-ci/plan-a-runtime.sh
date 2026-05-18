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
OVMF_CODE="/usr/local/share/qemu/edk2-x86_64-code.fd"
ESP_DIR="target/esp"

: > "$SER"

if [ ! -f "$ESP_DIR/EFI/nonos/kernel.bin" ]; then
  echo "FATAL: $ESP_DIR not packaged; run 'make nonos-mk-esp' first" | tee "$RES"
  exit 2
fi

qemu-system-x86_64 \
  -accel tcg -machine q35 -cpu max -m 4G -smp 2 \
  -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE" \
  -drive "format=raw,file=fat:rw:$ESP_DIR" \
  -device virtio-gpu-pci -device virtio-rng-pci \
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
