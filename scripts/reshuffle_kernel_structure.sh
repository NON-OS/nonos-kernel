#!/usr/bin/env bash
# Restructure kernel/src into pro-level layout

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
KERNEL="$ROOT/kernel/src"

mkdir -p "$KERNEL"/{arch/x86_64,drivers,memory,crypto,sched,syscall,kernel}

m() {
  local src="$1" dst="$2"
  [[ -e "$KERNEL/$src" ]] || return 0
  [[ -e "$KERNEL/$dst" ]] && { echo "skip $src → $dst"; return 0; }
  mv "$KERNEL/$src" "$KERNEL/$dst"
}

m gdt.rs             arch/x86_64/gdt.rs
m idt.rs             arch/x86_64/idt.rs
m interrupts.rs      arch/x86_64/interrupts.rs
m vga.rs             drivers/vga_text.rs
m serial.rs          drivers/serial.rs
m memory.rs          memory/paging.rs
m mem/mod.rs         memory/paging.rs
m heap.rs            memory/heap.rs
m crypto/mod.rs      crypto/vault.rs
m sched/mod.rs       sched/scheduler.rs
m syscall/mod.rs     syscall/mod.rs
m logger.rs          kernel/logger.rs
m cli.rs             kernel/cli.rs
m modules.rs         kernel/modules.rs

if [[ -f "$KERNEL/main.rs" ]]; then
  mv "$KERNEL/main.rs" "$KERNEL/bin_main.rs"
  echo "Renamed old main.rs → bin_main.rs (kept for ref)"
fi

echo "✅ Kernel tree reshuffle complete. Run: git status"
