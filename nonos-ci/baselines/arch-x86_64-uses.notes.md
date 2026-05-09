# `crate::arch::x86_64::*` baseline notes

The number in `arch-x86_64-uses.txt` only ever shrinks unless an
intentional bump is recorded here.

## Current breakdown (baseline 93)

- 67 long-standing or architecturally-correct refs:
  - `crate::arch::x86_64::cpu`, `time::*`, `interrupt::apic`, `idt`,
    `pci`, `vga`, `iommu`, `cpuid`, `watchdog`, `serial`
    (used by SMP, log, usercopy, scheduler, drivers, time path).
  - `boot/main/core_init.rs::arch::x86_64::gdt::init()` — Slice A
    (replaced the legacy `sys::gdt::setup`). Permanent.
  - `interrupts/handlers/exceptions/{page_fault,gpf,opcode}.rs::
    arch::x86_64::diag::dump_trap` — trap handlers are
    arch-coupled by definition. Permanent.

- 26 temporary diagnostic refs from the slice #74 observability
  pass. All marked for cleanup:
  - `process/userspace/asm.rs` (5): `dump_gdt`, `print_hex_u64` x4
    for the user-entry frame. Delete after iretq into CPL=3 is
    proven and the user side runs without #GP/#PF.
  - `process/scheduler/dispatch/run_queue.rs` (2),
    `process/scheduler/selection/switching.rs` (3),
    `interrupts/isr/timer_trampoline.rs` (2): `[SCHED]` traces.
  - `process/scheduler/selection/select.rs` (6): `[SCHED] select`
    trace, capped at 32 events per boot.
  - `syscall/microkernel/dispatch.rs` (4): `[SC]` trace +
    sc_kind/print, capped at 32 events.
  - `syscall/dispatch/router/mod.rs` (1): `[SYSCALL-UNKNOWN]`
    once-per-pid loud failure log on unmapped syscall numbers.
    Stays after cleanup; failing loud is the policy.
  - misc helper sites in the same diag pass.

## Cleanup track

- T1: CPL=3 proven without #GP → delete the 5 userspace/asm
  diagnostic refs.
- T2: introduce `crate::diag::*` shim and route the 17 sched / IPC
  / SC prints through it. The arch-x86_64 ref count drops by ~16
  (one ref per shim leaf instead of one per call site).
- T3: keep `[SYSCALL-UNKNOWN]` and the 3 trap-handler `dump_trap`
  refs as permanent loud-failure paths.
- T4: any further shrink is M-ARCH-0 work behind the Arch trait.

The baseline value must not grow without an entry here.
