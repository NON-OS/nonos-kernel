# NØNOS CPU and SMP model

This document is the SMP audit checkpoint. It states what the kernel
does today, what is honest single-CPU vs. SMP-shaped, and what must
change before broker MMIO/IRQ/DMA grant primitives can land safely
on real SMP hardware.

## 1. BSP / AP boot lifecycle

### Current state

- The active microkernel boot path (`nonos_main::_start` →
  `kernel_entry` → `boot::main::init_core_systems` →
  `kernel_core::init::microkernel_init`) does **not** call
  `crate::smp::init_bsp` or `crate::smp::start_aps`. Production
  builds run BSP-only at runtime today.
- The full SMP bring-up code (`src/smp/init.rs`) does exist and is
  reachable from the legacy `entry::kernel_main` path. That path is
  not on the live boot.
- BSP-side state: `process::scheduler::smp::init_smp_scheduler` is
  called from `sched::init()` in `microkernel_init`, so the per-CPU
  run-queue array is set up for CPU 0. `ACTIVE_CPU_COUNT = 1`.
  `SMP_INITIALIZED = true`.

### Honest classification

The kernel is **single-CPU at runtime**, with multi-CPU primitives
already coded but not on the live boot. SMP becomes live only after
the active boot wires `init_bsp` + `start_aps` into `core_init`.

## 2. AP stack allocation

### Current state

`smp::init::allocate_cpu_stack(cpu_id)` allocates `PERCPU_STACK_SIZE`
worth of frames per AP from the global frame allocator and maps them
at `layout::PERCPU_STACKS_BASE + cpu_id * PERCPU_STACK_SIZE`. One
stack per AP, mapped read-write in the kernel half of the address
space.

### Risk

`SAFE_BOOTSTRAP_ONLY`. Stacks are sized at compile time and indexed
by `cpu_id`. No stack guard page today; an AP stack overflow
silently runs into the next AP's stack. Adding a guard page is an
SMP-readiness item, not a single-CPU blocker.

## 3. Per-CPU GDT / IDT / TSS

### Current state

GDT is global today (`gdt::setup` runs once on the BSP). IDT is
global. TSS is global. `arch::x86_64::syscall::manager::entry`
programs `MSR_GS_BASE` and `MSR_KERNEL_GS_BASE` per CPU through
`smp::percpu::init_bsp`, but only for the BSP — no AP runs through
this path because `start_aps` is not invoked.

### Risk

`SMP_UNSAFE_NEEDS_FIX`. On real SMP each CPU needs its own TSS (so
the kernel-stack pointer for trap entry differs per CPU) and its
own MSR_GS_BASE pointing at that CPU's `PerCpuData`. The code to do
this exists in `smp::percpu`; it just is not wired to the AP boot
path.

## 4. Per-CPU kernel stack model

### Current state

`smp::init::allocate_cpu_stack` allocates one kernel stack per AP.
Per-process kernel stacks (allocated by
`kernel_core::process_spawn::allocate_kernel_stack`) are independent
of the per-CPU stack — a trap from CPL=3 lands on the per-CPU IST
stack, then the syscall path switches to the per-process kernel
stack via `gs:0x20`.

### Risk

`SMP_SAFE_GLOBAL_LOCK` for now. The model is correct in shape; the
only thing missing is the AP path. Per-process kernel stack lookup
goes through the PCB which is not per-CPU.

## 5. `CURRENT_PID` ownership

### Current state

`process::core::table::CURRENT_PID: AtomicU32` is a single global
written at every scheduler switch (`scheduler::selection::switching`)
and read by `current_pid()`, `fd_table::get_fd`,
`syscall::microkernel::process::sys_exit`, and several others.

### Risk

`SMP_UNSAFE_NEEDS_FIX` once SMP goes live. With one CPU, the global
is a correct identity. With more than one CPU it returns whichever
pid most recently scheduled on any CPU, which is not what any caller
wants. The fix is a per-CPU pointer (`gs:offset`), already partially
plumbed through `smp::percpu::set_current_process`. The cleanup is
deferred to the SMP-bring-up slice; it cannot be done before
`init_bsp`/`start_aps` are on the live path because there is nothing
to test against.

## 6. Scheduler state

### Current state

Two scheduler shapes coexist:

- `process::scheduler::dispatch::run_queue::PID_RUN_QUEUE: BTreeSet<u32>`,
  a single global RwLock'd set used by `add_to_run_queue`,
  `remove_from_run_queue`, and `is_in_run_queue`.
- `process::scheduler::smp::state::CPU_QUEUES: [Once<PerCpuRunQueue>; MAX_CPUS]`,
  one queue per CPU, populated only for CPU 0 today.

The active scheduler reads from the global `PID_RUN_QUEUE`. The
per-CPU queue array is initialized but the load-balancer
(`smp::tick`) only fires when `tick % LOAD_BALANCE_INTERVAL_TICKS ==
0 && cpu_id == 0`, so on a single-BSP system it is dormant.

### Risk

`SMP_SAFE_GLOBAL_LOCK` today (single CPU; the global RwLock is
correct). Becomes `SMP_UNSAFE_NEEDS_FIX` the moment APs come online
because two scheduling shapes would race. The fix is to commit to
one shape (per-CPU run queues plus a load balancer) before APs
start; that is its own slice.

## 7. Local timer model

### Current state

`crate::sys::timer::tsc::init_default` calibrates TSC against a
reference timer at boot. On the BSP this works. Local APIC timer
programming for periodic interrupts is per-CPU; `apic::init` runs
on the BSP only on the active path.

### Risk

`SAFE_BOOTSTRAP_ONLY` today. Each AP would need its own APIC timer
init when it comes online; the existing `apic::init` is BSP-shaped.

## 8. Interrupt nesting model

### Current state

Interrupts are masked during page-fault, double-fault, and other IST
trap entry by the IDT `IST_*` index assignment in
`arch::x86_64::gdt`. No software model for nesting beyond what the
IDT provides.

### Risk

`SAFE_BOOTSTRAP_ONLY`. Trap-from-trap on the same CPU is handled by
hardware IST switching. SMP does not change this layer.

## 9. TLB shootdown

### Current state

Every TLB invalidation today is local. `Arch::flush_tlb_one(addr)`
issues a single `invlpg`. `memory::paging::manager::flush_tlb` walks
the local CPU's TLB only. There is no IPI shootdown.

### Risk

`SMP_UNSAFE_NEEDS_FIX` for the moment two CPUs share an address
space. Required before:
- multi-threaded user processes (one process pinned to multiple CPUs),
- broker MMIO grants that get unmapped (a stale TLB on another CPU
  could write into freed physical memory).

The IPI plumbing exists in `smp::ipi`; the missing piece is a
"flush this VA range on these CPUs" abstraction that walks the
per-AS active-CPU set and sends TLB-shootdown IPIs.

## 10. Process exit on SMP

### Current state

`syscall::microkernel::process::sys_exit` calls
`broker::release_all_for_pid(pid)` then
`PROCESS_TABLE.terminate_process(pid)`. The latter only removes the
PCB from the table and the run queue. **It does not free user pages,
the per-process kernel stack, or the ASID.** That is a separate code
path (`address_space::lifecycle::release`) called only from the
legacy `process::core::api::syscalls::sys_exit`.

### Risk

`SMP_UNSAFE_NEEDS_FIX` and **also single-CPU correctness bug**.
Today every `MkExit` leaks the user pages, the kernel stack, and the
ASID. When SMP comes online this is also a TLB-shootdown problem
because the freed frames could be live in another CPU's TLB.

The fix is to consolidate exit teardown into one canonical function
(see `cpu_smp_model.md` next-slice section). The teardown today
should call `address_space::lifecycle::release` always; the SMP
shootdown call goes onto the same path when SMP goes live.

## 11. Broker claim / release / revocation on SMP

### Current state

`hardware::broker::claim` / `release` / `release_all_for_pid` use a
single `spin::Mutex<Vec<Claim>>`. Correct against concurrent claims
across CPUs. The exit hook in `sys_exit` calls
`release_all_for_pid` before terminating; under SMP this is still
correct because the lock serialises with any in-flight claim from
another CPU.

### Risk

`SMP_SAFE_GLOBAL_LOCK`. Becomes `SMP_UNSAFE_NEEDS_FIX` when grants
include MMIO/IRQ/DMA, because revocation needs to reach into other
CPUs' page tables and IRQ controllers. The revocation API today
returns the count of revoked claims; future MMIO/DMA revocation
must also issue TLB shootdown IPIs and APIC vector unmasks.

## 12. Panic stop-the-world

### Current state

`boot::panic::panic` writes to serial, prints on VGA, and calls
`halt_loop` on the calling CPU only. Other CPUs continue running.

### Risk

`SAFE_BOOTSTRAP_ONLY` today (one CPU). Becomes `SMP_UNSAFE_NEEDS_FIX`
the moment APs run, because a CPU racing to corrupt state while
another panics is the exact case panic exists to avoid. The fix is
a "panic IPI" (NMI vector) that every AP catches and halts on.

## 13. CPU affinity for future IRQ grants

### Current state

No affinity surface today. `smp::ipi::send_ipi` exists and accepts
an APIC ID, so the primitive to direct an IRQ at a specific CPU is
present at the lowest layer.

### Risk

`UNKNOWN_NEEDS_PROOF`. The IRQ grant primitive (`MkIrqBind`) needs
to decide whether grants are CPU-pinned or migratable. The simplest
correct policy is: pin every IRQ to the BSP until SMP scheduling is
proven; revisit when load-balancing the IRQ controller becomes
useful.

## 14. Findings table

| # | File / symbol | Behavior today | Risk | Class | Required fix |
|---|---|---|---|---|---|
| 1 | `boot/main/core_init` does not call `smp::init_bsp` / `start_aps` | runtime is BSP-only | not multi-CPU | `SMP_UNSAFE_NEEDS_FIX` | wire SMP init into the active boot path; until then docs must say single-CPU |
| 2 | `process::core::table::CURRENT_PID` global `AtomicU32` | read by FD/IPC/exit paths | wrong on multi-CPU | `SMP_UNSAFE_NEEDS_FIX` | move to per-CPU storage via `gs:offset`; partially plumbed in `smp::percpu` |
| 3 | `process::scheduler::dispatch::run_queue::PID_RUN_QUEUE` global | RwLock-guarded set used by active path | correct under one CPU; races with per-CPU queues on SMP | `SMP_SAFE_GLOBAL_LOCK` (today) | commit to per-CPU run queues + load balancer before APs come online |
| 4 | `memory::unified::tlb::flush_tlb_*` and `Arch::flush_tlb_one` | local CPU only | stale TLB on other CPUs after unmap | `SMP_UNSAFE_NEEDS_FIX` | IPI-driven shootdown when more than one CPU is online |
| 5 | `syscall::microkernel::process::sys_exit` | revokes broker claims, drops PCB | does not free user pages, kernel stack, or ASID | `SMP_UNSAFE_NEEDS_FIX` and single-CPU correctness bug | consolidate exit teardown to call `address_space::lifecycle::release`; this is the next-slice fix |
| 6 | `boot::panic::panic` | halts only the caller | other CPUs keep running on SMP | `SAFE_BOOTSTRAP_ONLY` (today) | NMI panic IPI when APs are live |
| 7 | `smp::init::start_aps` | code exists, not invoked from active boot | dead from production's view | `SAFE_BOOTSTRAP_ONLY` | wire into `core_init` after SMP scheduler/TLB shootdown ready |
| 8 | `process::scheduler::smp::state::init_cpu_queue` | gates SMP_INITIALIZED on cpu_id == 0 | bootstrap-only check | `SAFE_BOOTSTRAP_ONLY` | leave; legitimate BSP path |
| 9 | `process::scheduler::smp::tick::load_balance` | runs on cpu_id == 0 only | bootstrap-only election | `SAFE_BOOTSTRAP_ONLY` | leave; legitimate BSP duty |
| 10 | `boot::panic::halt_loop` / `disable_interrupts` / `enable_interrupts` / `interrupts_enabled` | direct `x86_64::instructions::*` calls | duplicates the new `ArchOps` trait | `SAFE_BOOTSTRAP_ONLY` | route through `Arch` trait once panic path is proven re-entrant; small follow-up |

## 15. Conclusion: is `MkMmioMap` safe to land next?

**Yes, with one precondition closed first.**

- The kernel runs single-CPU at runtime today (finding 1). MMIO grant
  + revocation is a single-thread sequence under that constraint;
  the shootdown problem (finding 4) is not exercised.
- The single-CPU correctness bug in `MkExit` (finding 5) **is**
  exercised today on every `MkExit`. Driver capsules will start
  exiting normally as soon as `capsule_driver_rng` ships, and
  leaking user pages on every clean exit is a real correctness
  regression that grows with usage.

The right ordering is:

1. **Next slice**: consolidate exit teardown so `MkExit` releases
   the user pages, kernel stack, and ASID. Wire one canonical
   `process::exit::teardown` from all three exit paths
   (`sys_exit` legacy, `MkExit`, signal-kill).
2. **Slice after that**: `MkMmioMap` end-to-end. The grant lifetime
   is now bounded by exit teardown, which is now correct.
3. **Slice after that**: `MkIrqBind`. CPU-pinned to BSP for now,
   per finding 13.
4. **SMP bring-up slice**: wire `init_bsp` + `start_aps` into
   `core_init`, plus per-CPU `CURRENT_PID`, plus IPI-driven TLB
   shootdown. Until that lands, real-hardware `multi-core` claims
   stay off.

`MkDmaMap` waits on either IOMMU integration or a bounce-pool
implementation; that is a separate slice.

## 16. What this document does not promise

- Multi-core boot today. NØNOS runs on one CPU at runtime.
- A running scheduler load balancer. The per-CPU queues exist for
  one CPU only; the balancer code is dormant.
- IPI-driven TLB shootdown. Local invalidation only.
- Stop-the-world panic. Caller-only halt.

A platform is documented as multi-core supported only when:

- the active boot wires `init_bsp` + `start_aps`,
- per-CPU `CURRENT_PID` is in place,
- TLB shootdown is real,
- the scheduler runs one shape (per-CPU queues plus balancer),
- a smoke script under `tests/boot/` shows two or more CPUs
  reaching `[CAPSULE] init ok`.

None of those are true today, and the matrix in
`arch_support_matrix.md` reflects that.
