# Memory: exec / mapping path audit

Scope: the canonical exec path on x86_64 from `exec_process` through
ELF segment mapping, stack setup, the iret transition into user mode,
fault behaviour on the new mappings, and teardown on exit.

This audit walks the path that `crate::elf::loader::load_elf_executable`
serves after the dual-loader resolution. Every claim below has a
file:line citation.

Verdicts: `OK`, `BROKEN`, `UNVERIFIED`.

---

## 1. Address-space creation — **BROKEN**

`exec_process` reuses the parent's address space rather than allocating
a fresh one.

- `src/process/operations_exec.rs:45-54` clears `mem.vmas`, decrements
  `resident_pages`, sets a new `code_start`/`code_end`, and resets
  `next_va = 0x0000_4000_0000`. No new page table is allocated.
- `src/process/operations_exec.rs:83` reads `current.cr3.load(Acquire)`
  and passes that value to the entry transition. It does not allocate
  a CR3.
- `src/process/userspace/transitions.rs:48` loads that same CR3
  unmodified before jumping to user mode.
- `src/memory/virtual_memory/manager/api.rs:27` defines
  `create_address_space(process_id) -> Result<u32, ...>`. Grep for
  callers: zero in the exec path.

The mapping primitive `virtual_memory::map_memory_range` at
`src/memory/virtual_memory/manager/api.rs:34` writes to a single
process-global `VMEM_MANAGER` static (`api.rs:21`). Every process's
mappings flow into the same shared manager. There is no per-process
isolation at the VMM layer on this path.

Implication: process A's `exec` can map over process B's address
space. The architectural claim of address-space isolation is not
backed by code on the exec path.

Fix shape: `exec_process` must call `create_address_space(pid)` and
store the resulting CR3 (or address-space handle) on the PCB before
load_segment runs. All subsequent `map_memory_range` calls must target
that address space, not the global.

---

## 2. Segment mapping — **OK on perms/BSS/align, depends on #1 for isolation**

`src/elf/loader/core/load_segment.rs:22-71`:

- Page flags constructed from the program header's writable/executable
  bits (`load_segment.rs:29-35`). `PRESENT | USER_ACCESSIBLE` always;
  `WRITABLE` if `ph.is_writable()`; `NO_EXECUTE` if not executable.
  Matches POSIX expectations.
- Pages allocated one at a time via `frame_alloc::allocate_frame()`
  (`load_segment.rs:36-49`). Page count is `(memsz + 0xFFF) >> 12`
  — page-aligned, no rounding error.
- File contents copied with `ptr::copy_nonoverlapping`
  (`load_segment.rs:55-60`). BSS (the gap from `file_size` to `memsz`)
  zeroed via `ptr::write_bytes` (`load_segment.rs:61-63`).
- Pure-BSS segment (no file content) zeroed in full
  (`load_segment.rs:65-69`).

`flags_to_protection` (`load_segment.rs:73-85`) collapses the
PageTableFlags into the VMM's `VmProtection` enum. The mapping
correctly distinguishes Read / ReadWrite / ReadExecute / ReadWriteExecute.

The mapping itself is correct in isolation. The bug is the global
VMM noted in #1: these correctly-flagged pages all land in the shared
VMEM_MANAGER, not in the process's own address space.

Fix shape: same as #1. Once the VMM is per-process, this code is
already correct.

---

## 3. Stack mapping — **BROKEN**

`src/elf/stack/setup.rs::setup_user_stack` (`setup.rs:167-174`)
constructs a `StackSetup` and writes argc/argv/envp/auxv onto the
user stack via `ptr::copy_nonoverlapping` and `ptr::write` against
raw user addresses (`setup.rs:108-128`).

It does not allocate or map any pages for the stack itself. The
`StackSetup::new` constructor (`setup.rs:33-37`) just records
`stack_top` and computes `stack_bottom = stack_top - stack_size`.
The first `push_string` write at `stack_top - len` will fault unless
those pages are already mapped.

`src/process/userspace/constants.rs:23-25` defines
`USER_STACK_SIZE = 2 MiB` and `USER_STACK_BASE = 0x0000_7FFF_FFFF_0000`.
Grep for any path that calls `map_memory_range` or
`virtual_memory::allocate_user_stack` for that range during exec:
zero hits.

There is no guard page below the stack either. Even if the stack
itself were mapped, a stack overflow would silently extend into
whatever sits below `USER_STACK_BASE - USER_STACK_SIZE`.

Fix shape: `exec_process` must explicitly map the stack range before
calling `setup_user_stack`, with a single guard page at
`stack_bottom - 4096` left unmapped (or mapped non-present). On
fault, the trap policy bridge from commit `96867c2f8` will already
deliver `SIGSEGV` cleanly.

---

## 4. User-mode entry transition — **BROKEN (validation gap)**

`src/process/userspace/transitions.rs::exec_process` (`transitions.rs:45-56`):
disables interrupts, loads `ctx.cr3` directly, calls
`jump_to_usermode(ctx.entry, ctx.stack, ctx.argc)`.

`src/process/userspace/asm.rs::jump_to_usermode` (`asm.rs:21-50`)
constructs an iretq frame with hardcoded `SS = 0x23`, `CS = 0x1B`,
`RFLAGS = 0x202`, and the caller-supplied RIP/RSP. iretq.

`Context::validate_userspace` exists (`src/process/context/full/restore.rs:53-62`)
and rejects non-canonical or kernel addresses for RIP/RSP. It is
**not called** anywhere in the exec entry path. A malformed ELF
with `e_entry = 0xffff_ffff_8000_0000` would iretq into kernel
space at user privilege level, which is well-defined to fault but
also a needless kernel-confusion event that should be rejected
earlier.

Fix shape: `exec_process` validates `entry` and `stack` against
`USER_SPACE_MAX = 0x0000_7FFF_FFFF_FFFF` before constructing the
`ExecContext`, returning an error to the caller instead of
delegating to a hardware trap.

---

## 5. Fault behaviour on user mappings — **OK**

User-mode synchronous faults route through the trap delivery contract.
A page fault on an unmapped or wrong-permission user address:

- `src/arch/trap/contract/delivery.rs:27-35` classifies as
  `TrapClass::UserFault(FaultKind::Page)`.
- `src/arch/trap/contract/policy.rs:20-30` calls
  `signal::fault_to_signal(FaultKind::Page) -> SIGSEGV`
  (`signal.rs:21-30`) and hands off to
  `terminate_current_with_signal(SIGSEGV)`
  (`process/api.rs:66-73`), which marks the PCB Terminated with exit
  code `128 + 11 = 139` and yields to the scheduler.

The VMM has its own `handle_page_fault`
(`src/memory/virtual_memory/manager/api.rs:57-59`). The trap policy
does not call it. That is intentional today — there is no demand
paging on this path, so there is nothing for the VMM fault handler
to do beyond what the policy already does.

Verified: a user fault on a missing stack page (issue #3) would land
here cleanly and terminate the process. The behaviour is honest.

---

## 6. Teardown on process exit — **BROKEN**

`src/process/core/api.rs::sys_exit` (`api.rs:87-101`):

- Records exit accounting (`api.rs:90`).
- Sets `exit_code`, sets state to `Zombie(code)` (`api.rs:91-93`).
- Records child exit, reparents orphans (`api.rs:94-95`).
- Removes from run queue (`api.rs:96`).
- Clears `CURRENT_PID` (`api.rs:98`).
- Halts the CPU (`api.rs:100`).

It does not touch `pcb.memory`. The VMA list, the
`resident_pages` counter, and the underlying frames stay allocated.

`pcb.on_thread_exit` (`src/process/core/pcb_ops.rs:63-71`) only
clears `clear_child_tid` and removes the thread from the thread
group. No memory teardown.

Implication: every process exit leaks all of its mapped memory.
The `resident_pages` counter on the PCB never decrements except
on the next exec for the same PID slot
(`operations_exec.rs:50: mem.resident_pages.fetch_sub(...)`).
Since the PCB is destroyed (or marked Zombie until reaped), that
"next exec" almost never happens, so the leak is permanent.

Fix shape: `sys_exit` (or a function it calls) must walk
`pcb.memory.lock().vmas`, call `unmap_memory_range` for each,
free the underlying frames, and zero `resident_pages`. This pairs
with the per-process VMM from #1 — once each process owns its
own address space, teardown is a single `destroy_address_space(pid)`
call.

---

## Summary

| # | Question | Verdict | Severity |
|---|---|---|---|
| 1 | Address-space creation | BROKEN | high — no isolation between processes |
| 2 | Segment mapping (perms/BSS/align) | OK | depends on #1 |
| 3 | Stack mapping | BROKEN | high — first push faults; no guard |
| 4 | User-mode entry transition validation | BROKEN | low — hardware traps cover it, but kernel should reject earlier |
| 5 | Fault behaviour | OK | trap policy from `96867c2f8` works here |
| 6 | Teardown | BROKEN | high — every exit leaks memory |

Three high-severity items: per-process address space, stack mapping
with guard page, exit teardown. The fix shape for #1 and #6 is the
same change set (per-process VMM with a single create/destroy seam).
The fix for #3 stands alone but is small.

These are the inputs to the next Memory commits. The order I would
land them: per-process VMM (#1 + #2 follow-on + #6 follow-on as one
coherent change), then stack mapping with guard page (#3), then the
entry validation tightening (#4) as a small follow-up.

`crate::elf::loader::init_elf_loader()` is now wired in
`src/entry/kernel_main.rs:39` (commit prior to this audit), so the
canonical loader is actually usable on the running kernel — without
that, every observation in this audit was reachable only by code
inspection, not by runtime behaviour.
