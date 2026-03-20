---
applyTo: "src/process/**,src/sched/**,src/elf/**,src/runtime/**,src/modules/**"
---

# Process Management & Scheduling — NONOS Kernel

## Process Architecture

```
src/process/
├── mod.rs          # ProcessTable, process creation/lookup
├── types.rs        # ProcessControlBlock (PCB), Pid, ProcessState
├── error.rs        # ProcessError enum
├── operations.rs   # fork(), clone(), execve(), exit()
├── address_space.rs # Per-process virtual address space
├── signals.rs      # Signal delivery and masks
├── accounting.rs   # UNIX-style exit recording
└── groups.rs       # Thread groups, sessions
```

## Process Control Block (PCB)

```rust
pub struct ProcessControlBlock {
    pub pid: Pid,
    pub parent_pid: Option<Pid>,
    pub state: ProcessState,           // Running, Ready, Blocked, Zombie, Dead
    pub address_space: AddressSpace,   // Page table root, VMA list
    pub capabilities: CapabilityToken, // What this process is allowed to do
    pub priority: Priority,            // Scheduling priority
    pub cpu_time: u64,                 // Accumulated CPU ticks
    pub kernel_stack: VirtAddr,        // Per-process kernel stack
    pub saved_context: CpuContext,     // Registers saved on context switch
    pub signals: SignalState,          // Pending signals, mask
    pub exit_code: Option<i32>,        // Set on exit()
}
```

## Process Lifecycle

```
fork()/clone() → Ready → [scheduled] → Running → exit() → Zombie → [parent waits] → Dead
                   ↑         ↓
                   ← Blocked (I/O, lock, signal)
```

### fork()

Creates a new process with a copy of the parent's address space:

```rust
pub fn sys_fork() -> Result<Pid, ProcessError> {
    let parent = current_process();

    // Copy-on-write: share pages, mark read-only, fault on write
    let child_space = parent.address_space.clone_cow()?;

    let child = ProcessControlBlock {
        pid: allocate_pid()?,
        parent_pid: Some(parent.pid),
        state: ProcessState::Ready,
        address_space: child_space,
        capabilities: parent.capabilities.derive_child()?,
        // ... inherit most fields from parent
    };

    PROCESS_TABLE.lock().insert(child.pid, child);
    scheduler::enqueue(child.pid);

    Ok(child.pid)
}
```

### clone() with flags

Like fork() but with fine-grained sharing:

```rust
pub fn sys_clone(flags: CloneFlags) -> Result<Pid, ProcessError> {
    // CLONE_VM: share address space (threads)
    // CLONE_FILES: share file descriptor table
    // CLONE_SIGHAND: share signal handlers
    // CLONE_THREAD: same thread group
}
```

### execve()

Replace the current process image with a new ELF:

```rust
pub fn sys_execve(path: &str, args: &[&str]) -> Result<!, ProcessError> {
    let elf = load_elf(path)?;           // src/elf/ — parse, validate, load segments
    validate_elf_signature(&elf)?;        // Capsule signature verification
    let caps = extract_manifest_caps(&elf)?; // Required capabilities from manifest

    // Check: does the process have the requested capabilities?
    check_capabilities_subset(current_caps(), caps)?;

    // Replace address space
    let new_space = create_address_space_from_elf(&elf)?;
    current_process_mut().address_space = new_space;

    // Apply ASLR to stack and heap
    let stack_top = randomize_stack_base()?;
    let entry = elf.entry_point();

    // Jump to new entry point — never returns
    switch_to_user_mode(entry, stack_top, args)
}
```

## ELF Loading

Location: `src/elf/` (4000+ lines)

- Full ELF64 parser with section and program header handling
- Dynamic linking support (`.dynamic`, `.dynsym`, `.rela.dyn`)
- ASLR: randomize load base for PIE executables
- Signature: verify Ed25519 signature from `.nonos.sig` section
- Manifest: read capabilities from `.nonos.manifest` section

## Scheduler

Location: `src/sched/` (2000+ lines)

### Scheduling Algorithm

Priority-based round-robin with per-process time slices:

```rust
pub fn schedule() -> Pid {
    // 1. Check for higher-priority runnable processes
    // 2. If current process exhausted its time slice, preempt
    // 3. If blocked, move to wait queue, pick next
    // 4. Round-robin among equal-priority processes
}
```

### Priority Levels

| Level | Use Case |
|-------|----------|
| `Realtime` | ISR deferred work, critical system tasks |
| `High` | System services |
| `Normal` | User applications |
| `Low` | Background tasks |
| `Idle` | Only runs when nothing else is runnable |

### Context Switch

```rust
pub fn context_switch(from: Pid, to: Pid) {
    let from_pcb = PROCESS_TABLE.lock().get_mut(from);
    let to_pcb = PROCESS_TABLE.lock().get_mut(to);

    // 1. Save current registers to from_pcb.saved_context
    save_context(&mut from_pcb.saved_context);

    // 2. Switch page table (CR3)
    load_cr3(to_pcb.address_space.page_table_root());

    // 3. Switch kernel stack
    set_kernel_stack(to_pcb.kernel_stack);

    // 4. Restore registers from to_pcb.saved_context
    restore_context(&to_pcb.saved_context);
}
```

**After switching CR3, flush TLB** (or use PCID to avoid full flush).

## Signal Handling

```rust
pub fn deliver_signal(pid: Pid, signal: Signal) -> Result<(), ProcessError> {
    let pcb = PROCESS_TABLE.lock().get_mut(pid)?;

    // Check signal mask
    if pcb.signals.is_blocked(signal) {
        pcb.signals.set_pending(signal);
        return Ok(());
    }

    // If process is blocked, wake it
    if pcb.state == ProcessState::Blocked {
        pcb.state = ProcessState::Ready;
        scheduler::enqueue(pid);
    }

    // Set up signal trampoline on user stack
    setup_signal_frame(pcb, signal)?;
    Ok(())
}
```

## Capsule Execution

Location: `src/runtime/`

Capsules are signed, capability-gated executables:

1. Verify capsule signature (Ed25519 from `.nonos.sig`)
2. Parse manifest (required capabilities, memory limits)
3. Create isolated address space
4. Grant only the declared capabilities
5. Execute with monitoring (resource quotas, time limits)
6. On exit: zeroize memory, release capabilities, clean up

## Module Loading

Location: `src/modules/`

Dynamic kernel modules (like Linux `insmod`):

- Verify module signature before loading
- Resolve symbols against kernel symbol table
- Apply relocations
- Run `module_init()` function
- Sandbox: module only gets capabilities declared in its manifest

## Common Pitfalls

1. **Forgetting to switch CR3** — process runs with wrong page table
2. **Kernel stack overflow** — each process needs its own kernel stack (guard page at bottom)
3. **Capability escalation via fork** — child must have ≤ parent's capabilities
4. **Signal delivery during syscall** — must handle EINTR correctly
5. **Zombie leak** — parent must wait() to reap children
6. **PID exhaustion** — recycle PIDs from dead processes
7. **Copy-on-write fault paths** — must handle OOM gracefully during CoW page duplication
