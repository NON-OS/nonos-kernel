---
applyTo: "src/interrupts/**,src/smp/**,src/arch/x86_64/**"
---

# Interrupt Handling & Concurrency — NONOS Kernel

## Interrupt Architecture

```
src/interrupts/
├── mod.rs       # IDT setup, vector allocation, init_idt()
├── handlers.rs  # Exception handlers (div-by-zero, page fault, GPF, etc.)
├── irq.rs       # Hardware IRQ routing (PIC/APIC → handler)
├── apic.rs      # Local APIC + I/O APIC management
└── *.rs         # Per-device ISR stubs
```

IDT is configured in `sys::idt`. ISRs are registered via `register_interrupt_handler()`.

## ISR Rules — Absolute

An Interrupt Service Routine runs with interrupts disabled, on the interrupt stack. These rules are non-negotiable:

| Rule | Reason |
|------|--------|
| **No allocation** | Heap lock may be held → deadlock |
| **No lock acquisition** | Any lock may be held → deadlock |
| **No I/O beyond the ack** | Timing-sensitive context, other IRQs blocked |
| **No `serial::println!`** | Serial port lock may be held |
| **No complex computation** | Blocks all other interrupts |
| **Flag-and-defer only** | Set atomic flag, return immediately |

### ISR Pattern

```rust
use core::sync::atomic::{AtomicU64, Ordering};

static PENDING_WORK: AtomicU64 = AtomicU64::new(0);
const WORK_KEYBOARD: u64 = 1 << 0;
const WORK_NETWORK:  u64 = 1 << 1;
const WORK_TIMER:    u64 = 1 << 2;
const WORK_DISK:     u64 = 1 << 3;

// ISR — runs with interrupts disabled, must be minimal
fn keyboard_isr() {
    // 1. Read the scancode from the port (required to clear the interrupt)
    let scancode = unsafe { inb(0x60) };

    // 2. Store it in a lockfree buffer
    SCANCODE_BUF.store(scancode as u64, Ordering::Release);

    // 3. Signal work pending
    PENDING_WORK.fetch_or(WORK_KEYBOARD, Ordering::Release);

    // 4. Acknowledge the interrupt at the PIC/APIC
    acknowledge_irq(IRQ_KEYBOARD);
    // RETURN — nothing else!
}

// Deferred handler — called from main loop, safe to do anything
fn drain_pending_work() {
    let bits = PENDING_WORK.swap(0, Ordering::Acquire);
    if bits & WORK_KEYBOARD != 0 { handle_keyboard_input(); }
    if bits & WORK_NETWORK  != 0 { handle_network_rx(); }
    if bits & WORK_TIMER    != 0 { handle_timer_tick(); }
    if bits & WORK_DISK     != 0 { handle_disk_completion(); }
}
```

### Naked ISR Stubs

Only at raw entry points. Immediately call a safe handler:

```rust
#[naked]
unsafe extern "x86-interrupt" fn raw_keyboard_isr(_frame: InterruptStackFrame) {
    core::arch::asm!(
        "call {handler}",
        "iretq",
        handler = sym keyboard_isr,
        options(noreturn)
    );
}
```

## Concurrency Primitives

### Spinlocks (Primary)

```rust
use spin::{Mutex, RwLock, Lazy};

// Mutex — exclusive access
static DEVICE_STATE: Mutex<DeviceState> = Mutex::new(DeviceState::new());

// RwLock — multiple readers, single writer
static CONFIG: RwLock<Config> = RwLock::new(Config::default());

// Lazy — init-once
static DRIVER: Lazy<Driver> = Lazy::new(|| Driver::init().expect("driver init"));
```

**No sleeping locks.** There is no scheduler guarantee in early boot. Spinlocks only.

### Atomics

| Ordering | Use Case |
|----------|----------|
| `Relaxed` | Flags, counters (no ordering guarantee needed) |
| `Acquire` / `Release` | Spinlock state, publish-subscribe patterns |
| `SeqCst` | Init-once guards, rare cases requiring total order |

```rust
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// Flag
static INITIALIZED: AtomicBool = AtomicBool::new(false);

// Counter
static PACKET_COUNT: AtomicU64 = AtomicU64::new(0);
PACKET_COUNT.fetch_add(1, Ordering::Relaxed);

// Init-once
if INITIALIZED.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
    // First caller — do one-time init
}
```

### Interrupt-Safe Lock Acquisition

If an ISR might contend on a lock, disable interrupts first:

```rust
use x86_64::instructions::interrupts;

let data = interrupts::without_interrupts(|| {
    let guard = MY_LOCK.lock();
    guard.read_value()
});
```

**Never hold a lock that an ISR might need without disabling interrupts first.**
Order: disable interrupts → acquire lock → release lock → enable interrupts.

## SMP (Symmetric Multiprocessing)

Location: `src/smp/`

### Per-CPU Data

Indexed by APIC ID. No shared mutable state without atomic protection:

```rust
use crate::smp::get_cpu_id;

static PER_CPU: [Mutex<CpuData>; MAX_CPUS] = /* ... */;

fn get_my_data() -> &'static Mutex<CpuData> {
    &PER_CPU[get_cpu_id() as usize]
}
```

### TLB Shootdown

When modifying page tables that affect other cores:

```rust
// 1. Modify page table entry
remap_page(vaddr, new_flags)?;

// 2. Flush local TLB
invlpg(vaddr);

// 3. Send IPI to other cores to flush their TLBs
smp::tlb_shootdown(vaddr);
```

**Missing TLB shootdown = stale translations on other cores = intermittent, hard-to-debug crashes.**

### Inter-Processor Interrupts (IPI)

- Used for TLB shootdown, scheduler kick, halt
- Sent via Local APIC ICR (Interrupt Command Register)
- Target: specific APIC ID, all-excluding-self, or all-including-self

## Exception Handlers

| Vector | Exception | Action |
|--------|-----------|--------|
| 0 | Divide by Zero | Kill process or panic |
| 6 | Invalid Opcode | Kill process |
| 8 | Double Fault | Panic (IST stack) |
| 13 | General Protection Fault | Kill process, log CR2 |
| 14 | Page Fault | Handle (CoW, demand paging) or kill |
| 18 | Machine Check | Log and halt |

Page fault handler must distinguish:
- **Demand paging** — allocate frame, map, resume
- **Copy-on-write** — duplicate page, remap writable, resume
- **Guard page hit** — stack overflow, kill process
- **Genuine fault** — invalid access, kill process or panic

## Common Bugs

1. **Deadlock on heap lock** — allocating in ISR while main thread holds heap lock
2. **Deadlock on serial lock** — `serial::println!` in ISR while main thread is printing
3. **Missing `without_interrupts`** — ISR fires mid-lock-acquisition → deadlock
4. **Missing TLB shootdown** — page table change not visible to other cores
5. **Wrong atomic ordering** — `Relaxed` where `Acquire/Release` needed → data race
6. **ISR does too much work** — blocks all interrupts, causes missed timer ticks

## Anti-Patterns

- **No allocation in ISR context**
- **No `spin::Mutex::lock()` in ISR context** (unless interrupt-disabled path)
- **No `static mut` across cores** — use atomics or per-CPU data
- **No sleeping/blocking in ISR** — return as fast as possible
- **No recursive interrupts** — keep interrupts disabled in handler
