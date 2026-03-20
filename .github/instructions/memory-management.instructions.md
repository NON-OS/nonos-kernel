---
applyTo: "src/mem/**,src/memory/**"
---

# Memory Management — NONOS Kernel

## Architecture Overview

NONOS has two memory subsystems:

| Subsystem | Location | Purpose |
|-----------|----------|---------|
| **Legacy PMM** | `src/mem/` | Simple page frame allocator (bitmap-based) |
| **Advanced VM** | `src/memory/` (21 submodules) | Full virtual memory: page tables, MMIO, DMA, KASLR, hardening |

New code should use the advanced VM subsystem. Legacy PMM exists for early boot only.

## Memory Model

- **Higher-half kernel:** virtual base `0xFFFF_8000_0000_0000`
- **Page sizes:** 4 KiB standard, 2 MiB huge pages for kernel text/heap
- **W⊕X enforced:** pages are writable XOR executable, never both
- **Heap:** minimum 2 MiB, managed by `linked_list_allocator` behind spinlock
- **Stack:** 64 KiB, placed after BSS in linker script

## Page Table Operations

```rust
// Map a virtual page to a physical frame
map_memory(virt_addr, phys_addr, flags)?;

// Translate virtual to physical
let phys = virt_to_phys(virt_addr)?;

// Flush TLB after page table changes — MANDATORY
flush_tlb_all(); // or invlpg for single page
```

**Critical rule:** Every page table modification MUST be followed by a TLB flush. Missing `invlpg` after a remap is the #1 cause of page fault bugs.

## Page Flags

```rust
// Standard combinations:
const KERNEL_CODE:  u64 = PRESENT | GLOBAL;           // RX (NX not set = executable)
const KERNEL_DATA:  u64 = PRESENT | WRITABLE | NX | GLOBAL;  // RW, not executable
const KERNEL_RODATA: u64 = PRESENT | NX | GLOBAL;     // RO, not executable
const USER_CODE:    u64 = PRESENT | USER | GLOBAL;     // User RX
const USER_DATA:    u64 = PRESENT | WRITABLE | USER | NX;    // User RW
```

**W⊕X invariant:** Never set both `WRITABLE` and executable (i.e., never `WRITABLE` without `NX`). This is enforced at the `map_memory()` level.

## KASLR

Kernel Address Space Layout Randomization is enabled by default (`nonos-kaslr` feature):

- Kernel text base is randomized at boot
- Heap base is randomized independently
- Driver MMIO regions get randomized virtual mappings
- The bootloader applies `.rela.dyn` PIE relocations after randomizing

When working with addresses, never assume fixed virtual addresses. Always use the symbols from the linker or the mapping API.

## Hardware Protections

Enabled by default via feature flags:

| Protection | Feature | Purpose |
|------------|---------|---------|
| NX (No Execute) | default | Prevent code execution from data pages |
| SMEP | `nonos-smep` | Supervisor Mode Execution Prevention |
| SMAP | `nonos-smap` | Supervisor Mode Access Prevention |
| CET | `nonos-cet` | Control-flow Enforcement Technology |
| PCID | `nonos-pcid` | Process-Context Identifiers (TLB tagging) |

## MMIO Mapping

```rust
use crate::drivers::security::mmio::validate_mmio_region;

// 1. Validate the physical address range
validate_mmio_region(phys_base, size)?;

// 2. Map into kernel virtual address space (uncacheable)
let virt = map_mmio_region(phys_base, size, MmioFlags::UNCACHEABLE)?;

// 3. Access through volatile operations only
// SAFETY: address validated and mapped above, within bounds
let val = unsafe { core::ptr::read_volatile(virt as *const u32) };
```

## Allocator Rules

- **Global allocator:** `linked_list_allocator` behind `AtomicBool` spinlock
- **ISR context:** allocation is FORBIDDEN — use pre-allocated buffers
- **Bounded collections:** prefer `ArrayVec<T, N>` or `heapless::Vec` over `alloc::vec::Vec`
- **Large allocations:** avoid — fragment the heap. Pre-allocate at init time.

```rust
// ✅ GOOD — bounded, no heap allocation
let mut buf: ArrayVec<u8, 4096> = ArrayVec::new();

// ❌ BAD in hot path — unbounded heap allocation
let mut buf: Vec<u8> = Vec::with_capacity(4096);
```

## Physical Frame Allocation

```rust
// Allocate a single 4K page frame
let frame = alloc_page()?;  // Returns PhysAddr

// Free it when done
free_page(frame);

// Allocate a contiguous range (for DMA, device buffers)
let frames = alloc_contiguous_pages(count)?;
```

## Address Types

Use newtypes — never pass raw `u64` for addresses:

```rust
pub struct PhysAddr(u64);  // Physical address
pub struct VirtAddr(u64);  // Virtual address

// Validated on construction:
let phys = PhysAddr::new(addr)?;  // Checks alignment, range
let virt = VirtAddr::new(addr)?;
```

## Common Bugs

1. **Missing TLB flush after remap** — stale translation, page fault on next access
2. **W⊕X violation** — mapping writable+executable triggers protection fault
3. **Allocating in ISR** — deadlocks on the heap spinlock
4. **Using physical address as virtual** — instant page fault; always map first
5. **Forgetting NX on data pages** — security vulnerability (code injection)
6. **Stack overflow** — only 64 KiB; deep recursion or large local arrays will overwrite BSS

## Submodule Map

| Module | Path | Purpose |
|--------|------|---------|
| Page tables | `memory/mmu/` | 4-level paging, map/unmap/remap |
| Heap | `memory/heap/` | Kernel heap allocator |
| PMM | `memory/pmm/` | Physical frame allocator |
| MMIO | `memory/mmio/` | Memory-mapped I/O regions |
| DMA | `memory/dma/` | DMA buffer management |
| KASLR | `memory/kaslr/` | Address randomization |
| Guards | `memory/guards/` | Guard pages, stack canaries |
| Hardening | `memory/hardening/` | SMEP, SMAP, NX enforcement |
