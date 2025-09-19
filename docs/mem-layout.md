# NØNOS Memory Layout (x86_64)

- Canonical, 4-level paging, 4 KiB pages (2 MiB later).
- Higher-half kernel base: `0xffffffff80000000`.

## Regions
- .text         : RX, global
- .rodata       : RO, NX
- .data/.bss    : RW, NX
- .percpu       : RW, NX (per-CPU TLS)
- kernel heap   : RW, NX (slab + vm alloc)
- stacks/IST    : RW, NX, with 1 guard page below each
- device mmio   : RW, NX, uncached (MTRR/PAT later)

## Page Flags
- PRESENT|RW|USER|PWT|PCD|ACCESSED|DIRTY|GLOBAL|NX

## KASLR
- Slide = 2 MiB granularity.
- Entropy: CPU RNG transcript → logged hash (no persistence).

## Zero-State
- On boot we emit a layout map + transcript hash via logger; no mutable state survives reboot.
