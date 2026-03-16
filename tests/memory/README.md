# Memory Module Tests

## Location

`src/memory/*/tests.rs`

## Coverage

### Heap Allocator (124 tests)

- Allocation/deallocation cycles
- Fragmentation handling
- OOM conditions
- Alignment guarantees
- Thread safety

Source: `src/memory/heap/tests.rs`

### Page Tables (98 tests)

- PML4/PDPT/PD/PT manipulation
- Page flags (present, writable, NX)
- Huge pages (2MB, 1GB)
- TLB invalidation

Source: `src/memory/paging/tests.rs`

### Frame Allocator (87 tests)

- Frame allocation bitmap
- Contiguous allocation
- Memory regions
- Statistics tracking

Source: `src/memory/frame/tests.rs`

### Layout (56 tests)

- Kernel sections (.text, .data, .bss)
- Stack boundaries
- Heap boundaries
- MMIO regions

Source: `src/memory/layout/tests.rs`

### Physical Memory (78 tests)

- E820 map parsing
- Memory type detection
- Region merging
- Reserved areas

Source: `src/memory/physical/tests.rs`

### Virtual Memory (89 tests)

- Address space creation
- VMA management
- Page fault handling
- Copy-on-write

Source: `src/memory/virtual/tests.rs`

### Cache (65 tests)

- Page cache operations
- LRU eviction
- Dirty page tracking
- Writeback

Source: `src/memory/cache/tests.rs`

## Running

```bash
cargo test --lib --features std memory::
```
