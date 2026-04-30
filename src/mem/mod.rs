// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// FROZEN: MIGRATION ONLY (Phase 1 kill list).
// Canonical memory authority lives under `src/memory` per
// CANONICAL_SUBSYSTEM_WINNER_MAP.md. No new VM/allocator/public API work
// allowed. Permitted work: inventory of uniquely useful code, extraction
// into `src/memory`, caller migration, deletion prep. End state: DeleteReady.
// See PHASE_1_KILL_LIST_AND_FREEZE_PLAN.md.
//
// CONFIRMED DUPLICATE AUTHORITY (must be reconciled in Wave 2):
//   - `MemoryType`            — both `crate::mem::types::MemoryType` and
//                               `crate::memory::MemoryType` (via unified)
//                               exist with different definitions.
//   - `KernelAllocator` /
//     `KERNEL_ALLOCATOR`      — dormant copy here in `heap/global.rs`; the
//                               live `#[global_allocator]` lives at
//                               `crate::memory::heap::manager::globals`.
//                               This tree's allocator type is unused.
//   - `pmm::phys_to_virt`     — also defined at
//                               `crate::memory::unified::phys_to_virt`.
//                               The two have separate state.
//   - `heap`, `pmm`, `slub`, `swap`, `oom`, `huge`, `numa`, `tlb`, `vm`
//                             — Linux-style mm authority; canonical
//                               replacement lives in
//                               `crate::memory::{phys,buddy_alloc,
//                               virtual_memory,unified}`.
//
// REMOVED THIS PASS (dead duplicate boot-init authority, zero callers):
//   - `pub fn init(mmap_ptr, size, count)` — was a parallel boot init never
//     called from any boot path. The active boot init flows through
//     `crate::memory::unified::init_all_memory_subsystems`.
//
// NARROWED THIS PASS (vestigial top-level re-exports with zero external
// callers; dropped from public surface, still reachable via submodule
// paths if needed): align_down, align_up, HEAP_BASE, HEAP_SIZE, MAX_PAGES,
// MAX_PHYS_MEM, PAGE_SHIFT, PAGE_SIZE, PHYS_MAP_BASE, MemoryRegion,
// alloc, free, realloc, heap_init, heap_is_init, heap_stats,
// KernelAllocator, KERNEL_ALLOCATOR, alloc_page, alloc_pages,
// alloc_pages_aligned, free_page, free_pages, free_pages_count,
// pmm_init, pmm_is_init, memory_stats, total_pages, used_pages.
//
// PHANTOM PATHS (reported separately, NOT inside this consolidation domain):
//   - `arch/x86_64/security/{kpti,stack}/*` calls `crate::mem::phys_to_virt`,
//     `crate::mem::virt_to_phys`, `crate::mem::map_page`,
//     `crate::mem::unmap_page`, `crate::mem::PageFlags::*` — none of which
//     exist in this tree (only `crate::mem::pmm::phys_to_virt` does).
//   - `src/mem/slub/cache.rs:221` calls `crate::mem::phys_to_virt` similarly.
//   - `src/mem/vm/*` calls `crate::mem::pmm::phys_to_virt` (works) but the
//     surrounding fault/cow/anonymous/file_backed wiring depends on
//     additional symbols this tree does not define.
//   These references compile only if their files are build-gated out, or
//   the build is currently broken on those paths. Pre-existing breakage —
//   resolution belongs to a separate arch/security reconciliation pass.

pub mod constants;
pub mod descriptor;
pub mod heap;
pub mod huge;
pub mod numa;
pub mod oom;
pub mod parse;
pub mod pmm;
pub mod slub;
pub mod swap;
pub mod tlb;
pub mod types;
pub mod vm;

pub use constants::{PhysAddr, VirtAddr};
pub use descriptor::MemoryDescriptor;
pub use types::MemoryType;
