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

// CANONICAL: memory authority namespace (Phase 1 winner).
// Per CANONICAL_SUBSYSTEM_WINNER_MAP.md, this tree owns physical/virtual
// memory, paging, MMU, KASLR, encryption, hardening, secure memory, DMA,
// frame allocator, and unified VM init. New memory-domain code must land
// here, not in `src/mem`. The unified entry points are
// `crate::memory::unified::{init_all_memory_subsystems, init_unified_vm}`.
// The live global allocator is `crate::memory::heap::manager::globals`.
//
// CONFIRMED DUPLICATE AUTHORITY (must be reconciled in Wave 2):
//   - `MemoryType`            — also defined in frozen `crate::mem::types`
//                               with a different definition.
//   - `KernelAllocator` /
//     `KERNEL_ALLOCATOR`      — frozen tree has a dormant copy in
//                               `crate::mem::heap::global` (no #[global_allocator]).
//   - `phys_to_virt` /
//     `virt_to_phys`          — `crate::memory::unified::*` is canonical;
//                               `crate::mem::pmm::phys_to_virt` is the
//                               legacy parallel implementation with
//                               separate state.
//
// `nonos_*` ALIASES retained because external consumers still resolve
// through them; renaming consumers and dropping the prefixed aliases is a
// later narrowing pass:
//   - `nonos_paging::map_page`     used by drivers/i2c, storage/{ahci,nvme}
//   - `nonos_layout`               used by smp/init
//   - `nonos_frame_alloc`          used by smp/init
//   - `nonos_virt::map_page_4k`    used by smp/init
//   - `memory` (= `secure_memory`) used by frozen modules/nonos_*

extern crate alloc;

mod api;

pub mod addr;
pub mod boot_memory;
pub mod buddy_alloc;
pub mod dma;
pub mod encryption;
#[cfg(target_arch = "x86_64")]
pub mod frame_alloc;
pub mod hardening;
pub mod heap;
pub mod kaslr;
pub mod layout;
pub mod mmio;
#[cfg(target_arch = "x86_64")]
pub mod mmu;
pub mod page_allocator;
pub mod page_info;
#[cfg(target_arch = "x86_64")]
pub mod paging;
pub mod phys;
pub mod proof;
pub mod region;
pub mod safety;
pub mod secure_memory;
pub mod stats;
#[cfg(test)]
mod tests;
pub mod unified;
#[cfg(target_arch = "x86_64")]
pub mod virt;
#[cfg(target_arch = "x86_64")]
pub mod virtual_memory;

pub use api::{get_memory_stats, get_process_vm_areas, read_process_memory};
pub use buddy_alloc as allocator;
#[cfg(target_arch = "x86_64")]
pub use frame_alloc as nonos_frame_alloc;
pub use hardening::{
    get_all_process_regions, init_module_memory_protection, read_bytes,
    verify_kernel_data_integrity, verify_kernel_page_tables,
};
pub use layout as nonos_layout;
#[cfg(target_arch = "x86_64")]
pub use paging as nonos_paging;
pub use secure_memory as memory;
pub use unified::{
    allocate_secure_region, flush_tlb_all, flush_tlb_range, get_memory_system_stats,
    get_unified_vm_stats, handle_unified_page_fault, init_all_memory_subsystems, init_unified_vm,
    is_address_mapped, map_memory, phys_to_virt, translate_virtual, unmap_memory, validate_access,
    verify_all_memory_integrity, virt_to_phys, MemoryProtection, MemorySystemStats, MemoryType,
    UnifiedVmStats,
};
#[cfg(target_arch = "x86_64")]
pub use virt as nonos_virt;
pub use addr::{PhysAddr, VirtAddr};
