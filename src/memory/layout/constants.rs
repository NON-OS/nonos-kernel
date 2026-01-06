// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
// ============================================================================
// PAGE SIZES AND MASKS
// ============================================================================
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;
pub const PAGE_MASK: u64 = !(PAGE_SIZE_U64 - 1);
pub const HUGE_PAGE_2M: usize = 2 * 1024 * 1024;
pub const HUGE_PAGE_1G: usize = 1024 * 1024 * 1024;
// ============================================================================
// CANONICAL ADDRESS SPACE
// ============================================================================
pub const CANONICAL_LOW_MAX: u64 = 0x0000_7FFF_FFFF_FFFF;
pub const CANONICAL_HIGH_MIN: u64 = 0xFFFF_8000_0000_0000;
pub const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;
pub const USER_BASE: u64 = 0x0000_0000_0000_0000;
pub const USER_TOP: u64 = CANONICAL_LOW_MAX;
// ============================================================================
// KERNEL PAGE TABLE ISOLATION (KPTI)
// ============================================================================
pub const KPTI_TRAMPOLINE: u64 = 0xFFFF_FFFF_FFFE_0000;
pub const PCID_KERNEL: u16 = 0x0001;
pub const PCID_USER: u16 = 0x0002;
// ============================================================================
// PAGE TABLE SELF-REFERENCE
// ============================================================================
pub const SELFREF_SLOT: usize = 510;
// ============================================================================
// KERNEL SECTIONS
// ============================================================================
pub const KTEXT_BASE: u64 = KERNEL_BASE;
pub const KTEXT_SIZE: u64 = 0x0200_0000;
pub const KDATA_BASE: u64 = KERNEL_BASE + KTEXT_SIZE;
pub const KDATA_SIZE: u64 = 0x0200_0000;
// ============================================================================
// DIRECT PHYSICAL MAP
// ============================================================================
pub const DIRECTMAP_BASE: u64 = 0xFFFF_FFFF_B000_0000;
pub const DIRECTMAP_SIZE: u64 = 0x0000_0000_1000_0000;
// ============================================================================
// KERNEL HEAP
// ============================================================================
/// Kernel heap base address
pub const KHEAP_BASE: u64 = 0xFFFF_FF00_0000_0000;
/// Kernel heap size (256 MiB)
pub const KHEAP_SIZE: u64 = 0x0000_0000_1000_0000;
// ============================================================================
// KERNEL VIRTUAL MEMORY
// ============================================================================
pub const KVM_BASE: u64 = 0xFFFF_FF10_0000_0000;
pub const KVM_SIZE: u64 = 0x0000_0000_2000_0000;
// ============================================================================
// MMIO
// ============================================================================
pub const MMIO_BASE: u64 = 0xFFFF_FF30_0000_0000;
pub const MMIO_SIZE: u64 = 0x0000_0000_2000_0000;
// ============================================================================
// VMAP (VMALLOC EQUIVALENT)
// ============================================================================
pub const VMAP_BASE: u64 = 0xFFFF_FF50_0000_0000;
pub const VMAP_SIZE: u64 = 0x0000_0000_1000_0000;
// ============================================================================
// DMA
// ============================================================================
pub const DMA_BASE: u64 = 0xFFFF_FF60_0000_0000;
pub const DMA_SIZE: u64 = 0x0000_0000_1000_0000;
// ============================================================================
// FIXMAP
// ============================================================================
pub const FIXMAP_BASE: u64 = 0xFFFF_FFA0_0000_0000;
pub const FIXMAP_SIZE: u64 = 0x0000_0010_0000_0000;
// ============================================================================
// BOOT IDENTITY MAP
// ============================================================================
pub const BOOT_IDMAP_BASE: u64 = 0xFFFF_FFB0_0000_0000;
pub const BOOT_IDMAP_SIZE: u64 = 0x0000_1000_0000;
// ============================================================================
// PER-CPU DATA
// ============================================================================
pub const PERCPU_BASE: u64 = 0xFFFF_FFC0_0000_0000;
pub const PERCPU_STRIDE: u64 = 0x0000_0100_0000;
// ============================================================================
// STACK CONFIGURATION
// ============================================================================
pub const KSTACK_SIZE: usize = 64 * 1024;
pub const IST_STACK_SIZE: usize = 32 * 1024;
pub const GUARD_PAGES: usize = 1;
pub const IST_STACKS_PER_CPU: usize = 8;
// ============================================================================
// PHYSICAL ADDRESS LIMITS
// ============================================================================
pub const MAX_PHYS_ADDR: u64 = 0x0000_FFFF_FFFF_FFFF;
// ============================================================================
// CPU LIMITS
// ============================================================================
pub const MAX_CPUS: u32 = 64;
// ============================================================================
// FIRMWARE REGION TYPE CODES
// ============================================================================
pub const FIRMWARE_REGION_USABLE: u32 = 1;
pub const FIRMWARE_REGION_RESERVED: u32 = 2;
pub const FIRMWARE_REGION_ACPI_RECLAIM: u32 = 3;
pub const FIRMWARE_REGION_ACPI_NVS: u32 = 4;
pub const FIRMWARE_REGION_MMIO: u32 = 7;
// ============================================================================
// PERMISSION BITS
// ============================================================================
pub const PERM_READ: u32 = 1;
pub const PERM_WRITE: u32 = 2;
pub const PERM_EXEC: u32 = 4;
// ============================================================================
// PAGE TABLE INDEXING
// ============================================================================
pub const SIGN_EXTEND_SHIFT: u64 = 48;
pub const SIGN_EXTEND_MASK: u64 = 0xFFFF;
pub const PML4_SHIFT: u64 = 39;
pub const PDPT_SHIFT: u64 = 30;
pub const PD_SHIFT: u64 = 21;
pub const PT_SHIFT: u64 = 12;
pub const PT_INDEX_MASK: u64 = 0x1FF;
// ============================================================================
// KERNEL SECTION CONFIGURATION
// ============================================================================
pub const KERNEL_SECTION_COUNT: usize = 4;
