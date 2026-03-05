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

//! Memory Layout Constants
//!
//! Defines all kernel memory layout constants including:
//! - Page sizes and alignment
//! - Canonical address ranges
//! - Kernel virtual address regions
//! - Stack and per-CPU area sizes

// ============================================================================
// PAGE SIZES AND MASKS
// ============================================================================

/// Standard page size (4 KiB)
pub const PAGE_SIZE: usize = 4096;

/// Page size as u64 for address calculations
pub const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;

/// Mask for page-aligned addresses
pub const PAGE_MASK: u64 = !(PAGE_SIZE_U64 - 1);

/// Huge page size (2 MiB)
pub const HUGE_PAGE_2M: usize = 2 * 1024 * 1024;

/// Giant page size (1 GiB)
pub const HUGE_PAGE_1G: usize = 1024 * 1024 * 1024;

// ============================================================================
// CANONICAL ADDRESS SPACE
// ============================================================================

/// Maximum user-space address (canonical low)
pub const CANONICAL_LOW_MAX: u64 = 0x0000_7FFF_FFFF_FFFF;

/// Minimum kernel-space address (canonical high)
pub const CANONICAL_HIGH_MIN: u64 = 0xFFFF_8000_0000_0000;

/// Kernel virtual base address
pub const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// User space base address
pub const USER_BASE: u64 = 0x0000_0000_0000_0000;

/// User space top address
pub const USER_TOP: u64 = CANONICAL_LOW_MAX;

// ============================================================================
// KERNEL PAGE TABLE ISOLATION (KPTI)
// ============================================================================

/// KPTI trampoline region base address
pub const KPTI_TRAMPOLINE: u64 = 0xFFFF_FFFF_FFFE_0000;

/// Process Context ID for kernel
pub const PCID_KERNEL: u16 = 0x0001;

/// Process Context ID for user space
pub const PCID_USER: u16 = 0x0002;

// ============================================================================
// PAGE TABLE SELF-REFERENCE
// ============================================================================

/// Page table self-reference slot in PML4 (entry 510)
pub const SELFREF_SLOT: usize = 510;

// ============================================================================
// KERNEL SECTIONS
// ============================================================================

/// Kernel text (code) base address
pub const KTEXT_BASE: u64 = KERNEL_BASE;

/// Kernel text section size (32 MiB)
pub const KTEXT_SIZE: u64 = 0x0200_0000;

/// Kernel data base address (after text)
pub const KDATA_BASE: u64 = KERNEL_BASE + KTEXT_SIZE;

/// Kernel data section size (32 MiB)
pub const KDATA_SIZE: u64 = 0x0200_0000;

// ============================================================================
// DIRECT PHYSICAL MAP
// ============================================================================

/// Direct physical memory map base
pub const DIRECTMAP_BASE: u64 = 0xFFFF_FFFF_B000_0000;

/// Direct physical memory map size (256 MiB)
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

/// Kernel VM allocation base
pub const KVM_BASE: u64 = 0xFFFF_FF10_0000_0000;

/// Kernel VM allocation size (512 MiB)
pub const KVM_SIZE: u64 = 0x0000_0000_2000_0000;

// ============================================================================
// MMIO
// ============================================================================

/// Memory-mapped I/O base address
pub const MMIO_BASE: u64 = 0xFFFF_FF30_0000_0000;

/// Memory-mapped I/O region size (512 MiB)
pub const MMIO_SIZE: u64 = 0x0000_0000_2000_0000;

// ============================================================================
// VMAP (VMALLOC EQUIVALENT)
// ============================================================================

/// Virtual mapping area base
pub const VMAP_BASE: u64 = 0xFFFF_FF50_0000_0000;

/// Virtual mapping area size (256 MiB)
pub const VMAP_SIZE: u64 = 0x0000_0000_1000_0000;

// ============================================================================
// DMA
// ============================================================================

/// DMA buffer region base
pub const DMA_BASE: u64 = 0xFFFF_FF60_0000_0000;

/// DMA buffer region size (256 MiB)
pub const DMA_SIZE: u64 = 0x0000_0000_1000_0000;

// ============================================================================
// FIXMAP
// ============================================================================

/// Fixed mapping area base
pub const FIXMAP_BASE: u64 = 0xFFFF_FFA0_0000_0000;

/// Fixed mapping area size (64 GiB)
pub const FIXMAP_SIZE: u64 = 0x0000_0010_0000_0000;

// ============================================================================
// BOOT IDENTITY MAP
// ============================================================================

/// Boot identity mapping base
pub const BOOT_IDMAP_BASE: u64 = 0xFFFF_FFB0_0000_0000;

/// Boot identity mapping size (256 MiB)
pub const BOOT_IDMAP_SIZE: u64 = 0x0000_1000_0000;

// ============================================================================
// PER-CPU DATA
// ============================================================================

/// Per-CPU data region base
pub const PERCPU_BASE: u64 = 0xFFFF_FFC0_0000_0000;

/// Per-CPU data stride (16 MiB per CPU)
pub const PERCPU_STRIDE: u64 = 0x0000_0100_0000;

/// Per-CPU stacks base address (after PERCPU data)
pub const PERCPU_STACKS_BASE: u64 = 0xFFFF_FFD0_0000_0000;

// ============================================================================
// STACK CONFIGURATION
// ============================================================================

/// Kernel stack size (64 KiB)
pub const KSTACK_SIZE: usize = 64 * 1024;

/// IST (Interrupt Stack Table) stack size (32 KiB)
pub const IST_STACK_SIZE: usize = 32 * 1024;

/// Number of guard pages between stacks
pub const GUARD_PAGES: usize = 1;

/// Number of IST stacks per CPU
pub const IST_STACKS_PER_CPU: usize = 8;

// ============================================================================
// PHYSICAL ADDRESS LIMITS
// ============================================================================

/// Maximum physical address (52-bit physical addressing)
pub const MAX_PHYS_ADDR: u64 = 0x0000_FFFF_FFFF_FFFF;

// ============================================================================
// CPU LIMITS
// ============================================================================

/// Maximum supported CPUs
pub const MAX_CPUS: u32 = 64;

// ============================================================================
// FIRMWARE REGION TYPE CODES
// ============================================================================

/// Firmware region type: Usable memory
pub const FIRMWARE_REGION_USABLE: u32 = 1;

/// Firmware region type: Reserved
pub const FIRMWARE_REGION_RESERVED: u32 = 2;

/// Firmware region type: ACPI reclaimable
pub const FIRMWARE_REGION_ACPI_RECLAIM: u32 = 3;

/// Firmware region type: ACPI NVS
pub const FIRMWARE_REGION_ACPI_NVS: u32 = 4;

/// Firmware region type: Memory-mapped I/O
pub const FIRMWARE_REGION_MMIO: u32 = 7;

// ============================================================================
// PERMISSION BITS
// ============================================================================

/// Permission: Readable
pub const PERM_READ: u32 = 1;

/// Permission: Writable
pub const PERM_WRITE: u32 = 2;

/// Permission: Executable
pub const PERM_EXEC: u32 = 4;

// ============================================================================
// PAGE TABLE INDEXING
// ============================================================================

/// Bits to shift for sign extension (canonical address)
pub const SIGN_EXTEND_SHIFT: u64 = 48;

/// Sign extension mask for canonical addresses
pub const SIGN_EXTEND_MASK: u64 = 0xFFFF;

/// Bits to shift for PML4 index
pub const PML4_SHIFT: u64 = 39;

/// Bits to shift for PDPT index
pub const PDPT_SHIFT: u64 = 30;

/// Bits to shift for PD index
pub const PD_SHIFT: u64 = 21;

/// Bits to shift for PT index
pub const PT_SHIFT: u64 = 12;

/// Mask for page table index (9 bits)
pub const PT_INDEX_MASK: u64 = 0x1FF;

// ============================================================================
// KERNEL SECTION CONFIGURATION
// ============================================================================

/// Number of kernel sections (text, rodata, data, bss)
pub const KERNEL_SECTION_COUNT: usize = 4;
