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

// Bootloader-side mirrors of the kernel paging contract. Kept in
// lockstep with `src/memory/layout/constants/regions.rs`; if the
// kernel changes the directmap window, the bootloader must change
// here too. The build will surface a marker mismatch in the
// kernel-side `init_unified_vm` validator if the two drift.

pub const PAGE_SIZE: u64 = 0x1000;
pub const HUGE_2M: u64 = 0x20_0000;
pub const HUGE_1G: u64 = 0x4000_0000;
pub const PAGE_TABLE_ENTRIES: usize = 512;

pub const DIRECTMAP_BASE: u64 = 0xFFFF_8000_0000_0000;
pub const DIRECTMAP_SIZE: u64 = 0x0000_0040_0000_0000;

// Identity-map low physical memory so the kernel ELF, bootloader
// text/data (the RIP that keeps executing across `mov cr3`), the
// handoff struct, boot stack, mmap area, and framebuffer all stay
// reachable through the CR3 swap. This must cover wherever the UEFI
// firmware physically placed the bootloader image: edk2/OVMF on
// QEMU 10.2.0 loads it above 4 GiB (observed RIP ~0x1_4001_F000),
// so a 4 GiB window faults on the instruction right after the CR3
// write. 64 GiB = 64 1-GiB hugepage entries in PML4[0]'s single
// PDPT (cap 512 GiB); the directmap (PML4[256]) does not help here
// because the bootloader executes at its firmware load phys, not
// the directmap window. The kernel tears this window down after its
// directmap probe regardless of size.
pub const IDENTITY_LOW_BYTES: u64 = 0x10_0000_0000;

// Bit positions for x86_64 page-table entries.
pub const PTE_P: u64 = 1 << 0;
pub const PTE_RW: u64 = 1 << 1;
pub const PTE_US: u64 = 1 << 2;
pub const PTE_PWT: u64 = 1 << 3;
pub const PTE_PCD: u64 = 1 << 4;
pub const PTE_PS: u64 = 1 << 7;
pub const PTE_G: u64 = 1 << 8;
pub const PTE_NX: u64 = 1 << 63;

pub const ADDR_MASK_4K: u64 = 0x000F_FFFF_FFFF_F000;
pub const ADDR_MASK_2M: u64 = 0x000F_FFFF_FFE0_0000;
pub const ADDR_MASK_1G: u64 = 0x000F_FFFF_C000_0000;

pub const PML4_INDEX_LOW_IDENTITY: usize = 0;
pub const PML4_INDEX_DIRECTMAP: usize = 256;

// Canonical kernel-text PML4 entry. Upper-half kernels link at
// 0xFFFFFFFF80000000+, which falls inside PML4[511]. The bootloader
// installs the per-segment phys -> virt mappings here before the CR3
// swap so the kernel can begin executing at its declared `e_entry`.
pub const PML4_INDEX_KERNEL_TEXT: usize = 511;
