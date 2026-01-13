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

use core::sync::atomic::{AtomicU64, Ordering};
use alloc::vec::Vec;
use x86_64::{PhysAddr, VirtAddr};

use super::pcid::{allocate_pcid, release_pcid, KERNEL_PCID};
use super::ops::free_user_page_tables;

pub const PAGE_SIZE: u64 = 4096;
pub const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
pub const HUGE_PAGE_SIZE: u64 = 1024 * 1024 * 1024;

pub const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;
pub const KERNEL_SPACE_START: u64 = 0xFFFF_8000_0000_0000;

pub const MAX_PCID: u16 = 4096;

pub mod pte_flags {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const USER_ACCESSIBLE: u64 = 1 << 2;
    pub const WRITE_THROUGH: u64 = 1 << 3;
    pub const NO_CACHE: u64 = 1 << 4;
    pub const ACCESSED: u64 = 1 << 5;
    pub const DIRTY: u64 = 1 << 6;
    pub const HUGE_PAGE: u64 = 1 << 7;
    pub const GLOBAL: u64 = 1 << 8;
    pub const NO_EXECUTE: u64 = 1 << 63;

    pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub fn new(phys_addr: PhysAddr, flags: u64) -> Self {
        Self((phys_addr.as_u64() & pte_flags::ADDR_MASK) | flags)
    }

    pub fn is_present(&self) -> bool {
        self.0 & pte_flags::PRESENT != 0
    }

    pub fn is_writable(&self) -> bool {
        self.0 & pte_flags::WRITABLE != 0
    }

    pub fn is_user_accessible(&self) -> bool {
        self.0 & pte_flags::USER_ACCESSIBLE != 0
    }

    pub fn is_huge_page(&self) -> bool {
        self.0 & pte_flags::HUGE_PAGE != 0
    }

    pub fn phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self.0 & pte_flags::ADDR_MASK)
    }

    pub fn flags(&self) -> u64 {
        self.0 & !pte_flags::ADDR_MASK
    }

    pub fn set_flags(&mut self, flags: u64) {
        self.0 = (self.0 & pte_flags::ADDR_MASK) | flags;
    }

    pub fn clear(&mut self) {
        self.0 = 0;
    }

    pub fn raw(&self) -> u64 {
        self.0
    }
}

impl core::fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PTE(0x{:016X})", self.0)
    }
}

#[repr(C, align(4096))]
pub struct PageTable {
    pub(crate) entries: [PageTableEntry; 512],
}

impl PageTable {
    pub const fn new() -> Self {
        const EMPTY: PageTableEntry = PageTableEntry::empty();
        Self { entries: [EMPTY; 512] }
    }

    pub fn entry(&self, index: usize) -> &PageTableEntry {
        &self.entries[index]
    }

    pub fn entry_mut(&mut self, index: usize) -> &mut PageTableEntry {
        &mut self.entries[index]
    }

    pub fn zero(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.clear();
        }
    }

    pub fn copy_from(&mut self, other: &PageTable) {
        for i in 0..512 {
            self.entries[i] = other.entries[i];
        }
    }

    pub fn copy_kernel_entries(&mut self, other: &PageTable) {
        // Kernel occupies indices 256-511 in PML4
        for i in 256..512 {
            self.entries[i] = other.entries[i];
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectionFlags {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub user: bool,
}

impl ProtectionFlags {
    pub fn new(read: bool, write: bool, execute: bool, user: bool) -> Self {
        Self { read, write, execute, user }
    }

    pub fn to_pte_flags(&self) -> u64 {
        let mut flags = pte_flags::PRESENT;

        if self.write {
            flags |= pte_flags::WRITABLE;
        }

        if self.user {
            flags |= pte_flags::USER_ACCESSIBLE;
        }

        if !self.execute {
            flags |= pte_flags::NO_EXECUTE;
        }

        flags
    }
}

impl Default for ProtectionFlags {
    fn default() -> Self {
        Self {
            read: true,
            write: false,
            execute: false,
            user: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Vma {
    pub start: VirtAddr,
    pub end: VirtAddr,
    pub prot: ProtectionFlags,
    pub cow: bool,
    pub anonymous: bool,
    pub refcount: u32,
}

impl Vma {
    pub fn new(start: VirtAddr, end: VirtAddr, prot: ProtectionFlags) -> Self {
        Self {
            start,
            end,
            prot,
            cow: false,
            anonymous: true,
            refcount: 1,
        }
    }

    pub fn size(&self) -> u64 {
        self.end.as_u64() - self.start.as_u64()
    }

    pub fn contains(&self, addr: VirtAddr) -> bool {
        addr >= self.start && addr < self.end
    }

    pub fn overlaps(&self, other: &Vma) -> bool {
        self.start < other.end && other.start < self.end
    }
}

pub struct AddressSpace {
    pub pid: u64,
    pub pml4_phys: PhysAddr,
    pub pcid: u16,
    pub vmas: Vec<Vma>,
    pub refcount: AtomicU64,
    pub is_kernel: bool,
    pub brk: VirtAddr,
    pub brk_max: VirtAddr,
    pub mmap_base: VirtAddr,
    pub stack_start: VirtAddr,
    pub stack_end: VirtAddr,
}

impl AddressSpace {
    pub fn new(pid: u64) -> Result<Self, &'static str> {
        // Allocate PML4 page
        let pml4_frame = crate::memory::phys::alloc(crate::memory::phys::AllocFlags::empty())
            .ok_or("Failed to allocate PML4")?;

        let pml4_ptr = (pml4_frame.0 + KERNEL_SPACE_START) as *mut PageTable;
        // # SAFETY: pml4_frame was just allocated from the frame allocator, so it
        // points to valid memory. Adding KERNEL_SPACE_START converts the physical
        // address to its kernel-mapped virtual address. PageTable is repr(C, align(4096))
        // and zero-initializing produces a valid empty page table.
        unsafe {
            (*pml4_ptr).zero();
        }

        let current_pml4 = super::ops::current_pml4();
        // # SAFETY: current_pml4() returns a valid pointer to the current page table.
        // # pml4_ptr was just allocated and zeroed above. copy_kernel_entries only
        // copies indices 256-511 (kernel space) which are shared across all processes.
        unsafe {
            (*pml4_ptr).copy_kernel_entries(&*current_pml4);
        }

        let pcid = allocate_pcid();

        Ok(Self {
            pid,
            pml4_phys: PhysAddr::new(pml4_frame.0),
            pcid,
            vmas: Vec::new(),
            refcount: AtomicU64::new(1),
            is_kernel: false,
            brk: VirtAddr::new(crate::process::userspace::USER_HEAP_START),
            brk_max: VirtAddr::new(0x0000_7000_0000_0000),
            mmap_base: VirtAddr::new(0x0000_7000_0000_0000),
            stack_start: VirtAddr::new(crate::process::userspace::USER_STACK_BASE),
            stack_end: VirtAddr::new(crate::process::userspace::USER_STACK_BASE - crate::process::userspace::USER_STACK_SIZE as u64),
        })
    }

    pub fn kernel() -> Self {
        let cr3: u64;
        // # SAFETY: Reading CR3 is always safe in kernel mode. It returns the current
        // page table base address. The nomem option is correct as this does not
        // access memory through a pointer. The nostack option is correct as no
        // stack space is used.
        unsafe {
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
        }

        Self {
            pid: 0,
            pml4_phys: PhysAddr::new(cr3 & pte_flags::ADDR_MASK),
            pcid: KERNEL_PCID,
            vmas: Vec::new(),
            refcount: AtomicU64::new(1),
            is_kernel: true,
            brk: VirtAddr::new(0),
            brk_max: VirtAddr::new(0),
            mmap_base: VirtAddr::new(0),
            stack_start: VirtAddr::new(0),
            stack_end: VirtAddr::new(0),
        }
    }

    pub fn cr3_value(&self) -> u64 {
        if super::pcid::pcid_enabled() {
            self.pml4_phys.as_u64() | (self.pcid as u64)
        } else {
            self.pml4_phys.as_u64()
        }
    }

    pub fn add_vma(&mut self, vma: Vma) -> Result<(), &'static str> {
        for existing in &self.vmas {
            if existing.overlaps(&vma) {
                return Err("VMA overlaps with existing mapping");
            }
        }

        self.vmas.push(vma);
        Ok(())
    }

    pub fn find_vma(&self, addr: VirtAddr) -> Option<&Vma> {
        self.vmas.iter().find(|vma| vma.contains(addr))
    }

    pub fn find_vma_mut(&mut self, addr: VirtAddr) -> Option<&mut Vma> {
        self.vmas.iter_mut().find(|vma| vma.contains(addr))
    }

    pub fn add_ref(&self) {
        self.refcount.fetch_add(1, Ordering::SeqCst);
    }

    pub fn release(&self) -> bool {
        self.refcount.fetch_sub(1, Ordering::SeqCst) == 1
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        if !self.is_kernel {
            // (Physical pages are reference-counted separately)
            free_user_page_tables(self.pml4_phys);
            release_pcid(self.pcid);
        }
    }
}
