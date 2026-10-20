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

use super::frame_ref::{is_device_leaf, release_frame, share_frame};
use super::tlb::flush_tlb_everywhere;
use super::types::{
    pte_flags, AddressSpace, PageTable, PageTableEntry, HUGE_PAGE_SIZE, KERNEL_SPACE_START,
    LARGE_PAGE_SIZE, PAGE_SIZE,
};
use crate::memory::addr::PhysAddr;

impl AddressSpace {
    pub fn clone_for_fork(&mut self, new_pid: u64) -> Result<Self, &'static str> {
        let mut new_space = AddressSpace::new(new_pid)?;

        clone_page_tables(self.pml4_phys, new_space.pml4_phys)?;
        mark_cow_pages(&mut new_space)?;
        mark_cow_pages(self)?;
        flush_tlb_everywhere(self.pcid);

        for vma in self.vmas.iter_mut() {
            vma.cow = true;
            new_space.vmas.push(vma.clone());
        }

        new_space.brk = self.brk;
        new_space.brk_max = self.brk_max;
        new_space.mmap_base = self.mmap_base;
        new_space.stack_start = self.stack_start;
        new_space.stack_end = self.stack_end;

        Ok(new_space)
    }
}

pub fn clone_page_tables(src_pml4: PhysAddr, dst_pml4: PhysAddr) -> Result<(), &'static str> {
    clone_entries(src_pml4, dst_pml4, 4, 256)
}

fn clone_entries(
    src_phys: PhysAddr,
    dst_phys: PhysAddr,
    level: u8,
    count: usize,
) -> Result<(), &'static str> {
    let src_ptr = (src_phys.as_u64() + KERNEL_SPACE_START) as *const PageTable;
    let dst_ptr = (dst_phys.as_u64() + KERNEL_SPACE_START) as *mut PageTable;

    for i in 0..count {
        // SAFETY: src_phys is the parent's PML4 or a table reached from one of its
        // present entries; dst_phys is the child's PML4 or a table this walk
        // allocated and linked into it. Adding KERNEL_SPACE_START converts physical
        // to kernel virtual address. A new table is linked before it is filled and
        // a leaf is copied only after its frame reference is taken, so on any error
        // the child's teardown sees exactly the tables and references it holds.
        unsafe {
            let src_entry = *(*src_ptr).entry(i);
            if !src_entry.is_present() {
                continue;
            }
            if level > 1 && !src_entry.is_huge_page() {
                let table = alloc_table()?;
                *(*dst_ptr).entry_mut(i) = PageTableEntry::new(table, src_entry.flags());
                clone_entries(src_entry.phys_addr(), table, level - 1, 512)?;
            } else {
                if !is_device_leaf(src_entry, level > 1) {
                    share_frame(src_entry.phys_addr())?;
                }
                *(*dst_ptr).entry_mut(i) = src_entry;
            }
        }
    }

    Ok(())
}

fn alloc_table() -> Result<PhysAddr, &'static str> {
    let frame = crate::memory::phys::alloc(crate::memory::phys::AllocFlags::empty())
        .ok_or("Failed to allocate page table clone")?;

    // SAFETY: frame was just allocated from the frame allocator. Adding
    // KERNEL_SPACE_START converts physical to kernel virtual address, and a
    // zeroed PageTable is a valid empty table.
    unsafe {
        (*((frame.0 + KERNEL_SPACE_START) as *mut PageTable)).zero();
    }

    Ok(PhysAddr::new(frame.0))
}

pub fn mark_cow_pages(space: &mut AddressSpace) -> Result<(), &'static str> {
    let pml4_ptr = (space.pml4_phys.as_u64() + KERNEL_SPACE_START) as *mut PageTable;

    for pml4_idx in 0..256 {
        // SAFETY: space.pml4_phys is a valid page table address from the AddressSpace.
        // Adding KERNEL_SPACE_START converts physical to kernel virtual address.
        // We only modify user-space entries (0-255) and check presence before access.
        unsafe {
            let pml4_entry = (*pml4_ptr).entry(pml4_idx);
            if pml4_entry.is_present() {
                mark_cow_pdpt(pml4_entry.phys_addr())?;
            }
        }
    }

    Ok(())
}

fn mark_cow_pdpt(pdpt_phys: PhysAddr) -> Result<(), &'static str> {
    let pdpt_ptr = (pdpt_phys.as_u64() + KERNEL_SPACE_START) as *mut PageTable;

    for i in 0..512 {
        // SAFETY: pdpt_phys is a valid page table address from a present PML4 entry.
        // Adding KERNEL_SPACE_START converts physical to kernel virtual address.
        // Removing WRITABLE flag triggers COW faults on write attempts.
        unsafe {
            let entry = (*pdpt_ptr).entry_mut(i);
            if entry.is_present() && !entry.is_huge_page() {
                mark_cow_pd(entry.phys_addr())?;
            } else if entry.is_present() && entry.is_huge_page() {
                entry.set_flags(entry.flags() & !pte_flags::WRITABLE);
            }
        }
    }

    Ok(())
}

fn mark_cow_pd(pd_phys: PhysAddr) -> Result<(), &'static str> {
    let pd_ptr = (pd_phys.as_u64() + KERNEL_SPACE_START) as *mut PageTable;

    for i in 0..512 {
        // SAFETY: pd_phys is a valid page table address from a present PDPT entry.
        // Adding KERNEL_SPACE_START converts physical to kernel virtual address.
        // Removing WRITABLE flag triggers COW faults on write attempts.
        unsafe {
            let entry = (*pd_ptr).entry_mut(i);
            if entry.is_present() && !entry.is_huge_page() {
                mark_cow_pt(entry.phys_addr())?;
            } else if entry.is_present() && entry.is_huge_page() {
                entry.set_flags(entry.flags() & !pte_flags::WRITABLE);
            }
        }
    }

    Ok(())
}

fn mark_cow_pt(pt_phys: PhysAddr) -> Result<(), &'static str> {
    let pt_ptr = (pt_phys.as_u64() + KERNEL_SPACE_START) as *mut PageTable;

    for i in 0..512 {
        // SAFETY: pt_phys is a valid page table address from a present PD entry.
        // Adding KERNEL_SPACE_START converts physical to kernel virtual address.
        // Removing WRITABLE flag triggers COW faults on write attempts.
        unsafe {
            let entry = (*pt_ptr).entry_mut(i);
            if entry.is_present() {
                entry.set_flags(entry.flags() & !pte_flags::WRITABLE);
            }
        }
    }

    Ok(())
}

pub fn free_user_page_tables(pml4_phys: PhysAddr) {
    let pml4_ptr = (pml4_phys.as_u64() + KERNEL_SPACE_START) as *mut PageTable;

    for i in 0..256 {
        // SAFETY: pml4_phys is a valid page table address. Adding KERNEL_SPACE_START
        // converts physical to kernel virtual address. We only free user-space entries
        // (0-255) to avoid freeing kernel mappings which are shared.
        unsafe {
            let entry = (*pml4_ptr).entry(i);
            if entry.is_present() {
                free_pdpt(entry.phys_addr());
            }
        }
    }

    let _ = crate::memory::phys::free(crate::memory::phys::Frame(pml4_phys.as_u64()));
}

fn free_pdpt(pdpt_phys: PhysAddr) {
    let pdpt_ptr = (pdpt_phys.as_u64() + KERNEL_SPACE_START) as *const PageTable;

    for i in 0..512 {
        // SAFETY: pdpt_phys is a valid page table address from a present PML4 entry.
        // Adding KERNEL_SPACE_START converts physical to kernel virtual address.
        // We check for huge pages to avoid treating 1GB pages as table pointers.
        unsafe {
            let entry = (*pdpt_ptr).entry(i);
            if entry.is_present() && !entry.is_huge_page() {
                free_pd(entry.phys_addr());
            } else if entry.is_present() {
                release_frame(*entry, (HUGE_PAGE_SIZE / PAGE_SIZE) as usize);
            }
        }
    }

    let _ = crate::memory::phys::free(crate::memory::phys::Frame(pdpt_phys.as_u64()));
}

fn free_pd(pd_phys: PhysAddr) {
    let pd_ptr = (pd_phys.as_u64() + KERNEL_SPACE_START) as *const PageTable;

    for i in 0..512 {
        // SAFETY: pd_phys is a valid page table address from a present PDPT entry.
        // Adding KERNEL_SPACE_START converts physical to kernel virtual address.
        // We check for huge pages to avoid treating 2MB pages as table pointers.
        unsafe {
            let entry = (*pd_ptr).entry(i);
            if entry.is_present() && !entry.is_huge_page() {
                free_pt(entry.phys_addr());
            } else if entry.is_present() {
                release_frame(*entry, (LARGE_PAGE_SIZE / PAGE_SIZE) as usize);
            }
        }
    }

    let _ = crate::memory::phys::free(crate::memory::phys::Frame(pd_phys.as_u64()));
}

fn free_pt(pt_phys: PhysAddr) {
    let pt_ptr = (pt_phys.as_u64() + KERNEL_SPACE_START) as *const PageTable;

    for i in 0..512 {
        // SAFETY: pt_phys is a valid page table address from a present PD entry.
        // Adding KERNEL_SPACE_START converts physical to kernel virtual address.
        // Every present entry at this level maps a 4KB frame, never a table.
        unsafe {
            let entry = (*pt_ptr).entry(i);
            if entry.is_present() {
                release_frame(*entry, 1);
            }
        }
    }

    let _ = crate::memory::phys::free(crate::memory::phys::Frame(pt_phys.as_u64()));
}
