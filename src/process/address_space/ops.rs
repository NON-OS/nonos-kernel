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

use x86_64::{PhysAddr, VirtAddr};
use super::types::{
    AddressSpace, PageTable, PageTableEntry, ProtectionFlags,
    pte_flags, KERNEL_SPACE_START, USER_SPACE_END,
};
use super::tlb::invlpg;

#[inline(always)]
pub fn pml4_index(virt: VirtAddr) -> usize {
    ((virt.as_u64() >> 39) & 0x1FF) as usize
}

#[inline(always)]
pub fn pdpt_index(virt: VirtAddr) -> usize {
    ((virt.as_u64() >> 30) & 0x1FF) as usize
}

#[inline(always)]
pub fn pd_index(virt: VirtAddr) -> usize {
    ((virt.as_u64() >> 21) & 0x1FF) as usize
}

#[inline(always)]
pub fn pt_index(virt: VirtAddr) -> usize {
    ((virt.as_u64() >> 12) & 0x1FF) as usize
}

pub fn current_pml4() -> *mut PageTable {
    let cr3: u64;
    // # SAFETY: Reading CR3 is always safe in kernel mode it returns the
    // current page table base address. The nomem option is correct as this
    // does not access memory through a pointer.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
    }
    let phys = cr3 & pte_flags::ADDR_MASK;
    (phys + KERNEL_SPACE_START) as *mut PageTable
}

pub fn get_or_create_table(table: &mut PageTable, index: usize) -> Result<PhysAddr, &'static str> {
    let entry = table.entry_mut(index);
    if entry.is_present() {
        Ok(entry.phys_addr())
    } else {
        let frame = crate::memory::phys::alloc(crate::memory::phys::AllocFlags::empty())
            .ok_or("Failed to allocate page table")?;

        let ptr = (frame.0 + KERNEL_SPACE_START) as *mut PageTable;
        // # SAFETY: The physical frame was just allocated from the frame allocator,
        // so it is valid memory. We add KERNEL_SPACE_START to convert the physical
        // address to its kernel-mapped virtual address. The PageTable struct is
        // repr(C) and zero-initializing it produces a valid, empty page table.
        unsafe {
            (*ptr).zero();
        }

        *entry = PageTableEntry::new(
            PhysAddr::new(frame.0),
            pte_flags::PRESENT | pte_flags::WRITABLE | pte_flags::USER_ACCESSIBLE,
        );

        Ok(PhysAddr::new(frame.0))
    }
}

impl AddressSpace {
    pub fn map_page(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        prot: ProtectionFlags,
    ) -> Result<(), &'static str> {
        if virt.as_u64() >= USER_SPACE_END && !self.is_kernel {
            return Err("Cannot map kernel address in user space");
        }

        let flags = prot.to_pte_flags();

        let pml4_ptr = (self.pml4_phys.as_u64() + KERNEL_SPACE_START) as *mut PageTable;

        let pml4_idx = pml4_index(virt);
        let pdpt_idx = pdpt_index(virt);
        let pd_idx = pd_index(virt);
        let pt_idx = pt_index(virt);
        // # SAFETY: This block walks and modifies the page table hierarchy.
        // # pml4_phys is valid because it comes from self.pml4_phys which was
        //   allocated during AddressSpace::new()
        // # Adding KERNEL_SPACE_START converts physical to kernel virtual address
        // # All intermediate page tables are either already present or allocated
        //   via get_or_create_table() which validates the allocation
        // # The final entry write maps a physical page to a virtual address
        unsafe {
            let pdpt_phys = get_or_create_table(&mut *pml4_ptr, pml4_idx)?;
            let pdpt_ptr = (pdpt_phys.as_u64() + KERNEL_SPACE_START) as *mut PageTable;
            let pd_phys = get_or_create_table(&mut *pdpt_ptr, pdpt_idx)?;
            let pd_ptr = (pd_phys.as_u64() + KERNEL_SPACE_START) as *mut PageTable;
            let pt_phys = get_or_create_table(&mut *pd_ptr, pd_idx)?;
            let pt_ptr = (pt_phys.as_u64() + KERNEL_SPACE_START) as *mut PageTable;
            let entry = (*pt_ptr).entry_mut(pt_idx);
            *entry = PageTableEntry::new(phys, flags);
        }

        Ok(())
    }

    pub fn unmap_page(&mut self, virt: VirtAddr) -> Result<PhysAddr, &'static str> {
        let pml4_ptr = (self.pml4_phys.as_u64() + KERNEL_SPACE_START) as *mut PageTable;
        let pml4_idx = pml4_index(virt);
        let pdpt_idx = pdpt_index(virt);
        let pd_idx = pd_index(virt);
        let pt_idx = pt_index(virt);
        // # SAFETY: This block walks the page table hierarchy to remove a mapping.
        // # pml4_phys is valid because it comes from self.pml4_phys
        // # Adding KERNEL_SPACE_START converts physical to kernel virtual address
        // # Each level is validated for presence before proceeding
        // # The final entry clear removes the mapping and invlpg flushes the TLB
        unsafe {
            let pml4_entry = (*pml4_ptr).entry(pml4_idx);
            if !pml4_entry.is_present() {
                return Err("Page not mapped (PML4)");
            }

            let pdpt_ptr = (pml4_entry.phys_addr().as_u64() + KERNEL_SPACE_START) as *mut PageTable;
            let pdpt_entry = (*pdpt_ptr).entry(pdpt_idx);
            if !pdpt_entry.is_present() {
                return Err("Page not mapped (PDPT)");
            }

            let pd_ptr = (pdpt_entry.phys_addr().as_u64() + KERNEL_SPACE_START) as *mut PageTable;
            let pd_entry = (*pd_ptr).entry(pd_idx);
            if !pd_entry.is_present() {
                return Err("Page not mapped (PD)");
            }

            let pt_ptr = (pd_entry.phys_addr().as_u64() + KERNEL_SPACE_START) as *mut PageTable;
            let pt_entry = (*pt_ptr).entry_mut(pt_idx);
            if !pt_entry.is_present() {
                return Err("Page not mapped (PT)");
            }

            let phys = pt_entry.phys_addr();
            pt_entry.clear();

            invlpg(virt);

            Ok(phys)
        }
    }

    pub fn clone_for_fork(&self, new_pid: u64) -> Result<Self, &'static str> {
        let mut new_space = AddressSpace::new(new_pid)?;
        for vma in &self.vmas {
            let mut new_vma = vma.clone();
            new_vma.cow = true;
            new_space.vmas.push(new_vma);
        }

        clone_page_tables(
            self.pml4_phys,
            new_space.pml4_phys,
        )?;

        mark_cow_pages(&mut new_space)?;

        new_space.brk = self.brk;
        new_space.brk_max = self.brk_max;
        new_space.mmap_base = self.mmap_base;
        new_space.stack_start = self.stack_start;
        new_space.stack_end = self.stack_end;

        Ok(new_space)
    }
}

pub fn clone_page_tables(src_pml4: PhysAddr, dst_pml4: PhysAddr) -> Result<(), &'static str> {
    let src_ptr = (src_pml4.as_u64() + KERNEL_SPACE_START) as *const PageTable;
    let dst_ptr = (dst_pml4.as_u64() + KERNEL_SPACE_START) as *mut PageTable;
    for i in 0..256 {
        // # SAFETY: Both src_pml4 and dst_pml4 are valid page table addresses:
        // # src_pml4 comes from an existing AddressSpace
        // # dst_pml4 was just allocated in AddressSpace::new()
        // Adding KERNEL_SPACE_START converts physical to kernel virtual address.
        // We only iterate user-space entries (0-255) to avoid touching kernel mappings.
        unsafe {
            let src_entry = (*src_ptr).entry(i);
            if src_entry.is_present() {
                let new_pdpt = clone_table(src_entry.phys_addr(), 3)?;
                let entry = (*dst_ptr).entry_mut(i);
                *entry = PageTableEntry::new(new_pdpt, src_entry.flags());
            }
        }
    }

    Ok(())
}

fn clone_table(src_phys: PhysAddr, level: u8) -> Result<PhysAddr, &'static str> {
    let dst_frame = crate::memory::phys::alloc(crate::memory::phys::AllocFlags::empty())
        .ok_or("Failed to allocate page table clone")?;

    let src_ptr = (src_phys.as_u64() + KERNEL_SPACE_START) as *const PageTable;
    let dst_ptr = (dst_frame.0 + KERNEL_SPACE_START) as *mut PageTable;
    // # SAFETY: src_phys is a valid page table physical address from a present entry.
    // dst_frame was just allocated from the frame allocator. Adding KERNEL_SPACE_START
    // converts physical to kernel virtual address. The recursive clone ensures all
    // intermediate page tables are properly duplicated.
    unsafe {
        (*dst_ptr).zero();
        for i in 0..512 {
            let src_entry = (*src_ptr).entry(i);
            if src_entry.is_present() {
                if level > 1 && !src_entry.is_huge_page() {
                    let new_table = clone_table(src_entry.phys_addr(), level - 1)?;
                    let entry = (*dst_ptr).entry_mut(i);
                    *entry = PageTableEntry::new(new_table, src_entry.flags());
                } else {
                    let entry = (*dst_ptr).entry_mut(i);
                    *entry = *src_entry;
                }
            }
        }
    }

    Ok(PhysAddr::new(dst_frame.0))
}

pub fn mark_cow_pages(space: &mut AddressSpace) -> Result<(), &'static str> {
    let pml4_ptr = (space.pml4_phys.as_u64() + KERNEL_SPACE_START) as *mut PageTable;
    for pml4_idx in 0..256 {
        // # SAFETY: space.pml4_phys is a valid page table address from the AddressSpace.
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
        // # SAFETY: pdpt_phys is a valid page table address from a present PML4 entry.
        // Adding KERNEL_SPACE_START converts physical to kernel virtual address.
        // Removing WRITABLE flag triggers COW faults on write attempts.
        unsafe {
            let entry = (*pdpt_ptr).entry_mut(i);
            if entry.is_present() && !entry.is_huge_page() {
                mark_cow_pd(entry.phys_addr())?;
            } else if entry.is_present() && entry.is_huge_page() {
                // Mark huge page as COW
                entry.set_flags(entry.flags() & !pte_flags::WRITABLE);
            }
        }
    }

    Ok(())
}

fn mark_cow_pd(pd_phys: PhysAddr) -> Result<(), &'static str> {
    let pd_ptr = (pd_phys.as_u64() + KERNEL_SPACE_START) as *mut PageTable;
    for i in 0..512 {
        // # SAFETY: pd_phys is a valid page table address from a present PDPT entry.
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
        // # SAFETY: pt_phys is a valid page table address from a present PD entry.
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
        // # SAFETY: pml4_phys is a valid page table address. Adding KERNEL_SPACE_START
        // converts physical to kernel virtual address. We only free user-space entries
        // (0-255) to avoid freeing kernel mappings which are shared.
        unsafe {
            let entry = (*pml4_ptr).entry(i);
            if entry.is_present() {
                free_pdpt(entry.phys_addr());
            }
        }
    }

    // Free PML4 itself
    let _ = crate::memory::phys::free(crate::memory::phys::Frame(pml4_phys.as_u64()));
}

fn free_pdpt(pdpt_phys: PhysAddr) {
    let pdpt_ptr = (pdpt_phys.as_u64() + KERNEL_SPACE_START) as *const PageTable;
    for i in 0..512 {
        // # SAFETY: pdpt_phys is a valid page table address from a present PML4 entry.
        // Adding KERNEL_SPACE_START converts physical to kernel virtual address.
        // We check for huge pages to avoid treating 1GB pages as table pointers.
        unsafe {
            let entry = (*pdpt_ptr).entry(i);
            if entry.is_present() && !entry.is_huge_page() {
                free_pd(entry.phys_addr());
            }
        }
    }

    let _ = crate::memory::phys::free(crate::memory::phys::Frame(pdpt_phys.as_u64()));
}

fn free_pd(pd_phys: PhysAddr) {
    let pd_ptr = (pd_phys.as_u64() + KERNEL_SPACE_START) as *const PageTable;
    for i in 0..512 {
        // # SAFETY: pd_phys is a valid page table address from a present PDPT entry.
        // Adding KERNEL_SPACE_START converts physical to kernel virtual address.
        // We check for huge pages to avoid treating 2MB pages as table pointers.
        // Note: Physical pages themselves are not freed here as they may be shared.
        unsafe {
            let entry = (*pd_ptr).entry(i);
            if entry.is_present() && !entry.is_huge_page() {
                let _ = crate::memory::phys::free(crate::memory::phys::Frame(entry.phys_addr().as_u64()));
            }
        }
    }

    let _ = crate::memory::phys::free(crate::memory::phys::Frame(pd_phys.as_u64()));
}
