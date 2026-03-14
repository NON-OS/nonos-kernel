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

use super::error::UsercopyError;
use crate::context::{get_current_context, ExecutionContext};

const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_FFFF;
const PAGE_SIZE: u64 = 4096;
const MAX_COPY_SIZE: usize = 64 * 1024 * 1024;

const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER: u64 = 1 << 2;

/// # Safety
/// Gets page table root from current context. For process context uses
/// stored page table. For kernel context reads CR3 directly.
fn get_page_table_root() -> Result<u64, UsercopyError> {
    match get_current_context() {
        ExecutionContext::Process(ctx) => Ok(ctx.page_table_root),
        ExecutionContext::Kernel(_) => {
            let cr3: u64;
            unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack)) };
            Ok(cr3 & !0xFFF)
        }
        ExecutionContext::None => Err(UsercopyError::NoProcessContext),
    }
}

/// # Safety
/// Validates page flags for user accessibility. Checks present, user, and
/// optionally writable bits. Returns error if page not accessible.
fn check_page_flags(addr: u64, need_write: bool) -> Result<(), UsercopyError> {
    let pt_root = get_page_table_root()?;
    let pte = walk_page_table(pt_root, addr)?;

    if (pte & PTE_PRESENT) == 0 {
        return Err(UsercopyError::PageNotMapped);
    }
    if (pte & PTE_USER) == 0 {
        return Err(UsercopyError::PageNotUser);
    }
    if need_write && (pte & PTE_WRITABLE) == 0 {
        return Err(UsercopyError::PageNotWritable);
    }
    Ok(())
}

/// # Safety
/// Walks x86_64 4-level page table to get PTE for virtual address.
/// Handles 1GB and 2MB huge pages. Returns error if any level not present.
fn walk_page_table(pt_root: u64, vaddr: u64) -> Result<u64, UsercopyError> {
    let pml4_idx = (vaddr >> 39) & 0x1FF;
    let pdpt_idx = (vaddr >> 30) & 0x1FF;
    let pd_idx = (vaddr >> 21) & 0x1FF;
    let pt_idx = (vaddr >> 12) & 0x1FF;

    let pml4 = phys_to_virt(pt_root);
    let pml4e = read_pte(pml4, pml4_idx)?;
    if (pml4e & PTE_PRESENT) == 0 {
        return Err(UsercopyError::PageNotMapped);
    }

    let pdpt = phys_to_virt(pml4e & 0x000F_FFFF_FFFF_F000);
    let pdpte = read_pte(pdpt, pdpt_idx)?;
    if (pdpte & PTE_PRESENT) == 0 {
        return Err(UsercopyError::PageNotMapped);
    }
    if (pdpte & (1 << 7)) != 0 {
        return Ok(pdpte);
    }

    let pd = phys_to_virt(pdpte & 0x000F_FFFF_FFFF_F000);
    let pde = read_pte(pd, pd_idx)?;
    if (pde & PTE_PRESENT) == 0 {
        return Err(UsercopyError::PageNotMapped);
    }
    if (pde & (1 << 7)) != 0 {
        return Ok(pde);
    }

    let pt = phys_to_virt(pde & 0x000F_FFFF_FFFF_F000);
    read_pte(pt, pt_idx)
}

/// # Safety
/// Converts physical address to virtual using direct mapping at 0xFFFF_8000_0000_0000.
fn phys_to_virt(phys: u64) -> u64 {
    phys + 0xFFFF_8000_0000_0000
}

/// # Safety
/// Reads page table entry using volatile read to prevent optimization.
fn read_pte(table_virt: u64, index: u64) -> Result<u64, UsercopyError> {
    let ptr = (table_virt + index * 8) as *const u64;
    Ok(unsafe { core::ptr::read_volatile(ptr) })
}

/// # Safety
/// Validates user memory region is readable. Checks address range is in
/// user space and all pages are present with user bit set.
pub fn validate_user_read(addr: u64, len: usize) -> Result<(), UsercopyError> {
    validate_range(addr, len, false)
}

/// # Safety
/// Validates user memory region is writable. Checks address range is in
/// user space and all pages are present with user and writable bits set.
pub fn validate_user_write(addr: u64, len: usize) -> Result<(), UsercopyError> {
    validate_range(addr, len, true)
}

/// # Safety
/// Core validation for user memory ranges. Iterates all pages in range
/// and validates each has required permissions.
fn validate_range(addr: u64, len: usize, need_write: bool) -> Result<(), UsercopyError> {
    if addr == 0 {
        return Err(UsercopyError::NullPointer);
    }
    if len > MAX_COPY_SIZE {
        return Err(UsercopyError::SizeTooLarge);
    }
    if len == 0 {
        return Ok(());
    }

    let end = addr.checked_add(len as u64 - 1).ok_or(UsercopyError::AddressOverflow)?;
    if end > USER_SPACE_END {
        return Err(UsercopyError::InvalidAddress);
    }

    let start_page = addr & !0xFFF;
    let end_page = end & !0xFFF;
    let mut page = start_page;

    while page <= end_page {
        check_page_flags(page, need_write)?;
        page = page.saturating_add(PAGE_SIZE);
        if page == 0 {
            break;
        }
    }
    Ok(())
}
