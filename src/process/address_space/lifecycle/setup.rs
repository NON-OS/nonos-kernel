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

//! Allocate / inherit / switch — the process-layer expression of
//! address-space setup. The CR3-shaped paging primitives stay below
//! this boundary in the two private handle helpers.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::process::core::ProcessControlBlock;

pub fn allocate(pcb: &Arc<ProcessControlBlock>) -> Result<(), &'static str> {
    crate::memory::paging::manager::create_address_space(pcb.pid).map_err(|e| {
        // Surface the exact PagingError so the boot fatal path names
        // the precondition that failed instead of swallowing it.
        crate::sys::serial::print(b"[PAGING-ERR] create_address_space failed: ");
        crate::sys::serial::println(paging_error_name(e).as_bytes());
        match e {
            crate::memory::paging::error::PagingError::FrameAllocationFailed => {
                "create_address_space: frame allocator returned None"
            }
            crate::memory::paging::error::PagingError::NoActivePageTable => {
                "create_address_space: no active page table or empty kernel half"
            }
            crate::memory::paging::error::PagingError::NotInitialized => {
                "create_address_space: paging manager not initialized"
            }
            _ => "create_address_space: paging error",
        }
    })?;
    let handle = crate::memory::paging::manager::get_process_cr3(pcb.pid)
        .ok_or("address space created but handle not retrievable")?;
    store_handle(pcb, handle);
    Ok(())
}

fn paging_error_name(e: crate::memory::paging::error::PagingError) -> &'static str {
    use crate::memory::paging::error::PagingError;
    match e {
        PagingError::NotInitialized => "NotInitialized",
        PagingError::NoActivePageTable => "NoActivePageTable",
        PagingError::FrameAllocationFailed => "FrameAllocationFailed",
        PagingError::PageNotMapped => "PageNotMapped",
        PagingError::Pml4NotPresent => "Pml4NotPresent",
        PagingError::PdptNotPresent => "PdptNotPresent",
        PagingError::PdNotPresent => "PdNotPresent",
        PagingError::PtNotPresent => "PtNotPresent",
        PagingError::AddressSpaceNotFound => "AddressSpaceNotFound",
        PagingError::InvalidAddress => "InvalidAddress",
        PagingError::WXViolation => "WXViolation",
        PagingError::AlreadyMapped => "AlreadyMapped",
        PagingError::PermissionDenied => "PermissionDenied",
        PagingError::UnhandledPageFault => "UnhandledPageFault",
        PagingError::CowFaultFailed => "CowFaultFailed",
        PagingError::DemandFaultFailed => "DemandFaultFailed",
        PagingError::InvalidPageSize => "InvalidPageSize",
        PagingError::NotAligned => "NotAligned",
        PagingError::KernelSpaceViolation => "KernelSpaceViolation",
    }
}

pub fn inherit(pcb: &Arc<ProcessControlBlock>, parent: &Arc<ProcessControlBlock>) {
    store_handle(pcb, load_handle(parent));
}

pub fn switch_to(pid: u32) -> Result<(), &'static str> {
    crate::memory::paging::manager::switch_to_process_address_space(pid)
        .map_err(|_| "failed to switch process address space")
}

fn store_handle(pcb: &Arc<ProcessControlBlock>, handle: u64) {
    pcb.cr3.store(handle, Ordering::Release);
}

fn load_handle(pcb: &Arc<ProcessControlBlock>) -> u64 {
    pcb.cr3.load(Ordering::Acquire)
}
