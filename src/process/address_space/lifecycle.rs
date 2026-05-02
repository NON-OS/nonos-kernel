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

//! Process address-space lifecycle. The functions here are the
//! process-layer expression of allocate / inherit / switch /
//! release. The underlying paging primitives are still x86_64-shaped
//! (CR3 handle, `paging::manager` API names); that flavor is held
//! below this boundary in `store_handle` and `load_handle`.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::process::core::ProcessControlBlock;

pub fn allocate(pcb: &Arc<ProcessControlBlock>) -> Result<(), &'static str> {
    crate::memory::paging::manager::create_address_space(pcb.pid)
        .map_err(|_| "failed to allocate process address space")?;
    let handle = crate::memory::paging::manager::get_process_cr3(pcb.pid)
        .ok_or("address space created but handle not retrievable")?;
    store_handle(pcb, handle);
    Ok(())
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
