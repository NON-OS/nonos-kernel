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

use super::super::{layout, virt, virtual_memory};
use super::types::{MemoryProtection, MemoryType};
use crate::memory::addr::VirtAddr;

pub fn map_memory(
    va: VirtAddr,
    size: usize,
    protection: MemoryProtection,
    mem_type: MemoryType,
) -> Result<(), &'static str> {
    let vm_protection = match protection {
        MemoryProtection::None => virtual_memory::VmProtection::None,
        MemoryProtection::Read => virtual_memory::VmProtection::Read,
        MemoryProtection::ReadWrite => virtual_memory::VmProtection::ReadWrite,
        MemoryProtection::ReadExecute => virtual_memory::VmProtection::ReadExecute,
    };

    let vm_type = match mem_type {
        MemoryType::Anonymous => virtual_memory::VmType::Anonymous,
        MemoryType::KernelCode | MemoryType::UserCode => virtual_memory::VmType::Code,
        MemoryType::KernelData | MemoryType::UserData => virtual_memory::VmType::Data,
        MemoryType::UserHeap => virtual_memory::VmType::Heap,
        MemoryType::UserStack => virtual_memory::VmType::Stack,
        MemoryType::Device => virtual_memory::VmType::Device,
        MemoryType::SecureCapsule => virtual_memory::VmType::File,
        MemoryType::Shared => virtual_memory::VmType::Shared,
    };

    virtual_memory::map_memory_range(va, size, vm_protection, vm_type)?;
    Ok(())
}

pub fn unmap_memory(va: VirtAddr, size: usize) -> Result<(), &'static str> {
    if virtual_memory::find_vm_area_by_address(va).is_some() {
        let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
        for i in 0..page_count {
            let page_va = VirtAddr::new(va.as_u64() + (i * layout::PAGE_SIZE) as u64);
            let _ = virt::unmap_page(page_va);
        }
    }
    Ok(())
}
