// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::super::constants::*;
use super::super::stats::VirtualMemoryStatistics;
use super::super::types::{VmArea, VmProtection, VmType};
use super::core::VirtualMemoryManager;
use crate::memory::addr::VirtAddr;
use crate::memory::paging;

impl VirtualMemoryManager {
    pub fn expand_heap(
        &mut self,
        new_size: usize,
        stats: &VirtualMemoryStatistics,
    ) -> Result<(), &'static str> {
        let current_asid = self.current_asid;
        let (heap_end, heap_start) = {
            let address_space =
                self.address_spaces.get(&current_asid).ok_or("Address space not found")?;
            (address_space.heap_end, address_space.heap_start)
        };
        let current_heap_size = (heap_end.as_u64() - heap_start.as_u64()) as usize;
        if new_size <= current_heap_size {
            return Ok(());
        }
        let additional_size = new_size - current_heap_size;
        let new_heap_end = VirtAddr::new(heap_start.as_u64() + new_size as u64);
        let heap_area =
            VmArea::new(heap_end, additional_size, VmProtection::ReadWrite, VmType::Heap);
        self.map_vm_area(heap_area, stats)?;
        let address_space =
            self.address_spaces.get_mut(&current_asid).ok_or("Address space not found")?;
        address_space.heap_end = new_heap_end;
        Ok(())
    }

    pub fn expand_stack(
        &mut self,
        additional_size: usize,
        stats: &VirtualMemoryStatistics,
    ) -> Result<(), &'static str> {
        let current_asid = self.current_asid;
        let stack_start = {
            let address_space =
                self.address_spaces.get(&current_asid).ok_or("Address space not found")?;
            address_space.stack_start
        };
        let new_stack_start = VirtAddr::new(stack_start.as_u64() - additional_size as u64);
        let stack_area =
            VmArea::new(new_stack_start, additional_size, VmProtection::ReadWrite, VmType::Stack);
        self.map_vm_area(stack_area, stats)?;
        let address_space =
            self.address_spaces.get_mut(&current_asid).ok_or("Address space not found")?;
        address_space.stack_start = new_stack_start;
        Ok(())
    }

    pub fn handle_page_fault(
        &mut self,
        fault_addr: VirtAddr,
        error_code: u64,
        stats: &VirtualMemoryStatistics,
    ) -> Result<(), &'static str> {
        stats.record_page_fault();
        let vm_area =
            self.find_vm_area_by_address(fault_addr).ok_or("No VM area for fault address")?;
        let area_id = self.find_vm_area_id_by_address(fault_addr).ok_or("VM area ID not found")?;
        if error_code & PF_PRESENT != 0 && error_code & PF_WRITE != 0 {
            if vm_area.protection == VmProtection::Read
                || vm_area.protection == VmProtection::ReadExecute
            {
                stats.record_protection_fault();
                return Err("Write to read-only memory");
            }
        }
        if error_code & PF_INSTRUCTION != 0 {
            if vm_area.protection == VmProtection::Read
                || vm_area.protection == VmProtection::ReadWrite
            {
                stats.record_protection_fault();
                return Err("Execute on non-executable memory");
            }
        }
        paging::handle_page_fault(fault_addr, error_code)
            .map_err(|_| "Failed to handle page fault")?;
        if let Some(area) = self.vm_areas.get_mut(&area_id) {
            area.fault_count += 1;
            area.access_count += 1;
        }
        Ok(())
    }
}
