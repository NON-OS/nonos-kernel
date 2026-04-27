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

use super::state::VirtualMemoryStatistics;
use crate::memory::virtual_memory::types::VmType;
use core::sync::atomic::Ordering;

impl VirtualMemoryStatistics {
    pub fn record_vm_area(&self, size: u64, vm_type: VmType) {
        self.total_vm_areas.fetch_add(1, Ordering::Relaxed);
        self.total_virtual_memory.fetch_add(size, Ordering::Relaxed);
        match vm_type {
            VmType::Heap => {
                self.heap_usage.fetch_add(size, Ordering::Relaxed);
            }
            VmType::Stack => {
                self.stack_usage.fetch_add(size, Ordering::Relaxed);
            }
            VmType::Anonymous | VmType::File | VmType::Shared => {
                self.mmap_usage.fetch_add(size, Ordering::Relaxed);
            }
            _ => {}
        };
    }

    pub fn record_vm_area_removal(&self, size: u64, vm_type: VmType) {
        self.total_vm_areas.fetch_sub(1, Ordering::Relaxed);
        self.total_virtual_memory.fetch_sub(size, Ordering::Relaxed);
        match vm_type {
            VmType::Heap => {
                self.heap_usage.fetch_sub(size, Ordering::Relaxed);
            }
            VmType::Stack => {
                self.stack_usage.fetch_sub(size, Ordering::Relaxed);
            }
            VmType::Anonymous | VmType::File | VmType::Shared => {
                self.mmap_usage.fetch_sub(size, Ordering::Relaxed);
            }
            _ => {}
        };
    }

    pub fn record_page_fault(&self) {
        self.page_faults.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_protection_fault(&self) {
        self.protection_faults.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_tlb_shootdowns(&self, count: u64) {
        self.tlb_shootdowns.fetch_add(count, Ordering::Relaxed);
    }
}
