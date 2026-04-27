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
use core::sync::atomic::Ordering;

impl VirtualMemoryStatistics {
    pub fn total_vm_areas(&self) -> usize {
        self.total_vm_areas.load(Ordering::Relaxed)
    }
    pub fn total_virtual_memory(&self) -> u64 {
        self.total_virtual_memory.load(Ordering::Relaxed)
    }
    pub fn heap_usage(&self) -> u64 {
        self.heap_usage.load(Ordering::Relaxed)
    }
    pub fn stack_usage(&self) -> u64 {
        self.stack_usage.load(Ordering::Relaxed)
    }
    pub fn mmap_usage(&self) -> u64 {
        self.mmap_usage.load(Ordering::Relaxed)
    }
    pub fn page_faults(&self) -> u64 {
        self.page_faults.load(Ordering::Relaxed)
    }
    pub fn protection_faults(&self) -> u64 {
        self.protection_faults.load(Ordering::Relaxed)
    }
    pub fn swap_operations(&self) -> u64 {
        self.swap_operations.load(Ordering::Relaxed)
    }
    pub fn tlb_shootdowns(&self) -> u64 {
        self.tlb_shootdowns.load(Ordering::Relaxed)
    }
}
