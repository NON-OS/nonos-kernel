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

use core::sync::atomic::{AtomicU64, AtomicUsize};

pub struct VirtualMemoryStatistics {
    pub(crate) total_vm_areas: AtomicUsize,
    pub(crate) total_virtual_memory: AtomicU64,
    pub(crate) heap_usage: AtomicU64,
    pub(crate) stack_usage: AtomicU64,
    pub(crate) mmap_usage: AtomicU64,
    pub(crate) page_faults: AtomicU64,
    pub(crate) protection_faults: AtomicU64,
    pub(crate) swap_operations: AtomicU64,
    pub(crate) tlb_shootdowns: AtomicU64,
}

impl VirtualMemoryStatistics {
    pub const fn new() -> Self {
        Self {
            total_vm_areas: AtomicUsize::new(0),
            total_virtual_memory: AtomicU64::new(0),
            heap_usage: AtomicU64::new(0),
            stack_usage: AtomicU64::new(0),
            mmap_usage: AtomicU64::new(0),
            page_faults: AtomicU64::new(0),
            protection_faults: AtomicU64::new(0),
            swap_operations: AtomicU64::new(0),
            tlb_shootdowns: AtomicU64::new(0),
        }
    }
}

impl Default for VirtualMemoryStatistics {
    fn default() -> Self {
        Self::new()
    }
}
