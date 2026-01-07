// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

extern crate alloc;
use alloc::vec::Vec;
use x86_64::{PhysAddr, VirtAddr};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmProtection {
    None,
    Read,
    ReadWrite,
    ReadExecute,
    ReadWriteExecute,
}

impl VmProtection {
    pub const fn is_readable(&self) -> bool {
        !matches!(self, Self::None)
    }

    pub const fn is_writable(&self) -> bool {
        matches!(self, Self::ReadWrite | Self::ReadWriteExecute)
    }

    pub const fn is_executable(&self) -> bool {
        matches!(self, Self::ReadExecute | Self::ReadWriteExecute)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmType {
    Anonymous,
    File,
    Device,
    Shared,
    Stack,
    Heap,
    Code,
    Data,
}

impl VmType {
    pub const fn is_zero_initialized(&self) -> bool {
        matches!(self, Self::Anonymous | Self::Heap | Self::Stack)
    }

    pub const fn is_demand_paged(&self) -> bool {
        matches!(self, Self::Anonymous | Self::Heap | Self::Stack)
    }
}

#[derive(Debug, Clone)]
pub struct VmArea {
    pub start: VirtAddr,
    pub size: usize,
    pub protection: VmProtection,
    pub vm_type: VmType,
    pub flags: u32,
    pub creation_time: u64,
    pub access_count: u64,
    pub fault_count: u64,
}

impl VmArea {
    pub fn new(start: VirtAddr, size: usize, protection: VmProtection, vm_type: VmType) -> Self {
        Self {
            start,
            size,
            protection,
            vm_type,
            flags: 0,
            creation_time: get_timestamp(),
            access_count: 0,
            fault_count: 0,
        }
    }

    pub fn end(&self) -> VirtAddr {
        VirtAddr::new(self.start.as_u64() + self.size as u64)
    }

    pub fn contains(&self, addr: VirtAddr) -> bool {
        addr >= self.start && addr < self.end()
    }

    pub fn overlaps(&self, other: &VmArea) -> bool {
        self.start < other.end() && other.start < self.end()
    }

    pub fn can_merge(&self, other: &VmArea) -> bool {
        self.protection == other.protection
            && self.vm_type == other.vm_type
            && (self.end() == other.start || other.end() == self.start)
    }
}

#[derive(Debug, Clone)]
pub struct AddressSpace {
    pub asid: u32,
    pub page_table: PhysAddr,
    pub vm_areas: Vec<u64>,
    pub heap_start: VirtAddr,
    pub heap_end: VirtAddr,
    pub stack_start: VirtAddr,
    pub stack_end: VirtAddr,
    pub mmap_start: VirtAddr,
    pub creation_time: u64,
}

#[derive(Debug)]
pub struct VmStats {
    pub total_vm_areas: usize,
    pub address_spaces: usize,
    pub total_virtual_memory: u64,
    pub heap_usage: u64,
    pub stack_usage: u64,
    pub mmap_usage: u64,
    pub page_faults: u64,
    pub protection_faults: u64,
    pub swap_operations: u64,
    pub tlb_shootdowns: u64,
}

fn get_timestamp() -> u64 {
    // SAFETY: rdtsc is always safe on x86_64.
    unsafe { core::arch::x86_64::_rdtsc() }
}
