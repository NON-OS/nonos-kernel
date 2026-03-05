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

//! Virtual Memory Types

extern crate alloc;

use alloc::vec::Vec;
use x86_64::{PhysAddr, VirtAddr};

/// Virtual memory protection flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmProtection {
    /// No access.
    None,
    /// Read-only.
    Read,
    /// Read and write.
    ReadWrite,
    /// Read and execute.
    ReadExecute,
    /// Read, write, and execute (violates W^X).
    ReadWriteExecute,
}

impl VmProtection {
    /// Returns true if readable.
    pub const fn is_readable(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Returns true if writable.
    pub const fn is_writable(&self) -> bool {
        matches!(self, Self::ReadWrite | Self::ReadWriteExecute)
    }

    /// Returns true if executable.
    pub const fn is_executable(&self) -> bool {
        matches!(self, Self::ReadExecute | Self::ReadWriteExecute)
    }
}

/// Virtual memory area type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmType {
    /// Anonymous memory (demand-paged).
    Anonymous,
    /// File-backed memory.
    File,
    /// Device memory (MMIO).
    Device,
    /// Shared memory.
    Shared,
    /// Stack memory.
    Stack,
    /// Heap memory.
    Heap,
    /// Code/text segment.
    Code,
    /// Data segment.
    Data,
}

impl VmType {
    /// Returns true if this type should be zero-initialized.
    pub const fn is_zero_initialized(&self) -> bool {
        matches!(self, Self::Anonymous | Self::Heap | Self::Stack)
    }

    /// Returns true if this type is demand-paged.
    pub const fn is_demand_paged(&self) -> bool {
        matches!(self, Self::Anonymous | Self::Heap | Self::Stack)
    }
}

/// Virtual memory area descriptor.
#[derive(Debug, Clone)]
pub struct VmArea {
    /// Start virtual address.
    pub start: VirtAddr,
    /// Size in bytes.
    pub size: usize,
    /// Protection flags.
    pub protection: VmProtection,
    /// Type of VM area.
    pub vm_type: VmType,
    /// Additional flags.
    pub flags: u32,
    /// Creation timestamp.
    pub creation_time: u64,
    /// Access count.
    pub access_count: u64,
    /// Page fault count.
    pub fault_count: u64,
}

impl VmArea {
    /// Creates a new VM area.
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

    /// Returns the end address.
    pub fn end(&self) -> VirtAddr {
        VirtAddr::new(self.start.as_u64() + self.size as u64)
    }

    /// Returns true if address is within this area.
    pub fn contains(&self, addr: VirtAddr) -> bool {
        addr >= self.start && addr < self.end()
    }

    /// Returns true if this area overlaps with another.
    pub fn overlaps(&self, other: &VmArea) -> bool {
        self.start < other.end() && other.start < self.end()
    }

    /// Returns true if this area can merge with another.
    pub fn can_merge(&self, other: &VmArea) -> bool {
        self.protection == other.protection
            && self.vm_type == other.vm_type
            && (self.end() == other.start || other.end() == self.start)
    }
}

/// Address space descriptor.
#[derive(Debug, Clone)]
pub struct AddressSpace {
    /// Address space ID.
    pub asid: u32,
    /// Page table physical address.
    pub page_table: PhysAddr,
    /// VM area IDs in this address space.
    pub vm_areas: Vec<u64>,
    /// Heap start address.
    pub heap_start: VirtAddr,
    /// Heap end address (current brk).
    pub heap_end: VirtAddr,
    /// Stack start address (lowest).
    pub stack_start: VirtAddr,
    /// Stack end address (highest).
    pub stack_end: VirtAddr,
    /// Mmap region start.
    pub mmap_start: VirtAddr,
    /// Creation timestamp.
    pub creation_time: u64,
}

/// Virtual memory statistics.
#[derive(Debug)]
pub struct VmStats {
    /// Total number of VM areas.
    pub total_vm_areas: usize,
    /// Number of address spaces.
    pub address_spaces: usize,
    /// Total virtual memory mapped.
    pub total_virtual_memory: u64,
    /// Heap memory usage.
    pub heap_usage: u64,
    /// Stack memory usage.
    pub stack_usage: u64,
    /// Mmap memory usage.
    pub mmap_usage: u64,
    /// Total page faults.
    pub page_faults: u64,
    /// Protection faults.
    pub protection_faults: u64,
    /// Swap operations.
    pub swap_operations: u64,
    /// TLB shootdowns.
    pub tlb_shootdowns: u64,
}

/// Gets current timestamp.
fn get_timestamp() -> u64 {
    // SAFETY: rdtsc is always safe on x86_64.
    unsafe { core::arch::x86_64::_rdtsc() }
}
