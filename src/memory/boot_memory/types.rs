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
use x86_64::PhysAddr;
use super::constants::*;
use super::error::{BootMemoryError, BootMemoryResult};

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BootHandoff {
    pub magic: u64,
    pub version: u16,
    pub flags: u16,
    pub memory_base: u64,
    pub memory_size: u64,
    pub kernel_base: u64,
    pub kernel_size: u64,
    pub capsule_base: u64,
    pub capsule_size: u64,
    pub entropy: [u8; BOOT_ENTROPY_SIZE],
    pub timestamp: u64,
}

impl BootHandoff {
    pub fn validate(&self) -> BootMemoryResult<()> {
        if self.magic != BOOT_HANDOFF_MAGIC { return Err(BootMemoryError::InvalidHandoffMagic); }
        if self.version < MIN_HANDOFF_VERSION || self.version > MAX_HANDOFF_VERSION { return Err(BootMemoryError::UnsupportedVersion); }
        Ok(())
    }

    pub const fn has_capsule(&self) -> bool { self.capsule_size > 0 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegionType {
    Available,
    Reserved,
    Kernel,
    Capsule,
    Hardware,
    Defective,
}

impl RegionType {
    pub const fn as_u8(&self) -> u8 {
        match self {
            Self::Available => REGION_TYPE_AVAILABLE,
            Self::Reserved => REGION_TYPE_RESERVED,
            Self::Kernel => REGION_TYPE_KERNEL,
            Self::Capsule => REGION_TYPE_CAPSULE,
            Self::Hardware => REGION_TYPE_HARDWARE,
            Self::Defective => REGION_TYPE_DEFECTIVE,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Available => "Available",
            Self::Reserved => "Reserved",
            Self::Kernel => "Kernel",
            Self::Capsule => "Capsule",
            Self::Hardware => "Hardware",
            Self::Defective => "Defective",
        }
    }

    pub const fn is_allocatable(&self) -> bool { matches!(self, Self::Available) }
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub start: PhysAddr,
    pub end: PhysAddr,
    pub region_type: RegionType,
    pub flags: u32,
}

impl MemoryRegion {
    pub const fn new(start: u64, end: u64, region_type: RegionType, flags: u32) -> Self {
        Self { start: PhysAddr::new(start), end: PhysAddr::new(end), region_type, flags }
    }

    #[inline]
    pub const fn size(&self) -> u64 {
        if self.end.as_u64() > self.start.as_u64() { self.end.as_u64() - self.start.as_u64() } else { 0 }
    }

    #[inline]
    pub const fn page_count(&self) -> u64 { self.size() / PAGE_SIZE_U64 }

    #[inline]
    pub const fn contains(&self, addr: PhysAddr) -> bool {
        addr.as_u64() >= self.start.as_u64() && addr.as_u64() < self.end.as_u64()
    }

    #[inline]
    pub const fn is_available(&self) -> bool { self.region_type.is_allocatable() }

    #[inline]
    pub const fn is_empty(&self) -> bool { self.end.as_u64() <= self.start.as_u64() }

    #[inline]
    pub const fn has_flag(&self, flag: u32) -> bool { (self.flags & flag) != 0 }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RegionStats {
    pub total_memory: u64,
    pub available_memory: u64,
    pub allocated_memory: u64,
    pub reserved_memory: u64,
    pub kernel_memory: u64,
    pub capsule_memory: u64,
    pub hardware_memory: u64,
    pub defective_memory: u64,
    pub region_count: usize,
}

impl RegionStats {
    #[inline]
    pub const fn free_memory(&self) -> u64 {
        if self.available_memory > self.allocated_memory { self.available_memory - self.allocated_memory } else { 0 }
    }

    #[inline]
    pub fn allocation_percent(&self) -> f64 {
        if self.available_memory == 0 { 0.0 } else { (self.allocated_memory as f64 / self.available_memory as f64) * 100.0 }
    }
}
