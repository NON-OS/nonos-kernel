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

use x86_64::{VirtAddr, PhysAddr};
use super::constants::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegionType {
    Code,
    Data,
    Stack,
    Heap,
    Device,
    Capsule,
}

impl RegionType {
    pub const fn as_u8(&self) -> u8 {
        match self {
            Self::Code => REGION_TYPE_CODE,
            Self::Data => REGION_TYPE_DATA,
            Self::Stack => REGION_TYPE_STACK,
            Self::Heap => REGION_TYPE_HEAP,
            Self::Device => REGION_TYPE_DEVICE,
            Self::Capsule => REGION_TYPE_CAPSULE,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Code => "Code",
            Self::Data => "Data",
            Self::Stack => "Stack",
            Self::Heap => "Heap",
            Self::Device => "Device",
            Self::Capsule => "Capsule",
        }
    }

    pub const fn is_writable(&self) -> bool {
        matches!(self, Self::Data | Self::Stack | Self::Heap | Self::Device)
    }

    pub const fn is_executable(&self) -> bool {
        matches!(self, Self::Code)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecurityLevel {
    Public,
    Internal,
    Confidential,
    Secret,
    TopSecret,
}

impl SecurityLevel {
    pub const fn as_u8(&self) -> u8 {
        match self {
            Self::Public => SECURITY_LEVEL_PUBLIC,
            Self::Internal => SECURITY_LEVEL_INTERNAL,
            Self::Confidential => SECURITY_LEVEL_CONFIDENTIAL,
            Self::Secret => SECURITY_LEVEL_SECRET,
            Self::TopSecret => SECURITY_LEVEL_TOP_SECRET,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "Public",
            Self::Internal => "Internal",
            Self::Confidential => "Confidential",
            Self::Secret => "Secret",
            Self::TopSecret => "TopSecret",
        }
    }

    pub const fn requires_encryption(&self) -> bool {
        self.as_u8() >= ENCRYPTION_THRESHOLD_LEVEL
    }

    pub const fn requires_secure_scrub(&self) -> bool {
        matches!(self, Self::Secret | Self::TopSecret)
    }

    pub const fn scrub_passes(&self) -> usize {
        match self {
            Self::TopSecret => SECURE_SCRUB_PASSES,
            Self::Secret => 1,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub region_id: u64,
    pub virtual_addr: VirtAddr,
    pub physical_addr: PhysAddr,
    pub size: usize,
    pub region_type: RegionType,
    pub security_level: SecurityLevel,
    pub owner_process: u64,
    pub encrypted: bool,
    pub creation_time: u64,
    pub access_count: u64,
}

impl MemoryRegion {
    pub const fn new(
        region_id: u64, virtual_addr: VirtAddr, physical_addr: PhysAddr,
        size: usize, region_type: RegionType, security_level: SecurityLevel,
        owner_process: u64, creation_time: u64,
    ) -> Self {
        Self {
            region_id, virtual_addr, physical_addr, size, region_type,
            security_level, owner_process, encrypted: security_level.requires_encryption(),
            creation_time, access_count: 0,
        }
    }

    #[inline]
    pub fn end_addr(&self) -> VirtAddr {
        VirtAddr::new(self.virtual_addr.as_u64().saturating_add(self.size as u64))
    }

    #[inline]
    pub fn contains(&self, addr: VirtAddr) -> bool {
        addr >= self.virtual_addr && addr < self.end_addr()
    }

    #[inline]
    pub const fn page_count(&self) -> usize {
        (self.size + PAGE_SIZE - 1) / PAGE_SIZE
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ManagerStats {
    pub total_regions: usize,
    pub allocated_memory: u64,
    pub peak_memory: u64,
    pub allocations: u64,
    pub deallocations: u64,
}

impl ManagerStats {
    #[inline]
    pub fn utilization_percent(&self) -> f64 {
        if self.peak_memory == 0 { 0.0 } else { (self.allocated_memory as f64 / self.peak_memory as f64) * 100.0 }
    }
}
