#![no_std]

use alloc::collections::BTreeMap;
use spin::{Mutex, RwLock};
use x86_64::{structures::paging::PageTableFlags, PhysAddr, VirtAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonosMemoryRegionType {
    Code = 0,
    Data = 1,
    Stack = 2,
    Heap = 3,
    Shared = 4,
    Device = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonosSecurityLevel {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Secret = 3,
    TopSecret = 4,
    QuantumSecure = 5,
}

#[derive(Debug)]
pub struct NonosMemoryRegion {
    pub region_id: u64,
    pub virtual_addr: VirtAddr,
    pub physical_addr: PhysAddr,
    pub size: usize,
    pub region_type: NonosMemoryRegionType,
    pub security_level: NonosSecurityLevel,
    pub permissions: PageTableFlags,
    pub owner_process: u64,
    pub encrypted: bool,
    pub isolation_domain: u64,
    pub created_time: u64,
    pub access_count: u64,
}

#[derive(Debug)]
pub struct NonosMemoryManager {
    regions: RwLock<BTreeMap<u64, NonosMemoryRegion>>,
    allocated_regions: RwLock<BTreeMap<VirtAddr, u64>>,
    next_region_id: Mutex<u64>,
    total_allocated: Mutex<usize>,
    security_enabled: bool,
    isolation_enabled: bool,
}

impl NonosMemoryManager {
    pub const fn new() -> Self {
        Self {
            regions: RwLock::new(BTreeMap::new()),
            allocated_regions: RwLock::new(BTreeMap::new()),
            next_region_id: Mutex::new(1),
            total_allocated: Mutex::new(0),
            security_enabled: true,
            isolation_enabled: true,
        }
    }

    pub fn allocate_secure_memory(
        &self,
        size: usize,
        region_type: NonosMemoryRegionType,
        security_level: NonosSecurityLevel,
        owner_process: u64,
    ) -> Result<VirtAddr, &'static str> {
        if size == 0 {
            return Err("Invalid size");
        }

        let region_id = {
            let mut next_id = self.next_region_id.lock();
            let id = *next_id;
            *next_id += 1;
            id
        };

        // Simplified allocation - in production this would use proper page allocation
        let virtual_addr = VirtAddr::new(0x10000000 + (region_id * 4096));
        let physical_addr = PhysAddr::new(0x10000000 + (region_id * 4096));

        let permissions = match region_type {
            NonosMemoryRegionType::Code => {
                PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE
            }
            NonosMemoryRegionType::Data => {
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE
            }
            NonosMemoryRegionType::Stack => {
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE
            }
            NonosMemoryRegionType::Heap => {
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE
            }
            NonosMemoryRegionType::Shared => {
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE
            }
            NonosMemoryRegionType::Device => {
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE
            }
        };

        let region = NonosMemoryRegion {
            region_id,
            virtual_addr,
            physical_addr,
            size,
            region_type,
            security_level,
            permissions,
            owner_process,
            encrypted: matches!(
                security_level,
                NonosSecurityLevel::Secret
                    | NonosSecurityLevel::TopSecret
                    | NonosSecurityLevel::QuantumSecure
            ),
            isolation_domain: self.calculate_isolation_domain(owner_process, security_level),
            created_time: self.get_timestamp(),
            access_count: 0,
        };

        // Register region
        self.regions.write().insert(region_id, region);
        self.allocated_regions.write().insert(virtual_addr, region_id);

        // Update total allocated
        *self.total_allocated.lock() += size;

        Ok(virtual_addr)
    }

    pub fn deallocate_secure_memory(&self, virtual_addr: VirtAddr) -> Result<(), &'static str> {
        let region_id = {
            let allocated = self.allocated_regions.read();
            *allocated.get(&virtual_addr).ok_or("Address not allocated")?
        };

        let mut regions = self.regions.write();
        let region = regions.remove(&region_id).ok_or("Region not found")?;

        // Update allocated regions
        self.allocated_regions.write().remove(&virtual_addr);

        // Update total allocated
        *self.total_allocated.lock() -= region.size;

        // In production, this would also clear/zero the memory for security

        Ok(())
    }

    pub fn get_region_info(
        &self,
        virtual_addr: VirtAddr,
    ) -> Result<NonosMemoryRegionInfo, &'static str> {
        let allocated = self.allocated_regions.read();
        let region_id = allocated.get(&virtual_addr).ok_or("Address not allocated")?;

        let regions = self.regions.read();
        let region = regions.get(region_id).ok_or("Region not found")?;

        Ok(NonosMemoryRegionInfo {
            region_id: region.region_id,
            virtual_addr: region.virtual_addr,
            size: region.size,
            region_type: region.region_type,
            security_level: region.security_level,
            owner_process: region.owner_process,
            encrypted: region.encrypted,
            isolation_domain: region.isolation_domain,
            created_time: region.created_time,
            access_count: region.access_count,
        })
    }

    pub fn check_memory_access(
        &self,
        process_id: u64,
        virtual_addr: VirtAddr,
        requested_access: PageTableFlags,
    ) -> bool {
        if !self.security_enabled {
            return true;
        }

        let allocated = self.allocated_regions.read();
        let region_id = match allocated.get(&virtual_addr) {
            Some(id) => *id,
            None => return false,
        };

        let regions = self.regions.read();
        let region = match regions.get(&region_id) {
            Some(r) => r,
            None => return false,
        };

        // Check ownership
        if region.owner_process != process_id {
            return false;
        }

        // Check permissions
        if !region.permissions.contains(requested_access) {
            return false;
        }

        // Check isolation domain if enabled
        if self.isolation_enabled {
            let expected_domain =
                self.calculate_isolation_domain(process_id, region.security_level);
            if region.isolation_domain != expected_domain {
                return false;
            }
        }

        true
    }

    fn calculate_isolation_domain(
        &self,
        process_id: u64,
        security_level: NonosSecurityLevel,
    ) -> u64 {
        // Simple domain calculation - in production this would be more sophisticated
        (process_id % 16) + ((security_level as u64) * 16)
    }

    fn get_timestamp(&self) -> u64 {
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    pub fn get_memory_statistics(&self) -> NonosMemoryStatistics {
        let total_allocated = *self.total_allocated.lock();
        let total_regions = self.regions.read().len();

        NonosMemoryStatistics {
            total_allocated_bytes: total_allocated,
            total_regions,
            security_enabled: self.security_enabled,
            isolation_enabled: self.isolation_enabled,
        }
    }

    pub fn zero_memory(&self, _virtual_addr: VirtAddr, _size: usize) -> Result<(), &'static str> {
        // Security function to zero memory
        // In production this would actually zero the memory
        Ok(())
    }
}

#[derive(Debug)]
pub struct NonosMemoryRegionInfo {
    pub region_id: u64,
    pub virtual_addr: VirtAddr,
    pub size: usize,
    pub region_type: NonosMemoryRegionType,
    pub security_level: NonosSecurityLevel,
    pub owner_process: u64,
    pub encrypted: bool,
    pub isolation_domain: u64,
    pub created_time: u64,
    pub access_count: u64,
}

#[derive(Debug)]
pub struct NonosMemoryStatistics {
    pub total_allocated_bytes: usize,
    pub total_regions: usize,
    pub security_enabled: bool,
    pub isolation_enabled: bool,
}

// Global memory manager instance
pub static NONOS_MEMORY_MANAGER: NonosMemoryManager = NonosMemoryManager::new();

// Convenience functions
pub fn allocate_nonos_secure_memory(
    size: usize,
    region_type: NonosMemoryRegionType,
    security_level: NonosSecurityLevel,
    owner_process: u64,
) -> Result<VirtAddr, &'static str> {
    NONOS_MEMORY_MANAGER.allocate_secure_memory(size, region_type, security_level, owner_process)
}

pub fn deallocate_nonos_secure_memory(virtual_addr: VirtAddr) -> Result<(), &'static str> {
    NONOS_MEMORY_MANAGER.deallocate_secure_memory(virtual_addr)
}

pub fn check_nonos_memory_access(
    process_id: u64,
    virtual_addr: VirtAddr,
    requested_access: PageTableFlags,
) -> bool {
    NONOS_MEMORY_MANAGER.check_memory_access(process_id, virtual_addr, requested_access)
}

pub fn get_nonos_memory_stats() -> NonosMemoryStatistics {
    NONOS_MEMORY_MANAGER.get_memory_statistics()
}
