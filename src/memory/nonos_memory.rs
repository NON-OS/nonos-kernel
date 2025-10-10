#![no_std]

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;
use x86_64::{PhysAddr, VirtAddr, structures::paging::PageTableFlags};

use crate::memory::layout::PAGE_SIZE;
use crate::memory::nonos_alloc as alloc_api;
use crate::memory::virt::{self, VmFlags};

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
    pub physical_addr: PhysAddr, // first page PA (informational)
    pub size: usize,
    pub region_type: NonosMemoryRegionType,
    pub security_level: NonosSecurityLevel,
    pub permissions: PageTableFlags,
    pub owner_process: u64,
    pub encrypted: bool,
    pub isolation_domain: u64,
    pub created_time: u64,
    pub access_count: u64,
    pub pages: usize,
}

#[derive(Debug)]
pub struct NonosMemoryManager {
    regions: RwLock<BTreeMap<u64, NonosMemoryRegion>>,
    by_va: RwLock<BTreeMap<u64, u64>>, // base VA -> region_id
    next_region_id: AtomicU64,
    total_allocated: AtomicU64,
    security_enabled: bool,
    isolation_enabled: bool,
}

impl NonosMemoryManager {
    pub const fn new() -> Self {
        Self {
            regions: RwLock::new(BTreeMap::new()),
            by_va: RwLock::new(BTreeMap::new()),
            next_region_id: AtomicU64::new(1),
            total_allocated: AtomicU64::new(0),
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

        let (vmf, pte) = perms_for_region(region_type)?;
        let pages = ((size + PAGE_SIZE - 1) / PAGE_SIZE).max(1);

        // Map anonymous kernel memory with the right permissions
        let base = unsafe { alloc_api::kalloc_pages(pages, vmf) };
        if base.as_u64() == 0 {
            return Err("Out of memory");
        }

        // First page PA (informational)
        let first_pa = virt::translate(base)
            .map(|(pa, _, _)| pa)
            .map_err(|_| "translate failed")?;

        let region_id = self.next_region_id.fetch_add(1, Ordering::SeqCst);
        let region = NonosMemoryRegion {
            region_id,
            virtual_addr: base,
            physical_addr: first_pa,
            size,
            region_type,
            security_level,
            permissions: pte,
            owner_process,
            encrypted: matches!(
                security_level,
                NonosSecurityLevel::Secret | NonosSecurityLevel::TopSecret | NonosSecurityLevel::QuantumSecure
            ),
            isolation_domain: self.calculate_isolation_domain(owner_process, security_level),
            created_time: rdtsc(),
            access_count: 0,
            pages,
        };

        {
            self.regions.write().insert(region_id, region);
            self.by_va.write().insert(base.as_u64(), region_id);
        }
        self.total_allocated.fetch_add(size as u64, Ordering::SeqCst);

        Ok(base)
    }

    pub fn deallocate_secure_memory(&self, virtual_addr: VirtAddr) -> Result<(), &'static str> {
        let rid = {
            let map = self.by_va.read();
            *map.get(&virtual_addr.as_u64()).ok_or("Address not allocated")?
        };

        let mut reg = self.regions.write();
        let region = reg.remove(&rid).ok_or("Region not found")?;

        // Scrub before unmap
        unsafe {
            for i in 0..region.pages {
                let va = VirtAddr::new(region.virtual_addr.as_u64() + (i * PAGE_SIZE) as u64);
                if virt::translate(va).is_ok() {
                    core::ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, PAGE_SIZE);
                }
            }
        }

        // Unmap and free frames
        unsafe { alloc_api::kfree_pages(region.virtual_addr, region.pages) };

        // Drop index and accounting
        self.by_va.write().remove(&region.virtual_addr.as_u64());
        self.total_allocated
            .fetch_sub(region.size as u64, Ordering::SeqCst);

        Ok(())
    }

    pub fn get_region_info(
        &self,
        virtual_addr: VirtAddr,
    ) -> Result<NonosMemoryRegionInfo, &'static str> {
        let rid = {
            let map = self.by_va.read();
            *map.get(&virtual_addr.as_u64()).ok_or("Address not allocated")?
        };
        let regs = self.regions.read();
        let r = regs.get(&rid).ok_or("Region not found")?;

        Ok(NonosMemoryRegionInfo {
            region_id: r.region_id,
            virtual_addr: r.virtual_addr,
            size: r.size,
            region_type: r.region_type,
            security_level: r.security_level,
            owner_process: r.owner_process,
            encrypted: r.encrypted,
            isolation_domain: r.isolation_domain,
            created_time: r.created_time,
            access_count: r.access_count,
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

        let rid = {
            let map = self.by_va.read();
            if let Some(id) = map.get(&virtual_addr.as_u64()) {
                *id
            } else {
                return false;
            }
        };
        let regs = self.regions.read();
        let r = if let Some(x) = regs.get(&rid) { x } else { return false };

        if r.owner_process != process_id {
            return false;
        }
        if !r.permissions.contains(requested_access) {
            return false;
        }
        if self.isolation_enabled {
            let expected = self.calculate_isolation_domain(process_id, r.security_level);
            if r.isolation_domain != expected {
                return false;
            }
        }
        true
    }

    #[inline]
    fn calculate_isolation_domain(
        &self,
        process_id: u64,
        security_level: NonosSecurityLevel,
    ) -> u64 {
        (process_id & 0xF) + ((security_level as u64) << 4)
    }

    pub fn get_memory_statistics(&self) -> NonosMemoryStatistics {
        NonosMemoryStatistics {
            total_allocated_bytes: self.total_allocated.load(Ordering::Relaxed) as usize,
            total_regions: self.regions.read().len(),
            security_enabled: self.security_enabled,
            isolation_enabled: self.isolation_enabled,
        }
    }

    pub fn zero_memory(&self, virtual_addr: VirtAddr, size: usize) -> Result<(), &'static str> {
        if size == 0 {
            return Ok(());
        }
        unsafe { core::ptr::write_bytes(virtual_addr.as_mut_ptr::<u8>(), 0, size) }
        Ok(())
    }

    // Back-compat helpers
    pub fn get_total_memory(&self) -> usize {
        64 * 1024 * 1024 * 1024
    }
    pub fn get_available_memory(&self) -> usize {
        self.get_total_memory()
            .saturating_sub(self.total_allocated.load(Ordering::Relaxed) as usize)
    }
    pub fn get_used_memory(&self) -> usize {
        self.total_allocated.load(Ordering::Relaxed) as usize
    }
    pub fn allocate(&self, size: usize) -> Result<u64, &'static str> {
        self.allocate_secure_memory(
            size,
            NonosMemoryRegionType::Heap,
            NonosSecurityLevel::Internal,
            0,
        )
        .map(|va| va.as_u64())
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

// Global singleton
pub static NONOS_MEMORY_MANAGER: NonosMemoryManager = NonosMemoryManager::new();

// Convenience wrappers
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

fn perms_for_region(kind: NonosMemoryRegionType) -> Result<(VmFlags, PageTableFlags), &'static str> {
    Ok(match kind {
        NonosMemoryRegionType::Code => (
            VmFlags::GLOBAL, // RX (NX not set)
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        ),
        NonosMemoryRegionType::Data
        | NonosMemoryRegionType::Stack
        | NonosMemoryRegionType::Heap
        | NonosMemoryRegionType::Shared => (
            VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL, // RW+NX
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::USER_ACCESSIBLE
                | PageTableFlags::NO_EXECUTE,
        ),
        NonosMemoryRegionType::Device => (
            VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL | VmFlags::PCD | VmFlags::PWT, // UC-
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_CACHE
                | PageTableFlags::WRITE_THROUGH
                | PageTableFlags::NO_EXECUTE,
        ),
    })
}

#[inline]
fn rdtsc() -> u64 {
    unsafe {
        let mut hi: u32;
        let mut lo: u32;
        core::arch::asm!("rdtsc", out("edx") hi, out("eax") lo, options(nomem, nostack, preserves_flags));
        ((hi as u64) << 32) | (lo as u64)
    }
}
