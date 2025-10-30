#![no_std]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::{VirtAddr, PhysAddr};
use crate::memory::nonos_layout as layout;

static REGION_MANAGER: Mutex<RegionManager> = Mutex::new(RegionManager::new());
static REGION_STATS: RegionStatistics = RegionStatistics::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegionType {
    Available,
    Reserved,
    Kernel,
    User,
    Stack,
    Heap,
    Mmio,
    Firmware,
    Bootloader,
    Dma,
    Guard,
    Shared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionFlags {
    Readable,
    Writable,
    Executable,
    Cacheable,
    Shared,
    Locked,
    Protected,
    Encrypted,
}

#[derive(Debug, Clone, Copy)]
pub struct MemRegion {
    pub start: u64,
    pub size: usize,
    pub region_type: RegionType,
    pub flags: u32,
    pub creation_time: u64,
    pub access_count: u64,
}

impl MemRegion {
    pub const fn new(start: u64, size: usize, region_type: RegionType) -> Self {
        Self {
            start,
            size,
            region_type,
            flags: 0,
            creation_time: 0,
            access_count: 0,
        }
    }

    pub fn start_addr(&self) -> VirtAddr {
        VirtAddr::new(self.start)
    }

    pub const fn end(&self) -> u64 {
        self.start + self.size as u64
    }

    pub fn end_addr(&self) -> VirtAddr {
        VirtAddr::new(self.end())
    }

    pub const fn size_bytes(&self) -> u64 {
        self.size as u64
    }

    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end()
    }

    pub const fn contains_range(&self, other: &MemRegion) -> bool {
        other.start >= self.start && other.end() <= self.end()
    }

    pub const fn overlaps(&self, other: &MemRegion) -> bool {
        self.start < other.end() && other.start < self.end()
    }

    pub fn has_flag(&self, flag: RegionFlags) -> bool {
        let flag_bit = match flag {
            RegionFlags::Readable => 1 << 0,
            RegionFlags::Writable => 1 << 1,
            RegionFlags::Executable => 1 << 2,
            RegionFlags::Cacheable => 1 << 3,
            RegionFlags::Shared => 1 << 4,
            RegionFlags::Locked => 1 << 5,
            RegionFlags::Protected => 1 << 6,
            RegionFlags::Encrypted => 1 << 7,
        };
        (self.flags & flag_bit) != 0
    }

    pub fn set_flag(&mut self, flag: RegionFlags) {
        let flag_bit = match flag {
            RegionFlags::Readable => 1 << 0,
            RegionFlags::Writable => 1 << 1,
            RegionFlags::Executable => 1 << 2,
            RegionFlags::Cacheable => 1 << 3,
            RegionFlags::Shared => 1 << 4,
            RegionFlags::Locked => 1 << 5,
            RegionFlags::Protected => 1 << 6,
            RegionFlags::Encrypted => 1 << 7,
        };
        self.flags |= flag_bit;
    }

    pub fn clear_flag(&mut self, flag: RegionFlags) {
        let flag_bit = match flag {
            RegionFlags::Readable => 1 << 0,
            RegionFlags::Writable => 1 << 1,
            RegionFlags::Executable => 1 << 2,
            RegionFlags::Cacheable => 1 << 3,
            RegionFlags::Shared => 1 << 4,
            RegionFlags::Locked => 1 << 5,
            RegionFlags::Protected => 1 << 6,
            RegionFlags::Encrypted => 1 << 7,
        };
        self.flags &= !flag_bit;
    }

    pub fn union(&self, other: &MemRegion) -> Option<MemRegion> {
        if self.region_type != other.region_type {
            return None;
        }

        if self.end() < other.start || other.end() < self.start {
            if self.end() == other.start || other.end() == self.start {
                let lo = self.start.min(other.start);
                let hi = self.end().max(other.end());
                let mut result = MemRegion::new(lo, (hi - lo) as usize, self.region_type);
                result.flags = self.flags | other.flags;
                result.creation_time = self.creation_time.min(other.creation_time);
                return Some(result);
            }
            return None;
        }

        let lo = self.start.min(other.start);
        let hi = self.end().max(other.end());
        let mut result = MemRegion::new(lo, (hi - lo) as usize, self.region_type);
        result.flags = self.flags | other.flags;
        result.creation_time = self.creation_time.min(other.creation_time);
        Some(result)
    }

    pub fn subtract(&self, other: &MemRegion) -> [Option<MemRegion>; 2] {
        if !self.overlaps(other) {
            return [Some(*self), None];
        }

        let mut fragments = [None, None];

        let left_lo = self.start;
        let left_hi = other.start.min(self.end());
        if left_hi > left_lo {
            let mut left = MemRegion::new(left_lo, (left_hi - left_lo) as usize, self.region_type);
            left.flags = self.flags;
            left.creation_time = self.creation_time;
            fragments[0] = Some(left);
        }

        let right_lo = other.end().max(self.start);
        let right_hi = self.end();
        if right_hi > right_lo {
            let mut right = MemRegion::new(right_lo, (right_hi - right_lo) as usize, self.region_type);
            right.flags = self.flags;
            right.creation_time = self.creation_time;
            fragments[1] = Some(right);
        }

        fragments
    }

    pub fn page_align(self, align: u64) -> MemRegion {
        let start = self.start & !(align - 1);
        let end = (self.end() + align - 1) & !(align - 1);
        let mut result = MemRegion::new(start, (end - start) as usize, self.region_type);
        result.flags = self.flags;
        result.creation_time = self.creation_time;
        result
    }
}

struct RegionManager {
    regions: BTreeMap<u64, MemRegion>,
    free_regions: Vec<MemRegion>,
    region_pools: BTreeMap<RegionType, Vec<MemRegion>>,
    next_region_id: u64,
    initialized: bool,
}

struct RegionStatistics {
    total_regions: AtomicUsize,
    allocated_bytes: AtomicU64,
    free_bytes: AtomicU64,
    fragmentation_count: AtomicUsize,
    allocation_count: AtomicU64,
    deallocation_count: AtomicU64,
    merge_count: AtomicU64,
    split_count: AtomicU64,
}

impl RegionStatistics {
    const fn new() -> Self {
        Self {
            total_regions: AtomicUsize::new(0),
            allocated_bytes: AtomicU64::new(0),
            free_bytes: AtomicU64::new(0),
            fragmentation_count: AtomicUsize::new(0),
            allocation_count: AtomicU64::new(0),
            deallocation_count: AtomicU64::new(0),
            merge_count: AtomicU64::new(0),
            split_count: AtomicU64::new(0),
        }
    }

    fn record_allocation(&self, size: u64) {
        self.allocation_count.fetch_add(1, Ordering::Relaxed);
        self.allocated_bytes.fetch_add(size, Ordering::Relaxed);
    }

    fn record_deallocation(&self, size: u64) {
        self.deallocation_count.fetch_add(1, Ordering::Relaxed);
        self.allocated_bytes.fetch_sub(size, Ordering::Relaxed);
        self.free_bytes.fetch_add(size, Ordering::Relaxed);
    }

    fn record_merge(&self) {
        self.merge_count.fetch_add(1, Ordering::Relaxed);
    }

    fn record_split(&self) {
        self.split_count.fetch_add(1, Ordering::Relaxed);
    }
}

impl RegionManager {
    const fn new() -> Self {
        Self {
            regions: BTreeMap::new(),
            free_regions: Vec::new(),
            region_pools: BTreeMap::new(),
            next_region_id: 1,
            initialized: false,
        }
    }

    fn init(&mut self) -> Result<(), &'static str> {
        if self.initialized {
            return Ok(());
        }

        self.regions.clear();
        self.free_regions.clear();
        self.region_pools.clear();

        self.add_initial_regions()?;
        self.initialized = true;

        Ok(())
    }

    fn add_initial_regions(&mut self) -> Result<(), &'static str> {
        let kernel_region = MemRegion::new(
            layout::KERNEL_BASE,
            (layout::KDATA_BASE - layout::KERNEL_BASE) as usize,
            RegionType::Kernel,
        );
        self.add_region(kernel_region)?;

        let heap_region = MemRegion::new(
            layout::KHEAP_BASE,
            layout::KHEAP_SIZE as usize,
            RegionType::Heap,
        );
        self.add_region(heap_region)?;

        let vmap_region = MemRegion::new(
            layout::VMAP_BASE,
            layout::VMAP_SIZE as usize,
            RegionType::Available,
        );
        self.add_region(vmap_region)?;

        let mmio_region = MemRegion::new(
            layout::MMIO_BASE,
            layout::MMIO_SIZE as usize,
            RegionType::Mmio,
        );
        self.add_region(mmio_region)?;

        Ok(())
    }

    fn add_region(&mut self, mut region: MemRegion) -> Result<u64, &'static str> {
        let region_id = self.next_region_id;
        self.next_region_id += 1;

        region.creation_time = get_timestamp();

        if self.has_overlap(&region) {
            return Err("Region overlaps with existing region");
        }

        self.regions.insert(region_id, region);
        REGION_STATS.total_regions.fetch_add(1, Ordering::Relaxed);

        if region.region_type == RegionType::Available {
            self.free_regions.push(region);
            REGION_STATS.free_bytes.fetch_add(region.size as u64, Ordering::Relaxed);
        } else {
            REGION_STATS.allocated_bytes.fetch_add(region.size as u64, Ordering::Relaxed);
        }

        let pool = self.region_pools.entry(region.region_type).or_insert_with(Vec::new);
        pool.push(region);

        Ok(region_id)
    }

    fn remove_region(&mut self, region_id: u64) -> Result<MemRegion, &'static str> {
        let region = self.regions.remove(&region_id)
            .ok_or("Region not found")?;

        REGION_STATS.total_regions.fetch_sub(1, Ordering::Relaxed);

        if region.region_type == RegionType::Available {
            self.free_regions.retain(|r| r.start != region.start);
            REGION_STATS.free_bytes.fetch_sub(region.size as u64, Ordering::Relaxed);
        } else {
            REGION_STATS.allocated_bytes.fetch_sub(region.size as u64, Ordering::Relaxed);
        }

        if let Some(pool) = self.region_pools.get_mut(&region.region_type) {
            pool.retain(|r| r.start != region.start);
        }

        Ok(region)
    }

    fn allocate_region(&mut self, size: usize, region_type: RegionType, align: u64) -> Result<MemRegion, &'static str> {
        let aligned_size = (size + align as usize - 1) & !(align as usize - 1);

        for (i, region) in self.free_regions.iter().enumerate() {
            let aligned_start = (region.start + align - 1) & !(align - 1);
            let available_size = region.end().saturating_sub(aligned_start);

            if available_size >= aligned_size as u64 {
                let mut allocated = MemRegion::new(aligned_start, aligned_size, region_type);
                allocated.creation_time = get_timestamp();

                let remaining_region = *region;
                self.free_regions.remove(i);

                let fragments = remaining_region.subtract(&allocated);
                for fragment in fragments.iter().flatten() {
                    self.free_regions.push(*fragment);
                }

                let region_id = self.next_region_id;
                self.next_region_id += 1;
                self.regions.insert(region_id, allocated);

                REGION_STATS.record_allocation(aligned_size as u64);

                return Ok(allocated);
            }
        }

        Err("No suitable free region found")
    }

    fn deallocate_region(&mut self, region: MemRegion) -> Result<(), &'static str> {
        let available_region = MemRegion::new(region.start, region.size, RegionType::Available);

        self.free_regions.push(available_region);
        self.merge_adjacent_free_regions();

        REGION_STATS.record_deallocation(region.size as u64);

        Ok(())
    }

    fn merge_adjacent_free_regions(&mut self) {
        self.free_regions.sort_by_key(|r| r.start);

        let mut merged_regions = Vec::new();
        let mut current_region: Option<MemRegion> = None;

        for region in self.free_regions.drain(..) {
            match current_region.as_mut() {
                Some(current) => {
                    if let Some(merged) = current.union(&region) {
                        *current = merged;
                        REGION_STATS.record_merge();
                    } else {
                        merged_regions.push(*current);
                        *current = region;
                    }
                },
                None => {
                    current_region = Some(region);
                }
            }
        }

        if let Some(region) = current_region {
            merged_regions.push(region);
        }

        self.free_regions = merged_regions;
    }

    fn split_region(&mut self, region_id: u64, offset: usize) -> Result<(MemRegion, MemRegion), &'static str> {
        let region = self.regions.get(&region_id)
            .ok_or("Region not found")?
            .clone();

        if offset >= region.size {
            return Err("Split offset beyond region size");
        }

        let first_part = MemRegion::new(region.start, offset, region.region_type);
        let second_part = MemRegion::new(
            region.start + offset as u64,
            region.size - offset,
            region.region_type,
        );

        self.regions.remove(&region_id);

        let first_id = self.next_region_id;
        self.next_region_id += 1;
        let second_id = self.next_region_id;
        self.next_region_id += 1;

        self.regions.insert(first_id, first_part);
        self.regions.insert(second_id, second_part);

        REGION_STATS.record_split();

        Ok((first_part, second_part))
    }

    fn find_region_by_address(&self, addr: u64) -> Option<&MemRegion> {
        self.regions.values().find(|r| r.contains(addr))
    }

    fn find_regions_by_type(&self, region_type: RegionType) -> Vec<MemRegion> {
        self.region_pools.get(&region_type)
            .map(|pool| pool.clone())
            .unwrap_or_default()
    }

    fn has_overlap(&self, region: &MemRegion) -> bool {
        self.regions.values().any(|r| r.overlaps(region))
    }

    fn get_fragmentation_info(&self) -> (usize, u64) {
        let fragment_count = self.free_regions.len();
        let largest_free = self.free_regions.iter()
            .map(|r| r.size as u64)
            .max()
            .unwrap_or(0);
        
        (fragment_count, largest_free)
    }

    fn protect_region(&mut self, region_id: u64, flags: RegionFlags) -> Result<(), &'static str> {
        let region = self.regions.get_mut(&region_id)
            .ok_or("Region not found")?;

        region.set_flag(flags);
        Ok(())
    }

    fn get_region_stats(&self) -> RegionStats {
        let (fragment_count, largest_free) = self.get_fragmentation_info();

        RegionStats {
            total_regions: self.regions.len(),
            free_regions: self.free_regions.len(),
            allocated_bytes: REGION_STATS.allocated_bytes.load(Ordering::Relaxed),
            free_bytes: REGION_STATS.free_bytes.load(Ordering::Relaxed),
            allocation_count: REGION_STATS.allocation_count.load(Ordering::Relaxed),
            deallocation_count: REGION_STATS.deallocation_count.load(Ordering::Relaxed),
            merge_count: REGION_STATS.merge_count.load(Ordering::Relaxed),
            split_count: REGION_STATS.split_count.load(Ordering::Relaxed),
            fragment_count,
            largest_free_block: largest_free,
        }
    }
}

#[derive(Debug)]
pub struct RegionStats {
    pub total_regions: usize,
    pub free_regions: usize,
    pub allocated_bytes: u64,
    pub free_bytes: u64,
    pub allocation_count: u64,
    pub deallocation_count: u64,
    pub merge_count: u64,
    pub split_count: u64,
    pub fragment_count: usize,
    pub largest_free_block: u64,
}

pub fn init() -> Result<(), &'static str> {
    let mut manager = REGION_MANAGER.lock();
    manager.init()
}

pub fn add_region(start: u64, size: usize, region_type: RegionType) -> Result<u64, &'static str> {
    let region = MemRegion::new(start, size, region_type);
    let mut manager = REGION_MANAGER.lock();
    manager.add_region(region)
}

pub fn remove_region(region_id: u64) -> Result<MemRegion, &'static str> {
    let mut manager = REGION_MANAGER.lock();
    manager.remove_region(region_id)
}

pub fn allocate_region(size: usize, region_type: RegionType) -> Result<MemRegion, &'static str> {
    let mut manager = REGION_MANAGER.lock();
    manager.allocate_region(size, region_type, layout::PAGE_SIZE as u64)
}

pub fn allocate_aligned_region(size: usize, align: u64, region_type: RegionType) -> Result<MemRegion, &'static str> {
    let mut manager = REGION_MANAGER.lock();
    manager.allocate_region(size, region_type, align)
}

pub fn deallocate_region(region: MemRegion) -> Result<(), &'static str> {
    let mut manager = REGION_MANAGER.lock();
    manager.deallocate_region(region)
}

pub fn find_region_by_address(addr: u64) -> Option<MemRegion> {
    let manager = REGION_MANAGER.lock();
    manager.find_region_by_address(addr).copied()
}

pub fn find_regions_by_type(region_type: RegionType) -> Vec<MemRegion> {
    let manager = REGION_MANAGER.lock();
    manager.find_regions_by_type(region_type)
}

pub fn split_region(region_id: u64, offset: usize) -> Result<(MemRegion, MemRegion), &'static str> {
    let mut manager = REGION_MANAGER.lock();
    manager.split_region(region_id, offset)
}

pub fn protect_region(region_id: u64, flags: RegionFlags) -> Result<(), &'static str> {
    let mut manager = REGION_MANAGER.lock();
    manager.protect_region(region_id, flags)
}

pub fn get_region_stats() -> RegionStats {
    let manager = REGION_MANAGER.lock();
    manager.get_region_stats()
}

pub fn merge_free_regions() {
    let mut manager = REGION_MANAGER.lock();
    manager.merge_adjacent_free_regions();
}

pub fn get_largest_free_block() -> u64 {
    let stats = get_region_stats();
    stats.largest_free_block
}

pub fn get_fragmentation_ratio() -> f64 {
    let stats = get_region_stats();
    if stats.free_bytes == 0 {
        return 0.0;
    }
    
    let avg_fragment_size = stats.free_bytes as f64 / stats.fragment_count as f64;
    let fragmentation = 1.0 - (stats.largest_free_block as f64 / stats.free_bytes as f64);
    fragmentation
}

pub fn validate_region(region: &MemRegion) -> bool {
    region.size > 0 && region.start < region.end()
}

pub fn is_region_available(start: u64, size: usize) -> bool {
    let manager = REGION_MANAGER.lock();
    let test_region = MemRegion::new(start, size, RegionType::Available);
    !manager.has_overlap(&test_region)
}

pub fn get_total_memory() -> u64 {
    let stats = get_region_stats();
    stats.allocated_bytes + stats.free_bytes
}

pub fn get_available_memory() -> u64 {
    let stats = get_region_stats();
    stats.free_bytes
}

pub fn get_used_memory() -> u64 {
    let stats = get_region_stats();
    stats.allocated_bytes
}

fn get_timestamp() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}