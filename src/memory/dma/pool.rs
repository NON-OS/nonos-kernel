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
use super::error::{DmaError, DmaResult};
use super::types::{DmaConstraints, DmaRegion};
pub struct DmaPool {
    regions: Vec<DmaRegion>,
    free_regions: Vec<usize>,
    constraints: DmaConstraints,
    total_size: usize,
    allocated_count: usize,
}

impl DmaPool {
    pub fn new(
        region_size: usize,
        capacity: usize,
        constraints: DmaConstraints,
    ) -> DmaResult<Self> {
        Ok(Self {
            regions: Vec::with_capacity(capacity),
            free_regions: Vec::with_capacity(capacity),
            constraints,
            total_size: region_size * capacity,
            allocated_count: 0,
        })
    }

    pub fn add_region(&mut self, region: DmaRegion) -> DmaResult<()> {
        if self.regions.len() >= self.regions.capacity() {
            return Err(DmaError::PoolFull);
        }

        let index = self.regions.len();
        self.regions.push(region);
        self.free_regions.push(index);
        Ok(())
    }

    pub fn allocate(&mut self) -> Option<DmaRegion> {
        if let Some(index) = self.free_regions.pop() {
            self.allocated_count += 1;
            Some(self.regions[index])
        } else {
            None
        }
    }

    pub fn deallocate(&mut self, region: DmaRegion) -> DmaResult<()> {
        for (index, stored_region) in self.regions.iter().enumerate() {
            if stored_region.virt_addr == region.virt_addr
                && stored_region.phys_addr == region.phys_addr
            {
                if !self.free_regions.contains(&index) {
                    self.free_regions.push(index);
                    self.allocated_count = self.allocated_count.saturating_sub(1);
                    return Ok(());
                } else {
                    return Err(DmaError::DoubleFree);
                }
            }
        }
        Err(DmaError::NotInPool)
    }

    pub fn available(&self) -> usize {
        self.free_regions.len()
    }

    pub fn allocated(&self) -> usize {
        self.allocated_count
    }

    pub fn capacity(&self) -> usize {
        self.regions.capacity()
    }

    pub fn total_size(&self) -> usize {
        self.total_size
    }

    pub fn constraints(&self) -> DmaConstraints {
        self.constraints
    }

    pub fn is_empty(&self) -> bool {
        self.free_regions.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.free_regions.len() == self.regions.len()
    }

    pub fn region_count(&self) -> usize {
        self.regions.len()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use x86_64::{PhysAddr, VirtAddr};
    fn make_region(va: u64, pa: u64) -> DmaRegion {
        DmaRegion {
            virt_addr: VirtAddr::new(va),
            phys_addr: PhysAddr::new(pa),
            size: 4096,
            coherent: true,
            dma32_compatible: true,
        }
    }
    #[test]
    fn test_pool_creation() {
        let pool = DmaPool::new(4096, 10, DmaConstraints::default()).unwrap();
        assert_eq!(pool.capacity(), 10);
        assert_eq!(pool.available(), 0);
        assert_eq!(pool.allocated(), 0);
    }
    #[test]
    fn test_pool_add_region() {
        let mut pool = DmaPool::new(4096, 2, DmaConstraints::default()).unwrap();
        pool.add_region(make_region(0x1000, 0x2000)).unwrap();
        assert_eq!(pool.available(), 1);
        assert_eq!(pool.region_count(), 1);
        pool.add_region(make_region(0x3000, 0x4000)).unwrap();
        assert_eq!(pool.available(), 2);
        assert_eq!(pool.region_count(), 2);
        let result = pool.add_region(make_region(0x5000, 0x6000));
        assert!(matches!(result, Err(DmaError::PoolFull)));
    }

    #[test]
    fn test_pool_allocate_deallocate() {
        let mut pool = DmaPool::new(4096, 2, DmaConstraints::default()).unwrap();
        pool.add_region(make_region(0x1000, 0x2000)).unwrap();
        let region = pool.allocate().unwrap();
        assert_eq!(pool.available(), 0);
        assert_eq!(pool.allocated(), 1);
        pool.deallocate(region).unwrap();
        assert_eq!(pool.available(), 1);
        assert_eq!(pool.allocated(), 0);
    }
    #[test]
    fn test_pool_double_free() {
        let mut pool = DmaPool::new(4096, 2, DmaConstraints::default()).unwrap();
        pool.add_region(make_region(0x1000, 0x2000)).unwrap();
        let region = pool.allocate().unwrap();
        pool.deallocate(region).unwrap();
        let result = pool.deallocate(region);
        assert!(matches!(result, Err(DmaError::DoubleFree)));
    }
    #[test]
    fn test_pool_not_in_pool() {
        let mut pool = DmaPool::new(4096, 2, DmaConstraints::default()).unwrap();
        let fake_region = make_region(0x9000, 0xA000);
        let result = pool.deallocate(fake_region);
        assert!(matches!(result, Err(DmaError::NotInPool)));
    }
}
