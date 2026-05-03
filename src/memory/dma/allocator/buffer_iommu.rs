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

use crate::memory::addr::PhysAddr;
use crate::memory::iommu::{IommuDomain, IommuProtection};

use super::super::coherency::{Coherency, DmaBuffer};
use super::super::error::{DmaError, DmaResult};
use super::super::stats::DmaStats;
use super::super::types::{DmaConstraints, DmaDirection};
use super::core::DmaAllocator;

impl DmaAllocator {
    /// Allocate a coherent buffer and install an IOMMU mapping for it
    /// in `domain` at `iova`. The returned `DmaBuffer` carries the IOVA
    /// as its bus address; the device sees the buffer through the
    /// domain's translation, not at the host-physical address.
    ///
    /// On any failure after the host allocation succeeds, the host
    /// allocation is rolled back before the error returns. The caller
    /// owns no partial state on error.
    // LIMIT: there is no kernel IOVA allocator yet, so the caller picks
    // `iova`. When an IOVA allocator exists, a no-IOVA variant of this
    // method will hand out a fresh address for the chosen domain.
    pub fn allocate_buffer_iommu(
        &mut self,
        size: usize,
        direction: DmaDirection,
        constraints: DmaConstraints,
        domain: &IommuDomain,
        iova: u64,
        stats: &DmaStats,
    ) -> DmaResult<DmaBuffer> {
        let region = self.allocate_coherent(size, constraints, stats)?;
        let protection = match direction {
            DmaDirection::ToDevice => IommuProtection::READ,
            DmaDirection::FromDevice => IommuProtection { read: false, write: true },
            DmaDirection::Bidirectional => IommuProtection::READ_WRITE,
        };
        // SAFETY: ek@nonos.systems — `region` was just produced by
        // `allocate_coherent`, so the host-physical range is fresh
        // kernel-owned memory of exactly `region.size` bytes that no
        // other agent has a mapping to. The IOVA range belongs to the
        // caller's domain discipline, not this fn's; on conflict the
        // backend rejects the call and the host region is freed below.
        let map_result = unsafe { domain.map(iova, region.phys_addr, region.size, protection) };
        if let Err(_) = map_result {
            let _ = self.free_coherent(region.virt_addr, stats);
            return Err(DmaError::IommuMapFailed);
        }
        let coherency = Coherency::from_bool(region.coherent);
        // SAFETY: ek@nonos.systems — the IOMMU has now installed the
        // translation, so `iova` is the device-visible address of the
        // host-physical buffer. The cpu_addr/size pair came from the
        // allocator above. The `from_parts` invariants hold.
        Ok(unsafe {
            DmaBuffer::from_parts(
                region.virt_addr,
                PhysAddr::new(iova),
                region.size,
                direction,
                coherency,
            )
        })
    }
}
