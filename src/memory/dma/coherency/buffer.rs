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

use crate::memory::addr::{PhysAddr, VirtAddr};
use crate::memory::dma::types::DmaDirection;

use super::mode::Coherency;

/// Handle for a kernel-allocated DMA buffer with explicit direction and
/// coherency intent.
// LIMIT: `bus_addr` is `PhysAddr`. With an IOMMU in front of the device,
// the field actually carries an IOVA returned by `IommuDomain::map`.
// Distinguishing host-physical from IOVA in the type system needs a
// `BusAddr` newtype; the discipline currently lives in the driver.
pub struct DmaBuffer {
    pub(super) cpu_addr: VirtAddr,
    pub(super) bus_addr: PhysAddr,
    pub(super) size: usize,
    pub(super) direction: DmaDirection,
    pub(super) coherency: Coherency,
}

// SAFETY: ek@nonos.systems — the DMA allocator arranges a kernel-global
// buffer mapping. Sending the handle moves the right to sync the buffer
// and to expose it to the device; the buffer memory itself is unchanged
// by the move.
unsafe impl Send for DmaBuffer {}

// SAFETY: ek@nonos.systems — the handle's fields are immutable after
// construction. Concurrent CPU access to the buffer's bytes is the
// driver's synchronisation problem and out of scope for this impl.
unsafe impl Sync for DmaBuffer {}

impl DmaBuffer {
    /// Construct a DMA buffer handle from its CPU address, bus address,
    /// size, direction, and coherency intent.
    ///
    /// # Safety
    ///
    /// ek@nonos.systems
    ///
    /// For the entire life of the returned handle:
    ///
    /// - `cpu_addr` is a non-null kernel virtual address mapping the
    ///   first byte of a contiguous device-accessible buffer of at
    ///   least `size` bytes.
    /// - `bus_addr` is exactly the address the device will use to reach
    ///   the same buffer — host-physical, or an IOVA if an IOMMU is in
    ///   front of the device.
    /// - `direction` is the data flow the device performs over this
    ///   buffer. Mixing directions without remapping breaks the cache
    ///   maintenance contract on non-coherent backends.
    /// - `coherency` matches the actual cache attributes of the
    ///   mapping. A non-coherent mapping marked `Coherent` produces
    ///   wrong device-visible data on hardware without bus coherency.
    /// - The mapping is not released, repurposed, or remapped while
    ///   any handle to it exists.
    pub const unsafe fn from_parts(
        cpu_addr: VirtAddr,
        bus_addr: PhysAddr,
        size: usize,
        direction: DmaDirection,
        coherency: Coherency,
    ) -> Self {
        Self { cpu_addr, bus_addr, size, direction, coherency }
    }

    /// Device-visible address of the buffer's first byte.
    #[inline]
    pub const fn dma_addr(&self) -> u64 {
        self.bus_addr.as_u64()
    }

    /// Buffer length in bytes, as declared at construction.
    #[inline]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Data flow direction the device will perform over this buffer.
    #[inline]
    pub const fn direction(&self) -> DmaDirection {
        self.direction
    }

    /// Cache attribute of the underlying mapping.
    #[inline]
    pub const fn coherency(&self) -> Coherency {
        self.coherency
    }
}
