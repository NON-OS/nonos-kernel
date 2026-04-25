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

use super::super::error::XhciResult;
use super::builder::DmaRegionBuilder;
use super::region::DmaRegion;

pub fn alloc_trb_ring(num_entries: usize) -> XhciResult<DmaRegion> {
    use super::super::trb::Trb;
    DmaRegionBuilder::new(num_entries * core::mem::size_of::<Trb>()).for_trb().build()
}

pub fn alloc_device_context() -> XhciResult<DmaRegion> {
    use super::super::types::DeviceContext;
    DmaRegion::new_aligned(core::mem::size_of::<DeviceContext>(), 64, true)
}

pub fn alloc_input_context() -> XhciResult<DmaRegion> {
    use super::super::types::InputContext;
    DmaRegion::new_aligned(core::mem::size_of::<InputContext>(), 64, true)
}

pub fn alloc_dcbaa(max_slots: usize) -> XhciResult<DmaRegion> {
    DmaRegion::new_aligned((max_slots + 1) * 8, 64, true)
}
pub fn alloc_scratchpad_array(num_entries: usize) -> XhciResult<DmaRegion> {
    DmaRegion::new_aligned(num_entries * 8, 64, true)
}
pub fn alloc_scratchpad_buffer() -> XhciResult<DmaRegion> {
    DmaRegion::new_aligned(4096, 4096, true)
}

pub fn alloc_erst(num_segments: usize) -> XhciResult<DmaRegion> {
    use super::super::types::ErstEntry;
    DmaRegion::new_aligned(num_segments * core::mem::size_of::<ErstEntry>(), 64, true)
}
