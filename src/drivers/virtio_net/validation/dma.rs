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

use x86_64::PhysAddr;
use super::super::constants::{DMA_ALIGNMENT, MAX_DMA_REGION_SIZE};
use super::super::error::VirtioNetError;

pub fn validate_dma_address(addr: PhysAddr, size: usize) -> Result<(), VirtioNetError> {
    if addr.as_u64() == 0 { return Err(VirtioNetError::InvalidDmaAddress); }
    if addr.as_u64() % DMA_ALIGNMENT as u64 != 0 { return Err(VirtioNetError::InvalidDmaAddress); }
    if size == 0 { return Err(VirtioNetError::InvalidDmaAddress); }
    if size > MAX_DMA_REGION_SIZE { return Err(VirtioNetError::InvalidDmaAddress); }
    if addr.as_u64().checked_add(size as u64).is_none() { return Err(VirtioNetError::InvalidDmaAddress); }
    Ok(())
}
