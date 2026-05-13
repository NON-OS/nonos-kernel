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

use crate::hardware::broker::dma::types::DmaMapError;
use crate::hardware::broker::dma::va;
use crate::memory::addr::PhysAddr;

// Reserve user VA + install page table entries. On `map_user_dma`
// failure the VA slot is not released — the bump allocator leaks it
// for the life of the boot; same shape as the original. The caller
// frees physical frames; this layer owns only the VA/page state.
pub(super) fn install(pages: u64, length: u64, phys_start: u64) -> Result<u64, DmaMapError> {
    let user_va = va::reserve(pages).ok_or(DmaMapError::NoVaSpace)?;
    if crate::memory::paging::map_user_dma(user_va, PhysAddr::new(phys_start), length as usize)
        .is_err()
    {
        return Err(DmaMapError::MapFailed);
    }
    Ok(user_va.as_u64())
}
