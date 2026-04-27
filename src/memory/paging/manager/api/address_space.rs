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

use super::globals::PAGING_MANAGER;
use crate::memory::paging::error::PagingResult;

pub fn create_address_space(process_id: u32) -> PagingResult<u32> {
    let mut mgr = PAGING_MANAGER.lock();
    if !mgr.is_initialized() {
        mgr.init()?;
    }
    mgr.create_address_space(process_id)
}

pub fn switch_address_space(asid: u32) -> PagingResult<()> {
    PAGING_MANAGER.lock().switch_address_space(asid)
}

pub fn cleanup_address_space(asid: u32) -> PagingResult<()> {
    PAGING_MANAGER.lock().cleanup_address_space(asid)
}

pub fn lookup_asid_for_process(process_id: u32) -> Option<u32> {
    PAGING_MANAGER.lock().lookup_asid_for_process(process_id)
}

pub fn switch_to_process_address_space(process_id: u32) -> PagingResult<()> {
    let asid = lookup_asid_for_process(process_id)
        .ok_or(crate::memory::paging::error::PagingError::AddressSpaceNotFound)?;
    switch_address_space(asid)
}

pub fn get_process_cr3(process_id: u32) -> Option<u64> {
    let mgr = PAGING_MANAGER.lock();
    for (_, addr_space) in mgr.address_spaces.iter() {
        if addr_space.process_id == process_id {
            return Some(addr_space.cr3_value.as_u64());
        }
    }
    None
}
