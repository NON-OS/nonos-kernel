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

use crate::memory::addr::VirtAddr;

use super::super::error::SecureMemoryResult;
use super::super::types::{MemoryRegion, RegionType, SecurityLevel};
use super::state::MEMORY_MANAGER;

pub fn init() -> SecureMemoryResult<()> {
    MEMORY_MANAGER.lock().init()
}

pub fn allocate_memory(
    size: usize,
    region_type: RegionType,
    security_level: SecurityLevel,
    owner_process: u64,
) -> SecureMemoryResult<VirtAddr> {
    MEMORY_MANAGER.lock().allocate_region(size, region_type, security_level, owner_process)
}

pub fn deallocate_memory(va: VirtAddr) -> SecureMemoryResult<()> {
    MEMORY_MANAGER.lock().deallocate_region(va)
}

pub fn get_region_info(va: VirtAddr) -> Option<MemoryRegion> {
    MEMORY_MANAGER.lock().get_region_info(va).copied()
}

pub fn validate_memory_access(process_id: u64, va: VirtAddr, write: bool) -> bool {
    MEMORY_MANAGER.lock().validate_access(process_id, va, write)
}

pub fn is_valid_address(va: VirtAddr) -> bool {
    MEMORY_MANAGER.lock().get_region_info(va).is_some()
}

pub fn is_initialized() -> bool {
    MEMORY_MANAGER.lock().initialized
}
