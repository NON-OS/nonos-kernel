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

use super::super::secure_memory as memory;
use x86_64::VirtAddr;

pub fn allocate_secure_region(
    size: usize,
    owner_process: u64,
    security_level: memory::SecurityLevel,
) -> Result<VirtAddr, &'static str> {
    memory::allocate_memory(size, memory::RegionType::Capsule, security_level, owner_process)
        .map_err(|_| "Failed to allocate secure region")
}

#[inline]
pub fn validate_access(process_id: u64, va: VirtAddr, write: bool) -> bool {
    memory::validate_memory_access(process_id, va, write)
}
