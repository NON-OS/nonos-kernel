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
use super::super::types::{RegionType, SecurityLevel};
use super::api::allocate_memory;

pub fn allocate_code_region(size: usize, owner_process: u64) -> SecureMemoryResult<VirtAddr> {
    allocate_memory(size, RegionType::Code, SecurityLevel::Public, owner_process)
}

pub fn allocate_data_region(size: usize, owner_process: u64) -> SecureMemoryResult<VirtAddr> {
    allocate_memory(size, RegionType::Data, SecurityLevel::Internal, owner_process)
}

pub fn allocate_heap_region(size: usize, owner_process: u64) -> SecureMemoryResult<VirtAddr> {
    allocate_memory(size, RegionType::Heap, SecurityLevel::Internal, owner_process)
}

pub fn allocate_stack_region(size: usize, owner_process: u64) -> SecureMemoryResult<VirtAddr> {
    allocate_memory(size, RegionType::Stack, SecurityLevel::Internal, owner_process)
}

pub fn allocate_secure_capsule(size: usize, owner_process: u64) -> SecureMemoryResult<VirtAddr> {
    allocate_memory(size, RegionType::Capsule, SecurityLevel::Secret, owner_process)
}

pub fn allocate_device_region(size: usize, owner_process: u64) -> SecureMemoryResult<VirtAddr> {
    allocate_memory(size, RegionType::Device, SecurityLevel::Public, owner_process)
}
