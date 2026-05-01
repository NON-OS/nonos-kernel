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

use super::helpers::get_timestamp;
use super::page_size::PageSize;
use super::permissions::PagePermissions;
use crate::memory::addr::{PhysAddr, VirtAddr};

#[derive(Debug, Clone)]
pub struct PageMapping {
    pub virtual_addr: VirtAddr,
    pub physical_addr: PhysAddr,
    pub size: PageSize,
    pub permissions: PagePermissions,
    pub process_id: Option<u32>,
    pub reference_count: u32,
    pub creation_time: u64,
    pub last_accessed: u64,
}

impl PageMapping {
    pub fn new(
        virtual_addr: VirtAddr,
        physical_addr: PhysAddr,
        size: PageSize,
        permissions: PagePermissions,
    ) -> Self {
        Self {
            virtual_addr,
            physical_addr,
            size,
            permissions,
            process_id: None,
            reference_count: 1,
            creation_time: get_timestamp(),
            last_accessed: get_timestamp(),
        }
    }

    pub fn kernel(
        virtual_addr: VirtAddr,
        physical_addr: PhysAddr,
        permissions: PagePermissions,
    ) -> Self {
        Self {
            virtual_addr,
            physical_addr,
            size: PageSize::Size4KiB,
            permissions,
            process_id: None,
            reference_count: 1,
            creation_time: get_timestamp(),
            last_accessed: get_timestamp(),
        }
    }

    pub fn user(
        virtual_addr: VirtAddr,
        physical_addr: PhysAddr,
        permissions: PagePermissions,
        process_id: u32,
    ) -> Self {
        Self {
            virtual_addr,
            physical_addr,
            size: PageSize::Size4KiB,
            permissions,
            process_id: Some(process_id),
            reference_count: 1,
            creation_time: get_timestamp(),
            last_accessed: get_timestamp(),
        }
    }

    pub const fn is_kernel(&self) -> bool {
        self.process_id.is_none()
    }
    pub const fn is_user(&self) -> bool {
        self.process_id.is_some()
    }
    pub const fn is_huge(&self) -> bool {
        matches!(self.size, PageSize::Size2MiB | PageSize::Size1GiB)
    }
    pub const fn is_shared(&self) -> bool {
        self.reference_count > 1 || self.permissions.contains(PagePermissions::SHARED)
    }
    pub fn touch(&mut self) {
        self.last_accessed = get_timestamp();
    }
}
