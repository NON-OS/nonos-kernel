// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::PhysAddr;

pub fn allocate_pages(pages: usize) -> Result<PhysAddr, &'static str> {
    if let Some(addr) = super::pmm::alloc_pages(pages) {
        Ok(addr)
    } else {
        Err("Out of memory")
    }
}

pub fn deallocate_pages(addr: PhysAddr, pages: usize) {
    super::pmm::free_pages(addr, pages);
}
