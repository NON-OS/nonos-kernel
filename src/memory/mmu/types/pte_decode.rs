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

use super::super::constants::*;
use super::pte::PageTableEntry;

impl PageTableEntry {
    pub fn from_raw(raw: u64) -> Self {
        Self {
            present: raw & PTE_PRESENT != 0,
            writable: raw & PTE_WRITABLE != 0,
            user_accessible: raw & PTE_USER != 0,
            write_through: raw & PTE_WRITE_THROUGH != 0,
            cache_disabled: raw & PTE_CACHE_DISABLE != 0,
            accessed: raw & PTE_ACCESSED != 0,
            dirty: raw & PTE_DIRTY != 0,
            huge_page: raw & PTE_HUGE_PAGE != 0,
            global: raw & PTE_GLOBAL != 0,
            no_execute: raw & PTE_NO_EXECUTE != 0,
            physical_address: raw & PTE_ADDR_MASK,
        }
    }
}
