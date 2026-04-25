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
    pub fn to_raw(&self) -> u64 {
        let mut raw = self.physical_address & PTE_ADDR_MASK;
        if self.present {
            raw |= PTE_PRESENT;
        }
        if self.writable {
            raw |= PTE_WRITABLE;
        }
        if self.user_accessible {
            raw |= PTE_USER;
        }
        if self.write_through {
            raw |= PTE_WRITE_THROUGH;
        }
        if self.cache_disabled {
            raw |= PTE_CACHE_DISABLE;
        }
        if self.accessed {
            raw |= PTE_ACCESSED;
        }
        if self.dirty {
            raw |= PTE_DIRTY;
        }
        if self.huge_page {
            raw |= PTE_HUGE_PAGE;
        }
        if self.global {
            raw |= PTE_GLOBAL;
        }
        if self.no_execute {
            raw |= PTE_NO_EXECUTE;
        }
        raw
    }

    pub const fn is_wx_violation(&self) -> bool {
        self.writable && !self.no_execute
    }
}
