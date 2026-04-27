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

use super::permissions::PagePermissions;
use super::pte::PageTableEntry;

impl PagePermissions {
    pub const fn is_wx_violation(&self) -> bool {
        self.writable && self.executable
    }

    pub fn to_pte(&self, physical_address: u64) -> PageTableEntry {
        PageTableEntry {
            present: true,
            writable: self.writable,
            user_accessible: self.user_accessible,
            write_through: false,
            cache_disabled: self.cache_disabled,
            accessed: false,
            dirty: false,
            huge_page: false,
            global: false,
            no_execute: !self.executable,
            physical_address,
        }
    }
}
