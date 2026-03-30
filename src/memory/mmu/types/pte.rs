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

#[derive(Debug, Clone, Copy, Default)]
pub struct PageTableEntry {
    pub present: bool,
    pub writable: bool,
    pub user_accessible: bool,
    pub write_through: bool,
    pub cache_disabled: bool,
    pub accessed: bool,
    pub dirty: bool,
    pub huge_page: bool,
    pub global: bool,
    pub no_execute: bool,
    pub physical_address: u64,
}

impl PageTableEntry {
    pub const fn empty() -> Self {
        Self {
            present: false,
            writable: false,
            user_accessible: false,
            write_through: false,
            cache_disabled: false,
            accessed: false,
            dirty: false,
            huge_page: false,
            global: false,
            no_execute: false,
            physical_address: 0,
        }
    }
}
