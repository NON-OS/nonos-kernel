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

pub mod flags {
    pub const PRESENT_BIT: u32 = 0;
    pub const WRITABLE_BIT: u32 = 1;
    pub const USER_BIT: u32 = 2;
    pub const DIRTY_BIT: u32 = 3;
    pub const ACCESSED_BIT: u32 = 4;
    pub const LOCKED_BIT: u32 = 5;
    pub const ENCRYPTED_BIT: u32 = 6;
}
pub const MAX_TRACKED_PAGES: usize = 1_000_000;
pub const INITIAL_REF_COUNT: u32 = 1;
pub const PAGE_SIZE: u64 = 4096;
