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

pub const INITIAL_PAGE_ID: u64 = 1;
pub const MAX_TRACKED_PAGES: usize = 100_000;
pub const ZERO_PATTERN: u8 = 0;
pub const MAX_ALLOCATION_SIZE: usize = 1024 * 1024 * 1024;
pub const MIN_ALLOCATION_SIZE: usize = 4096;
