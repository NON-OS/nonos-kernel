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

pub const PAGE_TABLE_ENTRIES: usize = 512;
pub const PML4_SHIFT: u64 = 39;
pub const PDPT_SHIFT: u64 = 30;
pub const PD_SHIFT: u64 = 21;
pub const PT_SHIFT: u64 = 12;
pub const INDEX_MASK: u64 = 0x1FF;
pub const PAGE_OFFSET_MASK: u64 = 0xFFF;
