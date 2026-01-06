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

pub const ALLOCATION_MAGIC: u32 = 0xDEADBEEF;
pub const CANARY_VALUE: u64 = 0xDEADBEEFCAFEBABE;
pub const FREED_MAGIC: u32 = 0xFEEDFACE;
pub const BOOTSTRAP_HEAP_SIZE: usize = 1024 * 1024;
pub const BOOTSTRAP_HEAP_ALIGN: usize = 4096;
pub const MIN_ALIGNMENT: usize = 8;
pub const MAX_ALIGNMENT: usize = 4096;
pub const DEFAULT_ALIGNMENT: usize = 16;
pub const MAX_ALLOCATION_SIZE: usize = 256 * 1024 * 1024;
pub const MIN_ALLOCATION_SIZE: usize = 8;
pub const LARGE_ALLOCATION_THRESHOLD: usize = 64 * 1024;
pub const ALLOCATION_HEADER_SIZE: usize = 24;
pub const CANARY_SIZE: usize = 8;
pub const ALLOCATION_OVERHEAD: usize = ALLOCATION_HEADER_SIZE + CANARY_SIZE;
pub const FREED_MEMORY_PATTERN: u8 = 0xDD;
pub const FRESH_MEMORY_PATTERN: u8 = 0xCD;
pub const GUARD_PAGE_PATTERN: u8 = 0xFD;
pub const MAX_ALLOCATION_COUNT: usize = usize::MAX - 1;
pub const MAX_MEMORY_USAGE: usize = usize::MAX - 1;
