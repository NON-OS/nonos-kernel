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

pub const MIN_ALLOCATION_SIZE: usize = 1;
pub const MAX_ALLOCATION_SIZE: usize = 1024 * 1024 * 1024;
pub const DEFAULT_ALIGNMENT: usize = 16;
pub const PAGE_SIZE: usize = 4096;

pub const SECURE_SCRUB_PATTERN: u8 = 0xAA;
pub const SECURE_SCRUB_PASSES: usize = 3;

pub const MAX_ALLOCATION_COUNT: u64 = u64::MAX - 1;
pub const MAX_MEMORY_USAGE: u64 = u64::MAX - 1;

pub const KERNEL_PROCESS_ID: u64 = 0;
pub const INVALID_PROCESS_ID: u64 = u64::MAX;

pub const PERM_READ: u32 = 0x01;
pub const PERM_WRITE: u32 = 0x02;
pub const PERM_EXECUTE: u32 = 0x04;
pub const PERM_USER: u32 = 0x08;
