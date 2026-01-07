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

pub const USER_HEAP_START: u64 = 0x10000000;
pub const USER_STACK_BOTTOM: u64 = 0x70000000;
pub const USER_STACK_TOP: u64 = 0x80000000;
pub const USER_MMAP_START: u64 = 0x40000000;
pub const SHARED_MEMORY_START: u64 = 0x50000000;
pub const PF_PRESENT: u64 = 0x01;
pub const PF_WRITE: u64 = 0x02;
pub const PF_USER: u64 = 0x04;
pub const PF_RESERVED: u64 = 0x08;
pub const PF_INSTRUCTION: u64 = 0x10;
