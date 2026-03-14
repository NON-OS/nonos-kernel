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

pub type PhysAddr = u64;
pub type VirtAddr = u64;

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;
pub const MAX_PHYS_MEM: usize = 1024 * 1024 * 1024;
pub const MAX_PAGES: usize = MAX_PHYS_MEM / PAGE_SIZE;
pub const PHYS_MAP_BASE: u64 = 0xFFFF_8000_0000_0000;
pub const HEAP_BASE: u64 = 0xFFFF_8000_4000_0000;
pub const HEAP_SIZE: usize = 256 * 1024 * 1024;

pub const fn align_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
}

pub const fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}
