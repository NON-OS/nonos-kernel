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

pub(super) const MIN_BLOCK_SIZE: usize = 32;
pub(super) const HEADER_SIZE: usize = core::mem::size_of::<BlockHeader>();
pub(super) const ALLOC_HEADER_SIZE: usize = core::mem::size_of::<AllocHeader>();
pub(super) const INITIAL_HEAP_SIZE: usize = 256 * 1024 * 1024;
pub(super) const BLOCK_MAGIC: u32 = 0xDEAD_BEEF;
pub(super) const ALLOC_MAGIC: u32 = 0xCAFE_BABE;

#[repr(C)]
pub(super) struct BlockHeader {
    pub size: usize,
    pub next: *mut BlockHeader,
    pub magic: u32,
}

#[repr(C)]
pub(super) struct AllocHeader {
    pub(super) size: usize,
    pub(super) magic: u32,
}
