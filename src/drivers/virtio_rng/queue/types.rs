// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::constants::{BUFFER_SIZE, QUEUE_SIZE, VQ_REGION_SIZE};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

#[repr(C)]
pub(super) struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; QUEUE_SIZE as usize],
    pub _used_event: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct VirtqUsedElem {
    pub _id: u32,
    pub len: u32,
}

#[repr(C)]
pub(super) struct VirtqUsed {
    pub _flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; QUEUE_SIZE as usize],
    pub _avail_event: u16,
}

#[repr(C, align(4096))]
pub(super) struct VirtqueueRegionBuf(pub [u8; VQ_REGION_SIZE]);

#[repr(C, align(4096))]
pub(super) struct DataBuf(pub [u8; BUFFER_SIZE]);
