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

use super::constants::{DATA_BUF_SIZE, QUEUE_SIZE, VQ_REGION_SIZE};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct VirtqDesc {
    pub(super) addr: u64,
    pub(super) len: u32,
    pub(super) flags: u16,
    pub(super) next: u16,
}

#[repr(C)]
pub(super) struct VirtqAvail {
    pub(super) flags: u16,
    pub(super) idx: u16,
    pub(super) ring: [u16; QUEUE_SIZE as usize],
    pub(super) used_event: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct VirtqUsedElem {
    pub(super) id: u32,
    pub(super) len: u32,
}

#[repr(C)]
pub(super) struct VirtqUsed {
    pub(super) flags: u16,
    pub(super) idx: u16,
    pub(super) ring: [VirtqUsedElem; QUEUE_SIZE as usize],
    pub(super) avail_event: u16,
}

#[repr(C, align(4096))]
pub(super) struct VirtqueueRegionBuf(pub(super) [u8; VQ_REGION_SIZE]);

#[repr(C, align(4096))]
pub(super) struct BlkDataBuf(pub(super) [u8; DATA_BUF_SIZE]);
