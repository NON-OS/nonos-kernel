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

use super::constants::{BUFFER_SIZE, QUEUE_SIZE};

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; QUEUE_SIZE],
    pub used_event: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; QUEUE_SIZE],
    pub avail_event: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

pub static mut RX_DESCS: [VirtqDesc; QUEUE_SIZE] =
    [VirtqDesc { addr: 0, len: 0, flags: 0, next: 0 }; QUEUE_SIZE];
pub static mut RX_AVAIL: VirtqAvail =
    VirtqAvail { flags: 0, idx: 0, ring: [0; QUEUE_SIZE], used_event: 0 };
pub static mut RX_USED: VirtqUsed = VirtqUsed {
    flags: 0,
    idx: 0,
    ring: [VirtqUsedElem { id: 0, len: 0 }; QUEUE_SIZE],
    avail_event: 0,
};
pub static mut RX_BUFFERS: [[u8; BUFFER_SIZE]; QUEUE_SIZE] = [[0; BUFFER_SIZE]; QUEUE_SIZE];

pub static mut TX_DESCS: [VirtqDesc; QUEUE_SIZE] =
    [VirtqDesc { addr: 0, len: 0, flags: 0, next: 0 }; QUEUE_SIZE];
pub static mut TX_AVAIL: VirtqAvail =
    VirtqAvail { flags: 0, idx: 0, ring: [0; QUEUE_SIZE], used_event: 0 };
pub static mut TX_USED: VirtqUsed = VirtqUsed {
    flags: 0,
    idx: 0,
    ring: [VirtqUsedElem { id: 0, len: 0 }; QUEUE_SIZE],
    avail_event: 0,
};
pub static mut TX_BUFFERS: [[u8; BUFFER_SIZE]; QUEUE_SIZE] = [[0; BUFFER_SIZE]; QUEUE_SIZE];
