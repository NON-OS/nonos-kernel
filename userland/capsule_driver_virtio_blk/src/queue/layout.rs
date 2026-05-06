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

//! `Queue` carries the pointers and bookkeeping post/used share.
//! Three DMA regions back the queue: `region` is the descriptor
//! table + avail ring + used ring (two pages, the legacy spec
//! requires the used ring page-aligned); `header` carries the
//! virtio-blk request header and the trailing status byte;
//! `data` carries the read or write payload.

use crate::constants::{DATA_BUF_LEN, QUEUE_SIZE};

#[derive(Debug, Clone, Copy)]
pub struct Queue {
    pub region_va: *mut u8,
    pub region_phys: u64,
    pub header_va: *mut u8,
    pub header_phys: u64,
    pub data_va: *mut u8,
    pub data_phys: u64,
    pub data_len: u32,
    pub last_used: u16,
}

impl Queue {
    pub fn new(
        region_va: u64,
        region_phys: u64,
        header_va: u64,
        header_phys: u64,
        data_va: u64,
        data_phys: u64,
    ) -> Self {
        Self {
            region_va: region_va as *mut u8,
            region_phys,
            header_va: header_va as *mut u8,
            header_phys,
            data_va: data_va as *mut u8,
            data_phys,
            data_len: DATA_BUF_LEN as u32,
            last_used: 0,
        }
    }

    pub const fn queue_size() -> u16 {
        QUEUE_SIZE
    }

    pub fn region_phys(&self) -> u64 {
        self.region_phys
    }
}
