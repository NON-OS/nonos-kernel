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

use super::constants::{BUFFER_SIZE, NUM_RX_DESC, NUM_TX_DESC};

#[repr(C, align(256))]
#[derive(Clone, Copy)]
pub struct Descriptor {
    pub opts1: u32,
    pub opts2: u32,
    pub addr_lo: u32,
    pub addr_hi: u32,
}

impl Descriptor {
    pub const fn new() -> Self {
        Self { opts1: 0, opts2: 0, addr_lo: 0, addr_hi: 0 }
    }
}

#[repr(C, align(256))]
pub struct DescriptorRing<const N: usize> {
    pub descs: [Descriptor; N],
}

impl<const N: usize> DescriptorRing<N> {
    pub const fn new() -> Self {
        Self { descs: [Descriptor::new(); N] }
    }
}

pub static mut RX_RING: DescriptorRing<NUM_RX_DESC> = DescriptorRing::new();
pub static mut TX_RING: DescriptorRing<NUM_TX_DESC> = DescriptorRing::new();
pub static mut RX_BUFFERS: [[u8; BUFFER_SIZE]; NUM_RX_DESC] = [[0; BUFFER_SIZE]; NUM_RX_DESC];
pub static mut TX_BUFFERS: [[u8; BUFFER_SIZE]; NUM_TX_DESC] = [[0; BUFFER_SIZE]; NUM_TX_DESC];
