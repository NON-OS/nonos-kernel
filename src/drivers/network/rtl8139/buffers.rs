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

use super::constants::{NUM_TX_BUFFERS, RX_BUF_SIZE, TX_BUF_SIZE};

#[repr(C, align(4096))]
pub struct RxBuffer {
    pub data: [u8; RX_BUF_SIZE],
}

impl RxBuffer {
    pub const fn new() -> Self {
        Self { data: [0; RX_BUF_SIZE] }
    }
}

#[repr(C, align(4))]
pub struct TxBuffer {
    pub data: [u8; TX_BUF_SIZE],
}

impl TxBuffer {
    pub const fn new() -> Self {
        Self { data: [0; TX_BUF_SIZE] }
    }
}

pub static mut RX_BUFFER: RxBuffer = RxBuffer::new();
pub static mut TX_BUFFERS: [TxBuffer; NUM_TX_BUFFERS] =
    [TxBuffer::new(), TxBuffer::new(), TxBuffer::new(), TxBuffer::new()];
