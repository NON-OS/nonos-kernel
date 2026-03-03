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

use super::constants::{NUM_RX_DESC, NUM_TX_DESC, RX_BUFFER_SIZE};

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct RxDesc {
    pub addr: u64,
    pub length: u16,
    pub checksum: u16,
    pub status: u8,
    pub errors: u8,
    pub special: u16,
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct TxDesc {
    pub addr: u64,
    pub length: u16,
    pub cso: u8,
    pub cmd: u8,
    pub status: u8,
    pub css: u8,
    pub special: u16,
}

impl RxDesc {
    pub const fn new_static() -> Self {
        Self {
            addr: 0,
            length: 0,
            checksum: 0,
            status: 0,
            errors: 0,
            special: 0,
        }
    }
}

impl TxDesc {
    pub const fn new_static() -> Self {
        Self {
            addr: 0,
            length: 0,
            cso: 0,
            cmd: 0,
            status: 0,
            css: 0,
            special: 0,
        }
    }
}

pub static mut STATIC_RX_DESCS: [RxDesc; NUM_RX_DESC] = [RxDesc::new_static(); NUM_RX_DESC];
pub static mut STATIC_TX_DESCS: [TxDesc; NUM_TX_DESC] = [TxDesc::new_static(); NUM_TX_DESC];
pub static mut STATIC_RX_BUFS: [[u8; RX_BUFFER_SIZE]; NUM_RX_DESC] =
    [[0u8; RX_BUFFER_SIZE]; NUM_RX_DESC];
pub static mut STATIC_TX_BUFS: [[u8; RX_BUFFER_SIZE]; NUM_TX_DESC] =
    [[0u8; RX_BUFFER_SIZE]; NUM_TX_DESC];
