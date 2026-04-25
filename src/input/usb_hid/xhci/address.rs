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

use super::structures::{DCBAA, DEV_CTX, INPUT_CTX};
use crate::input::usb_hid::ring::EP0_RING;
use core::ptr::addr_of_mut;

pub(super) unsafe fn setup_input_ctx_address(slot: u8, port: u8, speed: u8, max_pkt: u16) {
    let input_ctx_ptr = addr_of_mut!(INPUT_CTX);
    for i in 0..8 {
        (*input_ctx_ptr).ctrl[i] = 0;
        (*input_ctx_ptr).slot[i] = 0;
    }
    for i in 0..31 {
        for j in 0..8 {
            (*input_ctx_ptr).ep[i][j] = 0;
        }
    }
    (*input_ctx_ptr).ctrl[1] = 0x03;
    (*input_ctx_ptr).slot[0] = ((speed as u32) << 20) | (1 << 27);
    (*input_ctx_ptr).slot[1] = (port as u32) << 16;
    let ep0_p = addr_of_mut!(EP0_RING) as u64;
    (*input_ctx_ptr).ep[0][1] = (3 << 1) | (4 << 3) | ((max_pkt as u32) << 16);
    (*input_ctx_ptr).ep[0][2] = (ep0_p & 0xFFFFFFFF) as u32 | 1;
    (*input_ctx_ptr).ep[0][3] = (ep0_p >> 32) as u32;
    (*input_ctx_ptr).ep[0][4] = 8;
    let dev_p = addr_of_mut!(DEV_CTX) as u64;
    let dcbaa_ptr = addr_of_mut!(DCBAA);
    (*dcbaa_ptr).entries[slot as usize] = dev_p;
}
