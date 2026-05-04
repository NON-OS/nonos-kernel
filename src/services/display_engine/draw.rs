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

extern crate alloc;

use crate::display::{clear, fill_rect, write_pixel};
use crate::services::ServiceResponse;
use alloc::vec::Vec;

const ERR_INVAL: i32 = -22;
const ERR_NOT_INIT: i32 = -6;

pub(super) fn draw_pixel(seq: u32, data: &[u8]) -> ServiceResponse {
    if data.len() < 12 {
        return ServiceResponse::err(seq, ERR_INVAL);
    }
    let x = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let y = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let c = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    match write_pixel(x, y, c) {
        Ok(()) => ServiceResponse::ok(seq, Vec::new()),
        Err(_) => ServiceResponse::err(seq, ERR_NOT_INIT),
    }
}

pub(super) fn draw_rect(seq: u32, data: &[u8]) -> ServiceResponse {
    if data.len() < 20 {
        return ServiceResponse::err(seq, ERR_INVAL);
    }
    let x = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let y = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let w = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let h = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let c = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    match fill_rect(x, y, w, h, c) {
        Ok(()) => ServiceResponse::ok(seq, Vec::new()),
        Err(_) => ServiceResponse::err(seq, ERR_NOT_INIT),
    }
}

pub(super) fn draw_clear(seq: u32, data: &[u8]) -> ServiceResponse {
    let c =
        if data.len() >= 4 { u32::from_le_bytes([data[0], data[1], data[2], data[3]]) } else { 0 };
    match clear(c) {
        Ok(()) => ServiceResponse::ok(seq, Vec::new()),
        Err(_) => ServiceResponse::err(seq, ERR_NOT_INIT),
    }
}
