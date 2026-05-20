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

use crate::image::types::DecodeError;

pub const M_SOI: u8 = 0xD8;
pub const M_EOI: u8 = 0xD9;
pub const M_SOS: u8 = 0xDA;
pub const M_DQT: u8 = 0xDB;
pub const M_DHT: u8 = 0xC4;
pub const M_DRI: u8 = 0xDD;
pub const M_SOF0: u8 = 0xC0;
pub const M_COM: u8 = 0xFE;

pub fn is_app(marker: u8) -> bool {
    marker >= 0xE0 && marker <= 0xEF
}

pub fn is_rst(marker: u8) -> bool {
    marker >= 0xD0 && marker <= 0xD7
}

pub fn is_sof_unsupported(marker: u8) -> bool {
    matches!(
        marker,
        0xC1 | 0xC2 | 0xC3 | 0xC5 | 0xC6 | 0xC7 | 0xC9 | 0xCA | 0xCB | 0xCD | 0xCE | 0xCF
    )
}

pub fn read_marker(buf: &[u8], pos: &mut usize) -> Result<u8, DecodeError> {
    let mut p = *pos;
    while p < buf.len() && buf[p] != 0xFF {
        p += 1;
    }
    if p >= buf.len() {
        return Err(DecodeError::Truncated);
    }
    while p < buf.len() && buf[p] == 0xFF {
        p += 1;
    }
    if p >= buf.len() {
        return Err(DecodeError::Truncated);
    }
    let m = buf[p];
    *pos = p + 1;
    Ok(m)
}

pub fn read_segment_len(buf: &[u8], pos: &mut usize) -> Result<usize, DecodeError> {
    if *pos + 2 > buf.len() {
        return Err(DecodeError::Truncated);
    }
    let len = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]) as usize;
    if len < 2 {
        return Err(DecodeError::Truncated);
    }
    *pos += 2;
    if *pos + (len - 2) > buf.len() {
        return Err(DecodeError::Truncated);
    }
    Ok(len - 2)
}
