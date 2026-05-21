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

pub const E_NEED_MORE: u16 = 8;
pub const E_BAD_FRAME: u16 = 9;

pub fn frame_len(buf: &[u8], len: usize) -> Result<Option<(usize, usize)>, u16> {
    if len == 126 {
        if buf.len() < 4 {
            return Ok(None);
        }
        return Ok(Some((u16::from_be_bytes([buf[2], buf[3]]) as usize, 4)));
    }
    if len == 127 {
        return Err(E_BAD_FRAME);
    }
    Ok(Some((len, 2)))
}

pub fn copy_payload(
    buf: &[u8],
    out: &mut [u8],
    masked: bool,
    len: usize,
    off: usize,
) -> Result<usize, u16> {
    if len > out.len() {
        return Err(E_NEED_MORE);
    }
    let mask = if masked { &buf[off..off + 4] } else { &[0, 0, 0, 0] };
    let start = off + if masked { 4 } else { 0 };
    for i in 0..len {
        out[i] = buf[start + i] ^ mask[i % 4];
    }
    Ok(len)
}
