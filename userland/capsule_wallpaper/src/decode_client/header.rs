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

use crate::protocol::E_INVAL;

pub const DECODE_HDR_LEN: usize = 16;

#[derive(Clone, Copy)]
pub enum DecodeKind {
    Png,
    Bmp,
    Lz4Raw,
    Jpeg,
}

pub struct DecodeReq<'a> {
    pub kind: DecodeKind,
    pub width: u32,
    pub height: u32,
    pub payload: &'a [u8],
}

pub fn parse_decode_req(body: &[u8]) -> Result<DecodeReq<'_>, i32> {
    if body.len() < DECODE_HDR_LEN {
        return Err(E_INVAL);
    }
    let kind_raw = u32::from_le_bytes(body[0..4].try_into().unwrap());
    let width = u32::from_le_bytes(body[4..8].try_into().unwrap());
    let height = u32::from_le_bytes(body[8..12].try_into().unwrap());
    let payload_len = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
    if body.len() != DECODE_HDR_LEN + payload_len {
        return Err(E_INVAL);
    }
    let kind = match kind_raw {
        1 => DecodeKind::Png,
        2 => DecodeKind::Bmp,
        3 => DecodeKind::Lz4Raw,
        4 => DecodeKind::Jpeg,
        _ => return Err(E_INVAL),
    };
    Ok(DecodeReq { kind, width, height, payload: &body[DECODE_HDR_LEN..] })
}
