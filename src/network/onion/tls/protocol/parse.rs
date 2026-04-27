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

use crate::network::onion::OnionError;
use alloc::vec::Vec;

pub fn parse_handshake_view(input: &[u8]) -> Result<(u8, &[u8], usize), OnionError> {
    if input.len() < 4 {
        return Err(OnionError::InvalidCell);
    }
    let typ = input[0];
    let len = ((input[1] as usize) << 16) | ((input[2] as usize) << 8) | input[3] as usize;
    if input.len() < 4 + len {
        return Err(OnionError::InvalidCell);
    }
    Ok((typ, &input[4..4 + len], 4 + len))
}

pub fn parse_certificate_chain(body: &[u8]) -> Result<Vec<Vec<u8>>, OnionError> {
    if body.len() < 4 {
        return Err(OnionError::InvalidCell);
    }
    let mut off = 1 + body[0] as usize;
    let list_len =
        ((body[off] as usize) << 16) | ((body[off + 1] as usize) << 8) | (body[off + 2] as usize);
    off += 3;
    if body.len() < off + list_len {
        return Err(OnionError::InvalidCell);
    }
    let mut certs = Vec::new();
    let mut cur = &body[off..off + list_len];
    while cur.len() >= 3 {
        let clen = ((cur[0] as usize) << 16) | ((cur[1] as usize) << 8) | (cur[2] as usize);
        if cur.len() < 3 + clen + 2 {
            break;
        }
        certs.push(cur[3..3 + clen].to_vec());
        let elen = u16::from_be_bytes([cur[3 + clen], cur[3 + clen + 1]]) as usize;
        if cur.len() < 3 + clen + 2 + elen {
            break;
        }
        cur = &cur[3 + clen + 2 + elen..];
    }
    Ok(certs)
}

pub fn parse_certificate_verify(body: &[u8]) -> Result<(u16, Vec<u8>), OnionError> {
    if body.len() < 4 {
        return Err(OnionError::InvalidCell);
    }
    let alg = u16::from_be_bytes([body[0], body[1]]);
    let sl = u16::from_be_bytes([body[2], body[3]]) as usize;
    if body.len() < 4 + sl {
        return Err(OnionError::InvalidCell);
    }
    Ok((alg, body[4..4 + sl].to_vec()))
}
