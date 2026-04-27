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

use alloc::vec::Vec;

pub fn parse_new_session_ticket(
    body: &[u8],
) -> Result<(u32, u32, Vec<u8>, Vec<u8>, u32), &'static str> {
    if body.len() < 9 {
        return Err("NewSessionTicket too short");
    }
    let lifetime = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let age_add = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let nonce_len = body[8] as usize;
    let mut off = 9;
    if body.len() < off + nonce_len + 2 {
        return Err("NewSessionTicket nonce truncated");
    }
    let nonce = body[off..off + nonce_len].to_vec();
    off += nonce_len;
    let ticket_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + ticket_len + 2 {
        return Err("NewSessionTicket ticket truncated");
    }
    let ticket = body[off..off + ticket_len].to_vec();
    off += ticket_len;
    let mut max_early_data: u32 = 0;
    if body.len() >= off + 2 {
        let ext_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
        off += 2;
        let ext_end = (off + ext_len).min(body.len());
        let mut eoff = off;
        while eoff + 4 <= ext_end {
            let etype = u16::from_be_bytes([body[eoff], body[eoff + 1]]);
            let elen = u16::from_be_bytes([body[eoff + 2], body[eoff + 3]]) as usize;
            eoff += 4;
            if eoff + elen > ext_end {
                break;
            }
            if etype == 0x002a && elen == 4 {
                max_early_data = u32::from_be_bytes([
                    body[eoff],
                    body[eoff + 1],
                    body[eoff + 2],
                    body[eoff + 3],
                ]);
            }
            eoff += elen;
        }
    }
    Ok((lifetime, age_add, nonce, ticket, max_early_data))
}
