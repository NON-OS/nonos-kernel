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

use super::answer::Answer;
use super::error::ParseError;
use crate::dns::{TYPE_A, TYPE_AAAA};

pub(super) fn read_answer(message: &[u8], pos: usize) -> Result<(Answer, usize), ParseError> {
    if pos + 10 > message.len() {
        return Err(ParseError::Truncated);
    }
    let rtype = u16::from_be_bytes([message[pos], message[pos + 1]]);
    let ttl = be32(message, pos + 4);
    let rdlen = u16::from_be_bytes([message[pos + 8], message[pos + 9]]) as usize;
    let rdata = pos + 10;
    if rdata + rdlen > message.len() {
        return Err(ParseError::Truncated);
    }
    Ok((answer_from(rtype, ttl, &message[rdata..rdata + rdlen]), rdata + rdlen))
}

fn be32(message: &[u8], pos: usize) -> u32 {
    u32::from_be_bytes([message[pos], message[pos + 1], message[pos + 2], message[pos + 3]])
}

fn answer_from(rtype: u16, ttl: u32, rdata: &[u8]) -> Answer {
    Answer { rtype, ttl, ipv4: ipv4_from(rtype, rdata), ipv6: ipv6_from(rtype, rdata) }
}

fn ipv4_from(rtype: u16, rdata: &[u8]) -> Option<[u8; 4]> {
    if rtype != TYPE_A || rdata.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    out.copy_from_slice(rdata);
    Some(out)
}

fn ipv6_from(rtype: u16, rdata: &[u8]) -> Option<[u8; 16]> {
    if rtype != TYPE_AAAA || rdata.len() != 16 {
        return None;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(rdata);
    Some(out)
}
