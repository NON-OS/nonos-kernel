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

use super::header::{Header, HDR_LEN};
use super::name::{skip, NameError};
use super::types::{TYPE_A, TYPE_AAAA};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    BadName,
    NotAResponse,
}

impl From<NameError> for ParseError {
    fn from(_: NameError) -> Self {
        Self::BadName
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Answer {
    pub rtype: u16,
    pub ttl: u32,
    pub ipv4: Option<[u8; 4]>,
    pub ipv6: Option<[u8; 16]>,
}

// Parse the header, skip the question section, and walk answer
// records. The first A or AAAA record found is returned;
// subsequent answers are ignored. The caller can extend this to
// collect all records when the cache calls for it.
pub fn first_address(message: &[u8]) -> Result<(Header, Option<Answer>), ParseError> {
    if message.len() < HDR_LEN {
        return Err(ParseError::Truncated);
    }
    let header = Header {
        id: u16::from_be_bytes([message[0], message[1]]),
        flags: u16::from_be_bytes([message[2], message[3]]),
        qdcount: u16::from_be_bytes([message[4], message[5]]),
        ancount: u16::from_be_bytes([message[6], message[7]]),
        nscount: u16::from_be_bytes([message[8], message[9]]),
        arcount: u16::from_be_bytes([message[10], message[11]]),
    };
    if !header.is_response() {
        return Err(ParseError::NotAResponse);
    }
    let mut pos = HDR_LEN;
    for _ in 0..header.qdcount {
        pos = skip(message, pos)?;
        if pos + 4 > message.len() {
            return Err(ParseError::Truncated);
        }
        pos += 4;
    }
    for _ in 0..header.ancount {
        pos = skip(message, pos)?;
        if pos + 10 > message.len() {
            return Err(ParseError::Truncated);
        }
        let rtype = u16::from_be_bytes([message[pos], message[pos + 1]]);
        let ttl = u32::from_be_bytes(message[pos + 4..pos + 8].try_into().unwrap());
        let rdlen = u16::from_be_bytes([message[pos + 8], message[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > message.len() {
            return Err(ParseError::Truncated);
        }
        if rtype == TYPE_A && rdlen == 4 {
            let mut ipv4 = [0u8; 4];
            ipv4.copy_from_slice(&message[pos..pos + 4]);
            return Ok((header, Some(Answer { rtype, ttl, ipv4: Some(ipv4), ipv6: None })));
        }
        if rtype == TYPE_AAAA && rdlen == 16 {
            let mut ipv6 = [0u8; 16];
            ipv6.copy_from_slice(&message[pos..pos + 16]);
            return Ok((header, Some(Answer { rtype, ttl, ipv4: None, ipv6: Some(ipv6) })));
        }
        pos += rdlen;
    }
    Ok((header, None))
}
