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

use super::constants::*;
use super::message::Message;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    BadCookie,
    BadOption,
}

pub fn parse(bytes: &[u8]) -> Result<Message, ParseError> {
    if bytes.len() < HEADER_LEN {
        return Err(ParseError::TooShort);
    }
    if bytes[FIELD_COOKIE..FIELD_COOKIE + 4] != MAGIC_COOKIE {
        return Err(ParseError::BadCookie);
    }
    let mut m = Message {
        op: bytes[FIELD_OP],
        xid: u32::from_be_bytes(bytes[FIELD_XID..FIELD_XID + 4].try_into().unwrap()),
        flags: u16::from_be_bytes(bytes[FIELD_FLAGS..FIELD_FLAGS + 2].try_into().unwrap()),
        ciaddr: bytes[FIELD_CIADDR..FIELD_CIADDR + 4].try_into().unwrap(),
        yiaddr: bytes[FIELD_YIADDR..FIELD_YIADDR + 4].try_into().unwrap(),
        siaddr: bytes[FIELD_SIADDR..FIELD_SIADDR + 4].try_into().unwrap(),
        giaddr: bytes[FIELD_GIADDR..FIELD_GIADDR + 4].try_into().unwrap(),
        chaddr: bytes[FIELD_CHADDR..FIELD_CHADDR + 16].try_into().unwrap(),
        ..Default::default()
    };
    let mut i = HEADER_LEN;
    while i < bytes.len() {
        let tag = bytes[i];
        i += 1;
        if tag == OPT_END {
            break;
        }
        if tag == OPT_PAD {
            continue;
        }
        if i >= bytes.len() {
            return Err(ParseError::BadOption);
        }
        let len = bytes[i] as usize;
        i += 1;
        if i + len > bytes.len() {
            return Err(ParseError::BadOption);
        }
        match tag {
            OPT_MESSAGE_TYPE if len == 1 => m.message_type = bytes[i],
            OPT_SUBNET_MASK if len == 4 => m.subnet_mask.copy_from_slice(&bytes[i..i + 4]),
            OPT_ROUTER if len >= 4 => m.router.copy_from_slice(&bytes[i..i + 4]),
            OPT_DNS if len >= 4 => m.dns.copy_from_slice(&bytes[i..i + 4]),
            OPT_LEASE_TIME if len == 4 => {
                m.lease_seconds = u32::from_be_bytes(bytes[i..i + 4].try_into().unwrap());
            }
            OPT_SERVER_IDENTIFIER if len == 4 => {
                m.server_id.copy_from_slice(&bytes[i..i + 4]);
            }
            _ => {}
        }
        i += len;
    }
    Ok(m)
}
