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
pub enum BuildError {
    OutputTooSmall,
}

// Build the BOOTP fixed region plus the options block for a
// DHCPDISCOVER or DHCPREQUEST. `requested_ip` is included for
// REQUEST messages; pass [0;4] for DISCOVER. The output is the
// number of bytes written into `out` (variable, depends on
// which options are present).
pub fn build_request(
    msg: &Message,
    message_type: u8,
    requested_ip: Option<[u8; 4]>,
    server_id: Option<[u8; 4]>,
    out: &mut [u8],
) -> Result<usize, BuildError> {
    if out.len() < HEADER_LEN + 16 {
        return Err(BuildError::OutputTooSmall);
    }
    out[..HEADER_LEN].fill(0);
    out[FIELD_OP] = msg.op;
    out[FIELD_HTYPE] = HTYPE_ETHERNET;
    out[FIELD_HLEN] = HLEN_ETHERNET;
    out[FIELD_XID..FIELD_XID + 4].copy_from_slice(&msg.xid.to_be_bytes());
    out[FIELD_FLAGS..FIELD_FLAGS + 2].copy_from_slice(&msg.flags.to_be_bytes());
    out[FIELD_CHADDR..FIELD_CHADDR + 16].copy_from_slice(&msg.chaddr);
    out[FIELD_COOKIE..FIELD_COOKIE + 4].copy_from_slice(&MAGIC_COOKIE);

    let mut cur = HEADER_LEN;
    out[cur] = OPT_MESSAGE_TYPE;
    out[cur + 1] = 1;
    out[cur + 2] = message_type;
    cur += 3;
    if let Some(ip) = requested_ip {
        out[cur] = OPT_REQUESTED_IP;
        out[cur + 1] = 4;
        out[cur + 2..cur + 6].copy_from_slice(&ip);
        cur += 6;
    }
    if let Some(id) = server_id {
        out[cur] = OPT_SERVER_IDENTIFIER;
        out[cur + 1] = 4;
        out[cur + 2..cur + 6].copy_from_slice(&id);
        cur += 6;
    }
    out[cur] = OPT_PARAMETER_LIST;
    out[cur + 1] = 3;
    out[cur + 2] = OPT_SUBNET_MASK;
    out[cur + 3] = OPT_ROUTER;
    out[cur + 4] = OPT_DNS;
    cur += 5;
    out[cur] = OPT_END;
    cur += 1;
    Ok(cur)
}
