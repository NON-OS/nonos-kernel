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

use nonos_libc::mk_ipc_call;

use super::header::{parse_response, write_request};
use super::seq;
use super::wire::{IP_HDR_LEN, OP_SET_CONFIG};

// Body layout exactly matches `capsule_net_ip`'s set_config handler:
// 4-byte IPv4 + 1-byte prefix + 4-byte gateway = 9 bytes.
const BODY_LEN: usize = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyError {
    SendFailed,
    BadResponse,
    Refused(u16),
}

pub fn apply_lease(
    ip_port: u32,
    ipv4: [u8; 4],
    prefix: u8,
    gateway: [u8; 4],
) -> Result<(), ApplyError> {
    let total = IP_HDR_LEN + BODY_LEN;
    let mut req = [0u8; IP_HDR_LEN + BODY_LEN];
    let rid = seq::next();
    write_request(&mut req, OP_SET_CONFIG, rid, BODY_LEN as u32);
    req[IP_HDR_LEN..IP_HDR_LEN + 4].copy_from_slice(&ipv4);
    req[IP_HDR_LEN + 4] = prefix;
    req[IP_HDR_LEN + 5..IP_HDR_LEN + 9].copy_from_slice(&gateway);
    let mut resp = [0u8; IP_HDR_LEN];
    let n = mk_ipc_call(
        ip_port as u64,
        req.as_ptr(),
        total,
        resp.as_mut_ptr(),
        resp.len(),
    );
    if n < 0 {
        return Err(ApplyError::SendFailed);
    }
    let (op, errno, _, _) = parse_response(&resp).ok_or(ApplyError::BadResponse)?;
    if op != OP_SET_CONFIG {
        return Err(ApplyError::BadResponse);
    }
    if errno != 0 {
        return Err(ApplyError::Refused(errno));
    }
    Ok(())
}

// Bring the interface back to unconfigured. Same body layout, but
// all zeros. `net.ip` will subsequently refuse any send until the
// next lease lands.
pub fn clear_lease(ip_port: u32) -> Result<(), ApplyError> {
    apply_lease(ip_port, [0; 4], 0, [0; 4])
}
