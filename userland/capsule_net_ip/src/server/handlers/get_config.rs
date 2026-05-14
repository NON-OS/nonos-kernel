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

use core::sync::atomic::Ordering;

use crate::protocol::{E_OK, OP_GET_CONFIG};
use crate::server::parse_req::Request;
use crate::server::respond::respond;
use crate::state::IFACE;

// Body layout: 6 MAC + 4 IPv4 + 1 prefix + 4 gateway + 2 MTU = 17 bytes.
const PAYLOAD_LEN: u32 = 17;
const HDR_LEN: usize = 20;

pub fn handle(sender_pid: u32, req: &Request, tx: &mut [u8]) {
    let mac = *IFACE.mac.lock();
    let ipv4 = *IFACE.ipv4.lock();
    let gw = *IFACE.gateway.lock();
    let prefix = IFACE.prefix.load(Ordering::Acquire) as u8;
    let mtu = IFACE.mtu.load(Ordering::Acquire);
    let mut cursor = HDR_LEN;
    tx[cursor..cursor + 6].copy_from_slice(&mac);
    cursor += 6;
    tx[cursor..cursor + 4].copy_from_slice(&ipv4);
    cursor += 4;
    tx[cursor] = prefix;
    cursor += 1;
    tx[cursor..cursor + 4].copy_from_slice(&gw);
    cursor += 4;
    tx[cursor..cursor + 2].copy_from_slice(&mtu.to_le_bytes());
    let _ = respond(sender_pid, OP_GET_CONFIG, E_OK, req.request_id, PAYLOAD_LEN, tx);
}
