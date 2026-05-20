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

use alloc::vec;

use crate::crypto;
use crate::packet::{self, FLAG_COVER};
use crate::protocol::WIRE_PACKET_MAX;
use crate::setup;
use crate::state::{DEFAULT_CLIENT_PORT, TABLE};
use crate::udp_client;

pub fn drain_udp() {
    let udp_port = setup::udp_port();
    if udp_port == 0 {
        return;
    }
    let mut buf = vec![0u8; WIRE_PACKET_MAX + 6];
    if let Ok(dgram) = udp_client::recv_from(udp_port, DEFAULT_CLIENT_PORT, &mut buf) {
        route_packet(dgram.payload);
    }
}

fn route_packet(bytes: &[u8]) {
    let Ok(decoded) = packet::decode(bytes) else { return };
    if decoded.flags & FLAG_COVER != 0 {
        return;
    }
    let mut plain = vec![0u8; decoded.ciphertext.len()];
    let _ = TABLE.lock().with_id_mut(decoded.session_id, |s| {
        if let Ok(n) = crypto::open(&s.key, &decoded.nonce, decoded.ciphertext, &mut plain) {
            plain.truncate(n);
            s.push(plain);
        }
    });
}
