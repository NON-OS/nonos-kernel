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

use super::recv_plain;
use crate::crypto;
use crate::packet::{self, FLAG_COVER};
use crate::protocol::{NYM_PAYLOAD_BYTES, WIRE_PACKET_MAX};
use crate::setup;
use crate::state::TABLE;
use crate::tcp_client;

pub fn drain_stream() {
    let tcp_port = setup::tcp_port();
    let stream = match TABLE.lock().gateway_stream() {
        Some(stream) if tcp_port != 0 => stream,
        _ => return,
    };
    let mut chunk = vec![0u8; WIRE_PACKET_MAX];
    let Ok(n) = tcp_client::recv(tcp_port, stream, &mut chunk) else {
        return;
    };
    if n == 0 {
        return;
    }
    TABLE.lock().append_stream(&chunk[..n]);
    route_ready_packets();
}

fn route_ready_packets() {
    let mut packet = vec![0u8; WIRE_PACKET_MAX];
    loop {
        if !TABLE.lock().take_packet(&mut packet) {
            return;
        }
        route_packet(&packet);
    }
}

fn route_packet(bytes: &[u8]) {
    let Ok(decoded) = packet::decode(bytes) else { return };
    if decoded.flags & FLAG_COVER != 0 {
        return;
    }
    let mut plain = vec![0u8; NYM_PAYLOAD_BYTES];
    let routed = TABLE.lock().with_id_mut(decoded.session_id, |s| {
        if !s.accept_replay_tag(&decoded.replay_tag) {
            return;
        }
        if let Ok(n) = crypto::open(&s.key, &decoded.nonce, decoded.ciphertext, &mut plain) {
            recv_plain::queue(s, &plain[..n]);
        }
    });
    if routed.is_none() {
        return;
    }
}
