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
use alloc::vec::Vec;

use super::ethernet::{self, BROADCAST, ETHERTYPE_IPV4};
use super::ipv4::{self, PROTO_UDP};
use super::udp;
use crate::dhcp::{CLIENT_PORT, SERVER_PORT};

const BROADCAST_IP: [u8; 4] = [255, 255, 255, 255];
const UNSPECIFIED: [u8; 4] = [0; 4];

#[derive(Clone, Copy, Debug)]
pub struct ComposeInput<'a> {
    pub client_mac: &'a [u8; 6],
    pub identification: u16,
    pub bootp: &'a [u8],
}

// Wrap a BOOTP payload in UDP + IPv4 + Ethernet for the DISCOVER
// and REQUEST messages. Source IP is always 0.0.0.0 (no lease
// yet); destination is the broadcast at every layer.
pub fn broadcast_request(input: &ComposeInput<'_>) -> Vec<u8> {
    let ip_total = (ipv4::HDR_LEN + udp::HDR_LEN + input.bootp.len()) as u16;
    let frame_len = ethernet::HDR_LEN + ip_total as usize;
    let mut frame = vec![0u8; frame_len];
    let eth_end = ethernet::write(&mut frame, &BROADCAST, input.client_mac, ETHERTYPE_IPV4);
    let ip_end = eth_end
        + ipv4::write(
            &mut frame[eth_end..],
            &UNSPECIFIED,
            &BROADCAST_IP,
            PROTO_UDP,
            input.identification,
            ip_total,
        );
    let _ = udp::write(
        &mut frame[ip_end..],
        &UNSPECIFIED,
        &BROADCAST_IP,
        CLIENT_PORT,
        SERVER_PORT,
        input.bootp,
    );
    frame
}
