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

use crate::dhcp::{build_request, Message};
use crate::frame::{broadcast_request, ComposeInput};
use crate::l2_client::{send_frame, TxError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    BuildFailed,
    L2Failed,
}

const BOOTP_MAX: usize = 576;

// Build a BOOTP packet for the requested DHCP message type, wrap
// it in UDP+IPv4+Ethernet broadcast headers, and ship via L2.
pub fn send(
    l2_port: u32,
    msg: &Message,
    message_type: u8,
    requested_ip: Option<[u8; 4]>,
    server_id: Option<[u8; 4]>,
    identification: u16,
) -> Result<(), SendError> {
    let mut bootp = [0u8; BOOTP_MAX];
    let bootp_len = build_request(msg, message_type, requested_ip, server_id, &mut bootp)
        .map_err(|_| SendError::BuildFailed)?;
    let mut client_mac = [0u8; 6];
    client_mac.copy_from_slice(&msg.chaddr[..6]);
    let frame = broadcast_request(&ComposeInput {
        client_mac: &client_mac,
        identification,
        bootp: &bootp[..bootp_len],
    });
    send_frame(l2_port, &frame).map_err(|_: TxError| SendError::L2Failed)
}
