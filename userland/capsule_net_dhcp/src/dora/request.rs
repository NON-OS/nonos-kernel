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

use crate::dhcp::{Message, DHCPACK, DHCPNAK, DHCPREQUEST};

use super::send_bootp::{send as send_bootp, SendError};
use super::wait_reply::{wait_for, WaitError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestError {
    Send(SendError),
    Wait(WaitError),
    Nak,
}

// Issue a DHCPREQUEST for the offered yiaddr against the
// announced server_id, then wait for ACK (success) or NAK
// (caller resets to Init and retries).
pub fn run(l2_port: u32, msg: &Message, offer: &Message) -> Result<Message, RequestError> {
    send_bootp(
        l2_port,
        msg,
        DHCPREQUEST,
        Some(offer.yiaddr),
        Some(offer.server_id),
        msg.xid as u16,
    )
    .map_err(RequestError::Send)?;
    let reply = wait_for(l2_port, msg.xid, &[DHCPACK, DHCPNAK]).map_err(RequestError::Wait)?;
    if reply.message_type == DHCPNAK {
        return Err(RequestError::Nak);
    }
    Ok(reply)
}
