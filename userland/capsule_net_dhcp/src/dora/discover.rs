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

use crate::dhcp::{Message, DHCPDISCOVER, DHCPOFFER};

use super::send_bootp::{send as send_bootp, SendError};
use super::wait_reply::{wait_for, WaitError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoverError {
    Send(SendError),
    Wait(WaitError),
}

// Issue a single DHCPDISCOVER and return the first matching OFFER.
// Retries are owned by the caller (LEASE_REQUEST handler decides
// the high-level loop policy).
pub fn run(l2_port: u32, msg: &Message) -> Result<Message, DiscoverError> {
    send_bootp(l2_port, msg, DHCPDISCOVER, None, None, msg.xid as u16)
        .map_err(DiscoverError::Send)?;
    wait_for(l2_port, msg.xid, &[DHCPOFFER]).map_err(DiscoverError::Wait)
}
