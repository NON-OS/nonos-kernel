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

use crate::dhcp::{Message, DHCPRELEASE};

use super::send_bootp::{send as send_bootp, SendError};

// Ship a DHCPRELEASE for the bound lease. The server is supposed
// to free the binding on receipt; no response is expected, so we
// fire and forget after the L2 send returns.
pub fn run(l2_port: u32, msg: &Message, server_id: [u8; 4]) -> Result<(), SendError> {
    send_bootp(l2_port, msg, DHCPRELEASE, None, Some(server_id), msg.xid as u16)
}
