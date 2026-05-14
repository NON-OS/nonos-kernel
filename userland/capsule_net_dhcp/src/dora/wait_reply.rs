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

use nonos_libc::mk_yield;

use crate::dhcp::{parse as parse_bootp, Message};
use crate::frame::dhcp_payload;
use crate::l2_client::{poll_frame, RxError};

const MAX_POLL_ITERATIONS: u32 = 4000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitError {
    Timeout,
    LinkDown,
    L2Failed,
}

// Poll `net.l2` until we see a BOOTP frame whose xid matches and
// whose message_type is one of the accepted types. Other frames
// are dropped (real OFFER may race with ARP/ICMP traffic). The
// poll budget is bounded so a wedged link cannot deadlock the
// server task.
pub fn wait_for(
    l2_port: u32,
    expected_xid: u32,
    accepted_types: &[u8],
) -> Result<Message, WaitError> {
    for _ in 0..MAX_POLL_ITERATIONS {
        match poll_frame(l2_port) {
            Ok(frame) => {
                if let Some(payload) = dhcp_payload(&frame) {
                    if let Ok(msg) = parse_bootp(payload) {
                        if msg.xid == expected_xid && accepted_types.contains(&msg.message_type) {
                            return Ok(msg);
                        }
                    }
                }
            }
            Err(RxError::Empty) => {
                let _ = mk_yield();
            }
            Err(RxError::NoLink) => return Err(WaitError::LinkDown),
            Err(_) => return Err(WaitError::L2Failed),
        }
    }
    Err(WaitError::Timeout)
}
