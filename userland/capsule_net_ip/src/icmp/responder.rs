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

//! ICMP echo auto-responder. Sits between the IP ingress path and
//! the caller-visible poll handler: if an inbound packet is an
//! ICMP echo request addressed to us, build the reply and hand it
//! to egress immediately. The caller never sees ping traffic; the
//! capsule answers it the same way a real kernel network stack
//! does, without an external responder.

use alloc::vec;

use super::echo::{build_reply, echo_of, is_echo_request};
use super::parse::parse as icmp_parse;
use crate::egress::send as egress_send;

const PROTOCOL_ICMP: u8 = 1;
const ICMP_HDR_LEN: usize = 8;

// Try to consume an inbound packet as an ICMP echo request. Returns
// `true` if the packet was an echo request and a reply was sent (or
// at least attempted); `false` means the caller should keep
// processing the packet on the normal poll path.
pub fn try_reply(src: &[u8; 4], protocol: u8, payload: &[u8]) -> bool {
    if protocol != PROTOCOL_ICMP {
        return false;
    }
    let (hdr, body) = match icmp_parse(payload) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if !is_echo_request(&hdr) {
        return false;
    }
    let echo = echo_of(&hdr, body);
    let mut reply = vec![0u8; ICMP_HDR_LEN + echo.payload.len()];
    if build_reply(&echo, &mut reply).is_err() {
        return true;
    }
    let _ = egress_send(*src, PROTOCOL_ICMP, &reply);
    true
}
