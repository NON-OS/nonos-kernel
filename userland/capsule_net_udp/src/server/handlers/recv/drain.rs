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

use crate::ip_client::{poll_segment, RecvError, UdpInbound};
use crate::state::STATE;
use crate::udp::parse as udp_parse;

// Pull at most one segment off `net.ip` and stash it in the bind
// keyed by the parsed UDP destination port. Failures are swallowed
// — the caller will retry on the next recv tick.
pub fn drain_one() {
    let ip = STATE.ip_port();
    if ip == 0 {
        return;
    }
    match poll_segment(ip) {
        Ok(seg) => route(seg),
        Err(RecvError::Empty)
        | Err(RecvError::NotUdp)
        | Err(RecvError::NoConfig)
        | Err(RecvError::SendFailed)
        | Err(RecvError::BadResponse)
        | Err(RecvError::Other(_)) => {}
    }
}

fn route(seg: UdpInbound) {
    let dst_port = match udp_parse(&seg.src, &seg.dst, &seg.segment) {
        Ok((h, _)) => h.dst_port,
        Err(_) => return,
    };
    let mut table = STATE.binds.lock();
    if let Some(b) = table.find_by_port_mut(dst_port) {
        let _ = b.push(seg);
    }
}
