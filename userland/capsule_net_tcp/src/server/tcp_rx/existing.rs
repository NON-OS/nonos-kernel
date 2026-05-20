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

use alloc::vec::Vec;

use crate::state::{Entry, TABLE};
use crate::tcp::{Endpoint4, State, Tcb, TcpHeader, FLAG_ACK, FLAG_FIN, FLAG_SYN};

pub fn update(
    local: Endpoint4,
    remote: Endpoint4,
    hdr: TcpHeader,
    payload: &[u8],
) -> Option<(Tcb, u8, Vec<u8>)> {
    let mut table = TABLE.lock();
    let mut accepted = None;
    let plan = {
        let e = table.connection_match_mut(local, remote)?;
        if e.tcb.state == State::SynSent && both(&hdr, FLAG_SYN | FLAG_ACK) {
            syn_ack(e, hdr)
        } else if e.tcb.state == State::SynReceived && hdr.has_flag(FLAG_ACK) {
            e.tcb.state = State::Established;
            accepted = Some((e.parent, e.handle));
            None
        } else if e.tcb.state.accepts_data() {
            data(e, hdr, payload)
        } else {
            None
        }
    };
    if let Some((parent, handle)) = accepted {
        if let Some(p) = table.by_handle_mut(parent) {
            let _ = p.push_accept(handle);
        }
    }
    plan
}

fn syn_ack(e: &mut Entry, hdr: TcpHeader) -> Option<(Tcb, u8, Vec<u8>)> {
    e.tcb.recv.nxt = hdr.seq.wrapping_add(1);
    e.tcb.send.una = hdr.ack;
    e.tcb.state = State::Established;
    Some((e.tcb, FLAG_ACK, Vec::new()))
}

fn data(e: &mut Entry, hdr: TcpHeader, payload: &[u8]) -> Option<(Tcb, u8, Vec<u8>)> {
    if !payload.is_empty() && hdr.seq == e.tcb.recv.nxt {
        let _ = e.push_rx(payload);
        e.tcb.recv.nxt = e.tcb.recv.nxt.wrapping_add(payload.len() as u32);
    }
    if hdr.has_flag(FLAG_FIN) {
        e.tcb.recv.nxt = e.tcb.recv.nxt.wrapping_add(1);
        e.tcb.state = State::CloseWait;
    }
    Some((e.tcb, FLAG_ACK, Vec::new()))
}

fn both(hdr: &TcpHeader, mask: u8) -> bool {
    hdr.flags & mask == mask
}
