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

use crate::dhcp::{Message, State as ClientState};
use crate::dora::{discover, install, request, DiscoverError, InstallError, RequestError};
use crate::protocol::{E_NAK, E_NO_LINK, E_OK, E_TIMEOUT, OP_LEASE_REQUEST};
use crate::server::parse_req::Request;
use crate::server::respond::respond;
use crate::state::{Lease, STATE};

use super::xid_mac::current;

pub fn handle(sender_pid: u32, req: &Request, tx: &mut [u8]) {
    let (l2, ip, mac) = match current() {
        Some(v) => v,
        None => {
            let _ = respond(sender_pid, OP_LEASE_REQUEST, E_NO_LINK, req.request_id, 0, tx);
            return;
        }
    };
    let xid = STATE.next_xid();
    *STATE.client_state.lock() = ClientState::Selecting;
    let msg = Message::new_request(&mac, xid);
    let offer = match discover(l2, &msg) {
        Ok(m) => m,
        Err(DiscoverError::Wait(_)) => {
            *STATE.client_state.lock() = ClientState::Init;
            let _ = respond(sender_pid, OP_LEASE_REQUEST, E_TIMEOUT, req.request_id, 0, tx);
            return;
        }
        Err(DiscoverError::Send(_)) => {
            *STATE.client_state.lock() = ClientState::Init;
            let _ = respond(sender_pid, OP_LEASE_REQUEST, E_NO_LINK, req.request_id, 0, tx);
            return;
        }
    };
    *STATE.client_state.lock() = ClientState::Requesting;
    let ack = match request(l2, &msg, &offer) {
        Ok(m) => m,
        Err(RequestError::Nak) => {
            *STATE.client_state.lock() = ClientState::Init;
            let _ = respond(sender_pid, OP_LEASE_REQUEST, E_NAK, req.request_id, 0, tx);
            return;
        }
        Err(RequestError::Wait(_)) => {
            *STATE.client_state.lock() = ClientState::Init;
            let _ = respond(sender_pid, OP_LEASE_REQUEST, E_TIMEOUT, req.request_id, 0, tx);
            return;
        }
        Err(RequestError::Send(_)) => {
            *STATE.client_state.lock() = ClientState::Init;
            let _ = respond(sender_pid, OP_LEASE_REQUEST, E_NO_LINK, req.request_id, 0, tx);
            return;
        }
    };
    let prefix = match install(ip, &ack) {
        Ok(p) => p,
        Err(InstallError::BadMask) | Err(InstallError::IpRefused) => {
            *STATE.client_state.lock() = ClientState::Init;
            let _ = respond(sender_pid, OP_LEASE_REQUEST, E_NO_LINK, req.request_id, 0, tx);
            return;
        }
    };
    *STATE.lease.lock() = Lease {
        ipv4: ack.yiaddr,
        prefix,
        gateway: ack.router,
        server_id: ack.server_id,
        dns: ack.dns,
        lease_seconds: ack.lease_seconds,
    };
    *STATE.client_state.lock() = ClientState::Bound;
    let _ = respond(sender_pid, OP_LEASE_REQUEST, E_OK, req.request_id, 0, tx);
}
