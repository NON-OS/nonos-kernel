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

use crate::clients::{nym, tcp};
use crate::protocol::{E_NO_HANDLE, E_NO_TRANSPORT, E_OK, OP_CONNECT};
use crate::server::handlers::io::{ip4_at, u16_at, u32_at};
use crate::server::parse_req::Request;
use crate::server::respond::respond;
use crate::sockets::{Kind, RemoteAddr4, SocketKey, SOCKETS};
use crate::state;

pub fn handle(pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    let (handle, ip, port) = match parse_body(body) {
        Ok(v) => v,
        Err(e) => return status(pid, req, e, tx),
    };
    let errno = SOCKETS.with(SocketKey { pid, handle }, |s| {
        s.remote = Some(RemoteAddr4 { ip, port });
        if s.kind == Kind::Datagram {
            return E_OK;
        }
        if s.kind == Kind::Mixnet {
            return match connect_nym(ip, port) {
                Ok(h) => {
                    s.transport_handle = h;
                    E_OK
                }
                Err(_) => E_NO_TRANSPORT,
            };
        }
        match tcp::connect(state::tcp(), ip, port) {
            Ok(h) => {
                s.transport_handle = h;
                E_OK
            }
            Err(_) => E_NO_TRANSPORT,
        }
    });
    status(pid, req, errno.map_or(E_NO_HANDLE, |code| code), tx);
}

fn parse_body(body: &[u8]) -> Result<(u32, [u8; 4], u16), u16> {
    Ok((u32_at(body, 0)?, ip4_at(body, 4)?, u16_at(body, 8)?))
}

fn connect_nym(ip: [u8; 4], port: u16) -> Result<u32, u16> {
    let nym_port = state::nym();
    nym::set_gateway(nym_port, ip, port)?;
    nym::open(nym_port)
}

fn status(pid: u32, req: &Request, errno: u16, tx: &mut [u8]) {
    respond(pid, OP_CONNECT, errno, req.request_id, 0, tx);
}
