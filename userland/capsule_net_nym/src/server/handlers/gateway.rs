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

use crate::protocol::{E_NO_TCP, E_OK, OP_SET_GATEWAY};
use crate::server::handlers::io::{ip4_at, u16_at};
use crate::server::parse_req::Request;
use crate::server::respond::respond;
use crate::setup;
use crate::state::{Gateway, TABLE};
use crate::tcp_client;

pub fn handle(pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    let gateway = match parse_gateway(body) {
        Ok(g) => g,
        Err(e) => return respond(pid, OP_SET_GATEWAY, e, req.request_id, 0, tx),
    };
    let tcp_port = setup::tcp_port();
    if tcp_port == 0 {
        return respond(pid, OP_SET_GATEWAY, E_NO_TCP, req.request_id, 0, tx);
    }
    let stream = match tcp_client::connect(tcp_port, gateway.ip, gateway.port) {
        Ok(handle) => handle,
        Err(_) => return respond(pid, OP_SET_GATEWAY, E_NO_TCP, req.request_id, 0, tx),
    };
    let gateway = Gateway { stream, ..gateway };
    if let Some(old) = TABLE.lock().set_gateway(gateway) {
        if tcp_client::close(tcp_port, old.stream).is_err() {
            return respond(pid, OP_SET_GATEWAY, E_NO_TCP, req.request_id, 0, tx);
        }
    }
    respond(pid, OP_SET_GATEWAY, E_OK, req.request_id, 0, tx);
}

fn parse_gateway(body: &[u8]) -> Result<Gateway, u16> {
    let ip = ip4_at(body, 0)?;
    let port = u16_at(body, 4)?;
    Ok(Gateway { ip, port, stream: 0 })
}
