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

use crate::protocol::{E_NO_UDP, E_OK, OP_SET_GATEWAY};
use crate::server::handlers::io::{ip4_at, u16_at};
use crate::server::parse_req::Request;
use crate::server::respond::respond;
use crate::setup;
use crate::state::{Gateway, DEFAULT_CLIENT_PORT, TABLE};
use crate::udp_client;

pub fn handle(pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    let gateway = match parse_gateway(body) {
        Ok(g) => g,
        Err(e) => return respond(pid, OP_SET_GATEWAY, e, req.request_id, 0, tx),
    };
    let udp_port = setup::udp_port();
    if udp_port == 0 || udp_client::bind(udp_port, gateway.local_port).is_err() {
        return respond(pid, OP_SET_GATEWAY, E_NO_UDP, req.request_id, 0, tx);
    }
    TABLE.lock().set_gateway(gateway);
    respond(pid, OP_SET_GATEWAY, E_OK, req.request_id, 0, tx);
}

fn parse_gateway(body: &[u8]) -> Result<Gateway, u16> {
    let ip = ip4_at(body, 0)?;
    let port = u16_at(body, 4)?;
    let local_port = body.get(6..8).map_or(Ok(DEFAULT_CLIENT_PORT), |_| u16_at(body, 6))?;
    Ok(Gateway { ip, port, local_port })
}
