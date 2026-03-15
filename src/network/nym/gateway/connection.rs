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

use crate::network::nym::types::{Gateway, GatewayId, ClientId};
use crate::network::nym::error::NymError;
use super::state::GatewayState;

pub struct GatewayConnection {
    pub gateway_id: GatewayId,
    pub client_id: ClientId,
    pub state: GatewayState,
    pub shared_key: [u8; 32],
}

pub fn connect_to_gateway(gateway: &Gateway, client_id: &ClientId) -> Result<GatewayConnection, NymError> {
    let shared_key = perform_handshake(&gateway.sphinx_key, client_id)?;
    Ok(GatewayConnection {
        gateway_id: gateway.id,
        client_id: *client_id,
        state: GatewayState::Connected,
        shared_key,
    })
}

fn perform_handshake(gateway_key: &[u8; 32], client_id: &ClientId) -> Result<[u8; 32], NymError> {
    let (secret, _public) = crate::network::nym::crypto::generate_keypair();
    let shared = crate::network::nym::crypto::x25519_scalar_mult(&secret, gateway_key);
    let _ = client_id;
    Ok(shared)
}

impl GatewayConnection {
    pub fn send(&self, _data: &[u8]) -> Result<(), NymError> { Ok(()) }
    pub fn recv(&self, _buf: &mut [u8]) -> Result<usize, NymError> { Ok(0) }
    pub fn close(&mut self) { self.state = GatewayState::Disconnected; }
}
