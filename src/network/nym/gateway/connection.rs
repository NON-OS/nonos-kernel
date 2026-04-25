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

use super::state::GatewayState;
use crate::network::nym::error::NymError;
use crate::network::nym::types::{ClientId, Gateway, GatewayId};
use crate::network::tcp::{close_socket, connect_to, recv_socket, send_socket};

pub struct GatewayConnection {
    pub gateway_id: GatewayId,
    pub client_id: ClientId,
    pub state: GatewayState,
    pub shared_key: [u8; 32],
    tcp_handle: u32,
}

pub fn connect_to_gateway(
    gateway: &Gateway,
    client_id: &ClientId,
) -> Result<GatewayConnection, NymError> {
    let tcp_handle = connect_to(&gateway.host, gateway.clients_port, 10000)
        .map_err(|_| NymError::ConnectionFailed)?;
    let shared_key = perform_handshake(tcp_handle, &gateway.sphinx_key, client_id)?;
    Ok(GatewayConnection {
        gateway_id: gateway.id,
        client_id: *client_id,
        state: GatewayState::Connected,
        shared_key,
        tcp_handle,
    })
}

fn perform_handshake(
    handle: u32,
    gateway_key: &[u8; 32],
    client_id: &ClientId,
) -> Result<[u8; 32], NymError> {
    let (secret, public) = crate::network::nym::crypto::generate_keypair();
    let mut handshake_msg = [0u8; 64];
    handshake_msg[..32].copy_from_slice(&public);
    handshake_msg[32..].copy_from_slice(&client_id.0);
    send_socket(handle, &handshake_msg).map_err(|_| NymError::ConnectionFailed)?;
    let mut response = [0u8; 32];
    let n = recv_socket(handle, &mut response, 5000).map_err(|_| NymError::ConnectionFailed)?;
    if n != 32 {
        return Err(NymError::HandshakeFailed);
    }
    let shared = crate::network::nym::crypto::x25519_scalar_mult(&secret, gateway_key);
    Ok(shared)
}

impl GatewayConnection {
    pub fn send(&self, data: &[u8]) -> Result<(), NymError> {
        if self.state != GatewayState::Connected {
            return Err(NymError::NotConnected);
        }
        send_socket(self.tcp_handle, data).map_err(|_| NymError::SendFailed)
    }

    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, NymError> {
        if self.state != GatewayState::Connected {
            return Err(NymError::NotConnected);
        }
        recv_socket(self.tcp_handle, buf, 5000).map_err(|_| NymError::ReceiveFailed)
    }

    pub fn close(&mut self) {
        close_socket(self.tcp_handle);
        self.state = GatewayState::Disconnected;
    }
}

impl Drop for GatewayConnection {
    fn drop(&mut self) {
        if self.state == GatewayState::Connected {
            close_socket(self.tcp_handle);
        }
    }
}
