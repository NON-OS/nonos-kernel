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

use super::state::RemoteAttestationClient;
use crate::network::stack;
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

impl RemoteAttestationClient {
    pub(super) fn send_via_tcp(
        &self,
        target_address: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, ZKError> {
        let stack = stack::get_network_stack().ok_or(ZKError::NetworkError)?;

        let parts: Vec<&str> = target_address.split(':').collect();
        if parts.len() != 2 {
            return Err(ZKError::AttestationError("Invalid address format".into()));
        }

        let port: u16 =
            parts[1].parse().map_err(|_| ZKError::AttestationError("Invalid port".into()))?;

        let ip_parts: Vec<u8> = parts[0].split('.').filter_map(|p| p.parse().ok()).collect();
        if ip_parts.len() != 4 {
            return Err(ZKError::AttestationError("Invalid IP address".into()));
        }

        let dest_ip: [u8; 4] = [ip_parts[0], ip_parts[1], ip_parts[2], ip_parts[3]];
        let sock = stack::TcpSocket::new();
        stack.tcp_connect(&sock, dest_ip, port).map_err(|_| ZKError::NetworkError)?;

        let conn_id = sock.connection_id();
        stack.tcp_send(conn_id, request).map_err(|_| ZKError::NetworkError)?;

        let response = self.receive_tcp_response(&stack, conn_id)?;
        let _ = stack.tcp_close(conn_id);
        Ok(response)
    }
}
