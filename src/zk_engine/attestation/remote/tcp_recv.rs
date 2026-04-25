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
    pub(super) fn receive_tcp_response(
        &self,
        stack: &stack::NetworkStack,
        conn_id: u32,
    ) -> Result<Vec<u8>, ZKError> {
        let mut response = Vec::new();
        let timeout_ms = 5000;
        let start = crate::time::timestamp_millis();

        loop {
            if let Ok(data) = stack.tcp_receive(conn_id, 4096) {
                if !data.is_empty() {
                    response.extend_from_slice(&data);
                    if self.is_response_complete(&response) {
                        break;
                    }
                }
            }
            if crate::time::timestamp_millis() - start > timeout_ms {
                return Err(ZKError::AttestationError("Request timeout".into()));
            }
            core::hint::spin_loop();
        }
        Ok(response)
    }
}
