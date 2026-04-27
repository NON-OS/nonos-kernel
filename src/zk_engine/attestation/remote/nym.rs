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
use crate::network::nym;
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

impl RemoteAttestationClient {
    pub(super) fn send_via_nym(
        &self,
        target_address: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, ZKError> {
        let parts: Vec<&str> = target_address.split(':').collect();
        if parts.len() != 2 {
            return Err(ZKError::AttestationError("Invalid address format".into()));
        }

        let client = nym::get_nym_client().map_err(|_| ZKError::NetworkError)?;
        let mut client = client.lock();

        let dest_str = parts[0];
        let dest_bytes = dest_str.as_bytes();
        let mut dest_arr = [0u8; 64];
        let len = dest_bytes.len().min(64);
        dest_arr[..len].copy_from_slice(&dest_bytes[..len]);

        let dest = nym::NymAddress::from_bytes(&dest_arr).ok_or(ZKError::NetworkError)?;
        let mut stream = client.create_stream(dest).map_err(|_| ZKError::NetworkError)?;
        client.send(&mut stream, request).map_err(|_| ZKError::NetworkError)?;

        self.receive_nym_response(&mut client, &mut stream)
    }

    fn receive_nym_response(
        &self,
        client: &mut nym::NymClient,
        stream: &mut nym::NymStream,
    ) -> Result<Vec<u8>, ZKError> {
        let mut response = Vec::new();
        let timeout_ms = 15000;
        let start = crate::time::timestamp_millis();
        let mut buf = [0u8; 4096];

        loop {
            if let Ok(n) = client.recv(stream, &mut buf) {
                if n > 0 {
                    response.extend_from_slice(&buf[..n]);
                    if self.is_response_complete(&response) {
                        break;
                    }
                }
            }
            if crate::time::timestamp_millis() - start > timeout_ms {
                return Err(ZKError::AttestationError("NYM request timeout".into()));
            }
            core::hint::spin_loop();
        }
        Ok(response)
    }
}
