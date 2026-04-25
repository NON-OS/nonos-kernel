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
use crate::zk_engine::attestation::types::KernelAttestation;
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

impl RemoteAttestationClient {
    pub fn request_attestation(
        &mut self,
        target_address: &str,
    ) -> Result<KernelAttestation, ZKError> {
        let current_time = crate::time::timestamp_millis();
        if current_time < self.last_attestation_time + self.min_attestation_interval_ms {
            return Err(ZKError::AttestationError("Rate limited".into()));
        }
        self.last_attestation_time = current_time;

        let entropy = crate::crypto::entropy::get_entropy(32);
        self.current_nonce.copy_from_slice(&entropy[..32]);

        let mut request = Vec::new();
        request.extend_from_slice(b"ATTEST_REQ");
        request.extend_from_slice(&1u16.to_le_bytes());
        request.extend_from_slice(&self.current_nonce);
        request.extend_from_slice(&current_time.to_le_bytes());

        let response = self.send_attestation_request(target_address, &request)?;
        self.parse_attestation_response(&response)
    }

    pub(super) fn send_attestation_request(
        &self,
        target_address: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, ZKError> {
        let is_onion = target_address.ends_with(".onion");
        if is_onion {
            self.send_via_nym(target_address, request)
        } else {
            self.send_via_tcp(target_address, request)
        }
    }
}
