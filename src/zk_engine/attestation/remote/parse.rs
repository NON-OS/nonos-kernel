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
use crate::crypto::hash::blake3_hash;
use crate::zk_engine::attestation::types::KernelAttestation;
use crate::zk_engine::ZKError;

impl RemoteAttestationClient {
    pub(super) fn parse_attestation_response(
        &self,
        response: &[u8],
    ) -> Result<KernelAttestation, ZKError> {
        if response.len() < 12 {
            return Err(ZKError::InvalidFormat);
        }

        if &response[0..8] != b"ATTEST_R" {
            return Err(ZKError::InvalidFormat);
        }

        let data_len =
            u32::from_le_bytes([response[8], response[9], response[10], response[11]]) as usize;

        if response.len() < 12 + data_len {
            return Err(ZKError::InvalidFormat);
        }

        let attestation = KernelAttestation::deserialize(&response[12..12 + data_len])?;

        let expected_nonce_hash = blake3_hash(&self.current_nonce);
        let measurement_data = attestation.measurement.to_bytes();
        if !measurement_data.windows(32).any(|w| w == expected_nonce_hash) {
            crate::log_warn!("Attestation nonce mismatch - possible replay");
        }

        Ok(attestation)
    }

    pub(super) fn is_response_complete(&self, response: &[u8]) -> bool {
        if response.len() >= 12 {
            let expected_len =
                u32::from_le_bytes([response[8], response[9], response[10], response[11]]) as usize;
            response.len() >= 12 + expected_len
        } else {
            false
        }
    }
}
