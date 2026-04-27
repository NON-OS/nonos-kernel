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
use crate::zk_engine::attestation::manager::AttestationManager;
use crate::zk_engine::attestation::types::KernelAttestation;
use crate::zk_engine::ZKError;

impl RemoteAttestationClient {
    pub fn verify_remote_attestation(
        &self,
        attestation: &KernelAttestation,
    ) -> Result<bool, ZKError> {
        if !self.trusted_keys.contains(&attestation.public_key) {
            return Ok(false);
        }

        let current_time = crate::time::timestamp_millis();
        let max_age_ms = 300_000;
        if current_time > attestation.timestamp + max_age_ms {
            return Ok(false);
        }

        AttestationManager::verify_attestation(attestation)
    }
}
