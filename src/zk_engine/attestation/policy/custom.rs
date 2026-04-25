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

use crate::zk_engine::attestation::manager::AttestationManager;
use crate::zk_engine::attestation::types::KernelAttestation;
use crate::zk_engine::ZKError;
use alloc::{string::String, vec::Vec};

pub(super) fn verify_custom(
    attestation: &KernelAttestation,
    require_zk_proof: bool,
    max_age_seconds: u64,
    required_modules: &[String],
) -> Result<bool, ZKError> {
    if require_zk_proof && attestation.zk_proof.is_none() {
        return Ok(false);
    }

    let current_time = crate::time::timestamp_millis();
    if current_time - attestation.timestamp > (max_age_seconds * 1000) {
        return Ok(false);
    }

    let module_names: Vec<String> =
        attestation.measurement.module_hashes.iter().map(|m| m.name.clone()).collect();

    for required in required_modules {
        if !module_names.contains(required) {
            return Ok(false);
        }
    }

    AttestationManager::verify_attestation(attestation)
}
