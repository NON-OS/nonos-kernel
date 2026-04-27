// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::types::AttestationQuote;
use crate::security::attestation::pcr::DS_ATTESTATION;

impl AttestationQuote {
    pub fn compute_quote_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(DS_ATTESTATION);
        hasher.update(&self.nonce);
        hasher.update(&self.timestamp.to_le_bytes());
        for i in 0..self.pcr_count {
            hasher.update(&[self.pcr_values[i].0]);
            hasher.update(&self.pcr_values[i].1);
        }
        hasher.update(&self.kernel_hash);
        hasher.update(&self.bootloader_hash);
        hasher.update(&[self.zk_proof_verified as u8]);
        hasher.update(&[self.signature_verified as u8]);
        hasher.update(&self.program_hash);
        hasher.update(&self.capsule_commitment);
        *hasher.finalize().as_bytes()
    }
}
