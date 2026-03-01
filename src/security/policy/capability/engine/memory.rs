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

use alloc::format;

use crate::security::policy::capability::isolation::{IsolationLevel, SealedMemoryRegion};
use crate::security::policy::capability::attestation::AttestationLink;
use crate::security::policy::capability::types::Capability;

use super::types::CapabilityEngine;

impl CapabilityEngine {
    pub fn seal_memory_region(
        &self,
        chamber_id: u64,
        start_addr: u64,
        size: u64,
        protection: u32,
    ) -> Result<(), &'static str> {
        let chambers = self.chambers.read();
        let chamber = chambers.get(&chamber_id).ok_or("Chamber not found")?;

        let mut encryption_key = [0u8; 32];
        let mut integrity_hash = [0u8; 32];
        let mut access_pattern_hash = [0u8; 32];

        crate::crypto::fill_random(&mut encryption_key);
        crate::crypto::hash_memory_region(start_addr as usize, size as usize, &mut integrity_hash)?;
        crate::crypto::fill_random(&mut access_pattern_hash);

        let region = SealedMemoryRegion {
            start_addr,
            size,
            protection,
            encryption_key,
            integrity_hash,
            access_pattern_hash,
            sealed: true,
            ephemeral: matches!(
                chamber.level,
                IsolationLevel::Ephemeral | IsolationLevel::ZeroState
            ),
            quantum_locked: matches!(chamber.level, IsolationLevel::QuantumSecure),
        };

        chamber.sealed_memory_regions.write().push(region);
        Ok(())
    }

    pub fn create_attestation_chain(
        &self,
        chamber_id: u64,
        subject: [u8; 32],
        capabilities: &[Capability],
    ) -> Result<(), &'static str> {
        let chambers = self.chambers.read();
        let chamber = chambers.get(&chamber_id).ok_or("Chamber not found")?;

        let caps_bits = capabilities
            .iter()
            .fold(0u64, |acc, &cap| acc | (cap as u64));
        let timestamp = crate::time::get_kernel_time_ns();

        let mut nonce = [0u8; 16];
        crate::crypto::fill_random(&mut nonce);

        let _attestation_data = format!(
            "issuer:{:?},subject:{:?},caps:{},timestamp:{},nonce:{:?}",
            self.attestation_root, subject, caps_bits, timestamp, nonce
        );

        let mut signature = [0u8; 64];
        crate::crypto::fill_random(&mut signature[..32]);
        signature[32..].copy_from_slice(&self.signing_key);

        let quantum_proof = if matches!(chamber.level, IsolationLevel::QuantumSecure) {
            let mut proof = [0u8; 128];
            crate::crypto::fill_random(&mut proof);
            Some(proof)
        } else {
            None
        };

        let link = AttestationLink {
            issuer: self.attestation_root,
            subject,
            capabilities: caps_bits,
            timestamp,
            signature,
            quantum_proof,
            nonce,
        };

        chamber.attestation_chain.write().push(link);
        Ok(())
    }
}
