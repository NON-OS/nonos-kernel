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

extern crate alloc;

use super::types::{
    CircuitCategory, CircuitSectionHeader, DynamicCircuitEntry, CIRCUIT_SECTION_MAGIC,
};
use crate::zk::verify::ct_eq32;
use alloc::vec::Vec;
use core::mem::size_of;

pub fn parse_circuit_section(
    section: &[u8],
    verify_signature: bool,
    trusted_signers: &[[u8; 32]],
) -> Result<Vec<DynamicCircuitEntry>, &'static str> {
    if section.len() < size_of::<CircuitSectionHeader>() {
        return Err("circuit: section too small");
    }

    let magic = &section[0..4];
    if magic != CIRCUIT_SECTION_MAGIC {
        return Err("circuit: invalid magic");
    }

    let version = u32::from_le_bytes(
        section[4..8]
            .try_into()
            .map_err(|_| "circuit: version parse failed")?,
    );
    if version != 1 {
        return Err("circuit: unsupported version");
    }

    let count = u32::from_le_bytes(
        section[8..12]
            .try_into()
            .map_err(|_| "circuit: count parse failed")?,
    ) as usize;

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&section[16..80]);

    let mut signer = [0u8; 32];
    signer.copy_from_slice(&section[80..112]);
    if verify_signature {
        let mut trusted = false;
        for ts in trusted_signers {
            if ct_eq32(ts, &signer) {
                trusted = true;
                break;
            }
        }
        if !trusted {
            return Err("circuit: untrusted signer");
        }

        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let verifying_key =
            VerifyingKey::from_bytes(&signer).map_err(|_| "circuit: invalid signer public key")?;

        let sig = Signature::from_bytes(&signature);
        let mut signed_data = Vec::with_capacity(section.len() - 64);
        signed_data.extend_from_slice(&section[0..16]);
        signed_data.extend_from_slice(&section[80..]);

        verifying_key
            .verify(&signed_data, &sig)
            .map_err(|_| "circuit: signature verification failed")?;
    }

    let mut entries = Vec::with_capacity(count);
    let mut offset = 112;
    for _ in 0..count {
        if offset + 48 > section.len() {
            return Err("circuit: truncated entry");
        }

        let mut program_hash = [0u8; 32];
        program_hash.copy_from_slice(&section[offset..offset + 32]);
        offset += 32;

        let permissions = u32::from_le_bytes(
            section[offset..offset + 4]
                .try_into()
                .map_err(|_| "circuit: permissions parse failed")?,
        );
        offset += 4;

        let category_byte = section[offset];
        let category = match category_byte {
            0 => CircuitCategory::System,
            1 => CircuitCategory::Community,
            2 => CircuitCategory::User,
            _ => return Err("circuit: invalid category"),
        };
        offset += 1;

        let name_len = section[offset] as usize;
        offset += 1;
        let version_len = section[offset] as usize;
        offset += 1;
        offset += 1;
        let vk_offset = u32::from_le_bytes(
            section[offset..offset + 4]
                .try_into()
                .map_err(|_| "circuit: vk_offset parse failed")?,
        ) as usize;
        offset += 4;
        let vk_len = u32::from_le_bytes(
            section[offset..offset + 4]
                .try_into()
                .map_err(|_| "circuit: vk_len parse failed")?,
        ) as usize;
        offset += 4;

        if offset + name_len + version_len > section.len() {
            return Err("circuit: truncated strings");
        }
        let name = section[offset..offset + name_len].to_vec();
        offset += name_len;
        offset += version_len;

        if vk_offset + vk_len > section.len() {
            return Err("circuit: VK out of bounds");
        }
        let vk_bytes = section[vk_offset..vk_offset + vk_len].to_vec();
        entries.push(DynamicCircuitEntry {
            program_hash,
            vk_bytes,
            name,
            permissions,
            category,
            loaded_at: 0,
        });
    }

    Ok(entries)
}
