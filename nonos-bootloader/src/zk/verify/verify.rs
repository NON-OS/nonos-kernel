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

use crate::zk::binding::{compute_commit, select_binding};
use crate::zk::errors::ZkError;

use super::constants::{MAX_INPUT_SIZE, MAX_PROOF_SIZE};
use super::types::{ZkProof, ZkVerifyResult};

#[cfg(feature = "zk-groth16")]
use super::constants::GROTH16_PROOF_LEN;
#[cfg(feature = "zk-groth16")]
use super::groth16::groth16_verify;
#[cfg(feature = "zk-groth16")]
use crate::zk::registry;
#[cfg(feature = "zk-zeroize")]
use zeroize::Zeroize;
/// Constant-time 32-byte comparison
#[inline]
pub fn ct_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut x = 0u8;
    for i in 0..32 {
        x |= a[i] ^ b[i];
    }
    x == 0
}

pub fn verify_proof(p: &mut ZkProof) -> ZkVerifyResult {
    if p.proof_blob.len() > MAX_PROOF_SIZE {
        return ZkVerifyResult::Unsupported(ZkError::ProofTooLarge.as_str());
    }
    if p.public_inputs.len() > MAX_INPUT_SIZE {
        return ZkVerifyResult::Unsupported(ZkError::InputsTooLarge.as_str());
    }
    if p.public_inputs.len() % 32 != 0 {
        return ZkVerifyResult::Invalid(ZkError::InputsMisaligned.as_str());
    }

    #[cfg(feature = "zk-groth16")]
    {
        if p.proof_blob.len() != GROTH16_PROOF_LEN {
            return ZkVerifyResult::Invalid(ZkError::ProofSizeInvalid.as_str());
        }
    }

    let binding = match select_binding(&p.public_inputs, p.manifest.as_deref()) {
        Ok(b) => b,
        Err(e) => return ZkVerifyResult::Invalid(e),
    };
    let local_commit = compute_commit(binding);
    if !ct_eq32(&local_commit, &p.capsule_commitment) {
        return ZkVerifyResult::Invalid(ZkError::CommitmentMismatch.as_str());
    }

    #[cfg(feature = "zk-groth16")]
    {
        let vk_bytes = match registry::lookup(&p.program_hash) {
            Some(v) if !v.is_empty() => v,
            Some(_) => return ZkVerifyResult::Error(ZkError::VerifyingKeyEmpty.as_str()),
            None => return ZkVerifyResult::Unsupported(ZkError::UnknownProgramHash.as_str()),
        };

        match groth16_verify(vk_bytes, &p.proof_blob, &p.public_inputs) {
            Ok(true) => {
                zeroize_if(p);
                ZkVerifyResult::Valid
            }
            Ok(false) => {
                zeroize_if(p);
                ZkVerifyResult::Invalid(ZkError::BackendVerifyFailed.as_str())
            }
            Err(e) => {
                zeroize_if(p);
                ZkVerifyResult::Error(e.as_str())
            }
        }
    }

    #[cfg(not(feature = "zk-groth16"))]
    {
        zeroize_if(p);
        ZkVerifyResult::Unsupported(ZkError::BackendUnsupported.as_str())
    }
}

/// ## if feature enabled then zeroize
#[cfg(feature = "zk-zeroize")]
fn zeroize_if(p: &mut ZkProof) {
    p.proof_blob.zeroize();
    p.public_inputs.zeroize();
    if let Some(m) = &mut p.manifest {
        m.zeroize();
    }
}

/// ## No-op when zeroize not enabled
#[cfg(not(feature = "zk-zeroize"))]
fn zeroize_if(_p: &mut ZkProof) {}

pub fn derive_program_hash(program_id_bytes: &[u8]) -> [u8; 32] {
    use super::constants::DS_PROGRAM_HASH;
    let mut h = blake3::Hasher::new_derive_key(DS_PROGRAM_HASH);
    h.update(program_id_bytes);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn mk_base_proof() -> ZkProof {
        ZkProof {
            program_hash: [0u8; 32],
            capsule_commitment: [0u8; 32],
            public_inputs: vec![0u8; 32],
            proof_blob: vec![0u8; 0],
            manifest: None,
        }
    }

    #[test]
    fn size_cap_inputs() {
        let mut p = mk_base_proof();
        p.public_inputs = vec![0u8; MAX_INPUT_SIZE + 32];
        let r = verify_proof(&mut p);
        assert!(matches!(r, ZkVerifyResult::Unsupported(_)));
    }

    #[test]
    fn misaligned_inputs() {
        let mut p = mk_base_proof();
        p.public_inputs = vec![0u8; 31];
        let r = verify_proof(&mut p);
        assert!(matches!(r, ZkVerifyResult::Invalid(_)));
    }

    #[test]
    fn commitment_mismatch() {
        let mut p = mk_base_proof();
        p.capsule_commitment[0] = 1;
        let r = verify_proof(&mut p);
        assert!(matches!(r, ZkVerifyResult::Invalid(_)));
    }
}

#[cfg(test)]
extern crate alloc;
