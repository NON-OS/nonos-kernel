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
use alloc::vec::Vec;

use crate::crypto::util::rng;
use crate::crypto::asymmetric::ed25519;
use crate::crypto::hash;

#[derive(Debug, Clone, Copy)]
pub enum SignatureAlgorithm {
    Ed25519,
    EcdsaP256,
    Rsa2048,
}

pub fn secure_random_u32() -> u32 {
    let mut bytes = [0u8; 4];
    rng::fill_random_bytes(&mut bytes);
    u32::from_le_bytes(bytes)
}

pub fn estimate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * log2_approx(p);
        }
    }

    entropy
}

fn log2_approx(x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    let bits = x.to_bits();
    let exp = ((bits >> 52) & 0x7FF) as i64 - 1023;
    let mantissa = f64::from_bits((bits & 0x000F_FFFF_FFFF_FFFF) | 0x3FF0_0000_0000_0000);
    let log2_mantissa = (mantissa - 1.0) * (2.0 - 0.333333 * (mantissa - 1.0));
    exp as f64 + log2_mantissa
}

pub fn generate_keypair(algorithm: SignatureAlgorithm) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            let keypair = ed25519::KeyPair::generate();
            Ok((keypair.public.to_vec(), keypair.private.to_vec()))
        },
        SignatureAlgorithm::EcdsaP256 => {
            let (sk, pk) = crate::crypto::asymmetric::p256::generate_keypair();
            Ok((pk.to_vec(), sk.to_vec()))
        },
        SignatureAlgorithm::Rsa2048 => {
            match crate::crypto::asymmetric::rsa::generate_keypair_with_bits(2048) {
                Ok((public_key, private_key)) => {
                    let pk = public_key.n.to_bytes_be();
                    let sk = private_key.d.to_bytes_be();
                    Ok((pk, sk))
                },
                Err(_) => Err("RSA key generation failed"),
            }
        },
    }
}

pub fn ed25519_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, &'static str> {
    if pk.len() != 32 || sig.len() != 64 {
        return Ok(false);
    }
    let mut pk_array = [0u8; 32];
    let mut sig_array = [0u8; 64];
    pk_array.copy_from_slice(pk);
    sig_array.copy_from_slice(sig);
    let sig_obj = ed25519::Signature::from_bytes(&sig_array);
    Ok(ed25519::verify(&pk_array, msg, &sig_obj))
}

pub mod sig {
    pub use super::{generate_keypair, SignatureAlgorithm, ed25519_verify};

    pub mod ed25519 {
        pub use crate::crypto::asymmetric::ed25519::{verify as verify_signature, Signature as Ed25519Signature};
        pub fn scalar_mult_base(scalar: &[u8; 32]) -> Result<[u8; 32], &'static str> {
            let kp = crate::crypto::asymmetric::ed25519::KeyPair::from_seed(*scalar);
            Ok(kp.public)
        }
    }
}

pub fn init_crypto_subsystem() -> Result<(), &'static str> {
    rng::init_rng();
    Ok(())
}

pub fn generate_plonk_proof(witness: &[u8]) -> Result<Vec<u8>, &'static str> {
    if witness.len() < 64 {
        return Err("Witness must contain at least 2 field elements");
    }
    let num_elements = witness.len() / 32;
    let mut elements = Vec::with_capacity(num_elements);
    for i in 0..num_elements {
        let mut elem = [0u8; 32];
        elem.copy_from_slice(&witness[i * 32..(i + 1) * 32]);
        elements.push(elem);
    }
    match crate::crypto::zk::zk_kernel::plonk_prove(&elements) {
        Ok(proof) => Ok(proof.to_bytes()),
        Err(e) => Err(e),
    }
}

pub fn verify_plonk_proof(proof: &[u8], public_inputs: &[u8]) -> bool {
    let plonk_proof = match crate::crypto::zk::zk_kernel::PlonkProof::from_bytes(proof) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let num_inputs = public_inputs.len() / 32;
    let mut inputs = Vec::with_capacity(num_inputs);
    for i in 0..num_inputs {
        let mut inp = [0u8; 32];
        inp.copy_from_slice(&public_inputs[i * 32..(i + 1) * 32]);
        inputs.push(inp);
    }
    crate::crypto::zk::zk_kernel::plonk_verify(&plonk_proof, &inputs)
}

pub fn fill_random(buf: &mut [u8]) {
    rng::fill_random_bytes(buf);
}

pub fn generate_secure_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rng::fill_random_bytes(&mut key);
    key
}

const MAX_MEMORY_REGION_SIZE: usize = 16 * 1024 * 1024;

const MIN_VALID_ADDR: usize = 0x1000;

pub fn hash_memory_region(start_addr: usize, size: usize, out: &mut [u8; 32]) -> Result<(), &'static str> {
    if start_addr < MIN_VALID_ADDR {
        return Err("Invalid address: null or low memory");
    }

    if size == 0 {
        return Err("Invalid size: zero");
    }
    if size > MAX_MEMORY_REGION_SIZE {
        return Err("Invalid size: exceeds maximum allowed region");
    }

    let end_addr = start_addr.checked_add(size).ok_or("Address overflow")?;
    if end_addr < start_addr {
        return Err("Address overflow");
    }

    // SAFETY: We've validated:
    // - start_addr >= MIN_VALID_ADDR (not null)
    // - size > 0 and size <= MAX_MEMORY_REGION_SIZE
    // - No address overflow
    // Caller must still ensure the memory region is mapped and readable
    let data = unsafe { core::slice::from_raw_parts(start_addr as *const u8, size) };
    *out = hash::sha256(data);
    Ok(())
}

pub fn secure_zero(data: &mut [u8]) {
    for byte in data.iter_mut() {
        // SAFETY: Using volatile write to prevent optimizer from removing the zeroing
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
}

pub fn secure_erase_memory_region(start_addr: usize, size: usize) -> Result<(), &'static str> {
    if start_addr < MIN_VALID_ADDR {
        return Err("Invalid address: null or low memory");
    }

    if size == 0 {
        return Err("Invalid size: zero");
    }
    if size > MAX_MEMORY_REGION_SIZE {
        return Err("Invalid size: exceeds maximum allowed region");
    }

    let end_addr = start_addr.checked_add(size).ok_or("Address overflow")?;
    if end_addr < start_addr {
        return Err("Address overflow");
    }

    // SAFETY: We've validated:
    // - start_addr >= MIN_VALID_ADDR (not null)
    // - size > 0 and size <= MAX_MEMORY_REGION_SIZE
    // - No address overflow
    // Caller must still ensure the memory region is mapped and writable
    let data = unsafe { core::slice::from_raw_parts_mut(start_addr as *mut u8, size) };
    secure_zero(data);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    Ok(())
}

pub fn secure_random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    rng::fill_random_bytes(&mut bytes);
    u64::from_le_bytes(bytes)
}

pub fn secure_random_u8() -> u8 {
    let mut bytes = [0u8; 1];
    rng::fill_random_bytes(&mut bytes);
    bytes[0]
}

pub fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    if signature.len() == 64 && public_key.len() == 32 {
        let mut sig_array = [0u8; 64];
        let mut key_array = [0u8; 32];
        sig_array.copy_from_slice(signature);
        key_array.copy_from_slice(public_key);

        let sig_struct = ed25519::Signature::from_bytes(&sig_array);
        ed25519::verify(&key_array, message, &sig_struct)
    } else {
        false
    }
}

pub fn hkdf_expand_labeled(
    prk: &crate::crypto::hash::Hash256,
    label: &[u8],
    context: &[u8],
    okm: &mut [u8]
) -> Result<(), crate::crypto::CryptoError> {
    let mut info = Vec::with_capacity(label.len() + context.len());
    info.extend_from_slice(label);
    info.extend_from_slice(context);
    crate::crypto::hash::hkdf_expand(prk, &info, okm).map_err(|_| crate::crypto::CryptoError::InvalidLength)
}

pub fn init() {
    rng::init_rng();
}

pub fn feature_summary() -> &'static str {
    #[cfg(feature = "mlkem512")] { return "kyber=512"; }
    #[cfg(feature = "mlkem768")] { return "kyber=768"; }
    #[cfg(feature = "mlkem1024")] { return "kyber=1024"; }
    "kyber=off"
}
