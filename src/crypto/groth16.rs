//! Groth16 verifier (BN254 via arkworks) 

#![cfg(feature = "zk-groth16")]

extern crate alloc;
use alloc::vec::Vec;
use core::fmt;

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;

const MAX_VK_BYTES: usize = 16 * 1024 * 1024;    // 16 MiB
const MAX_PROOF_BYTES: usize = 1 * 1024 * 1024;  // 1 MiB
const MAX_PUBLIC_INPUTS: usize = 1 << 20;

#[derive(Debug)]
pub enum Groth16Error {
    Deserialize(&'static str),
    SizeLimit(&'static str),
    InvalidPublicInput,
    VerifyFailed,
}

impl fmt::Display for Groth16Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Groth16Error::Deserialize(m) => write!(f, "deserialize error: {}", m),
            Groth16Error::SizeLimit(m) => write!(f, "size exceeds limit: {}", m),
            Groth16Error::InvalidPublicInput => write!(f, "invalid public input"),
            Groth16Error::VerifyFailed => write!(f, "proof verification failed"),
        }
    }
}

fn read_vk(vk_bytes: &[u8]) -> Result<VerifyingKey<Bn254>, Groth16Error> {
    if vk_bytes.len() > MAX_VK_BYTES {
        return Err(Groth16Error::SizeLimit("verifying key"));
    }
    VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes)
        .or_else(|_| VerifyingKey::<Bn254>::deserialize_uncompressed(vk_bytes))
        .map_err(|_| Groth16Error::Deserialize("verifying key"))
}

fn read_proof(proof_bytes: &[u8]) -> Result<Proof<Bn254>, Groth16Error> {
    if proof_bytes.len() > MAX_PROOF_BYTES {
        return Err(Groth16Error::SizeLimit("proof"));
    }
    Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .or_else(|_| Proof::<Bn254>::deserialize_uncompressed(proof_bytes))
        .map_err(|_| Groth16Error::Deserialize("proof"))
}

fn public_inputs_from_le_bytes(fr_le32: &[[u8; 32]]) -> Result<Vec<Fr>, Groth16Error> {
    if fr_le32.len() > MAX_PUBLIC_INPUTS {
        return Err(Groth16Error::SizeLimit("public inputs"));
    }
    let mut res = Vec::with_capacity(fr_le32.len());
    for bytes in fr_le32 {
        res.push(Fr::from_le_bytes_mod_order(bytes));
    }
    Ok(res)
}

/// Reusable Groth16 verifier (caches prepared VK).
pub struct Groth16Verifier {
    pvk: PreparedVerifyingKey<Bn254>,
    expected_inputs: usize,
}

impl Groth16Verifier {
    /// Construct verifier from serialized verifying key (compressed preferred).
    pub fn from_bytes(vk_bytes: &[u8]) -> Result<Self, Groth16Error> {
        let vk = read_vk(vk_bytes)?;
        let expected_inputs = vk.gamma_abc_g1.len().saturating_sub(1);
        let pvk = PreparedVerifyingKey::from(vk);
        Ok(Self { pvk, expected_inputs })
    }

    /// Number of expected public inputs.
    pub fn expected_public_inputs(&self) -> usize { self.expected_inputs }

    /// Verify a single proof with public inputs (Fr LE32).
    pub fn verify(&self, proof_bytes: &[u8], public_inputs_fr_le32: &[[u8; 32]]) -> Result<(), Groth16Error> {
        let pi = public_inputs_from_le_bytes(public_inputs_fr_le32)?;
        if pi.len() != self.expected_inputs {
            return Err(Groth16Error::InvalidPublicInput);
        }
        let proof = read_proof(proof_bytes)?;
        Groth16::<Bn254>::verify_with_processed_vk(&self.pvk, &pi, &proof)
            .map_err(|_| Groth16Error::VerifyFailed)
    }

    /// Verify multiple proofs sequentially (throughput-friendly).
    pub fn verify_many(&self, proofs: &[&[u8]], public_inputs_list: &[&[[u8; 32]]]) -> Result<(), Groth16Error> {
        if proofs.len() != public_inputs_list.len() {
            return Err(Groth16Error::InvalidPublicInput);
        }
        for (proof_bytes, pi_le) in proofs.iter().zip(public_inputs_list.iter()) {
            self.verify(proof_bytes, pi_le)?;
        }
        Ok(())
    }
}

/// One-shot verification (constructs verifier internally).
pub fn groth16_verify_bn254(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_fr_le32: &[[u8; 32]],
) -> Result<(), Groth16Error> {
    let verifier = Groth16Verifier::from_bytes(vk_bytes)?;
    verifier.verify(proof_bytes, public_inputs_fr_le32)
}
