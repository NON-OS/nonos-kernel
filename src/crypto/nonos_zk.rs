//! NONOS ZK 

#![allow(clippy::result_unit_err)]

extern crate alloc;
use alloc::vec::Vec;
use core::ptr;

use crate::crypto::hash::{blake3_hash, sha256};
use crate::crypto::rng::{get_random_bytes, random_u64};
use crate::crypto::ed25519::{KeyPair, Signature as EdSig, sign as ed25519_sign, verify as ed25519_verify};

// Domain separation tags
const DOM_ATTEST: &[u8] = b"NONOS_ATTEST_V1";
const DOM_COMMIT: &[u8] = b"NONOS_COMMIT_V1";
const DOM_CRED:   &[u8] = b"NONOS_CRED_V1";

// ------------------------ Attestations ------------------------

#[repr(C)]
#[derive(Clone, Copy)]
#[derive(Debug)]
pub struct AttestationProof {
    pub msg_hash: [u8; 32],   // SHA-256(message)
    pub nonce:    [u8; 32],   // 256-bit random nonce
    pub signature: [u8; 64],  // Ed25519 signature over transcript
    pub pubkey:    [u8; 32],  // Ed25519 public key of signer (for transport/debug)
}

/// Create an attestation over arbitrary data using Ed25519.
///
/// Transcript M = DOM_ATTEST || msg_hash || nonce
pub fn create_attestation(data: &[u8], keypair: &KeyPair) -> AttestationProof {
    let msg_hash = sha256(data);
    let nonce = get_random_bytes();

    let mut t = Vec::with_capacity(DOM_ATTEST.len() + 32 + 32);
    t.extend_from_slice(DOM_ATTEST);
    t.extend_from_slice(&msg_hash);
    t.extend_from_slice(&nonce);

    let sig = ed25519_sign(keypair, &t).to_bytes();

    // zeroize transcript buffer
    for b in t.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }

    AttestationProof {
        msg_hash,
        nonce,
        signature: sig,
        pubkey: keypair.public,
    }
}

/// Verify an attestation given the data, expected signer public key, and proof.
///
/// IMPORTANT: do not trust the public key embedded in the proof for authorization.
/// Always provide and enforce the expected_pubkey of the intended signer.
///
/// Checks:
/// - msg_hash matches SHA-256(data)
/// - proof.pubkey equals expected_pubkey (transport sanity)
/// - Ed25519 signature over transcript M = DOM_ATTEST || msg_hash || nonce with expected_pubkey
pub fn verify_attestation(
    data: &[u8],
    expected_pubkey: &[u8; 32],
    proof: &AttestationProof,
) -> bool {
    if sha256(data) != proof.msg_hash {
        return false;
    }
    if &proof.pubkey != expected_pubkey {
        return false;
    }

    let mut t = Vec::with_capacity(DOM_ATTEST.len() + 32 + 32);
    t.extend_from_slice(DOM_ATTEST);
    t.extend_from_slice(&proof.msg_hash);
    t.extend_from_slice(&proof.nonce);

    let sig = EdSig::from_bytes(&proof.signature);
    let ok = ed25519_verify(expected_pubkey, &t, &sig);

    // zeroize transcript buffer
    for b in t.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }

    ok
}

// ------------------------ Commitments ------------------------
//
// Hash-based commitment (binding and hiding if randomness is secret):
// C = BLAKE3(DOM_COMMIT || len(value) || value || nonce)
//

/// Commit to an arbitrary value with 32-byte randomness (nonce).
pub fn commit(value: &[u8], nonce32: &[u8; 32]) -> [u8; 32] {
    let mut t = Vec::with_capacity(DOM_COMMIT.len() + 8 + value.len() + 32);
    t.extend_from_slice(DOM_COMMIT);
    t.extend_from_slice(&(value.len() as u64).to_le_bytes());
    t.extend_from_slice(value);
    t.extend_from_slice(nonce32);
    let c = blake3_hash(&t);

    // zeroize transcript buffer
    for b in t.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }
    c
}

/// Verify a commitment against a value and nonce.
pub fn verify_commitment(commitment: &[u8; 32], value: &[u8], nonce32: &[u8; 32]) -> bool {
    &commit(value, nonce32) == commitment
}

/// Convenience: commit to a u64 in little-endian.
pub fn commit_u64(value: u64, nonce32: &[u8; 32]) -> [u8; 32] {
    commit(&value.to_le_bytes(), nonce32)
}

// ------------------------ Credentials (Issuer-signed) ------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Credential {
    pub id: [u8; 32],           // identifier derived from contents
    pub subject_pubkey: [u8; 32],
    pub attrs_hash: [u8; 32],   // BLAKE3(attributes)
    pub timestamp: u64,         // caller-provided (e.g., UNIX seconds)
    pub signature: [u8; 64],    // Ed25519 over transcript digest
    pub issuer_pubkey: [u8; 32],
}

impl Credential {
    fn transcript_digest(&self) -> [u8; 32] {
        // H = BLAKE3(DOM_CRED || id || subject_pubkey || attrs_hash || timestamp_le)
        let mut t = Vec::with_capacity(DOM_CRED.len() + 32 + 32 + 32 + 8);
        t.extend_from_slice(DOM_CRED);
        t.extend_from_slice(&self.id);
        t.extend_from_slice(&self.subject_pubkey);
        t.extend_from_slice(&self.attrs_hash);
        t.extend_from_slice(&self.timestamp.to_le_bytes());
        let h = blake3_hash(&t);
        // zeroize t
        for b in t.iter_mut() {
            unsafe { ptr::write_volatile(b, 0) };
        }
        h
    }
}

/// Issue a credential from an issuer Ed25519 keypair to a subject public key and attributes.
pub fn issue_credential(
    issuer: &KeyPair,
    subject_pubkey: &[u8; 32],
    attributes: &[u8],
    timestamp: u64,
) -> Credential {
    let attrs_hash = blake3_hash(attributes);

    // deterministically derive an ID from subject, attrs_hash, and timestamp with extra randomness
    let mut id_t = Vec::with_capacity(32 + 32 + 8 + 16);
    id_t.extend_from_slice(subject_pubkey);
    id_t.extend_from_slice(&attrs_hash);
    id_t.extend_from_slice(&timestamp.to_le_bytes());
    // add 16 bytes of randomness to prevent collisions under identical inputs
    id_t.extend_from_slice(&random_u64().to_le_bytes());
    id_t.extend_from_slice(&random_u64().to_le_bytes());
    let id = blake3_hash(&id_t);
    for b in id_t.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }

    let mut cred = Credential {
        id,
        subject_pubkey: *subject_pubkey,
        attrs_hash,
        timestamp,
        signature: [0u8; 64],
        issuer_pubkey: issuer.public,
    };

    // Sign transcript digest
    let digest = cred.transcript_digest();
    let sig = ed25519_sign(issuer, &digest).to_bytes();
    cred.signature = sig;

    // zeroize digest copy
    let mut d = [0u8; 32];
    d.copy_from_slice(&digest);
    for b in d.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }

    cred
}

/// Verify a credential using the issuer's public key embedded in the credential.
///
/// Callers should also separately authorize issuer_pubkey against a trusted root or allowlist.
pub fn verify_credential(cred: &Credential) -> bool {
    let digest = cred.transcript_digest();
    let sig = EdSig::from_bytes(&cred.signature);
    let ok = ed25519_verify(&cred.issuer_pubkey, &digest, &sig);

    // zeroize digest copy
    let mut d = [0u8; 32];
    d.copy_from_slice(&digest);
    for b in d.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }

    ok
}

// ------------------------ Range proofs via ZK (verification shims) ------------------------
//
// Halo2 or Groth16 circuits to prove ranges, relations, etc.
// We only provide verification wrappers here. Proof generation belongs to host tools.

// Halo2 (KZG/Bn256), host-only
#[cfg(feature = "zk-halo2")]
pub mod halo2_range {
    extern crate alloc;
    use alloc::vec::Vec;

    use crate::crypto::halo2::{Halo2Error, halo2_verify_kzg_bn256};

    /// Verify a Halo2 proof using KZG/Bn256 (Blake2b transcript) with per-column public inputs.
    /// - params_bytes: serialized ParamsKZG::<Bn256>
    /// - vk_bytes:     serialized VerifyingKey::<G1Affine>
    /// - proof_bytes:  transcript-encoded proof
    /// - public_inputs_columns_le32: &[&[[u8; 32]]], each inner slice is one instance column of Fr (LE32)
    pub fn verify(
        params_bytes: &[u8],
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        public_inputs_columns_le32: &[&[[u8; 32]]],
    ) -> Result<(), Halo2Error> {
        halo2_verify_kzg_bn256(params_bytes, vk_bytes, proof_bytes, public_inputs_columns_le32)
    }

    /// Helper to convert a single public input vector into one-column layout.
    pub fn single_column(inputs_le32: &[[u8; 32]]) -> [&[[u8; 32]]; 1] {
        [inputs_le32]
    }
}

// Groth16 (BN254), host-only
#[cfg(feature = "zk-groth16")]
pub mod groth16_range {
    use crate::crypto::groth16::{Groth16Error, groth16_verify_bn254};

    /// Verify a Groth16 proof over BN254.
    /// - vk_bytes: canonical serialized verifying key (compressed or uncompressed)
    /// - proof_bytes: canonical serialized proof (compressed or uncompressed)
    /// - public_inputs_fr_le32: list of 32-byte LE encodings of Fr public inputs
    pub fn verify(
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        public_inputs_fr_le32: &[[u8; 32]],
    ) -> Result<(), Groth16Error> {
        groth16_verify_bn254(vk_bytes, proof_bytes, public_inputs_fr_le32)
    }
}

// ------------------------ Utilities ------------------------

/// Wipe a mutable slice using volatile writes.
#[inline(always)]
pub fn zeroize_mut(buf: &mut [u8]) {
    for b in buf {
        unsafe { ptr::write_volatile(b, 0) };
    }
}

/// Wipe a fixed array by value (returns a zeroed clone).
#[inline(always)]
pub fn zeroize_array<const N: usize>(mut a: [u8; N]) -> [u8; N] {
    for b in a.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }
    [0u8; N]
}

// ------------------------ Tests (host-only) ------------------------

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn attest_roundtrip() {
        let kp = KeyPair::from_seed([7u8; 32]);
        let data = b"attest test";
        let proof = create_attestation(data, &kp);
        assert!(verify_attestation(data, &kp.public, &proof));

        // tamper: wrong signer
        let other = KeyPair::from_seed([8u8; 32]);
        assert!(!verify_attestation(data, &other.public, &proof));
    }

    #[test]
    fn commit_roundtrip() {
        let v = b"secret";
        let r = get_random_bytes();
        let c = commit(v, &r);
        assert!(verify_commitment(&c, v, &r));

        // tamper
        let mut rr = r;
        rr[0] ^= 1;
        assert!(!verify_commitment(&c, v, &rr));
    }

    #[test]
    fn credential_roundtrip() {
        let issuer = KeyPair::from_seed([9u8; 32]);
        let subject = KeyPair::from_seed([1u8; 32]);
        let attrs = b"anon cred attrs";
        let cred = issue_credential(&issuer, &subject.public, attrs, 123456789);
        assert!(verify_credential(&cred));

        // tamper signature
        let mut bad = cred;
        bad.signature[1] ^= 1;
        assert!(!verify_credential(&bad));
    }
}
