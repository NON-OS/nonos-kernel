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

#![allow(clippy::too_many_arguments)]

extern crate alloc;

pub mod application;
pub mod asymmetric;
pub mod core;
pub mod hash;
pub mod pqc;
pub mod symmetric;
pub mod util;
pub mod zk;

pub use util::constant_time;
pub use util::rng;
pub use util::entropy;
pub use util::hmac;
pub use util::bigint;

pub use symmetric::aes;
pub use symmetric::chacha20poly1305;
pub use symmetric::aes_gcm;

pub use hash::sha512;
pub use hash::sha3;
pub use hash::blake3;

pub use hash::{sha256, hmac_sha256, hmac_verify, hkdf_expand, Hash256};
pub use hash::Hash512;
pub use hash::{Sha3_256, Sha3_512, Shake128, Shake256, Keccak256};
pub use hash::sha3::{sha3_256, sha3_512, shake128, shake256, keccak256};
pub use hash::blake3::{blake3_hash, Hasher as Blake3Hasher, blake3_keyed_hash, blake3_derive_key, blake3_hash_xof};
pub use hash::blake3::blake3_hash as hash_blake3_hash;

pub use rng::{get_random_bytes, fill_random_bytes, random_u32};
pub use symmetric::aes::{Aes128, Aes256, BLOCK_SIZE as AES_BLOCK_SIZE};
pub use symmetric::chacha20poly1305::{aead_decrypt as chacha20poly1305_decrypt, aead_encrypt as chacha20poly1305_encrypt};
pub use symmetric::aes_gcm::{aes256_gcm_decrypt, aes256_gcm_encrypt};
pub use asymmetric::ed25519::{KeyPair, Signature, sign, verify, verify as verify_ed25519};
pub use asymmetric::{rsa, ed25519, curve25519, p256, secp256k1};

#[cfg(any(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
pub use pqc::kyber;
#[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
pub use pqc::dilithium;
pub use pqc::sphincs;
pub use pqc::ntru;
pub use pqc::mceliece;
pub use pqc::quantum;

pub use zk::zk_kernel;
pub use zk::nonos_zk;

#[cfg(feature = "zk-halo2")]
pub use zk::halo2::{Halo2Verifier, Halo2Error, halo2_verify};
#[cfg(feature = "zk-groth16")]
pub use zk::groth16::{Groth16Verifier, Groth16Error, groth16_verify_bn254};

pub use zk::zk_kernel::{
    FieldElement, PedersenCommitment, SchnorrProof, SigmaProof, RangeProof,
    EqualityProof, MembershipProof,
    PlonkProof, PlonkEvaluations, PlonkCircuit, plonk_prove, plonk_verify,
    KernelZkVerifier, KERNEL_ZK_VERIFIER, ZkResult, ProofSystem,
    ZkError, syscall_zk_verify, syscall_zk_commit, syscall_zk_prove_schnorr,
    syscall_zk_prove_plonk,
    zeroize as zk_zeroize,
};

pub use zk::nonos_zk::{
    AttestationProof, create_attestation, verify_attestation,
    commit, verify_commitment, commit_u64,
    Credential, issue_credential, verify_credential,
    zeroize_mut, zeroize_array,
};

pub use application::certification;
pub use application::vault;
pub use application::ethereum;
pub use application::nonos_signing;

pub use core::aead::{Aead, Chacha20Poly1305Aead, Aes256GcmAead, aead_wrap, aead_unwrap};
pub use core::api::{
    SignatureAlgorithm, secure_random_u32, estimate_entropy, generate_keypair, ed25519_verify,
    sig, init_crypto_subsystem, generate_plonk_proof, verify_plonk_proof, fill_random,
    generate_secure_key, hash_memory_region, secure_zero, secure_erase_memory_region,
    secure_random_u64, secure_random_u8, verify_signature, hkdf_expand_labeled, init,
    feature_summary,
};
pub use core::syscall::{SyscallCryptoError, syscall_blake3_hash, sha256_hash, sha512_hash, sign_message, verify_signature_syscall};
pub use core::traits::{Kem, Sig, Ed25519Sig};
#[cfg(any(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
pub use core::traits::KyberKem;
#[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
pub use core::traits::DilithiumSig;

#[cfg(any(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
pub use kyber::{
    KyberPublicKey, KyberSecretKey, KyberCiphertext, KyberKeyPair,
    kyber_keygen, kyber_encaps, kyber_decaps,
    kyber_serialize_public_key, kyber_deserialize_public_key,
    kyber_serialize_secret_key, kyber_deserialize_secret_key,
    kyber_serialize_ciphertext, kyber_deserialize_ciphertext,
    KYBER_PARAM_NAME, PUBLICKEY_BYTES as KYBER_PUB_BYTES,
    SECRETKEY_BYTES as KYBER_SK_BYTES, CIPHERTEXT_BYTES as KYBER_CT_BYTES,
};

#[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
pub use dilithium::{
    DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature, DilithiumKeyPair,
    dilithium_keypair, dilithium_sign, dilithium_verify,
    dilithium_serialize_public_key, dilithium_deserialize_public_key,
    dilithium_serialize_secret_key, dilithium_deserialize_secret_key,
    dilithium_serialize_signature, dilithium_deserialize_signature,
    D_PARAM_NAME, PUBLICKEY_BYTES as DILITHIUM_PUB_BYTES,
    SECRETKEY_BYTES as DILITHIUM_SK_BYTES, SIGNATURE_BYTES as DILITHIUM_SIG_BYTES,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    AeadTagMismatch,
    InvalidLength,
    KemError,
    SigError,
    InvalidInput,
    KeyNotFound,
    BufferTooSmall,
    VerificationFailed,
}

pub type CryptoResult<T> = Result<T, CryptoError>;
