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

/*
 * NONOS Cryptographic Subsystem.
 *
 * Provides all cryptographic primitives for the operating system:
 *
 * Symmetric: AES-128/256, ChaCha20-Poly1305, AES-GCM
 * Asymmetric: Ed25519, Curve25519/X25519, secp256k1, RSA, P-256
 * Hash: SHA-256, SHA-512, SHA-3, BLAKE3, HMAC
 * Post-Quantum: ML-KEM (Kyber), ML-DSA (Dilithium), SPHINCS+, NTRU, McEliece
 * Zero-Knowledge: Schnorr proofs, PLONK, Groth16, Halo2
 *
 * All implementations are constant-time where required. Key generation
 * uses aggressive entropy collection from 12+ sources to ensure unique
 * keys even in virtualized or deterministic environments.
 */

#![allow(clippy::too_many_arguments)]

extern crate alloc;

pub mod application;
pub mod asymmetric;
pub mod core;
pub mod error;
pub mod hash;
pub mod pqc;
pub mod random_api;
pub mod symmetric;
pub mod util;
pub mod zk;
pub mod zk_kernel;

pub use error::{CryptoError, CryptoResult};
pub use random_api as random;

pub use util::bigint;
pub use util::constant_time;
pub use util::entropy;
pub use util::hmac;
pub use util::rng;

pub use symmetric::aes;
pub use symmetric::aes_gcm;
pub use symmetric::chacha20poly1305;

pub use hash::blake3;
pub use hash::sha3;
pub use hash::sha512;

pub use hash::{hkdf_expand, hmac_sha256, hmac_verify, sha256, Hash256, Hash512};
pub use hash::{Keccak256, Sha3_256, Sha3_512, Shake128, Shake256};
pub use hash::sha3::{keccak256, sha3_256, sha3_512, shake128, shake256};
pub use hash::blake3::{
    blake3_derive_key, blake3_hash, blake3_hash as hash_blake3_hash,
    blake3_hash_xof, blake3_keyed_hash, Hasher as Blake3Hasher,
};

pub use rng::{fill_random_bytes, get_random_bytes, random_u32};

pub use symmetric::aes::{Aes128, Aes256, BLOCK_SIZE as AES_BLOCK_SIZE};
pub use symmetric::chacha20poly1305::{
    aead_decrypt as chacha20poly1305_decrypt, aead_encrypt as chacha20poly1305_encrypt,
};
pub use symmetric::aes_gcm::{aes256_gcm_decrypt, aes256_gcm_encrypt};

pub use asymmetric::ed25519::{
    sign, verify, verify as verify_ed25519, KeyPair, Signature,
};
pub use asymmetric::{curve25519, ed25519, p256, rsa, secp256k1};

#[cfg(any(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
pub use pqc::kyber;
#[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
pub use pqc::dilithium;
pub use pqc::mceliece;
pub use pqc::ntru;
pub use pqc::quantum;
pub use pqc::sphincs;

pub use zk::nonos_zk;

#[cfg(feature = "zk-halo2")]
pub use zk::halo2::{halo2_verify, Halo2Error, Halo2Verifier};
#[cfg(feature = "zk-groth16")]
pub use zk::groth16::{groth16_verify_bn254, Groth16Error, Groth16Verifier};

pub use zk_kernel::{
    plonk_prove, plonk_verify, syscall_zk_commit, syscall_zk_prove_plonk,
    syscall_zk_prove_schnorr, syscall_zk_verify, zeroize as zk_zeroize,
    EqualityProof, FieldElement, KernelZkVerifier, MembershipProof,
    PedersenCommitment, PlonkCircuit, PlonkEvaluations, PlonkProof,
    ProofSystem, SchnorrProof, SigmaProof, ZkError, ZkResult,
    KERNEL_ZK_VERIFIER,
};

pub use zk::nonos_zk::{
    commit, commit_u64, create_attestation, issue_credential, verify_attestation,
    verify_commitment, verify_credential, zeroize_array, zeroize_mut,
    AttestationProof, Credential,
};

pub use application::certification;
pub use application::ethereum;
pub use application::nonos_signing;
pub use application::vault;

pub use core::aead::{
    aead_unwrap, aead_wrap, Aead, Aes256GcmAead, Chacha20Poly1305Aead,
};
pub use core::api::{
    ed25519_verify, estimate_entropy, feature_summary, fill_random,
    generate_keypair, generate_plonk_proof, generate_secure_key,
    hash_memory_region, hkdf_expand_labeled, init, init_crypto_subsystem,
    secure_erase_memory_region, secure_random_u32, secure_random_u64,
    secure_random_u8, secure_zero, sig, verify_plonk_proof, verify_signature,
    SignatureAlgorithm,
};
pub use core::syscall::{
    sha256_hash, sha512_hash, sign_message, syscall_blake3_hash,
    verify_signature_syscall, SyscallCryptoError,
};
pub use core::traits::{Ed25519Sig, Kem, Sig};
#[cfg(any(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
pub use core::traits::KyberKem;
#[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
pub use core::traits::DilithiumSig;

#[cfg(any(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
pub use kyber::{
    kyber_decaps, kyber_deserialize_ciphertext, kyber_deserialize_public_key,
    kyber_deserialize_secret_key, kyber_encaps, kyber_keygen,
    kyber_serialize_ciphertext, kyber_serialize_public_key,
    kyber_serialize_secret_key, KyberCiphertext, KyberKeyPair,
    KyberPublicKey, KyberSecretKey, CIPHERTEXT_BYTES as KYBER_CT_BYTES,
    KYBER_PARAM_NAME, PUBLICKEY_BYTES as KYBER_PUB_BYTES,
    SECRETKEY_BYTES as KYBER_SK_BYTES,
};

#[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
pub use dilithium::{
    dilithium_deserialize_public_key, dilithium_deserialize_secret_key,
    dilithium_deserialize_signature, dilithium_keypair,
    dilithium_serialize_public_key, dilithium_serialize_secret_key,
    dilithium_serialize_signature, dilithium_sign, dilithium_verify,
    DilithiumKeyPair, DilithiumPublicKey, DilithiumSecretKey,
    DilithiumSignature, D_PARAM_NAME, PUBLICKEY_BYTES as DILITHIUM_PUB_BYTES,
    SECRETKEY_BYTES as DILITHIUM_SK_BYTES, SIGNATURE_BYTES as DILITHIUM_SIG_BYTES,
};
