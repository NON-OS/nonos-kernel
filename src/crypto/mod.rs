//! NØNOS Crypto Module —

#![allow(clippy::too_many_arguments)]

extern crate alloc;
use alloc::vec::Vec;

// Core primitives
pub mod constant_time;
pub mod hash;
pub mod rng;
pub mod aes;
pub mod sha512;
pub mod chacha20poly1305;
pub mod aes_gcm;
pub mod ed25519;
pub mod sha3;
pub mod blake3;

// PQC: Kyber (ML-KEM) via PQClean
#[cfg(any(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
pub mod kyber;

// PQC: Dilithium (ML-DSA) via PQClean
#[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
pub mod dilithium;

// Host-only ZK verifiers
#[cfg(feature = "zk-halo2")]
pub mod halo2;
#[cfg(feature = "zk-groth16")]
pub mod groth16;

// NONOS ZK helpers (attestations, commitments, ZK shims)
pub mod nonos_zk;

// -----------------------------
// Back-compat re-exports (core)
// -----------------------------
// pub use constant_time::*;
pub use hash::{sha256, blake3_hash, hmac_sha256, hmac_verify, hkdf_expand, Hash256};
// pub use sha3::{Sha3_256, Sha3_512, Shake128, Shake256, sha3_256, sha3_512, shake128, shake256};
pub use rng::{get_random_bytes, fill_random_bytes, random_u32};
pub use aes::Aes256;
pub use sha512::{sha512, Hash512};
pub use chacha20poly1305::{aead_decrypt as chacha20poly1305_decrypt, aead_encrypt as chacha20poly1305_encrypt};
pub use aes_gcm::{aes256_gcm_decrypt, aes256_gcm_encrypt};
pub use ed25519::{KeyPair, Signature, sign, verify, verify as verify_ed25519};

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
            // log2(x) = ln(x) / ln(2) (no_std doesn't have log2)
            entropy -= p * 3.321928;
        }
    }
    
    entropy
}

#[derive(Debug, Clone, Copy)]
pub enum SignatureAlgorithm {
    Ed25519,
    EcdsaP256,
    Rsa2048,
}

pub fn generate_keypair(algorithm: SignatureAlgorithm) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            let keypair = crate::crypto::ed25519::KeyPair::generate();
            Ok((keypair.public.to_vec(), keypair.private.to_vec()))
        },
        _ => Err("Algorithm not implemented"),
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
    let sig_obj = crate::crypto::ed25519::Signature::from_bytes(&sig_array);
    Ok(crate::crypto::ed25519::verify(&pk_array, msg, &sig_obj))
}

// Signature verification module for compatibility
pub mod sig {
    pub use super::{generate_keypair, SignatureAlgorithm, ed25519_verify};
    
    pub mod ed25519 {
        pub use crate::crypto::ed25519::{verify as verify_signature, Signature as Ed25519Signature};
        
        pub fn scalar_mult_base(scalar: &[u8; 32]) -> Result<[u8; 32], &'static str> {
            let kp = crate::crypto::ed25519::KeyPair::from_seed(*scalar);
            Ok(kp.public)
        }
    }
}

pub mod vault;
pub mod entropy;
pub mod rsa;
pub mod curve25519;
pub mod hmac;
pub mod bigint;
pub mod util;

// Quantum crypto module
pub mod quantum {
    pub use super::kyber::*;
    pub use super::dilithium::*;
    
    // Kyber variants
    pub fn kyber1024_keypair() -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), &'static str> {
        match super::kyber::kyber_keygen() {
            Ok(keypair) => Ok((keypair.public_key.bytes.to_vec(), keypair.secret_key.bytes.to_vec())),
            Err(_) => Err("Kyber keygen failed"),
        }
    }
    
    pub fn kyber768_keypair() -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), &'static str> {
        match super::kyber::kyber_keygen() {
            Ok(keypair) => Ok((keypair.public_key.bytes.to_vec(), keypair.secret_key.bytes.to_vec())),
            Err(_) => Err("Kyber keygen failed"),
        }
    }
    
    // Dilithium variants  
    pub fn dilithium3_keypair() -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), &'static str> {
        match super::dilithium::dilithium_keypair() {
            Ok(keypair) => Ok((super::dilithium::dilithium_serialize_public_key(&keypair.public_key), super::dilithium::dilithium_serialize_secret_key(&keypair.secret_key))),
            Err(_) => Err("Dilithium keygen failed"),
        }
    }
    
    pub fn dilithium3_sign(message: &[u8], sk: &[u8]) -> Result<alloc::vec::Vec<u8>, &'static str> {
        let dilithium_sk = match super::dilithium::dilithium_deserialize_secret_key(sk) {
            Ok(k) => k,
            Err(_) => return Err("Invalid secret key"),
        };
        match super::dilithium::dilithium_sign(&dilithium_sk, message) {
            Ok(sig) => Ok(super::dilithium::dilithium_serialize_signature(&sig)),
            Err(_) => Err("Signing failed"),
        }
    }
    
    pub fn dilithium3_verify(message: &[u8], sig: &[u8], pk: &[u8]) -> bool {
        // Convert byte arrays to proper types
        let dilithium_pk = match super::dilithium::dilithium_deserialize_public_key(pk) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let dilithium_sig = match super::dilithium::dilithium_deserialize_signature(sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        super::dilithium::dilithium_verify(&dilithium_pk, message, &dilithium_sig)
    }
    
    // Placeholder implementations for other algorithms
    pub fn sphincs128s_keypair() -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), &'static str> {
        Err("SPHINCS+ not implemented")
    }
    
    pub fn ntruhps4096821_keypair() -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), &'static str> {
        Err("NTRU not implemented")
    }
    
    pub fn mceliece348864_keypair() -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), &'static str> {
        Err("McEliece not implemented")
    }
    
    pub fn lattice_keypair() -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), &'static str> {
        Err("Lattice not implemented")
    }
    
    pub fn sphincs128s_sign(_message: &[u8], _sk: &[u8]) -> Result<alloc::vec::Vec<u8>, &'static str> {
        Err("SPHINCS+ not implemented")
    }
    
    pub fn sphincs128s_verify(_message: &[u8], _sig: &[u8], _pk: &[u8]) -> bool {
        false
    }
    
    pub fn kyber1024_encapsulate(_pk: &[u8]) -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), &'static str> {
        let kyber_pk = match super::kyber::kyber_deserialize_public_key(_pk) {
            Ok(k) => k,
            Err(_) => return Err("Invalid public key"),
        };
        match super::kyber::kyber_encaps(&kyber_pk) {
            Ok((ct, ss)) => Ok((ct.bytes.to_vec(), ss.to_vec())),
            Err(_) => Err("Encapsulation failed"),
        }
    }
    
    pub fn kyber768_encapsulate(_pk: &[u8]) -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), &'static str> {
        let kyber_pk = match super::kyber::kyber_deserialize_public_key(_pk) {
            Ok(k) => k,
            Err(_) => return Err("Invalid public key"),
        };
        match super::kyber::kyber_encaps(&kyber_pk) {
            Ok((ct, ss)) => Ok((ct.bytes.to_vec(), ss.to_vec())),
            Err(_) => Err("Encapsulation failed"),
        }
    }
    
    pub fn ntruhps4096821_encapsulate(_pk: &[u8]) -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), &'static str> {
        Err("NTRU not implemented")
    }
    
    pub fn mceliece348864_encapsulate(_pk: &[u8]) -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), &'static str> {
        Err("McEliece not implemented")
    }
    
    pub fn kyber1024_decapsulate(_ct: &[u8], _sk: &[u8]) -> Result<alloc::vec::Vec<u8>, &'static str> {
        let kyber_ct = match super::kyber::kyber_deserialize_ciphertext(_ct) {
            Ok(ct) => ct,
            Err(_) => return Err("Invalid ciphertext"),
        };
        let kyber_sk = match super::kyber::kyber_deserialize_secret_key(_sk) {
            Ok(sk) => sk,
            Err(_) => return Err("Invalid secret key"),
        };
        match super::kyber::kyber_decaps(&kyber_ct, &kyber_sk) {
            Ok(shared_secret) => Ok(shared_secret.to_vec()),
            Err(_) => Err("Kyber decapsulation failed"),
        }
    }
    
    pub fn kyber768_decapsulate(_ct: &[u8], _sk: &[u8]) -> Result<alloc::vec::Vec<u8>, &'static str> {
        let kyber_ct = match super::kyber::kyber_deserialize_ciphertext(_ct) {
            Ok(ct) => ct,
            Err(_) => return Err("Invalid ciphertext"),
        };
        let kyber_sk = match super::kyber::kyber_deserialize_secret_key(_sk) {
            Ok(sk) => sk,
            Err(_) => return Err("Invalid secret key"),
        };
        match super::kyber::kyber_decaps(&kyber_ct, &kyber_sk) {
            Ok(shared_secret) => Ok(shared_secret.to_vec()),
            Err(_) => Err("Kyber decapsulation failed"),
        }
    }
    
    pub fn ntruhps4096821_decapsulate(_ct: &[u8], _sk: &[u8]) -> Result<alloc::vec::Vec<u8>, &'static str> {
        Err("NTRU not implemented")
    }
    
    pub fn mceliece348864_decapsulate(_ct: &[u8], _sk: &[u8]) -> Result<alloc::vec::Vec<u8>, &'static str> {
        Err("McEliece not implemented")
    }
}

// Crypto subsystem init
pub fn init_crypto_subsystem() -> Result<(), &'static str> {
    rng::init_rng();
    Ok(())
}

// ZK proof functions
pub fn generate_plonk_proof(_circuit: &[u8]) -> Result<Vec<u8>, &'static str> { Err("Not implemented") }
pub fn verify_plonk_proof(_proof: &[u8], _vk: &[u8]) -> bool { false }
pub fn fill_random(buf: &mut [u8]) { rng::fill_random_bytes(buf); }

// PQC re-exports: Kyber
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

// PQC re-exports: Dilithium
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

// ZK re-exports (host-only)
#[cfg(feature = "zk-halo2")]
pub use halo2::{Halo2Verifier, Halo2Error, halo2_verify_kzg_bn256};
#[cfg(feature = "zk-groth16")]
pub use groth16::{Groth16Verifier, Groth16Error, groth16_verify_bn254};

// -----------------------------
// Advanced unified interfaces
// -----------------------------

/// Unified crypto errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    AeadTagMismatch,
    InvalidLength,
    KemError,
    SigError,
}

/// Common result alias.
pub type CryptoResult<T> = core::result::Result<T, CryptoError>;

// ----- AEAD facade -----

/// AEAD trait for encrypt-then-MAC constructions with 96-bit nonces and 16-byte tags.
pub trait Aead {
    /// Seal: returns ciphertext || tag.
    fn seal(&self, nonce96: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>>;
    /// Open: returns plaintext if tag verifies.
    fn open(&self, nonce96: &[u8; 12], aad: &[u8], ciphertext_and_tag: &[u8]) -> CryptoResult<Vec<u8>>;
    /// AEAD key length (bytes).
    fn key_len() -> usize { 32 }
    /// AEAD nonce length (bytes).
    fn nonce_len() -> usize { 12 }
    /// AEAD tag length (bytes).
    fn tag_len() -> usize { 16 }
}

/// ChaCha20-Poly1305 AEAD (RFC 8439).
pub struct Chacha20Poly1305Aead {
    key: [u8; 32],
}

impl Chacha20Poly1305Aead {
    pub fn new(key: &[u8; 32]) -> Self { Self { key: *key } }
}

impl Aead for Chacha20Poly1305Aead {
    fn seal(&self, nonce96: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        chacha20poly1305::aead_encrypt(&self.key, nonce96, aad, plaintext)
            .map_err(|_| CryptoError::SigError) // map to generic; AEAD-only error below too
    }
    fn open(&self, nonce96: &[u8; 12], aad: &[u8], ct_and_tag: &[u8]) -> CryptoResult<Vec<u8>> {
        chacha20poly1305::aead_decrypt(&self.key, nonce96, aad, ct_and_tag)
            .map_err(|_| CryptoError::AeadTagMismatch)
    }
}

/// AES-256-GCM AEAD (SP 800-38D).
pub struct Aes256GcmAead {
    key: [u8; 32],
}

impl Aes256GcmAead {
    pub fn new(key: &[u8; 32]) -> Self { Self { key: *key } }
}

impl Aead for Aes256GcmAead {
    fn seal(&self, nonce96: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        aes_gcm::aes256_gcm_encrypt(&self.key, nonce96, aad, plaintext)
            .map_err(|_| CryptoError::SigError)
    }
    fn open(&self, nonce96: &[u8; 12], aad: &[u8], ct_and_tag: &[u8]) -> CryptoResult<Vec<u8>> {
        aes_gcm::aes256_gcm_decrypt(&self.key, nonce96, aad, ct_and_tag)
            .map_err(|_| CryptoError::AeadTagMismatch)
    }
}

/// Wrap a key buffer using an AEAD: returns nonce || ciphertext || tag.
/// Caller supplies a fresh 96-bit nonce (do not reuse per key).
pub fn aead_wrap<A: Aead>(aead: &A, nonce96: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut out = Vec::with_capacity(12 + plaintext.len() + 16);
    out.extend_from_slice(nonce96);
    let ct = aead.seal(nonce96, aad, plaintext)?;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap a buffer produced by aead_wrap: expects nonce || ciphertext || tag.
pub fn aead_unwrap<A: Aead>(aead: &A, aad: &[u8], wrapped: &[u8]) -> CryptoResult<Vec<u8>> {
    if wrapped.len() < 12 + 16 {
        return Err(CryptoError::InvalidLength);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&wrapped[..12]);
    let ct_and_tag = &wrapped[12..];
    aead.open(&nonce, aad, ct_and_tag)
}

// ----- KEM facade (Kyber) -----

/// KEM common interface (encapsulates to a peer public key).
pub trait Kem {
    type PublicKey;
    type SecretKey;
    type Ciphertext;
    type SharedSecret;

    fn keypair() -> CryptoResult<(Self::PublicKey, Self::SecretKey)>;
    fn encaps(pk: &Self::PublicKey) -> CryptoResult<(Self::Ciphertext, Self::SharedSecret)>;
    fn decaps(ct: &Self::Ciphertext, sk: &Self::SecretKey) -> CryptoResult<Self::SharedSecret>;
}

#[cfg(any(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
pub struct KyberKem;

#[cfg(any(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
impl Kem for KyberKem {
    type PublicKey = KyberPublicKey;
    type SecretKey = KyberSecretKey;
    type Ciphertext = KyberCiphertext;
    type SharedSecret = [u8; 32];

    fn keypair() -> CryptoResult<(Self::PublicKey, Self::SecretKey)> {
        kyber_keygen().map(|kp| (kp.public_key, kp.secret_key)).map_err(|_| CryptoError::KemError)
    }
    fn encaps(pk: &Self::PublicKey) -> CryptoResult<(Self::Ciphertext, Self::SharedSecret)> {
        kyber_encaps(pk).map_err(|_| CryptoError::KemError)
    }
    fn decaps(ct: &Self::Ciphertext, sk: &Self::SecretKey) -> CryptoResult<Self::SharedSecret> {
        kyber_decaps(ct, sk).map_err(|_| CryptoError::KemError)
    }
}

// ----- SIG (Ed25519 and optional Dilithium) -----

pub trait Sig {
    type PublicKey;
    type SecretKey;
    type Signature;

    fn keygen() -> (Self::PublicKey, Self::SecretKey);
    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature;
    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool;
}

pub struct Ed25519Sig;

impl Sig for Ed25519Sig {
    type PublicKey = [u8; 32];
    type SecretKey = KeyPair; // we store seed; public derivable
    type Signature = Signature;

    fn keygen() -> (Self::PublicKey, Self::SecretKey) {
        let kp = KeyPair::generate();
        (kp.public, kp)
    }
    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature {
        ed25519::sign(sk, msg)
    }
    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
        ed25519::verify(pk, msg, sig)
    }
}

#[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
pub struct DilithiumSig;

#[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
impl Sig for DilithiumSig {
    type PublicKey = DilithiumPublicKey;
    type SecretKey = DilithiumSecretKey;
    type Signature = DilithiumSignature;

    fn keygen() -> (Self::PublicKey, Self::SecretKey) {
        let kp = dilithium_keypair().expect("dilithium keygen failed");
        (kp.public_key, kp.secret_key)
    }
    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature {
        dilithium::dilithium_sign(sk, msg).expect("dilithium sign failed")
    }
    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
        dilithium::dilithium_verify(pk, msg, sig)
    }
}

// ----- Labeled HKDF helper -----

/// Labeled HKDF expand: OKM = HKDF-Expand(PRK, label || context, L)
pub fn hkdf_expand_labeled(prk: &Hash256, label: &[u8], context: &[u8], okm: &mut [u8]) -> CryptoResult<()> {
    let mut info = Vec::with_capacity(label.len() + context.len());
    info.extend_from_slice(label);
    info.extend_from_slice(context);
    hkdf_expand(prk, &info, okm).map_err(|_| CryptoError::InvalidLength)
}

// ----- Init facade -----

/// Initialize the crypto subsystem (RNG).
pub fn init() {
    rng::init_rng();
}

// Optional: feature summary string for diagnostics
#[allow(dead_code)]
pub fn feature_summary() -> &'static str {
    #[cfg(feature = "mlkem512")] { return "kyber=512"; }
    #[cfg(feature = "mlkem768")] { return "kyber=768"; }
    #[cfg(feature = "mlkem1024")] { return "kyber=1024"; }
    "kyber=off"
}

// Missing crypto utility functions
pub fn generate_secure_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rng::fill_random_bytes(&mut key);
    key
}

pub fn hash_memory_region(start_addr: usize, size: usize, out: &mut [u8; 32]) -> Result<(), &'static str> {
    // Hash the memory region - simplified implementation
    let data = unsafe { core::slice::from_raw_parts(start_addr as *const u8, size) };
    *out = hash::sha256(data);
    Ok(())
}

pub fn secure_zero(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
}

pub fn secure_erase_memory_region(start_addr: usize, size: usize) -> Result<(), &'static str> {
    let data = unsafe { core::slice::from_raw_parts_mut(start_addr as *mut u8, size) };
    secure_zero(data);
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
    // Use Ed25519 verification
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
