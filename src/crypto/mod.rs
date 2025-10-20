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
pub use ed25519::{KeyPair, Signature, sign, verify};

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
