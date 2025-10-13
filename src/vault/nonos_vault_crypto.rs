//! NØNOS Vault Crypto Module 

extern crate alloc;
use alloc::{vec::Vec, string::String};
use crate::crypto::{
    aes_gcm::{aes256_gcm_encrypt, aes256_gcm_decrypt},
    chacha20poly1305::{aead_encrypt as chacha_encrypt, aead_decrypt as chacha_decrypt},
    blake3_hash, sha256, hkdf_expand, hmac_sha256, hmac_verify,
    ed25519::{KeyPair, Signature, sign as ed_sign, verify as ed_verify},
    kyber::{KyberKeyPair, kyber_keygen, kyber_encaps, kyber_decaps, KyberPublicKey, KyberSecretKey, KyberCiphertext},
    dilithium::{DilithiumKeyPair, dilithium_keypair, dilithium_sign, dilithium_verify, DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature},
    get_random_bytes,
    constant_time::{ct_eq, ct_eq_32}
};

/// Encrypt data using AES-256-GCM (returns ciphertext || tag)
pub fn vault_encrypt_aes(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    aes256_gcm_encrypt(key, nonce, aad, plaintext)
}

/// Decrypt data using AES-256-GCM
pub fn vault_decrypt_aes(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext_and_tag: &[u8]) -> Result<Vec<u8>, &'static str> {
    aes256_gcm_decrypt(key, nonce, aad, ciphertext_and_tag)
}

/// Encrypt data using ChaCha20-Poly1305
pub fn vault_encrypt_chacha(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    chacha_encrypt(key, nonce, aad, plaintext)
}

/// Decrypt data using ChaCha20-Poly1305
pub fn vault_decrypt_chacha(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext_and_tag: &[u8]) -> Result<Vec<u8>, &'static str> {
    chacha_decrypt(key, nonce, aad, ciphertext_and_tag)
}

/// Key wrapping (AES-GCM, returns nonce || ciphertext || tag)
pub fn vault_wrap_aes(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, &'static str> {
    let nonce = &get_random_bytes()[..12];
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce);
    let mut out = Vec::with_capacity(12 + plaintext.len() + 16);
    out.extend_from_slice(&nonce_arr);
    let ct = aes256_gcm_encrypt(key, &nonce_arr, aad, plaintext)?;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Key unwrapping (AES-GCM, expects nonce || ciphertext || tag)
pub fn vault_unwrap_aes(key: &[u8; 32], wrapped: &[u8], aad: &[u8]) -> Result<Vec<u8>, &'static str> {
    if wrapped.len() < 12 + 16 {
        return Err("wrapped buffer too short");
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&wrapped[..12]);
    let ct_and_tag = &wrapped[12..];
    aes256_gcm_decrypt(key, &nonce, aad, ct_and_tag)
}

/// Hash data (BLAKE3)
pub fn vault_hash_blake3(data: &[u8]) -> [u8; 32] {
    blake3_hash(data)
}

/// Hash data (SHA256)
pub fn vault_hash_sha256(data: &[u8]) -> [u8; 32] {
    sha256(data)
}

/// HKDF-Expand
pub fn vault_hkdf_expand(prk: &[u8; 32], info: &[u8], out_len: usize) -> Result<Vec<u8>, &'static str> {
    let mut okm = vec![0u8; out_len];
    hkdf_expand(prk, info, &mut okm).map_err(|_| "HKDF error")?;
    Ok(okm)
}

/// HMAC-SHA256
pub fn vault_hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    hmac_sha256(key, data)
}

/// HMAC verify (constant-time)
pub fn vault_hmac_verify(key: &[u8], data: &[u8], mac: &[u8]) -> bool {
    hmac_verify(key, data, mac)
}

/// Ed25519 sign
pub fn vault_sign_ed25519(keypair: &KeyPair, data: &[u8]) -> Signature {
    ed_sign(keypair, data)
}

/// Ed25519 verify
pub fn vault_verify_ed25519(public: &[u8; 32], data: &[u8], sig: &Signature) -> bool {
    ed_verify(public, data, sig)
}

/// Kyber keypair generation (PQClean)
pub fn vault_kyber_keygen() -> Result<KyberKeyPair, &'static str> {
    kyber_keygen().map_err(|_| "Kyber keygen error")
}

/// Kyber encapsulation
pub fn vault_kyber_encaps(pk: &KyberPublicKey) -> Result<(KyberCiphertext, [u8; 32]), &'static str> {
    kyber_encaps(pk).map_err(|_| "Kyber encaps error")
}

/// Kyber decapsulation
pub fn vault_kyber_decaps(ct: &KyberCiphertext, sk: &KyberSecretKey) -> Result<[u8; 32], &'static str> {
    kyber_decaps(ct, sk).map_err(|_| "Kyber decaps error")
}

/// Dilithium keypair generation (PQClean)
pub fn vault_dilithium_keygen() -> Result<DilithiumKeyPair, &'static str> {
    dilithium_keypair().map_err(|_| "Dilithium keygen error")
}

/// Dilithium sign
pub fn vault_dilithium_sign(sk: &DilithiumSecretKey, msg: &[u8]) -> Result<DilithiumSignature, &'static str> {
    dilithium_sign(sk, msg).map_err(|_| "Dilithium sign error")
}

/// Dilithium verify
pub fn vault_dilithium_verify(pk: &DilithiumPublicKey, msg: &[u8], sig: &DilithiumSignature) -> bool {
    dilithium_verify(pk, msg, sig)
}

/// Secure zeroization helpers
pub fn vault_zeroize(buf: &mut [u8]) {
    for b in buf {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

pub fn vault_zeroize_vec(vec: &mut Vec<u8>) {
    for b in vec.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    vec.clear();
}

/// Constant-time equality for secrets
pub fn vault_ct_eq(a: &[u8], b: &[u8]) -> bool {
    ct_eq(a, b)
}

/// Constant-time equality for hash (32 bytes)
pub fn vault_ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    ct_eq_32(a, b)
}
