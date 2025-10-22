//! ML-KEM (Kyber) — via PQClean (constant-time, audited).
//!
//! Default parameter set: ML-KEM-768 (Kyber768).
//! Switch with features: `mlkem512` or `mlkem1024`.
//!
//! Sizes (FIPS 203):
//! - ML-KEM-512:  pk=800,   sk=1632, ct=768,  ss=32
//! - ML-KEM-768:  pk=1184,  sk=2400, ct=1088, ss=32
//! - ML-KEM-1024: pk=1568,  sk=3168, ct=1568, ss=32
//!
//! The complete cryptography lives in vendored C under third_party/pqclean.

extern crate alloc;
use alloc::vec::Vec;
use core::ptr;

// PQClean RNG bridge — used by src/crypto/pqclean_support/randombytes.c
#[no_mangle]
pub extern "C" fn nonos_randombytes(buf: *mut u8, n: usize) {
    if buf.is_null() || n == 0 { return; }
    unsafe {
        let slice = core::slice::from_raw_parts_mut(buf, n);
        crate::crypto::rng::fill_random_bytes(slice);
    }
}

#[cfg(feature = "mlkem512")]
pub const KYBER_PARAM_NAME: &str = "ML-KEM-512";
#[cfg(feature = "mlkem768")]
pub const KYBER_PARAM_NAME: &str = "ML-KEM-768";
#[cfg(feature = "mlkem1024")]
pub const KYBER_PARAM_NAME: &str = "ML-KEM-1024";

#[cfg(feature = "mlkem512")]
pub const PUBLICKEY_BYTES: usize = 800;
#[cfg(feature = "mlkem512")]
pub const SECRETKEY_BYTES: usize = 1632;
#[cfg(feature = "mlkem512")]
pub const CIPHERTEXT_BYTES: usize = 768;

#[cfg(feature = "mlkem768")]
pub const PUBLICKEY_BYTES: usize = 1184;
#[cfg(feature = "mlkem768")]
pub const SECRETKEY_BYTES: usize = 2400;
#[cfg(feature = "mlkem768")]
pub const CIPHERTEXT_BYTES: usize = 1088;

#[cfg(feature = "mlkem1024")]
pub const PUBLICKEY_BYTES: usize = 1568;
#[cfg(feature = "mlkem1024")]
pub const SECRETKEY_BYTES: usize = 3168;
#[cfg(feature = "mlkem1024")]
pub const CIPHERTEXT_BYTES: usize = 1568;

pub const SHAREDSECRET_BYTES: usize = 32;

#[repr(C)]
#[derive(Clone)]
#[derive(Debug)]
pub struct KyberPublicKey { pub bytes: [u8; PUBLICKEY_BYTES] }

#[repr(C)]
#[derive(Clone)]
#[derive(Debug)]
pub struct KyberSecretKey { pub bytes: [u8; SECRETKEY_BYTES] }

impl Drop for KyberSecretKey {
    fn drop(&mut self) {
        for b in &mut self.bytes {
            unsafe { ptr::write_volatile(b, 0) };
        }
    }
}

#[repr(C)]
pub struct KyberCiphertext { pub bytes: [u8; CIPHERTEXT_BYTES] }

#[repr(C)]
#[derive(Debug)]
pub struct KyberKeyPair {
    pub public_key: KyberPublicKey,
    pub secret_key: KyberSecretKey,
}

#[cfg(all(feature = "mlkem768", not(feature = "mlkem512"), not(feature = "mlkem1024")))]
mod ffi {
    extern "C" {
        pub fn PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> i32;
        pub fn PQCLEAN_KYBER768_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> i32;
        pub fn PQCLEAN_KYBER768_CLEAN_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
    }
    pub unsafe fn keypair(pk: *mut u8, sk: *mut u8) -> i32 { PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair(pk, sk) }
    pub unsafe fn encaps(ct: *mut u8, ss: *mut u8, pk: *const u8) -> i32 { PQCLEAN_KYBER768_CLEAN_crypto_kem_enc(ct, ss, pk) }
    pub unsafe fn decaps(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32 { PQCLEAN_KYBER768_CLEAN_crypto_kem_dec(ss, ct, sk) }
}

#[cfg(feature = "mlkem512")]
mod ffi {
    extern "C" {
        pub fn PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> i32;
        pub fn PQCLEAN_KYBER512_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> i32;
        pub fn PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
    }
    pub unsafe fn keypair(pk: *mut u8, sk: *mut u8) -> i32 { PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(pk, sk) }
    pub unsafe fn encaps(ct: *mut u8, ss: *mut u8, pk: *const u8) -> i32 { PQCLEAN_KYBER512_CLEAN_crypto_kem_enc(ct, ss, pk) }
    pub unsafe fn decaps(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32 { PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(ss, ct, sk) }
}

#[cfg(feature = "mlkem1024")]
mod ffi {
    extern "C" {
        pub fn PQCLEAN_KYBER1024_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> i32;
        pub fn PQCLEAN_KYBER1024_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> i32;
        pub fn PQCLEAN_KYBER1024_CLEAN_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
    }
    pub unsafe fn keypair(pk: *mut u8, sk: *mut u8) -> i32 { PQCLEAN_KYBER1024_CLEAN_crypto_kem_keypair(pk, sk) }
    pub unsafe fn encaps(ct: *mut u8, ss: *mut u8, pk: *const u8) -> i32 { PQCLEAN_KYBER1024_CLEAN_crypto_kem_enc(ct, ss, pk) }
    pub unsafe fn decaps(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32 { PQCLEAN_KYBER1024_CLEAN_crypto_kem_dec(ss, ct, sk) }
}

#[derive(Debug)]
pub enum KyberError { FfiError, InvalidLength }

#[inline] fn ok(rc: i32) -> Result<(), KyberError> { if rc == 0 { Ok(()) } else { Err(KyberError::FfiError) } }

pub fn kyber_keygen() -> Result<KyberKeyPair, KyberError> {
    let mut pk = KyberPublicKey { bytes: [0u8; PUBLICKEY_BYTES] };
    let mut sk = KyberSecretKey { bytes: [0u8; SECRETKEY_BYTES] };
    let rc = unsafe { ffi::keypair(pk.bytes.as_mut_ptr(), sk.bytes.as_mut_ptr()) };
    ok(rc)?;
    Ok(KyberKeyPair { public_key: pk, secret_key: sk })
}

pub fn kyber_encaps(pk: &KyberPublicKey) -> Result<(KyberCiphertext, [u8; SHAREDSECRET_BYTES]), KyberError> {
    let mut ct = KyberCiphertext { bytes: [0u8; CIPHERTEXT_BYTES] };
    let mut ss = [0u8; SHAREDSECRET_BYTES];
    let rc = unsafe { ffi::encaps(ct.bytes.as_mut_ptr(), ss.as_mut_ptr(), pk.bytes.as_ptr()) };
    ok(rc)?;
    Ok((ct, ss))
}

pub fn kyber_decaps(ct: &KyberCiphertext, sk: &KyberSecretKey) -> Result<[u8; SHAREDSECRET_BYTES], KyberError> {
    let mut ss = [0u8; SHAREDSECRET_BYTES];
    let rc = unsafe { ffi::decaps(ss.as_mut_ptr(), ct.bytes.as_ptr(), sk.bytes.as_ptr()) };
    ok(rc)?;
    Ok(ss)
}

// Serialization helpers

pub fn kyber_serialize_public_key(pk: &KyberPublicKey) -> Vec<u8> { pk.bytes.to_vec() }
pub fn kyber_deserialize_public_key(data: &[u8]) -> Result<KyberPublicKey, KyberError> {
    if data.len() != PUBLICKEY_BYTES { return Err(KyberError::InvalidLength); }
    let mut bytes = [0u8; PUBLICKEY_BYTES]; bytes.copy_from_slice(data);
    Ok(KyberPublicKey { bytes })
}
pub fn kyber_serialize_secret_key(sk: &KyberSecretKey) -> Vec<u8> { sk.bytes.to_vec() }
pub fn kyber_deserialize_secret_key(data: &[u8]) -> Result<KyberSecretKey, KyberError> {
    if data.len() != SECRETKEY_BYTES { return Err(KyberError::InvalidLength); }
    let mut bytes = [0u8; SECRETKEY_BYTES]; bytes.copy_from_slice(data);
    Ok(KyberSecretKey { bytes })
}
pub fn kyber_serialize_ciphertext(ct: &KyberCiphertext) -> Vec<u8> { ct.bytes.to_vec() }
pub fn kyber_deserialize_ciphertext(data: &[u8]) -> Result<KyberCiphertext, KyberError> {
    if data.len() != CIPHERTEXT_BYTES { return Err(KyberError::InvalidLength); }
    let mut bytes = [0u8; CIPHERTEXT_BYTES]; bytes.copy_from_slice(data);
    Ok(KyberCiphertext { bytes })
}
