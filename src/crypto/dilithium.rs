//! ML-DSA (Dilithium) — via PQClean audited

extern crate alloc;
use alloc::vec::Vec;
use core::ptr;

#[cfg(feature = "mldsa2")]
pub const D_PARAM_NAME: &str = "ML-DSA-44 (Dilithium2)";
#[cfg(feature = "mldsa3")]
pub const D_PARAM_NAME: &str = "ML-DSA-65 (Dilithium3)";
#[cfg(feature = "mldsa5")]
pub const D_PARAM_NAME: &str = "ML-DSA-87 (Dilithium5)";

#[cfg(feature = "mldsa2")]
pub const PUBLICKEY_BYTES: usize = 1312;
#[cfg(feature = "mldsa2")]
pub const SECRETKEY_BYTES: usize = 2528;
#[cfg(feature = "mldsa2")]
pub const SIGNATURE_BYTES: usize = 2420;

#[cfg(feature = "mldsa3")]
pub const PUBLICKEY_BYTES: usize = 1952;
#[cfg(feature = "mldsa3")]
pub const SECRETKEY_BYTES: usize = 4000;
#[cfg(feature = "mldsa3")]
pub const SIGNATURE_BYTES: usize = 3293;

#[cfg(feature = "mldsa5")]
pub const PUBLICKEY_BYTES: usize = 2592;
#[cfg(feature = "mldsa5")]
pub const SECRETKEY_BYTES: usize = 4864;
#[cfg(feature = "mldsa5")]
pub const SIGNATURE_BYTES: usize = 4595;

#[repr(C)]
#[derive(Clone)]
pub struct DilithiumPublicKey {
    pub bytes: [u8; PUBLICKEY_BYTES],
}

#[repr(C)]
#[derive(Clone)]
pub struct DilithiumSecretKey {
    pub bytes: [u8; SECRETKEY_BYTES],
}

impl Drop for DilithiumSecretKey {
    fn drop(&mut self) {
        for b in &mut self.bytes {
            unsafe { ptr::write_volatile(b, 0) };
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct DilithiumSignature {
    pub bytes: [u8; SIGNATURE_BYTES],
}

#[repr(C)]
pub struct DilithiumKeyPair {
    pub public_key: DilithiumPublicKey,
    pub secret_key: DilithiumSecretKey,
}

#[derive(Debug)]
pub enum DilithiumError {
    FfiError,
    InvalidLength,
}

// FFI bindings per parameter set
#[cfg(all(feature = "mldsa2", not(feature = "mldsa3"), not(feature = "mldsa5")))]
mod ffi {
    extern "C" {
        pub fn PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> i32;
        pub fn PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(
            sig: *mut u8,
            siglen: *mut usize,
            m: *const u8,
            mlen: usize,
            sk: *const u8,
        ) -> i32;
        pub fn PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(
            sig: *const u8,
            siglen: usize,
            m: *const u8,
            mlen: usize,
            pk: *const u8,
        ) -> i32;
    }
    pub unsafe fn keypair(pk: *mut u8, sk: *mut u8) -> i32 {
        PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(pk, sk)
    }
    pub unsafe fn sign(sig: *mut u8, siglen: *mut usize, m: *const u8, mlen: usize, sk: *const u8) -> i32 {
        PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk)
    }
    pub unsafe fn verify(sig: *const u8, siglen: usize, m: *const u8, mlen: usize, pk: *const u8) -> i32 {
        PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk)
    }
}

#[cfg(all(feature = "mldsa3", not(feature = "mldsa2"), not(feature = "mldsa5")))]
mod ffi {
    extern "C" {
        pub fn PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> i32;
        pub fn PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_signature(
            sig: *mut u8,
            siglen: *mut usize,
            m: *const u8,
            mlen: usize,
            sk: *const u8,
        ) -> i32;
        pub fn PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_verify(
            sig: *const u8,
            siglen: usize,
            m: *const u8,
            mlen: usize,
            pk: *const u8,
        ) -> i32;
    }
    pub unsafe fn keypair(pk: *mut u8, sk: *mut u8) -> i32 {
        PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_keypair(pk, sk)
    }
    pub unsafe fn sign(sig: *mut u8, siglen: *mut usize, m: *const u8, mlen: usize, sk: *const u8) -> i32 {
        PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk)
    }
    pub unsafe fn verify(sig: *const u8, siglen: usize, m: *const u8, mlen: usize, pk: *const u8) -> i32 {
        PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk)
    }
}

#[cfg(all(feature = "mldsa5", not(feature = "mldsa2"), not(feature = "mldsa3")))]
mod ffi {
    extern "C" {
        pub fn PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> i32;
        pub fn PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_signature(
            sig: *mut u8,
            siglen: *mut usize,
            m: *const u8,
            mlen: usize,
            sk: *const u8,
        ) -> i32;
        pub fn PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_verify(
            sig: *const u8,
            siglen: usize,
            m: *const u8,
            mlen: usize,
            pk: *const u8,
        ) -> i32;
    }
    pub unsafe fn keypair(pk: *mut u8, sk: *mut u8) -> i32 {
        PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_keypair(pk, sk)
    }
    pub unsafe fn sign(sig: *mut u8, siglen: *mut usize, m: *const u8, mlen: usize, sk: *const u8) -> i32 {
        PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk)
    }
    pub unsafe fn verify(sig: *const u8, siglen: usize, m: *const u8, mlen: usize, pk: *const u8) -> i32 {
        PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk)
    }
}

#[inline]
fn ok(rc: i32) -> Result<(), DilithiumError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(DilithiumError::FfiError)
    }
}

// API

pub fn dilithium_keypair() -> Result<DilithiumKeyPair, DilithiumError> {
    let mut pk = DilithiumPublicKey { bytes: [0u8; PUBLICKEY_BYTES] };
    let mut sk = DilithiumSecretKey { bytes: [0u8; SECRETKEY_BYTES] };
    let rc = unsafe { ffi::keypair(pk.bytes.as_mut_ptr(), sk.bytes.as_mut_ptr()) };
    ok(rc)?;
    Ok(DilithiumKeyPair { public_key: pk, secret_key: sk })
}

pub fn dilithium_sign(sk: &DilithiumSecretKey, msg: &[u8]) -> Result<DilithiumSignature, DilithiumError> {
    let mut sig = DilithiumSignature { bytes: [0u8; SIGNATURE_BYTES] };
    let mut siglen: usize = 0;
    let rc = unsafe {
        ffi::sign(
            sig.bytes.as_mut_ptr(),
            &mut siglen as *mut usize,
            msg.as_ptr(),
            msg.len(),
            sk.bytes.as_ptr(),
        )
    };
    ok(rc)?;
    if siglen != SIGNATURE_BYTES {
        return Err(DilithiumError::FfiError);
    }
    Ok(sig)
}

pub fn dilithium_verify(pk: &DilithiumPublicKey, msg: &[u8], sig: &DilithiumSignature) -> bool {
    let rc = unsafe {
        ffi::verify(
            sig.bytes.as_ptr(),
            SIGNATURE_BYTES,
            msg.as_ptr(),
            msg.len(),
            pk.bytes.as_ptr(),
        )
    };
    rc == 0
}

// Serialization helpers

pub fn dilithium_serialize_public_key(pk: &DilithiumPublicKey) -> Vec<u8> {
    pk.bytes.to_vec()
}
pub fn dilithium_deserialize_public_key(data: &[u8]) -> Result<DilithiumPublicKey, DilithiumError> {
    if data.len() != PUBLICKEY_BYTES {
        return Err(DilithiumError::InvalidLength);
    }
    let mut bytes = [0u8; PUBLICKEY_BYTES];
    bytes.copy_from_slice(data);
    Ok(DilithiumPublicKey { bytes })
}
pub fn dilithium_serialize_secret_key(sk: &DilithiumSecretKey) -> Vec<u8> {
    sk.bytes.to_vec()
}
pub fn dilithium_deserialize_secret_key(data: &[u8]) -> Result<DilithiumSecretKey, DilithiumError> {
    if data.len() != SECRETKEY_BYTES {
        return Err(DilithiumError::InvalidLength);
    }
    let mut bytes = [0u8; SECRETKEY_BYTES];
    bytes.copy_from_slice(data);
    Ok(DilithiumSecretKey { bytes })
}
pub fn dilithium_serialize_signature(sig: &DilithiumSignature) -> Vec<u8> {
    sig.bytes.to_vec()
}
pub fn dilithium_deserialize_signature(data: &[u8]) -> Result<DilithiumSignature, DilithiumError> {
    if data.len() != SIGNATURE_BYTES {
        return Err(DilithiumError::InvalidLength);
    }
    let mut bytes = [0u8; SIGNATURE_BYTES];
    bytes.copy_from_slice(data);
    Ok(DilithiumSignature { bytes })
}
