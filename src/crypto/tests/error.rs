// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::crypto::error::{CryptoError, CryptoResult};

#[test]
fn test_crypto_error_aead_tag_mismatch() {
    let err = CryptoError::AeadTagMismatch;
    assert_eq!(err, CryptoError::AeadTagMismatch);
}

#[test]
fn test_crypto_error_invalid_length() {
    let err = CryptoError::InvalidLength;
    assert_eq!(err, CryptoError::InvalidLength);
}

#[test]
fn test_crypto_error_kem_error() {
    let err = CryptoError::KemError;
    assert_eq!(err, CryptoError::KemError);
}

#[test]
fn test_crypto_error_sig_error() {
    let err = CryptoError::SigError;
    assert_eq!(err, CryptoError::SigError);
}

#[test]
fn test_crypto_error_invalid_input() {
    let err = CryptoError::InvalidInput;
    assert_eq!(err, CryptoError::InvalidInput);
}

#[test]
fn test_crypto_error_invalid_key() {
    let err = CryptoError::InvalidKey;
    assert_eq!(err, CryptoError::InvalidKey);
}

#[test]
fn test_crypto_error_key_not_found() {
    let err = CryptoError::KeyNotFound;
    assert_eq!(err, CryptoError::KeyNotFound);
}

#[test]
fn test_crypto_error_buffer_too_small() {
    let err = CryptoError::BufferTooSmall;
    assert_eq!(err, CryptoError::BufferTooSmall);
}

#[test]
fn test_crypto_error_verification_failed() {
    let err = CryptoError::VerificationFailed;
    assert_eq!(err, CryptoError::VerificationFailed);
}

#[test]
fn test_crypto_error_invalid_state() {
    let err = CryptoError::InvalidState;
    assert_eq!(err, CryptoError::InvalidState);
}

#[test]
fn test_crypto_error_authentication_failed() {
    let err = CryptoError::AuthenticationFailed;
    assert_eq!(err, CryptoError::AuthenticationFailed);
}

#[test]
fn test_crypto_error_insufficient_entropy() {
    let err = CryptoError::InsufficientEntropy;
    assert_eq!(err, CryptoError::InsufficientEntropy);
}

#[test]
fn test_crypto_error_clone() {
    let err1 = CryptoError::InvalidKey;
    let err2 = err1.clone();
    assert_eq!(err1, err2);
}

#[test]
fn test_crypto_error_copy() {
    let err1 = CryptoError::InvalidKey;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn test_crypto_error_debug() {
    let err = CryptoError::InvalidKey;
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("InvalidKey"));
}

#[test]
fn test_crypto_error_all_variants_distinct() {
    let variants = [
        CryptoError::AeadTagMismatch,
        CryptoError::InvalidLength,
        CryptoError::KemError,
        CryptoError::SigError,
        CryptoError::InvalidInput,
        CryptoError::InvalidKey,
        CryptoError::KeyNotFound,
        CryptoError::BufferTooSmall,
        CryptoError::VerificationFailed,
        CryptoError::InvalidState,
        CryptoError::AuthenticationFailed,
        CryptoError::InsufficientEntropy,
    ];

    for i in 0..variants.len() {
        for j in (i + 1)..variants.len() {
            assert_ne!(variants[i], variants[j]);
        }
    }
}

#[test]
fn test_crypto_result_ok() {
    let result: CryptoResult<u32> = Ok(42);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn test_crypto_result_err() {
    let result: CryptoResult<u32> = Err(CryptoError::InvalidKey);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), CryptoError::InvalidKey);
}

#[test]
fn test_crypto_result_map() {
    let result: CryptoResult<u32> = Ok(10);
    let mapped = result.map(|x| x * 2);
    assert_eq!(mapped.unwrap(), 20);
}

#[test]
fn test_crypto_result_map_err() {
    let result: CryptoResult<u32> = Err(CryptoError::InvalidKey);
    let mapped = result.map_err(|_| CryptoError::InvalidInput);
    assert_eq!(mapped.unwrap_err(), CryptoError::InvalidInput);
}

#[test]
fn test_crypto_result_and_then() {
    let result: CryptoResult<u32> = Ok(10);
    let chained = result.and_then(|x| Ok(x + 5));
    assert_eq!(chained.unwrap(), 15);
}

#[test]
fn test_crypto_result_or_else() {
    let result: CryptoResult<u32> = Err(CryptoError::InvalidKey);
    let recovered = result.or_else(|_| Ok(0));
    assert_eq!(recovered.unwrap(), 0);
}

#[test]
fn test_crypto_result_unwrap_or() {
    let result: CryptoResult<u32> = Err(CryptoError::InvalidKey);
    assert_eq!(result.unwrap_or(99), 99);
}

#[test]
fn test_crypto_result_unwrap_or_else() {
    let result: CryptoResult<u32> = Err(CryptoError::InvalidKey);
    assert_eq!(result.unwrap_or_else(|_| 100), 100);
}

#[test]
fn test_crypto_error_not_equal_to_different() {
    assert_ne!(CryptoError::InvalidKey, CryptoError::KeyNotFound);
    assert_ne!(CryptoError::AeadTagMismatch, CryptoError::AuthenticationFailed);
    assert_ne!(CryptoError::BufferTooSmall, CryptoError::InvalidLength);
}
