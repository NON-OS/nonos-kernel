// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Crypto error handling tests

extern crate alloc;
use alloc::format;

use crate::crypto::error::{CryptoError, CryptoResult};
use crate::test::framework::TestResult;

pub(crate) fn test_crypto_error_aead_tag_mismatch() -> TestResult {
    let err = CryptoError::AeadTagMismatch;
    if err != CryptoError::AeadTagMismatch {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_error_invalid_length() -> TestResult {
    let err = CryptoError::InvalidLength;
    if err != CryptoError::InvalidLength {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_error_kem_error() -> TestResult {
    let err = CryptoError::KemError;
    if err != CryptoError::KemError {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_error_sig_error() -> TestResult {
    let err = CryptoError::SigError;
    if err != CryptoError::SigError {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_error_invalid_input() -> TestResult {
    let err = CryptoError::InvalidInput;
    if err != CryptoError::InvalidInput {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_error_invalid_key() -> TestResult {
    let err = CryptoError::InvalidKey;
    if err != CryptoError::InvalidKey {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_error_key_not_found() -> TestResult {
    let err = CryptoError::KeyNotFound;
    if err != CryptoError::KeyNotFound {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_error_buffer_too_small() -> TestResult {
    let err = CryptoError::BufferTooSmall;
    if err != CryptoError::BufferTooSmall {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_error_verification_failed() -> TestResult {
    let err = CryptoError::VerificationFailed;
    if err != CryptoError::VerificationFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_error_invalid_state() -> TestResult {
    let err = CryptoError::InvalidState;
    if err != CryptoError::InvalidState {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_error_authentication_failed() -> TestResult {
    let err = CryptoError::AuthenticationFailed;
    if err != CryptoError::AuthenticationFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_error_insufficient_entropy() -> TestResult {
    let err = CryptoError::InsufficientEntropy;
    if err != CryptoError::InsufficientEntropy {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_error_clone() -> TestResult {
    let err1 = CryptoError::InvalidKey;
    let err2 = err1.clone();
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_error_copy() -> TestResult {
    let err1 = CryptoError::InvalidKey;
    let err2 = err1;
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_error_debug() -> TestResult {
    let err = CryptoError::InvalidKey;
    let debug_str = format!("{:?}", err);
    if !debug_str.contains("InvalidKey") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_error_all_variants_distinct() -> TestResult {
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
            if variants[i] == variants[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_result_ok() -> TestResult {
    let result: CryptoResult<u32> = Ok(42);
    if !result.is_ok() {
        return TestResult::Fail;
    }
    if result.unwrap() != 42 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_result_err() -> TestResult {
    let result: CryptoResult<u32> = Err(CryptoError::InvalidKey);
    if !result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != CryptoError::InvalidKey {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_result_map() -> TestResult {
    let result: CryptoResult<u32> = Ok(10);
    let mapped = result.map(|x| x * 2);
    if mapped.unwrap() != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_result_map_err() -> TestResult {
    let result: CryptoResult<u32> = Err(CryptoError::InvalidKey);
    let mapped = result.map_err(|_| CryptoError::InvalidInput);
    if mapped.unwrap_err() != CryptoError::InvalidInput {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_result_and_then() -> TestResult {
    let result: CryptoResult<u32> = Ok(10);
    let chained = result.and_then(|x| Ok(x + 5));
    if chained.unwrap() != 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_result_or_else() -> TestResult {
    let result: CryptoResult<u32> = Err(CryptoError::InvalidKey);
    let recovered = result.or_else(|_| Ok(0));
    if recovered.unwrap() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_result_unwrap_or() -> TestResult {
    let result: CryptoResult<u32> = Err(CryptoError::InvalidKey);
    if result.unwrap_or(99) != 99 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_result_unwrap_or_else() -> TestResult {
    let result: CryptoResult<u32> = Err(CryptoError::InvalidKey);
    if result.unwrap_or_else(|_| 100) != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_error_not_equal_to_different() -> TestResult {
    if CryptoError::InvalidKey == CryptoError::KeyNotFound {
        return TestResult::Fail;
    }
    if CryptoError::AeadTagMismatch == CryptoError::AuthenticationFailed {
        return TestResult::Fail;
    }
    if CryptoError::BufferTooSmall == CryptoError::InvalidLength {
        return TestResult::Fail;
    }
    TestResult::Pass
}
