// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::boot::handoff::api::HandoffError;
use crate::boot::handoff::types::HANDOFF_VERSION;
use crate::test::framework::TestResult;

pub(crate) fn test_handoff_error_null_pointer_str() -> TestResult {
    let err = HandoffError::NullPointer;
    if err.as_str() != "Null handoff pointer" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_handoff_error_invalid_magic_str() -> TestResult {
    let err = HandoffError::InvalidMagic;
    if err.as_str() != "Invalid handoff magic value" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_handoff_error_version_mismatch_str() -> TestResult {
    let err = HandoffError::VersionMismatch { expected: 1, got: 2 };
    if err.as_str() != "Handoff version mismatch" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_handoff_error_size_mismatch_str() -> TestResult {
    let err = HandoffError::SizeMismatch { expected: 256, got: 128 };
    if err.as_str() != "Handoff size mismatch" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_handoff_error_already_initialized_str() -> TestResult {
    let err = HandoffError::AlreadyInitialized;
    if err.as_str() != "Handoff already initialized" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_handoff_error_invalid_data_str() -> TestResult {
    let err = HandoffError::InvalidData;
    if err.as_str() != "Invalid handoff data" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_handoff_error_equality() -> TestResult {
    if HandoffError::NullPointer != HandoffError::NullPointer { return TestResult::Fail; }
    if HandoffError::InvalidMagic != HandoffError::InvalidMagic { return TestResult::Fail; }
    if HandoffError::AlreadyInitialized != HandoffError::AlreadyInitialized { return TestResult::Fail; }
    if HandoffError::InvalidData != HandoffError::InvalidData { return TestResult::Fail; }
    let v1 = HandoffError::VersionMismatch { expected: 1, got: 2 };
    let v2 = HandoffError::VersionMismatch { expected: 1, got: 2 };
    let v3 = HandoffError::VersionMismatch { expected: 1, got: 3 };
    if v1 != v2 { return TestResult::Fail; }
    if v1 == v3 { return TestResult::Fail; }
    let s1 = HandoffError::SizeMismatch { expected: 256, got: 128 };
    let s2 = HandoffError::SizeMismatch { expected: 256, got: 128 };
    let s3 = HandoffError::SizeMismatch { expected: 256, got: 64 };
    if s1 != s2 { return TestResult::Fail; }
    if s1 == s3 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_handoff_error_not_equal_different_variants() -> TestResult {
    if HandoffError::NullPointer == HandoffError::InvalidMagic { return TestResult::Fail; }
    if HandoffError::InvalidMagic == HandoffError::AlreadyInitialized { return TestResult::Fail; }
    if HandoffError::AlreadyInitialized == HandoffError::InvalidData { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_handoff_error_clone() -> TestResult {
    let err = HandoffError::VersionMismatch { expected: 1, got: 2 };
    let cloned = err.clone();
    if err != cloned { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_handoff_error_copy() -> TestResult {
    let err = HandoffError::NullPointer;
    let copied = err;
    if err != copied { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_handoff_version_current() -> TestResult {
    if HANDOFF_VERSION != 1 { return TestResult::Fail; }
    TestResult::Pass
}
