// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Secure boot tests

extern crate alloc;

use crate::security::*;
use crate::test::framework::TestResult;
use alloc::string::String;

pub(crate) fn test_secure_boot_policy_disabled() -> TestResult {
    let policy = SecureBootPolicy::Disabled;
    if policy != SecureBootPolicy::Disabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_policy_permissive() -> TestResult {
    let policy = SecureBootPolicy::Permissive;
    if policy != SecureBootPolicy::Permissive {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_policy_enforcing() -> TestResult {
    let policy = SecureBootPolicy::Enforcing;
    if policy != SecureBootPolicy::Enforcing {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_policy_strict() -> TestResult {
    let policy = SecureBootPolicy::Strict;
    if policy != SecureBootPolicy::Strict {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_policy_equality() -> TestResult {
    if SecureBootPolicy::Disabled != SecureBootPolicy::Disabled {
        return TestResult::Fail;
    }
    if SecureBootPolicy::Disabled == SecureBootPolicy::Enforcing {
        return TestResult::Fail;
    }
    if SecureBootPolicy::Permissive == SecureBootPolicy::Strict {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_error_variants() -> TestResult {
    let errors = [
        SecureBootError::NotInitialized,
        SecureBootError::NoTrustedKeys,
        SecureBootError::SignatureInvalid,
        SecureBootError::KeyRevoked,
        SecureBootError::KeyExpired,
        SecureBootError::HashMismatch,
        SecureBootError::NotMeasured,
        SecureBootError::ChainBroken,
        SecureBootError::PolicyViolation,
        SecureBootError::CryptoError,
    ];
    if errors.len() != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_measurements_new() -> TestResult {
    let measurements = BootMeasurements::new();
    if measurements.bootloader_hash != [0u8; 32] {
        return TestResult::Fail;
    }
    if measurements.kernel_hash != [0u8; 32] {
        return TestResult::Fail;
    }
    if measurements.initrd_hash.is_some() {
        return TestResult::Fail;
    }
    if measurements.acpi_hash.is_some() {
        return TestResult::Fail;
    }
    if measurements.kernel_signature_valid {
        return TestResult::Fail;
    }
    if measurements.uefi_secure_boot {
        return TestResult::Fail;
    }
    if measurements.boot_timestamp != 0 {
        return TestResult::Fail;
    }
    if measurements.chain_verified {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_measurements_getters() -> TestResult {
    let measurements = BootMeasurements::new();
    if measurements.get_bootloader_hash() != &[0u8; 32] {
        return TestResult::Fail;
    }
    if measurements.get_kernel_hash() != &[0u8; 32] {
        return TestResult::Fail;
    }
    if measurements.has_initrd() {
        return TestResult::Fail;
    }
    if measurements.has_acpi() {
        return TestResult::Fail;
    }
    if measurements.get_initrd_hash().is_some() {
        return TestResult::Fail;
    }
    if measurements.get_acpi_hash().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_measurements_signature_state() -> TestResult {
    let measurements = BootMeasurements::new();
    if measurements.is_signature_valid() {
        return TestResult::Fail;
    }
    if measurements.is_uefi_secure_boot() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_measurements_pcr_values() -> TestResult {
    let measurements = BootMeasurements::new();
    if measurements.get_pcr(0).is_some() {
        return TestResult::Fail;
    }
    if measurements.get_pcr(23).is_some() {
        return TestResult::Fail;
    }
    if measurements.get_pcr(100).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_measurements_timestamp() -> TestResult {
    let measurements = BootMeasurements::new();
    if measurements.get_boot_timestamp() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_measurements_chain_verified() -> TestResult {
    let measurements = BootMeasurements::new();
    if measurements.is_chain_verified() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_boot_keys_new() -> TestResult {
    let keys = TrustedBootKeys::new();
    if !keys.production_keys.is_empty() {
        return TestResult::Fail;
    }
    if !keys.development_keys.is_empty() {
        return TestResult::Fail;
    }
    if !keys.revoked_fingerprints.is_empty() {
        return TestResult::Fail;
    }
    if keys.rotation_count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_boot_keys_getters() -> TestResult {
    let keys = TrustedBootKeys::new();
    if !keys.get_production_keys().is_empty() {
        return TestResult::Fail;
    }
    if !keys.get_development_keys().is_empty() {
        return TestResult::Fail;
    }
    if !keys.get_revoked().is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_boot_keys_revocation_check() -> TestResult {
    let keys = TrustedBootKeys::new();
    let fingerprint = [0u8; 32];
    if keys.is_revoked(&fingerprint) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_boot_keys_rotation_count() -> TestResult {
    let keys = TrustedBootKeys::new();
    if keys.get_rotation_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_boot_keys_total_count() -> TestResult {
    let keys = TrustedBootKeys::new();
    if keys.total_keys() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_attestation_report_fields() -> TestResult {
    let measurements = BootMeasurements::new();
    let report = AttestationReport {
        measurements: measurements.clone(),
        policy: SecureBootPolicy::Enforcing,
        enforcing: true,
        violation_count: 0,
        trusted_key_count: 5,
        revoked_key_count: 1,
        chain_verified: true,
    };
    if !report.enforcing {
        return TestResult::Fail;
    }
    if report.trusted_key_count != 5 {
        return TestResult::Fail;
    }
    if report.revoked_key_count != 1 {
        return TestResult::Fail;
    }
    if !report.chain_verified {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_stats_fields() -> TestResult {
    let stats = SecureBootStats {
        initialized: true,
        enforcing: true,
        policy: SecureBootPolicy::Strict,
        chain_verified: true,
        violation_count: 0,
        trusted_keys: 10,
        revoked_keys: 2,
    };
    if !stats.initialized {
        return TestResult::Fail;
    }
    if !stats.enforcing {
        return TestResult::Fail;
    }
    if stats.policy != SecureBootPolicy::Strict {
        return TestResult::Fail;
    }
    if !stats.chain_verified {
        return TestResult::Fail;
    }
    if stats.trusted_keys != 10 {
        return TestResult::Fail;
    }
    if stats.revoked_keys != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_result_ok() -> TestResult {
    let result: SecureBootResult<u32> = Ok(42);
    if !result.is_ok() {
        return TestResult::Fail;
    }
    if result.unwrap() != 42 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_result_err() -> TestResult {
    let result: SecureBootResult<u32> = Err(SecureBootError::SignatureInvalid);
    if !result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != SecureBootError::SignatureInvalid {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_error_equality() -> TestResult {
    if SecureBootError::NotInitialized != SecureBootError::NotInitialized {
        return TestResult::Fail;
    }
    if SecureBootError::NotInitialized == SecureBootError::SignatureInvalid {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_measurements_with_initrd() -> TestResult {
    let mut measurements = BootMeasurements::new();
    measurements.initrd_hash = Some([0xABu8; 32]);
    if !measurements.has_initrd() {
        return TestResult::Fail;
    }
    if measurements.get_initrd_hash() != Some(&[0xABu8; 32]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_measurements_with_acpi() -> TestResult {
    let mut measurements = BootMeasurements::new();
    measurements.acpi_hash = Some([0xCDu8; 32]);
    if !measurements.has_acpi() {
        return TestResult::Fail;
    }
    if measurements.get_acpi_hash() != Some(&[0xCDu8; 32]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_measurements_clone() -> TestResult {
    let measurements = BootMeasurements::new();
    let cloned = measurements.clone();
    if cloned.bootloader_hash != measurements.bootloader_hash {
        return TestResult::Fail;
    }
    if cloned.kernel_hash != measurements.kernel_hash {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_key_creation() -> TestResult {
    let key = secure_boot::types::TrustedKey {
        name: String::from("test_key"),
        public_key: [0x11u8; 32],
        fingerprint: [0x22u8; 32],
        created_at: 1000,
        expires_at: 2000,
        is_production: true,
    };
    if key.name() != "test_key" {
        return TestResult::Fail;
    }
    if key.public_key() != &[0x11u8; 32] {
        return TestResult::Fail;
    }
    if key.fingerprint() != &[0x22u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_key_expiration() -> TestResult {
    let key = secure_boot::types::TrustedKey {
        name: String::from("expiring_key"),
        public_key: [0u8; 32],
        fingerprint: [0u8; 32],
        created_at: 1000,
        expires_at: 2000,
        is_production: false,
    };
    if key.is_expired(1500) {
        return TestResult::Fail;
    }
    if !key.is_expired(2500) {
        return TestResult::Fail;
    }
    if key.is_production() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_key_timestamps() -> TestResult {
    let key = secure_boot::types::TrustedKey {
        name: String::from("timestamp_key"),
        public_key: [0u8; 32],
        fingerprint: [0u8; 32],
        created_at: 100,
        expires_at: 200,
        is_production: true,
    };
    if key.created_at() != 100 {
        return TestResult::Fail;
    }
    if key.expires_at() != 200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
