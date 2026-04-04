use crate::security::*;

#[test]
fn test_secure_boot_policy_disabled() {
    let policy = SecureBootPolicy::Disabled;
    assert_eq!(policy, SecureBootPolicy::Disabled);
}

#[test]
fn test_secure_boot_policy_permissive() {
    let policy = SecureBootPolicy::Permissive;
    assert_eq!(policy, SecureBootPolicy::Permissive);
}

#[test]
fn test_secure_boot_policy_enforcing() {
    let policy = SecureBootPolicy::Enforcing;
    assert_eq!(policy, SecureBootPolicy::Enforcing);
}

#[test]
fn test_secure_boot_policy_strict() {
    let policy = SecureBootPolicy::Strict;
    assert_eq!(policy, SecureBootPolicy::Strict);
}

#[test]
fn test_secure_boot_policy_equality() {
    assert_eq!(SecureBootPolicy::Disabled, SecureBootPolicy::Disabled);
    assert_ne!(SecureBootPolicy::Disabled, SecureBootPolicy::Enforcing);
    assert_ne!(SecureBootPolicy::Permissive, SecureBootPolicy::Strict);
}

#[test]
fn test_secure_boot_error_variants() {
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
    assert_eq!(errors.len(), 10);
}

#[test]
fn test_boot_measurements_new() {
    let measurements = BootMeasurements::new();
    assert_eq!(measurements.bootloader_hash, [0u8; 32]);
    assert_eq!(measurements.kernel_hash, [0u8; 32]);
    assert!(measurements.initrd_hash.is_none());
    assert!(measurements.acpi_hash.is_none());
    assert!(!measurements.kernel_signature_valid);
    assert!(!measurements.uefi_secure_boot);
    assert_eq!(measurements.boot_timestamp, 0);
    assert!(!measurements.chain_verified);
}

#[test]
fn test_boot_measurements_getters() {
    let measurements = BootMeasurements::new();
    assert_eq!(measurements.get_bootloader_hash(), &[0u8; 32]);
    assert_eq!(measurements.get_kernel_hash(), &[0u8; 32]);
    assert!(!measurements.has_initrd());
    assert!(!measurements.has_acpi());
    assert!(measurements.get_initrd_hash().is_none());
    assert!(measurements.get_acpi_hash().is_none());
}

#[test]
fn test_boot_measurements_signature_state() {
    let measurements = BootMeasurements::new();
    assert!(!measurements.is_signature_valid());
    assert!(!measurements.is_uefi_secure_boot());
}

#[test]
fn test_boot_measurements_pcr_values() {
    let measurements = BootMeasurements::new();
    assert!(measurements.get_pcr(0).is_none());
    assert!(measurements.get_pcr(23).is_none());
    assert!(measurements.get_pcr(100).is_none());
}

#[test]
fn test_boot_measurements_timestamp() {
    let measurements = BootMeasurements::new();
    assert_eq!(measurements.get_boot_timestamp(), 0);
}

#[test]
fn test_boot_measurements_chain_verified() {
    let measurements = BootMeasurements::new();
    assert!(!measurements.is_chain_verified());
}

#[test]
fn test_trusted_boot_keys_new() {
    let keys = TrustedBootKeys::new();
    assert!(keys.production_keys.is_empty());
    assert!(keys.development_keys.is_empty());
    assert!(keys.revoked_fingerprints.is_empty());
    assert_eq!(keys.rotation_count, 0);
}

#[test]
fn test_trusted_boot_keys_getters() {
    let keys = TrustedBootKeys::new();
    assert!(keys.get_production_keys().is_empty());
    assert!(keys.get_development_keys().is_empty());
    assert!(keys.get_revoked().is_empty());
}

#[test]
fn test_trusted_boot_keys_revocation_check() {
    let keys = TrustedBootKeys::new();
    let fingerprint = [0u8; 32];
    assert!(!keys.is_revoked(&fingerprint));
}

#[test]
fn test_trusted_boot_keys_rotation_count() {
    let keys = TrustedBootKeys::new();
    assert_eq!(keys.get_rotation_count(), 0);
}

#[test]
fn test_trusted_boot_keys_total_count() {
    let keys = TrustedBootKeys::new();
    assert_eq!(keys.total_keys(), 0);
}

#[test]
fn test_attestation_report_fields() {
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
    assert!(report.enforcing);
    assert_eq!(report.trusted_key_count, 5);
    assert_eq!(report.revoked_key_count, 1);
    assert!(report.chain_verified);
}

#[test]
fn test_secure_boot_stats_fields() {
    let stats = SecureBootStats {
        initialized: true,
        enforcing: true,
        policy: SecureBootPolicy::Strict,
        chain_verified: true,
        violation_count: 0,
        trusted_keys: 10,
        revoked_keys: 2,
    };
    assert!(stats.initialized);
    assert!(stats.enforcing);
    assert_eq!(stats.policy, SecureBootPolicy::Strict);
    assert!(stats.chain_verified);
    assert_eq!(stats.trusted_keys, 10);
    assert_eq!(stats.revoked_keys, 2);
}

#[test]
fn test_secure_boot_result_ok() {
    let result: SecureBootResult<u32> = Ok(42);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn test_secure_boot_result_err() {
    let result: SecureBootResult<u32> = Err(SecureBootError::SignatureInvalid);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), SecureBootError::SignatureInvalid);
}

#[test]
fn test_secure_boot_error_equality() {
    assert_eq!(SecureBootError::NotInitialized, SecureBootError::NotInitialized);
    assert_ne!(SecureBootError::NotInitialized, SecureBootError::SignatureInvalid);
}

#[test]
fn test_boot_measurements_with_initrd() {
    let mut measurements = BootMeasurements::new();
    measurements.initrd_hash = Some([0xABu8; 32]);
    assert!(measurements.has_initrd());
    assert_eq!(measurements.get_initrd_hash(), Some(&[0xABu8; 32]));
}

#[test]
fn test_boot_measurements_with_acpi() {
    let mut measurements = BootMeasurements::new();
    measurements.acpi_hash = Some([0xCDu8; 32]);
    assert!(measurements.has_acpi());
    assert_eq!(measurements.get_acpi_hash(), Some(&[0xCDu8; 32]));
}

#[test]
fn test_boot_measurements_clone() {
    let measurements = BootMeasurements::new();
    let cloned = measurements.clone();
    assert_eq!(cloned.bootloader_hash, measurements.bootloader_hash);
    assert_eq!(cloned.kernel_hash, measurements.kernel_hash);
}

#[test]
fn test_trusted_key_creation() {
    use alloc::string::String;
    let key = secure_boot::types::TrustedKey {
        name: String::from("test_key"),
        public_key: [0x11u8; 32],
        fingerprint: [0x22u8; 32],
        created_at: 1000,
        expires_at: 2000,
        is_production: true,
    };
    assert_eq!(key.name(), "test_key");
    assert_eq!(key.public_key(), &[0x11u8; 32]);
    assert_eq!(key.fingerprint(), &[0x22u8; 32]);
}

#[test]
fn test_trusted_key_expiration() {
    use alloc::string::String;
    let key = secure_boot::types::TrustedKey {
        name: String::from("expiring_key"),
        public_key: [0u8; 32],
        fingerprint: [0u8; 32],
        created_at: 1000,
        expires_at: 2000,
        is_production: false,
    };
    assert!(!key.is_expired(1500));
    assert!(key.is_expired(2500));
    assert!(!key.is_production());
}

#[test]
fn test_trusted_key_timestamps() {
    use alloc::string::String;
    let key = secure_boot::types::TrustedKey {
        name: String::from("timestamp_key"),
        public_key: [0u8; 32],
        fingerprint: [0u8; 32],
        created_at: 100,
        expires_at: 200,
        is_production: true,
    };
    assert_eq!(key.created_at(), 100);
    assert_eq!(key.expires_at(), 200);
}
