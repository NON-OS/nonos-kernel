// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct BootMeasurements {
    pub bootloader_hash: [u8; 32],
    pub kernel_hash: [u8; 32],
    pub initrd_hash: Option<[u8; 32]>,
    pub acpi_hash: Option<[u8; 32]>,
    pub kernel_signature_valid: bool,
    pub uefi_secure_boot: bool,
    pub pcr_values: [Option<[u8; 32]>; 24],
    pub boot_timestamp: u64,
    pub chain_verified: bool,
}

impl BootMeasurements {
    pub const fn new() -> Self {
        Self {
            bootloader_hash: [0u8; 32],
            kernel_hash: [0u8; 32],
            initrd_hash: None,
            acpi_hash: None,
            kernel_signature_valid: false,
            uefi_secure_boot: false,
            pcr_values: [None; 24],
            boot_timestamp: 0,
            chain_verified: false,
        }
    }

    /// Get bootloader hash
    pub fn get_bootloader_hash(&self) -> &[u8; 32] {
        &self.bootloader_hash
    }

    /// Get kernel hash
    pub fn get_kernel_hash(&self) -> &[u8; 32] {
        &self.kernel_hash
    }

    /// Check if initrd was measured
    pub fn has_initrd(&self) -> bool {
        self.initrd_hash.is_some()
    }

    /// Get initrd hash if present
    pub fn get_initrd_hash(&self) -> Option<&[u8; 32]> {
        self.initrd_hash.as_ref()
    }

    /// Check if ACPI was measured
    pub fn has_acpi(&self) -> bool {
        self.acpi_hash.is_some()
    }

    /// Get ACPI hash if present
    pub fn get_acpi_hash(&self) -> Option<&[u8; 32]> {
        self.acpi_hash.as_ref()
    }

    /// Check if kernel signature was verified
    pub fn is_signature_valid(&self) -> bool {
        self.kernel_signature_valid
    }

    /// Check if UEFI secure boot is active
    pub fn is_uefi_secure_boot(&self) -> bool {
        self.uefi_secure_boot
    }

    /// Get a specific PCR value
    pub fn get_pcr(&self, index: usize) -> Option<&[u8; 32]> {
        self.pcr_values.get(index).and_then(|p| p.as_ref())
    }

    /// Get boot timestamp
    pub fn get_boot_timestamp(&self) -> u64 {
        self.boot_timestamp
    }

    /// Check if chain is verified
    pub fn is_chain_verified(&self) -> bool {
        self.chain_verified
    }
}

pub struct TrustedBootKeys {
    pub production_keys: Vec<TrustedKey>,
    pub development_keys: Vec<TrustedKey>,
    pub revoked_fingerprints: Vec<[u8; 32]>,
    pub rotation_count: u64,
}

impl TrustedBootKeys {
    pub const fn new() -> Self {
        Self {
            production_keys: Vec::new(),
            development_keys: Vec::new(),
            revoked_fingerprints: Vec::new(),
            rotation_count: 0,
        }
    }

    /// Get production keys
    pub fn get_production_keys(&self) -> &[TrustedKey] {
        &self.production_keys
    }

    /// Get development keys
    pub fn get_development_keys(&self) -> &[TrustedKey] {
        &self.development_keys
    }

    /// Get revoked fingerprints
    pub fn get_revoked(&self) -> &[[u8; 32]] {
        &self.revoked_fingerprints
    }

    /// Check if a fingerprint is revoked
    pub fn is_revoked(&self, fingerprint: &[u8; 32]) -> bool {
        self.revoked_fingerprints.iter().any(|f| f == fingerprint)
    }

    /// Get rotation count
    pub fn get_rotation_count(&self) -> u64 {
        self.rotation_count
    }

    /// Get total key count
    pub fn total_keys(&self) -> usize {
        self.production_keys.len() + self.development_keys.len()
    }
}

#[derive(Clone)]
pub struct TrustedKey {
    pub name: String,
    pub public_key: [u8; 32],
    pub fingerprint: [u8; 32],
    pub created_at: u64,
    pub expires_at: u64,
    pub is_production: bool,
}

impl TrustedKey {
    /// Get key name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get public key
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Get fingerprint
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Get creation timestamp
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Get expiration timestamp
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Check if this is a production key
    pub fn is_production(&self) -> bool {
        self.is_production
    }

    /// Check if key is expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.expires_at
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBootPolicy {
    Disabled,
    Permissive,
    Enforcing,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBootError {
    NotInitialized,
    NoTrustedKeys,
    SignatureInvalid,
    KeyRevoked,
    KeyExpired,
    HashMismatch,
    NotMeasured,
    ChainBroken,
    PolicyViolation,
    CryptoError,
}

pub type SecureBootResult<T> = Result<T, SecureBootError>;

#[derive(Debug, Clone)]
pub struct AttestationReport {
    pub measurements: BootMeasurements,
    pub policy: SecureBootPolicy,
    pub enforcing: bool,
    pub violation_count: u64,
    pub trusted_key_count: usize,
    pub revoked_key_count: usize,
    pub chain_verified: bool,
}

#[derive(Debug, Clone)]
pub struct SecureBootStats {
    pub initialized: bool,
    pub enforcing: bool,
    pub policy: SecureBootPolicy,
    pub chain_verified: bool,
    pub violation_count: u64,
    pub trusted_keys: usize,
    pub revoked_keys: usize,
}
