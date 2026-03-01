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
