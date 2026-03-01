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

use core::sync::atomic::Ordering;
use crate::crypto::constant_time::ct_eq_32;
use crate::crypto::ed25519;
use super::types::{SecureBootError, SecureBootResult};
use super::state::{SECURE_BOOT_INITIALIZED, TRUSTED_BOOT_KEYS, BOOT_MEASUREMENTS, VIOLATION_COUNT, BOOT_CHAIN_VERIFIED};
use super::policy::is_enforcing;

pub fn verify_code_signature(code: &[u8], signature: &[u8; 64]) -> SecureBootResult<[u8; 32]> {
    if !SECURE_BOOT_INITIALIZED.load(Ordering::SeqCst) {
        return Err(SecureBootError::NotInitialized);
    }

    let keys = TRUSTED_BOOT_KEYS.read();

    if keys.production_keys.is_empty() {
        return Err(SecureBootError::NoTrustedKeys);
    }

    let code_hash = crate::crypto::blake3::blake3_hash(code);
    let now = crate::time::timestamp_secs();

    for key in &keys.production_keys {
        let mut is_revoked = false;
        for revoked_fp in &keys.revoked_fingerprints {
            if ct_eq_32(&key.fingerprint, revoked_fp) {
                is_revoked = true;
                break;
            }
        }
        if is_revoked {
            continue;
        }

        if key.expires_at != 0 && now > key.expires_at {
            continue;
        }

        let sig = crate::crypto::ed25519::Signature::from_bytes(signature);
        if ed25519::verify(&key.public_key, &code_hash, &sig) {
            crate::log::info!("[SECURE_BOOT] Signature verified with key: {}", key.name);
            return Ok(key.fingerprint);
        }
    }

    if is_enforcing() {
        VIOLATION_COUNT.fetch_add(1, Ordering::SeqCst);
        crate::log::error!("[SECURE_BOOT] VIOLATION: Signature verification FAILED");
    }

    Err(SecureBootError::SignatureInvalid)
}

pub fn verify_kernel(kernel_data: &[u8]) -> SecureBootResult<()> {
    const MIN_KERNEL_SIZE: usize = 64 + 4096;

    if kernel_data.len() < MIN_KERNEL_SIZE {
        return Err(SecureBootError::CryptoError);
    }

    let sig_offset = kernel_data.len() - 64;
    let code = &kernel_data[..sig_offset];
    let sig_bytes = &kernel_data[sig_offset..];

    let mut signature = [0u8; 64];
    signature.copy_from_slice(sig_bytes);

    if signature.iter().all(|&b| b == 0) {
        return Err(SecureBootError::SignatureInvalid);
    }

    let _result = verify_code_signature(code, &signature)?;

    let mut measurements = BOOT_MEASUREMENTS.write();
    measurements.kernel_hash = crate::crypto::blake3::blake3_hash(code);
    measurements.kernel_signature_valid = true;

    crate::log::info!("[SECURE_BOOT] Kernel signature VALID");

    Ok(())
}

pub fn record_boot_measurements(bootloader_hash: [u8; 32], kernel_hash: [u8; 32], uefi_secure_boot: bool) {
    let mut measurements = BOOT_MEASUREMENTS.write();
    measurements.bootloader_hash = bootloader_hash;
    measurements.kernel_hash = kernel_hash;
    measurements.uefi_secure_boot = uefi_secure_boot;
    measurements.boot_timestamp = crate::arch::x86_64::time::tsc::read_tsc();
}

pub fn verify_boot_chain() -> SecureBootResult<()> {
    if !SECURE_BOOT_INITIALIZED.load(Ordering::SeqCst) {
        return Err(SecureBootError::NotInitialized);
    }

    let measurements = BOOT_MEASUREMENTS.read();

    if measurements.kernel_hash.iter().all(|&b| b == 0) {
        return Err(SecureBootError::NotMeasured);
    }

    if !measurements.kernel_signature_valid {
        if is_enforcing() {
            return Err(SecureBootError::ChainBroken);
        }
        crate::log::log_warning!("[SECURE_BOOT] Boot chain incomplete - kernel not signed");
    }

    drop(measurements);
    BOOT_MEASUREMENTS.write().chain_verified = true;
    BOOT_CHAIN_VERIFIED.store(true, Ordering::SeqCst);

    crate::log::info!("[SECURE_BOOT] Boot chain verification complete");

    Ok(())
}

pub fn is_boot_chain_verified() -> bool {
    BOOT_CHAIN_VERIFIED.load(Ordering::SeqCst)
}
