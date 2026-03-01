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
use super::types::{BootMeasurements, AttestationReport, SecureBootStats, SecureBootResult};
use super::state::{SECURE_BOOT_INITIALIZED, BOOT_CHAIN_VERIFIED, VIOLATION_COUNT, BOOT_MEASUREMENTS, TRUSTED_BOOT_KEYS};
use super::policy::{get_policy, is_enforcing};
use super::keys::load_embedded_keys;

pub fn init() -> SecureBootResult<()> {
    if SECURE_BOOT_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    load_embedded_keys()?;

    SECURE_BOOT_INITIALIZED.store(true, Ordering::SeqCst);

    crate::log::info!("[SECURE_BOOT] Subsystem initialized");

    Ok(())
}

pub fn get_boot_measurements() -> BootMeasurements {
    BOOT_MEASUREMENTS.read().clone()
}

pub fn generate_attestation_report() -> AttestationReport {
    let measurements = BOOT_MEASUREMENTS.read();
    let keys = TRUSTED_BOOT_KEYS.read();

    AttestationReport {
        measurements: measurements.clone(),
        policy: get_policy(),
        enforcing: is_enforcing(),
        violation_count: VIOLATION_COUNT.load(Ordering::SeqCst),
        trusted_key_count: keys.production_keys.len(),
        revoked_key_count: keys.revoked_fingerprints.len(),
        chain_verified: BOOT_CHAIN_VERIFIED.load(Ordering::SeqCst),
    }
}

pub fn get_stats() -> SecureBootStats {
    let keys = TRUSTED_BOOT_KEYS.read();

    SecureBootStats {
        initialized: SECURE_BOOT_INITIALIZED.load(Ordering::SeqCst),
        enforcing: is_enforcing(),
        policy: get_policy(),
        chain_verified: BOOT_CHAIN_VERIFIED.load(Ordering::SeqCst),
        violation_count: VIOLATION_COUNT.load(Ordering::SeqCst),
        trusted_keys: keys.production_keys.len() + keys.development_keys.len(),
        revoked_keys: keys.revoked_fingerprints.len(),
    }
}
