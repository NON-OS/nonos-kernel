// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::policy::EnforcementResult;
use crate::log::logger::log_error;
use crate::security::types::SecurityContext;

pub fn enforce_crypto_selftests(ctx: &SecurityContext, result: &mut EnforcementResult) {
    if !ctx.blake3_selftest_ok {
        result.deny("BLAKE3 selftest failed");
        log_error("enforce", "BLAKE3 selftest FAILED");
    }
    if !ctx.ed25519_selftest_ok {
        result.deny("Ed25519 selftest failed");
        log_error("enforce", "Ed25519 selftest FAILED");
    }
}

pub fn enforce_keys_loaded(ctx: &SecurityContext, result: &mut EnforcementResult) {
    if !ctx.production_keys_loaded {
        result.deny("signing keys not loaded");
        log_error("enforce", "no signing keys");
    }
    if ctx.key_count == 0 {
        result.deny("zero signing keys");
        log_error("enforce", "key count is zero");
    }
}

pub fn enforce_hardware_rng(ctx: &SecurityContext, result: &mut EnforcementResult) {
    if !ctx.hardware_rng_available {
        result.deny("HW RNG required");
        log_error("enforce", "BLOCKED: HW RNG required");
    }
}

pub fn enforce_secure_boot(ctx: &SecurityContext, result: &mut EnforcementResult) {
    if !ctx.secure_boot_enabled {
        result.deny("SecureBoot required");
        log_error("enforce", "BLOCKED: SecureBoot required");
    }
}

pub fn enforce_platform_key(ctx: &SecurityContext, result: &mut EnforcementResult) {
    if !ctx.platform_key_verified {
        result.deny("PlatformKey required");
        log_error("enforce", "BLOCKED: PlatformKey required");
    }
}

pub fn enforce_signature_db(ctx: &SecurityContext, result: &mut EnforcementResult) {
    if !ctx.signature_database_valid {
        result.deny("SignatureDB required");
        log_error("enforce", "BLOCKED: SignatureDB required");
    }
}

pub fn enforce_measured_boot(ctx: &SecurityContext, result: &mut EnforcementResult) {
    if !ctx.measured_boot_active {
        result.deny("TPM required");
        log_error("enforce", "BLOCKED: TPM required");
    }
}
