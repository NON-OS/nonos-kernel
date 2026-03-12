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

/*
 * Security policy enforcement.
 *
 * Enforces different policies based on build configuration:
 * - Development: warnings only
 * - Standard: some requirements
 * - Hardened: all security features mandatory
 */

extern crate alloc;

use alloc::format;
use uefi::cstr16;
use uefi::prelude::*;

use crate::log::logger::{log_error, log_info, log_warn};

use super::policy::{EnforcementResult, SecurityPolicy};
use crate::security::types::SecurityContext;

pub fn enforce_security_policy(
    ctx: &SecurityContext,
    system_table: &mut SystemTable<Boot>,
) -> EnforcementResult {
    let policy = SecurityPolicy::from_build();
    let mut result = EnforcementResult::new(policy);

    log_info("enforce", &format!("policy: {:?}", policy));

    enforce_crypto_selftests(ctx, &mut result);
    enforce_keys_loaded(ctx, &mut result);

    match policy {
        SecurityPolicy::Development => {
            if !ctx.secure_boot_enabled { result.warn("SecureBoot disabled"); }
            if !ctx.measured_boot_active { result.warn("TPM not available"); }
        }
        SecurityPolicy::Standard => {
            if !ctx.secure_boot_enabled {
                result.warn("SecureBoot disabled");
                log_warn("enforce", "SecureBoot not enabled");
            }
        }
        SecurityPolicy::Hardened => {
            enforce_hardened_requirements(ctx, &mut result);
        }
    }

    display_result(&result, system_table);
    result
}

fn enforce_hardened_requirements(ctx: &SecurityContext, result: &mut EnforcementResult) {
    if !ctx.secure_boot_enabled {
        result.deny("SecureBoot required");
        log_error("enforce", "BLOCKED: SecureBoot required");
    }
    if !ctx.platform_key_verified {
        result.deny("PlatformKey required");
        log_error("enforce", "BLOCKED: PlatformKey required");
    }
    if !ctx.signature_database_valid {
        result.deny("SignatureDB required");
        log_error("enforce", "BLOCKED: SignatureDB required");
    }
    if !ctx.measured_boot_active {
        result.deny("TPM required");
        log_error("enforce", "BLOCKED: TPM required");
    }
    if !ctx.hardware_rng_available {
        result.deny("HW RNG required");
        log_error("enforce", "BLOCKED: HW RNG required");
    }
}

fn enforce_crypto_selftests(ctx: &SecurityContext, result: &mut EnforcementResult) {
    if !ctx.blake3_selftest_ok {
        result.deny("BLAKE3 selftest failed");
        log_error("enforce", "BLAKE3 selftest FAILED");
    }
    if !ctx.ed25519_selftest_ok {
        result.deny("Ed25519 selftest failed");
        log_error("enforce", "Ed25519 selftest FAILED");
    }
}

fn enforce_keys_loaded(ctx: &SecurityContext, result: &mut EnforcementResult) {
    if !ctx.production_keys_loaded {
        result.deny("signing keys not loaded");
        log_error("enforce", "no signing keys");
    }
    if ctx.key_count == 0 {
        result.deny("zero signing keys");
        log_error("enforce", "key count is zero");
    }
}

fn display_result(result: &EnforcementResult, system_table: &mut SystemTable<Boot>) {
    if result.allow_boot {
        let _ = system_table.stdout().output_string(cstr16!("[SECURITY] PASSED\r\n"));
    } else {
        let _ = system_table.stdout().output_string(cstr16!("[SECURITY] BLOCKED\r\n"));
    }
    for i in 0..result.warning_count {
        if let Some(warning) = result.warnings[i] {
            log_warn("enforce", warning);
        }
    }
}
