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

use uefi::cstr16;
use uefi::prelude::*;

use crate::crypto::sig::init_production_keys;
use crate::log::logger::{log_error, log_info, log_warn};

use super::check::{
    check_hardware_rng, check_measured_boot, check_platform_key, check_secure_boot,
    check_signature_db,
};
use super::crypto::{blake3_selftest, ed25519_selftest};
use super::types::SecurityContext;

pub fn initialize_security_subsystem(system_table: &mut SystemTable<Boot>) -> SecurityContext {
    let mut ctx = SecurityContext::new();

    let _ = system_table
        .stdout()
        .output_string(cstr16!("=== Security Init ===\r\n"));

    let _ = system_table.stdout().output_string(cstr16!(
        "   [INFO] Initializing cryptographic keystore...\r\n"
    ));

    match init_production_keys() {
        Ok(count) => {
            ctx.production_keys_loaded = true;
            ctx.key_count = count;
            log_info("security", "Production keys loaded successfully");
        }
        Err(_) => {
            ctx.production_keys_loaded = false;
            ctx.key_count = 0;
            log_error("security", "CRITICAL: Failed to load production keys!");
            let _ = system_table
                .stdout()
                .output_string(cstr16!("   [CRITICAL] Key initialization FAILED!\r\n"));
        }
    }

    ctx.secure_boot_enabled = check_secure_boot(system_table);
    ctx.platform_key_verified = check_platform_key(system_table);
    ctx.signature_database_valid = check_signature_db(system_table);
    ctx.hardware_rng_available = check_hardware_rng(system_table);

    ctx.blake3_selftest_ok = blake3_selftest();
    ctx.ed25519_selftest_ok = ed25519_selftest();

    ctx.measured_boot_active = check_measured_boot(system_table);

    display_security_status(&ctx, system_table);

    ctx
}

fn display_security_status(ctx: &SecurityContext, system_table: &mut SystemTable<Boot>) {
    let _ = system_table
        .stdout()
        .output_string(cstr16!("=== Security Status ===\r\n"));

    output_status(system_table, "Production Keys", ctx.production_keys_loaded);
    output_status(system_table, "SecureBoot", ctx.secure_boot_enabled);
    output_status(system_table, "PlatformKey", ctx.platform_key_verified);
    output_status(system_table, "SignatureDB", ctx.signature_database_valid);
    output_status(system_table, "HW RNG", ctx.hardware_rng_available);
    output_status(system_table, "Measured Boot", ctx.measured_boot_active);
    output_status(system_table, "Ed25519", ctx.ed25519_selftest_ok);
    output_status(system_table, "BLAKE3", ctx.blake3_selftest_ok);

    let _ = system_table
        .stdout()
        .output_string(cstr16!("=======================\r\n"));
}

fn output_status(system_table: &mut SystemTable<Boot>, name: &str, ok: bool) {
    if ok {
        let _ = system_table.stdout().output_string(match name {
            "Production Keys" => cstr16!("Production Keys: LOADED\r\n"),
            "SecureBoot" => cstr16!("SecureBoot: ENABLED\r\n"),
            "PlatformKey" => cstr16!("PlatformKey: OK\r\n"),
            "SignatureDB" => cstr16!("SignatureDB: OK\r\n"),
            "HW RNG" => cstr16!("HW RNG: AVAILABLE\r\n"),
            "Measured Boot" => cstr16!("Measured Boot: ACTIVE\r\n"),
            "Ed25519" => cstr16!("Ed25519: PASS\r\n"),
            "BLAKE3" => cstr16!("BLAKE3: PASS\r\n"),
            _ => cstr16!("Unknown: OK\r\n"),
        });
    } else {
        let _ = system_table.stdout().output_string(match name {
            "Production Keys" => cstr16!("Production Keys: FAILED!\r\n"),
            "SecureBoot" => cstr16!("SecureBoot: DISABLED\r\n"),
            "PlatformKey" => cstr16!("PlatformKey: MISSING\r\n"),
            "SignatureDB" => cstr16!("SignatureDB: MISSING\r\n"),
            "HW RNG" => cstr16!("HW RNG: MISSING\r\n"),
            "Measured Boot" => cstr16!("Measured Boot: INACTIVE\r\n"),
            "Ed25519" => cstr16!("Ed25519: FAIL\r\n"),
            "BLAKE3" => cstr16!("BLAKE3: FAIL\r\n"),
            _ => cstr16!("Unknown: FAIL\r\n"),
        });
    }
}

pub fn assess_security_posture(ctx: &SecurityContext, system_table: &mut SystemTable<Boot>) -> u32 {
    let score = ctx.security_score();

    let _ = system_table
        .stdout()
        .output_string(cstr16!("   [INFO] Security posture assessment:\r\n"));

    if score >= 80 {
        let _ = system_table
            .stdout()
            .output_string(cstr16!("   [SUCCESS] Security Score: EXCELLENT\r\n"));
        log_info("security", "Security posture: EXCELLENT");
    } else if score >= 60 {
        let _ = system_table
            .stdout()
            .output_string(cstr16!("   [INFO] Security Score: GOOD\r\n"));
        log_info("security", "Security posture: GOOD");
    } else if score >= 40 {
        let _ = system_table
            .stdout()
            .output_string(cstr16!("   [WARN] Security Score: MODERATE\r\n"));
        log_warn(
            "security",
            "Security posture: MODERATE - some features missing",
        );
    } else {
        let _ = system_table
            .stdout()
            .output_string(cstr16!("   [CRITICAL] Security Score: LOW\r\n"));
        log_error(
            "security",
            "Security posture: LOW - critical features missing!",
        );
    }

    score
}
