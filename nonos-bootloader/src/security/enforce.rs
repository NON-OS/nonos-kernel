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

extern crate alloc;

use alloc::format;
use uefi::cstr16;
use uefi::prelude::*;

use super::tpm::{extend_pcr_measurement, pcr};
use super::types::SecurityContext;
use crate::log::logger::{log_error, log_info, log_warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityPolicy {
    Development,
    Standard,
    Hardened,
}

impl SecurityPolicy {
    pub fn from_build() -> Self {
        #[cfg(feature = "hardened")]
        {
            return SecurityPolicy::Hardened;
        }

        #[cfg(feature = "standard")]
        {
            return SecurityPolicy::Standard;
        }

        #[cfg(not(any(feature = "standard", feature = "hardened")))]
        {
            if cfg!(debug_assertions) {
                SecurityPolicy::Development
            } else {
                SecurityPolicy::Standard
            }
        }
    }
}

#[derive(Debug)]
pub struct EnforcementResult {
    pub allow_boot: bool,
    pub reason: &'static str,
    pub warnings: [Option<&'static str>; 8],
    pub warning_count: usize,
    pub policy: SecurityPolicy,
}

impl EnforcementResult {
    fn new(policy: SecurityPolicy) -> Self {
        Self {
            allow_boot: true,
            reason: "checks passed",
            warnings: [None; 8],
            warning_count: 0,
            policy,
        }
    }

    fn deny(&mut self, reason: &'static str) {
        self.allow_boot = false;
        self.reason = reason;
    }

    fn warn(&mut self, warning: &'static str) {
        if self.warning_count < 8 {
            self.warnings[self.warning_count] = Some(warning);
            self.warning_count += 1;
        }
    }
}

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
            if !ctx.secure_boot_enabled {
                result.warn("SecureBoot disabled");
            }
            if !ctx.measured_boot_active {
                result.warn("TPM not available");
            }
        }
        SecurityPolicy::Standard => {
            if !ctx.secure_boot_enabled {
                result.warn("SecureBoot disabled");
                log_warn("enforce", "SecureBoot not enabled");
            }
        }
        SecurityPolicy::Hardened => {
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
    }

    display_result(&result, system_table);
    result
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
        let _ = system_table
            .stdout()
            .output_string(cstr16!("[SECURITY] PASSED\r\n"));
    } else {
        let _ = system_table
            .stdout()
            .output_string(cstr16!("[SECURITY] BLOCKED\r\n"));
    }
    for i in 0..result.warning_count {
        if let Some(warning) = result.warnings[i] {
            log_warn("enforce", warning);
        }
    }
}

pub fn extend_boot_measurements(
    system_table: &mut SystemTable<Boot>,
    kernel_hash: &[u8; 32],
    signature: &[u8; 64],
    zk_proof_hash: &[u8; 32],
) -> bool {
    let mut composite = [0u8; 128];
    composite[0..32].copy_from_slice(kernel_hash);
    composite[32..96].copy_from_slice(signature);
    composite[96..128].copy_from_slice(zk_proof_hash);

    let extended = extend_pcr_measurement(system_table, pcr::KERNEL, &composite);
    if extended {
        log_info("enforce", "measurements extended to PCR9");
    } else {
        log_warn("enforce", "TPM not available");
    }

    let _ = extend_pcr_measurement(system_table, pcr::CAPSULE, zk_proof_hash);
    extended
}

pub fn verify_kernel_version(embedded_version: u32, minimum_version: u32) -> bool {
    if embedded_version < minimum_version {
        log_error(
            "enforce",
            &format!("version {} < minimum {}", embedded_version, minimum_version),
        );
        return false;
    }
    log_info("enforce", &format!("version {} accepted", embedded_version));
    true
}

pub fn detect_secure_boot_bypass(system_table: &mut SystemTable<Boot>) -> bool {
    let rt = system_table.runtime_services();
    let mut setup_mode = [0u8; 1];
    if let Ok(_) = rt.get_variable(
        cstr16!("SetupMode"),
        &uefi::table::runtime::VariableVendor::GLOBAL_VARIABLE,
        &mut setup_mode,
    ) {
        if setup_mode[0] == 1 {
            log_warn("enforce", "UEFI in SetupMode");
            return true;
        }
    }

    let mut audit_mode = [0u8; 1];
    if let Ok(_) = rt.get_variable(
        cstr16!("AuditMode"),
        &uefi::table::runtime::VariableVendor::GLOBAL_VARIABLE,
        &mut audit_mode,
    ) {
        if audit_mode[0] == 1 {
            log_warn("enforce", "UEFI in AuditMode");
            return true;
        }
    }

    false
}

pub fn verify_secure_boot_chain(
    ctx: &SecurityContext,
    system_table: &mut SystemTable<Boot>,
) -> bool {
    if !ctx.secure_boot_enabled {
        return true;
    }
    if detect_secure_boot_bypass(system_table) {
        log_warn("enforce", "SecureBoot bypass detected");
        return false;
    }
    if !ctx.platform_key_verified {
        log_warn("enforce", "PlatformKey not verified");
        return false;
    }
    if !ctx.signature_database_valid {
        log_warn("enforce", "SignatureDB not valid");
        return false;
    }
    log_info("enforce", "SecureBoot chain verified");
    true
}
