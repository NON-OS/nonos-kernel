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
 * Security verification checks.
 *
 * Detects SecureBoot bypass attempts and verifies chain integrity.
 */

extern crate alloc;

use alloc::format;
use uefi::cstr16;
use uefi::prelude::*;

use crate::log::logger::{log_error, log_info, log_warn};
use crate::security::tpm::{extend_pcr_measurement, pcr};
use crate::security::types::SecurityContext;

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
        log_error("enforce", &format!("version {} < minimum {}", embedded_version, minimum_version));
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

pub fn verify_secure_boot_chain(ctx: &SecurityContext, system_table: &mut SystemTable<Boot>) -> bool {
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
