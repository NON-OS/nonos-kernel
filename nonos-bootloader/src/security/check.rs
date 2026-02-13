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

use crate::log::logger::{log_debug, log_error, log_info, log_warn};

pub fn check_secure_boot(system_table: &mut SystemTable<Boot>) -> bool {
    let rt = system_table.runtime_services();
    let mut buf = [0u8; 1];
    let name = cstr16!("SecureBoot");
    match rt.get_variable(
        name,
        &uefi::table::runtime::VariableVendor::GLOBAL_VARIABLE,
        &mut buf,
    ) {
        Ok(_) => {
            let enabled = buf[0] == 1;
            log_info(
                "security",
                if enabled {
                    "SecureBoot ENABLED"
                } else {
                    "SecureBoot DISABLED"
                },
            );
            enabled
        }
        Err(e) => {
            log_error(
                "security",
                &format!("Cannot read SecureBoot variable: {:?}", e.status()),
            );
            false
        }
    }
}

pub fn check_platform_key(system_table: &mut SystemTable<Boot>) -> bool {
    let rt = system_table.runtime_services();
    let mut buf = [0u8; 2048];
    let name = cstr16!("PK");
    match rt.get_variable(
        name,
        &uefi::table::runtime::VariableVendor::GLOBAL_VARIABLE,
        &mut buf,
    ) {
        Ok(_) => {
            log_info("security", "Platform Key present");
            buf.iter().any(|&b| b != 0)
        }
        Err(e) => {
            log_error(
                "security",
                &format!("Platform Key missing: {:?}", e.status()),
            );
            false
        }
    }
}

pub fn check_signature_db(system_table: &mut SystemTable<Boot>) -> bool {
    let rt = system_table.runtime_services();
    let mut buf = [0u8; 4096];
    let name = cstr16!("db");
    match rt.get_variable(
        name,
        &uefi::table::runtime::VariableVendor::GLOBAL_VARIABLE,
        &mut buf,
    ) {
        Ok(_) => {
            log_info("security", "Signature DB present");
            buf.iter().any(|&b| b != 0)
        }
        Err(e) => {
            log_error(
                "security",
                &format!("Signature DB missing: {:?}", e.status()),
            );
            false
        }
    }
}

pub fn check_hardware_rng(system_table: &mut SystemTable<Boot>) -> bool {
    let bs = system_table.boot_services();
    if let Ok(handles) = bs.find_handles::<uefi::proto::rng::Rng>() {
        if !handles.is_empty() {
            log_info("rng", "EFI RNG protocol detected");
            return true;
        }
    }

    #[cfg(target_arch = "x86_64")]
    if cpu_rng_supported() {
        log_info("rng", "CPU RDRAND/RDSEED available");
        return true;
    }

    log_warn("rng", "No hardware RNG found");
    false
}

pub fn check_measured_boot(system_table: &mut SystemTable<Boot>) -> bool {
    use super::tpm::{extend_pcr_measurement, pcr};
    let test_data = b"NONOS:TPM:PROBE:v1";
    if extend_pcr_measurement(system_table, pcr::BOOTLOADER, test_data) {
        log_info("security", "TPM 2.0 measured boot available");
        true
    } else {
        log_debug("security", "TPM 2.0 not available or not responding");
        false
    }
}

#[cfg(target_arch = "x86_64")]
fn cpu_rng_supported() -> bool {
    unsafe {
        let (_, _, ecx, _) = cpuid(1);
        let rdrand = (ecx & (1 << 30)) != 0;
        let (_, ebx, _, _) = cpuid(7);
        let rdseed = (ebx & (1 << 18)) != 0;
        rdrand || rdseed
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    core::arch::asm!(
        "push rbx",
        "cpuid",
        "mov {ebx_out:e}, ebx",
        "pop rbx",
        inout("eax") leaf => eax,
        ebx_out = out(reg) ebx,
        out("ecx") ecx,
        out("edx") edx,
        options(nostack, preserves_flags)
    );

    (eax, ebx, ecx, edx)
}
