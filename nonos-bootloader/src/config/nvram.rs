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

use uefi::prelude::*;
use uefi::{cstr16, CStr16};

use crate::log::logger::{log_debug, log_error, log_info};

use super::types::{BootloaderConfig, GraphicsMode, NetworkPolicy, SecurityPolicy};

const MAX_BOOT_TIMEOUT: u32 = 300;

pub fn load_bootloader_config(system_table: &mut SystemTable<Boot>) -> BootloaderConfig {
    let mut config = BootloaderConfig::default();

    system_table
        .stdout()
        .output_string(cstr16!("=== Loading Bootloader Configuration ===\r\n"))
        .unwrap_or(());

    let security_policy = {
        let rt = system_table.runtime_services();
        load_security_policy(rt)
    };
    if let Some(policy) = security_policy {
        config.security_policy = policy;
        system_table
            .stdout()
            .output_string(cstr16!(
                "   [SUCCESS] Security policy loaded from NVRAM\r\n"
            ))
            .unwrap_or(());
        log_info("config", "Security policy loaded from NVRAM");
    } else {
        system_table
            .stdout()
            .output_string(cstr16!("   [INFO] Using default security policy\r\n"))
            .unwrap_or(());
        log_debug("config", "Using default security policy");
    }

    let network_policy = {
        let rt = system_table.runtime_services();
        load_network_policy(rt)
    };
    if let Some(policy) = network_policy {
        config.network_policy = policy;
        system_table
            .stdout()
            .output_string(cstr16!("   [SUCCESS] Network policy loaded from NVRAM\r\n"))
            .unwrap_or(());
        log_info("config", "Network policy loaded from NVRAM");
    } else {
        system_table
            .stdout()
            .output_string(cstr16!("   [INFO] Using default network policy\r\n"))
            .unwrap_or(());
        log_debug("config", "Using default network policy");
    }

    let boot_timeout = {
        let rt = system_table.runtime_services();
        load_boot_timeout(rt)
    };
    if let Some(timeout) = boot_timeout {
        config.boot_timeout_seconds = timeout;
        system_table
            .stdout()
            .output_string(cstr16!("   [SUCCESS] Boot timeout loaded from NVRAM\r\n"))
            .unwrap_or(());
        log_info("config", "Boot timeout loaded from NVRAM");
    }

    let graphics_mode = {
        let rt = system_table.runtime_services();
        load_graphics_mode(rt)
    };
    if let Some(mode) = graphics_mode {
        config.graphics_mode = mode;
        system_table
            .stdout()
            .output_string(cstr16!("   [SUCCESS] Graphics mode loaded from NVRAM\r\n"))
            .unwrap_or(());
        log_info("config", "Graphics mode loaded from NVRAM");
    }

    config.verbose_logging = {
        let rt = system_table.runtime_services();
        load_bool_variable(rt, cstr16!("NonosVerboseLogging"))
    };
    config.diagnostic_output = {
        let rt = system_table.runtime_services();
        load_bool_variable(rt, cstr16!("NonosDiagnosticOutput"))
    };

    system_table
        .stdout()
        .output_string(cstr16!("========================================\r\n"))
        .unwrap_or(());
    log_info("config", "Configuration loading completed");

    config
}

fn load_security_policy(rt: &uefi::table::runtime::RuntimeServices) -> Option<SecurityPolicy> {
    let mut buffer = [0u8; 4];
    let var_name = cstr16!("NonosSecurityPolicy");

    match rt.get_variable(
        var_name,
        &uefi::table::runtime::VariableVendor::GLOBAL_VARIABLE,
        &mut buffer,
    ) {
        Ok(_) => SecurityPolicy::from_u8(buffer[0]),
        Err(_) => None,
    }
}

fn load_network_policy(rt: &uefi::table::runtime::RuntimeServices) -> Option<NetworkPolicy> {
    let mut buffer = [0u8; 4];
    let var_name = cstr16!("NonosNetworkPolicy");

    match rt.get_variable(
        var_name,
        &uefi::table::runtime::VariableVendor::GLOBAL_VARIABLE,
        &mut buffer,
    ) {
        Ok(_) => NetworkPolicy::from_u8(buffer[0]),
        Err(_) => None,
    }
}

fn load_boot_timeout(rt: &uefi::table::runtime::RuntimeServices) -> Option<u32> {
    let mut buffer = [0u8; 4];
    let var_name = cstr16!("NonosBootTimeout");

    match rt.get_variable(
        var_name,
        &uefi::table::runtime::VariableVendor::GLOBAL_VARIABLE,
        &mut buffer,
    ) {
        Ok(_) => {
            let timeout = u32::from_le_bytes(buffer);
            if timeout <= MAX_BOOT_TIMEOUT {
                Some(timeout)
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

fn load_graphics_mode(rt: &uefi::table::runtime::RuntimeServices) -> Option<GraphicsMode> {
    let mut buffer = [0u8; 4];
    let var_name = cstr16!("NonosGraphicsMode");

    match rt.get_variable(
        var_name,
        &uefi::table::runtime::VariableVendor::GLOBAL_VARIABLE,
        &mut buffer,
    ) {
        Ok(_) => GraphicsMode::from_u8(buffer[0]),
        Err(_) => None,
    }
}

fn load_bool_variable(rt: &uefi::table::runtime::RuntimeServices, name: &CStr16) -> bool {
    let mut buffer = [0u8; 1];

    match rt.get_variable(
        name,
        &uefi::table::runtime::VariableVendor::GLOBAL_VARIABLE,
        &mut buffer,
    ) {
        Ok(_) => buffer[0] != 0,
        Err(_) => false,
    }
}

pub fn save_configuration(config: &BootloaderConfig, system_table: &mut SystemTable<Boot>) -> bool {
    system_table
        .stdout()
        .output_string(cstr16!("=== Saving Configuration ===\r\n"))
        .unwrap_or(());

    let mut save_successful = true;

    let policy_saved = {
        let rt = system_table.runtime_services();
        save_u8_variable(
            rt,
            cstr16!("NonosSecurityPolicy"),
            config.security_policy.to_u8(),
        )
    };
    if policy_saved {
        system_table
            .stdout()
            .output_string(cstr16!("   [SUCCESS] Security policy saved\r\n"))
            .unwrap_or(());
        log_info("config", "Security policy saved to NVRAM");
    } else {
        system_table
            .stdout()
            .output_string(cstr16!("   [ERROR] Failed to save security policy\r\n"))
            .unwrap_or(());
        log_error("config", "Failed to save security policy to NVRAM");
        save_successful = false;
    }

    let network_policy_saved = {
        let rt = system_table.runtime_services();
        save_u8_variable(
            rt,
            cstr16!("NonosNetworkPolicy"),
            config.network_policy.to_u8(),
        )
    };
    if network_policy_saved {
        system_table
            .stdout()
            .output_string(cstr16!("   [SUCCESS] Network policy saved\r\n"))
            .unwrap_or(());
        log_info("config", "Network policy saved to NVRAM");
    } else {
        system_table
            .stdout()
            .output_string(cstr16!("   [ERROR] Failed to save network policy\r\n"))
            .unwrap_or(());
        log_error("config", "Failed to save network policy to NVRAM");
        save_successful = false;
    }

    system_table
        .stdout()
        .output_string(cstr16!("=============================\r\n"))
        .unwrap_or(());

    if save_successful {
        log_info("config", "Configuration saved successfully");
    } else {
        log_error("config", "Configuration saving completed with some errors");
    }

    save_successful
}

fn save_u8_variable(rt: &uefi::table::runtime::RuntimeServices, name: &CStr16, value: u8) -> bool {
    let data = [value];
    let attributes = uefi::table::runtime::VariableAttributes::NON_VOLATILE
        | uefi::table::runtime::VariableAttributes::BOOTSERVICE_ACCESS
        | uefi::table::runtime::VariableAttributes::RUNTIME_ACCESS;

    rt.set_variable(
        name,
        &uefi::table::runtime::VariableVendor::GLOBAL_VARIABLE,
        attributes,
        &data,
    )
    .is_ok()
}
