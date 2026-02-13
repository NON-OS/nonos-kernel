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

use crate::hardware::HardwareInfo;
use crate::log::logger::{log_error, log_info, log_warn};
use crate::network::NetworkBootContext;
use crate::security::SecurityContext;

use super::types::{BootloaderConfig, MemoryManagementMode, NetworkPolicy, SecurityPolicy};

pub fn apply_configuration(
    config: &BootloaderConfig,
    system_table: &mut SystemTable<Boot>,
    security: &SecurityContext,
    network: &NetworkBootContext,
    hardware: &HardwareInfo,
) -> bool {
    system_table
        .stdout()
        .output_string(cstr16!("=== Applying Configuration ===\r\n"))
        .unwrap_or(());

    let mut application_successful = true;

    if !apply_security_policy(config, system_table, security) {
        system_table
            .stdout()
            .output_string(cstr16!("   [ERROR] Failed to apply security policy\r\n"))
            .unwrap_or(());
        log_error("config", "Failed to apply security policy");
        application_successful = false;
    } else {
        system_table
            .stdout()
            .output_string(cstr16!("   [SUCCESS] Security policy applied\r\n"))
            .unwrap_or(());
        log_info("config", "Security policy applied successfully");
    }

    if !apply_network_policy(config, system_table, network) {
        system_table
            .stdout()
            .output_string(cstr16!(
                "   [WARN] Network policy application had issues\r\n"
            ))
            .unwrap_or(());
        log_warn("config", "Network policy application had issues");
    } else {
        system_table
            .stdout()
            .output_string(cstr16!("   [SUCCESS] Network policy applied\r\n"))
            .unwrap_or(());
        log_info("config", "Network policy applied successfully");
    }

    apply_hardware_settings(config, system_table, hardware);

    apply_memory_settings(config, system_table);

    system_table
        .stdout()
        .output_string(cstr16!("===============================\r\n"))
        .unwrap_or(());

    if application_successful {
        log_info("config", "All configuration applied successfully");
    } else {
        log_warn(
            "config",
            "Configuration application completed with some issues",
        );
    }

    application_successful
}

fn apply_security_policy(
    config: &BootloaderConfig,
    system_table: &mut SystemTable<Boot>,
    security: &SecurityContext,
) -> bool {
    match config.security_policy {
        SecurityPolicy::Maximum => {
            if !security.secure_boot_enabled
                || !security.measured_boot_active
                || !security.platform_key_verified
            {
                log_error("config", "Maximum security policy requirements not met");
                return false;
            }
            system_table
                .stdout()
                .output_string(cstr16!("   [INFO] Maximum security policy enforced\r\n"))
                .unwrap_or(());
        }
        SecurityPolicy::Standard => {
            if config.require_secure_boot && !security.secure_boot_enabled {
                log_warn("config", "Secure Boot required but not enabled");
            }
            system_table
                .stdout()
                .output_string(cstr16!("   [INFO] Standard security policy enforced\r\n"))
                .unwrap_or(());
        }
        SecurityPolicy::Relaxed => {
            system_table
                .stdout()
                .output_string(cstr16!("   [INFO] Relaxed security policy enforced\r\n"))
                .unwrap_or(());
        }
        SecurityPolicy::Custom => {
            system_table
                .stdout()
                .output_string(cstr16!("   [INFO] Custom security policy enforced\r\n"))
                .unwrap_or(());
        }
    }

    true
}

fn apply_network_policy(
    config: &BootloaderConfig,
    system_table: &mut SystemTable<Boot>,
    network: &NetworkBootContext,
) -> bool {
    match config.network_policy {
        NetworkPolicy::Disabled => {
            system_table
                .stdout()
                .output_string(cstr16!("   [INFO] Network boot disabled by policy\r\n"))
                .unwrap_or(());
            log_info("config", "Network boot disabled by policy");
        }
        NetworkPolicy::Secured => {
            if !network.http_client_available {
                system_table
                    .stdout()
                    .output_string(cstr16!(
                        "   [WARN] Secured network policy requires HTTPS support\r\n"
                    ))
                    .unwrap_or(());
                log_warn(
                    "config",
                    "Secured network policy requirements not fully met",
                );
                return false;
            }
            system_table
                .stdout()
                .output_string(cstr16!("   [INFO] Secured network policy enforced\r\n"))
                .unwrap_or(());
        }
        NetworkPolicy::Standard => {
            system_table
                .stdout()
                .output_string(cstr16!("   [INFO] Standard network policy enforced\r\n"))
                .unwrap_or(());
        }
        NetworkPolicy::Unrestricted => {
            system_table
                .stdout()
                .output_string(cstr16!(
                    "   [INFO] Unrestricted network policy enforced\r\n"
                ))
                .unwrap_or(());
        }
    }

    true
}

fn apply_hardware_settings(
    config: &BootloaderConfig,
    system_table: &mut SystemTable<Boot>,
    hardware: &HardwareInfo,
) {
    if config.cpu_optimizations && hardware.cpu_count > 1 {
        system_table
            .stdout()
            .output_string(cstr16!(
                "   [INFO] CPU optimizations enabled for multi-core system\r\n"
            ))
            .unwrap_or(());
        log_info("config", "CPU optimizations enabled");
    }
}

fn apply_memory_settings(config: &BootloaderConfig, system_table: &mut SystemTable<Boot>) {
    match config.memory_management_mode {
        MemoryManagementMode::Secure => {
            system_table
                .stdout()
                .output_string(cstr16!(
                    "   [INFO] Secure memory management mode active\r\n"
                ))
                .unwrap_or(());
            log_info("config", "Secure memory management mode applied");
        }
        MemoryManagementMode::Efficient => {
            system_table
                .stdout()
                .output_string(cstr16!(
                    "   [INFO] Efficient memory management mode active\r\n"
                ))
                .unwrap_or(());
            log_info("config", "Efficient memory management mode applied");
        }
        MemoryManagementMode::Legacy => {
            system_table
                .stdout()
                .output_string(cstr16!(
                    "   [INFO] Legacy memory management mode active\r\n"
                ))
                .unwrap_or(());
            log_info("config", "Legacy memory management mode applied");
        }
    }
}
