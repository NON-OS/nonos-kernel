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

use crate::log::logger::{log_error, log_warn};
use crate::security::SecurityContext;

use super::types::{BootloaderConfig, SecurityPolicy};

pub fn apply_security_policy(
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
