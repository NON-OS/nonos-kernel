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

use super::types::{
    BootloaderConfig, NetworkPolicy, PreferredBootMethod, SecurityPolicy,
};

pub fn display_configuration(config: &BootloaderConfig, system_table: &mut SystemTable<Boot>) {
    system_table
        .stdout()
        .output_string(cstr16!("====== BOOT CONFIGURATION ======\r\n"))
        .unwrap_or(());

    display_security_policy(config, system_table);
    display_network_policy(config, system_table);
    display_boot_method(config, system_table);
    display_other_settings(config, system_table);

    system_table
        .stdout()
        .output_string(cstr16!("================================\r\n\r\n"))
        .unwrap_or(());
}

fn display_security_policy(config: &BootloaderConfig, system_table: &mut SystemTable<Boot>) {
    match config.security_policy {
        SecurityPolicy::Maximum => {
            system_table
                .stdout()
                .output_string(cstr16!("Security Policy:   MAXIMUM\r\n"))
                .unwrap_or(());
        }
        SecurityPolicy::Standard => {
            system_table
                .stdout()
                .output_string(cstr16!("Security Policy:   STANDARD\r\n"))
                .unwrap_or(());
        }
        SecurityPolicy::Relaxed => {
            system_table
                .stdout()
                .output_string(cstr16!("Security Policy:   RELAXED\r\n"))
                .unwrap_or(());
        }
        SecurityPolicy::Custom => {
            system_table
                .stdout()
                .output_string(cstr16!("Security Policy:   CUSTOM\r\n"))
                .unwrap_or(());
        }
    }
}

fn display_network_policy(config: &BootloaderConfig, system_table: &mut SystemTable<Boot>) {
    match config.network_policy {
        NetworkPolicy::Disabled => {
            system_table
                .stdout()
                .output_string(cstr16!("Network Policy:    DISABLED\r\n"))
                .unwrap_or(());
        }
        NetworkPolicy::Secured => {
            system_table
                .stdout()
                .output_string(cstr16!("Network Policy:    SECURED\r\n"))
                .unwrap_or(());
        }
        NetworkPolicy::Standard => {
            system_table
                .stdout()
                .output_string(cstr16!("Network Policy:    STANDARD\r\n"))
                .unwrap_or(());
        }
        NetworkPolicy::Unrestricted => {
            system_table
                .stdout()
                .output_string(cstr16!("Network Policy:    UNRESTRICTED\r\n"))
                .unwrap_or(());
        }
    }
}

fn display_boot_method(config: &BootloaderConfig, system_table: &mut SystemTable<Boot>) {
    match config.preferred_boot_method {
        PreferredBootMethod::Local => {
            system_table
                .stdout()
                .output_string(cstr16!("Boot Method:       LOCAL PREFERRED\r\n"))
                .unwrap_or(());
        }
        PreferredBootMethod::Network => {
            system_table
                .stdout()
                .output_string(cstr16!("Boot Method:       NETWORK PREFERRED\r\n"))
                .unwrap_or(());
        }
        PreferredBootMethod::Intelligent => {
            system_table
                .stdout()
                .output_string(cstr16!("Boot Method:       INTELLIGENT SELECTION\r\n"))
                .unwrap_or(());
        }
    }
}

fn display_other_settings(config: &BootloaderConfig, system_table: &mut SystemTable<Boot>) {
    if config.verbose_logging {
        system_table
            .stdout()
            .output_string(cstr16!("Verbose Logging:   ENABLED\r\n"))
            .unwrap_or(());
    } else {
        system_table
            .stdout()
            .output_string(cstr16!("Verbose Logging:   DISABLED\r\n"))
            .unwrap_or(());
    }
}
