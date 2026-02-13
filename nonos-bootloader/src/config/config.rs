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

use alloc::string::String;

use super::enums::{
    FallbackBehavior, GraphicsMode, MemoryManagementMode, NetworkPolicy, PreferredBootMethod,
    SecurityPolicy, VerificationLevel,
};

#[derive(Debug, Clone)]
pub struct BootloaderConfig {
    pub security_policy: SecurityPolicy,
    pub require_secure_boot: bool,
    pub require_tpm_measurement: bool,
    pub signature_verification_level: VerificationLevel,

    pub network_policy: NetworkPolicy,
    pub preferred_boot_method: PreferredBootMethod,
    pub network_timeout_seconds: u32,

    pub graphics_mode: GraphicsMode,
    pub boot_splash_enabled: bool,
    pub verbose_logging: bool,
    pub diagnostic_output: bool,

    pub cpu_optimizations: bool,
    pub memory_management_mode: MemoryManagementMode,
    pub acpi_enabled: bool,

    pub boot_timeout_seconds: u32,
    pub auto_boot_enabled: bool,
    pub fallback_behavior: FallbackBehavior,
    pub kernel_command_line: String,
}

impl Default for BootloaderConfig {
    fn default() -> Self {
        Self {
            security_policy: SecurityPolicy::default(),
            require_secure_boot: true,
            require_tpm_measurement: true,
            signature_verification_level: VerificationLevel::default(),

            network_policy: NetworkPolicy::default(),
            preferred_boot_method: PreferredBootMethod::default(),
            network_timeout_seconds: 30,

            graphics_mode: GraphicsMode::default(),
            boot_splash_enabled: true,
            verbose_logging: false,
            diagnostic_output: false,

            cpu_optimizations: true,
            memory_management_mode: MemoryManagementMode::default(),
            acpi_enabled: true,

            boot_timeout_seconds: 10,
            auto_boot_enabled: true,
            fallback_behavior: FallbackBehavior::default(),
            kernel_command_line: String::new(),
        }
    }
}

impl BootloaderConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_security_policy(mut self, policy: SecurityPolicy) -> Self {
        self.security_policy = policy;
        self
    }

    pub fn with_network_policy(mut self, policy: NetworkPolicy) -> Self {
        self.network_policy = policy;
        self
    }

    pub fn with_verbose_logging(mut self, enabled: bool) -> Self {
        self.verbose_logging = enabled;
        self
    }
}
