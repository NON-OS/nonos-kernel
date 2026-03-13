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

mod apply;
mod apply_hardware;
mod apply_network;
mod apply_policy;
mod apply_security;
mod boot_method;
mod config;
mod fallback;
mod graphics_mode;
mod memory_mode;
mod network_policy;
pub mod nvram;
mod policy_network;
mod policy_security;
mod policy_system;
mod security_policy;
pub mod types;
mod verification_level;

pub use apply::apply_configuration;
pub use types::{
    BootloaderConfig, FallbackBehavior, GraphicsMode, MemoryManagementMode, NetworkPolicy,
    PreferredBootMethod, SecurityPolicy, VerificationLevel,
};

pub use nvram::{load_bootloader_config, save_configuration};

pub use apply_policy::{
    apply_hardware_settings, apply_memory_settings, apply_network_policy, apply_security_policy,
};
