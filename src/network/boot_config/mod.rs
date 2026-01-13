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

pub mod apply;
pub mod config;
pub mod parse;
pub mod presets;
pub mod serialize;
pub mod status;
pub mod types;

pub use apply::apply_boot_config;
pub use config::{configure, get_config, init, is_locked, lock_config};
pub use parse::{export_as_cmdline, init_from_handoff, parse_cmdline, parse_ipv4};
pub use presets::{preset_anonymous, preset_isolated, preset_maximum, preset_standard};
pub use serialize::{deserialize_config, serialize_config};
pub use status::{get_status, print_status};
pub use types::{
    DnsMode, FirewallConfig, Ipv4Config, NetworkBootConfig, OnionConfig, PrivacyMode,
};
