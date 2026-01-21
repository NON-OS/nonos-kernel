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

mod api;
pub mod constants;
pub mod crc;
pub mod error;
pub mod manager;
pub mod secure_boot;
pub mod signature;
pub mod stats;
pub mod tables;
pub mod types;
pub mod variable;

pub use api::{
    get_firmware_info, get_time, get_uefi_stats, get_variable, init, is_secure_boot_enabled,
    is_setup_mode, reset_system, set_variable, verify_boot_services, verify_runtime_services,
};
pub use constants::status;
pub use crc::{compute as crc32_compute, Crc32};
pub use error::{UefiError, UefiResult};
pub use manager::{is_initialized, UefiManager, UEFI_MANAGER};
pub use signature::{
    build_signature_list, hash_in_signature_lists, parse_signature_lists, SignatureEntry,
    SignatureList,
};
pub use stats::UefiStats;
pub use tables::{EfiTime, EfiTimeCapabilities, MemoryDescriptor, MemoryType, RuntimeServices, TableHeader};
pub use types::{Guid, ResetType, VariableAttributes};
pub use variable::{FirmwareInfo, UefiVariable};
