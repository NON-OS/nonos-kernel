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

use super::error::UefiError;
use super::manager::{is_initialized, UEFI_MANAGER};
use super::stats::UefiStats;
use super::tables::EfiTime;
use super::types::{Guid, ResetType, VariableAttributes};
use super::variable::{FirmwareInfo, UefiVariable};

#[inline]
pub fn init(runtime_services_addr: Option<u64>) -> Result<(), UefiError> {
    UEFI_MANAGER.init(runtime_services_addr)
}

#[inline]
pub fn get_firmware_info() -> Option<FirmwareInfo> {
    if !is_initialized() {
        return None;
    }
    Some(UEFI_MANAGER.get_firmware_info())
}

#[inline]
pub fn get_variable(name: &str, guid: &Guid) -> Option<UefiVariable> {
    UEFI_MANAGER.get_variable(name, guid).ok()
}

#[inline]
pub fn set_variable(
    name: &str,
    guid: &Guid,
    attributes: VariableAttributes,
    data: &[u8],
) -> Result<(), UefiError> {
    UEFI_MANAGER.set_variable(name, guid, attributes, data)
}

#[inline]
pub fn is_secure_boot_enabled() -> bool {
    UEFI_MANAGER.is_secure_boot_enabled()
}

#[inline]
pub fn is_setup_mode() -> bool {
    UEFI_MANAGER.is_setup_mode()
}

#[inline]
pub fn reset_system(reset_type: ResetType) -> Result<(), UefiError> {
    UEFI_MANAGER.reset_system(reset_type)
}

#[inline]
pub fn get_uefi_stats() -> UefiStats {
    UEFI_MANAGER.get_stats()
}

#[inline]
pub fn verify_runtime_services() -> bool {
    is_initialized() && UEFI_MANAGER.get_firmware_info().runtime_services_supported
}

#[inline]
pub fn verify_boot_services() -> bool {
    true
}

#[inline]
pub fn get_time() -> Result<EfiTime, UefiError> {
    UEFI_MANAGER.get_time()
}
