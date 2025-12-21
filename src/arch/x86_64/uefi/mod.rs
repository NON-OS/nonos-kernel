// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
// NØNOS x86_64 UEFI Module

pub mod nonos_uefi;

// ============================================================================
// Structures
// ============================================================================

pub use nonos_uefi::FirmwareInfo;
pub use nonos_uefi::UefiVariable;
pub use nonos_uefi::UefiManager;
pub use nonos_uefi::RuntimeServices;
pub use nonos_uefi::ServiceTableHeader;
pub use nonos_uefi::Guid;
pub use nonos_uefi::VariableAttributes;
pub use nonos_uefi::UefiStats;

// ============================================================================
// Enumerations
// ============================================================================

pub use nonos_uefi::ResetType;

// ============================================================================
// Submodules
// ============================================================================

pub use nonos_uefi::secure_boot;

// ============================================================================
// Initialization
// ============================================================================

/// Initialize UEFI
#[inline]
pub fn init(runtime_services_addr: Option<u64>) -> Result<(), &'static str> {
    nonos_uefi::init(runtime_services_addr)
}

// ============================================================================
// Query Functions
// ============================================================================

/// Get firmware information
#[inline]
pub fn get_firmware_info() -> Option<FirmwareInfo> {
    nonos_uefi::get_firmware_info()
}

/// Get UEFI variable
#[inline]
pub fn get_variable(name: &str, guid: &Guid) -> Option<UefiVariable> {
    nonos_uefi::get_variable(name, guid)
}

/// Set UEFI variable
#[inline]
pub fn set_variable(
    name: &str,
    guid: &Guid,
    attributes: VariableAttributes,
    data: &[u8],
) -> Result<(), &'static str> {
    nonos_uefi::set_variable(name, guid, attributes, data)
}

/// Check if Secure Boot is enabled
#[inline]
pub fn is_secure_boot_enabled() -> bool {
    nonos_uefi::is_secure_boot_enabled()
}

/// Check if in setup mode
#[inline]
pub fn is_setup_mode() -> bool {
    nonos_uefi::is_setup_mode()
}

/// Reset system
#[inline]
pub fn reset_system(reset_type: ResetType) -> Result<(), &'static str> {
    nonos_uefi::reset_system(reset_type)
}

/// Get UEFI statistics
#[inline]
pub fn get_uefi_stats() -> UefiStats {
    nonos_uefi::get_uefi_stats()
}

/// Verify runtime services
#[inline]
pub fn verify_runtime_services() -> bool {
    nonos_uefi::verify_runtime_services()
}

/// Verify boot services
#[inline]
pub fn verify_boot_services() -> bool {
    nonos_uefi::verify_boot_services()
}
