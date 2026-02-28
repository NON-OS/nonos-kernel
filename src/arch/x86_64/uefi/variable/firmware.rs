// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

#[derive(Debug, Clone)]
pub struct FirmwareInfo {
    pub vendor: String,
    pub version: String,
    pub revision: u32,
    pub firmware_revision: u32,
    pub secure_boot_enabled: bool,
    pub setup_mode: bool,
    pub variable_support: bool,
    pub runtime_services_supported: bool,
}

impl FirmwareInfo {
    pub fn uefi_major_version(&self) -> u16 {
        (self.revision >> 16) as u16
    }

    pub fn uefi_minor_version(&self) -> u16 {
        self.revision as u16
    }
}

impl Default for FirmwareInfo {
    fn default() -> Self {
        Self {
            vendor: String::from("Unknown"),
            version: String::from("0.0"),
            revision: 0,
            firmware_revision: 0,
            secure_boot_enabled: false,
            setup_mode: true,
            variable_support: false,
            runtime_services_supported: false,
        }
    }
}
