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
use core::ptr;

use crate::arch::x86_64::uefi::constants::status;
use crate::arch::x86_64::uefi::error::UefiError;
use crate::arch::x86_64::uefi::stats::UefiStats;
use crate::arch::x86_64::uefi::tables::{EfiTime, EfiTimeCapabilities};
use crate::arch::x86_64::uefi::types::{Guid, ResetType};
use crate::arch::x86_64::uefi::variable::FirmwareInfo;
use super::core::UefiManager;

impl UefiManager {
    pub fn get_firmware_info(&self) -> FirmwareInfo {
        self.firmware_info.read().clone()
    }

    pub fn is_secure_boot_enabled(&self) -> bool {
        self.firmware_info.read().secure_boot_enabled
    }

    pub fn is_setup_mode(&self) -> bool {
        if let Ok(var) = self.get_variable("SetupMode", &Guid::GLOBAL_VARIABLE) {
            var.as_bool()
        } else {
            false
        }
    }

    pub fn get_time(&self) -> Result<EfiTime, UefiError> {
        let rt_guard = self.runtime_services.read();
        let rt_ptr = (*rt_guard).ok_or(UefiError::RuntimeServicesNotAvailable)?;

        let mut time = EfiTime::default();
        let mut capabilities = EfiTimeCapabilities::default();

        // SAFETY: rt_ptr validated during init
        let time_status = unsafe {
            let get_time = (*rt_ptr).get_time;
            get_time(&mut time, &mut capabilities)
        };

        if time_status != status::EFI_SUCCESS {
            return Err(
                UefiError::from_efi_status(time_status).unwrap_or(UefiError::VariableReadFailed {
                    status: time_status,
                }),
            );
        }

        Ok(time)
    }

    pub fn reset_system(&self, reset_type: ResetType) -> Result<(), UefiError> {
        let rt_guard = self.runtime_services.read();
        let rt_ptr = (*rt_guard).ok_or(UefiError::RuntimeServicesNotAvailable)?;

        // SAFETY: rt_ptr validated during init, reset_system never returns
        unsafe {
            let reset_system = (*rt_ptr).reset_system;
            reset_system(reset_type.as_u32(), 0, 0, ptr::null());
        }
    }

    pub fn invalidate_cache(&self) {
        self.variables_cache.write().clear();
    }

    pub fn invalidate_cache_entry(&self, name: &str, guid: &Guid) {
        self.variables_cache
            .write()
            .remove(&(String::from(name), *guid));
    }

    pub fn get_stats(&self) -> UefiStats {
        let cache = self.variables_cache.read();
        let info = self.firmware_info.read();

        UefiStats {
            total_variables: cache.len() as u64,
            variable_reads: self.stats.reads(),
            variable_writes: self.stats.writes(),
            variable_read_errors: self.stats.read_errors(),
            variable_write_errors: self.stats.write_errors(),
            cache_hits: self.stats.cache_hits(),
            cache_misses: self.stats.cache_misses(),
            secure_boot_enabled: info.secure_boot_enabled,
            setup_mode: info.setup_mode,
            runtime_services_available: info.runtime_services_supported,
        }
    }

    pub fn reset_stats(&self) {
        self.stats.reset();
    }
}
