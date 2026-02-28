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
use core::sync::atomic::Ordering;

use crate::arch::x86_64::uefi::error::UefiError;
use crate::arch::x86_64::uefi::tables::RuntimeServices;
use crate::arch::x86_64::uefi::types::{Guid, VariableAttributes};
use crate::arch::x86_64::uefi::variable::{FirmwareInfo, UefiVariable};
use super::core::UefiManager;
use super::state::INITIALIZED;

impl UefiManager {
    pub fn init(&self, runtime_services_addr: Option<u64>) -> Result<(), UefiError> {
        if INITIALIZED.load(Ordering::SeqCst) {
            return Err(UefiError::AlreadyInitialized);
        }

        if let Some(addr) = runtime_services_addr {
            if addr != 0 {
                let rt_ptr = addr as *const RuntimeServices;

                // SAFETY: Caller guarantees valid runtime services address
                unsafe {
                    RuntimeServices::validate(rt_ptr)?;
                }

                *self.runtime_services.write() = Some(rt_ptr);
            }
        }

        self.detect_firmware_info();
        self.cache_security_variables();

        INITIALIZED.store(true, Ordering::SeqCst);

        Ok(())
    }

    pub(crate) fn detect_firmware_info(&self) {
        let mut info = FirmwareInfo::default();

        let has_rt = self.runtime_services.read().is_some();
        info.runtime_services_supported = has_rt;
        info.variable_support = has_rt;

        if let Ok(var) = self.read_variable_raw("SecureBoot", &Guid::GLOBAL_VARIABLE) {
            info.secure_boot_enabled = !var.is_empty() && var[0] == 1;
        }

        if let Ok(var) = self.read_variable_raw("SetupMode", &Guid::GLOBAL_VARIABLE) {
            info.setup_mode = !var.is_empty() && var[0] == 1;
        }

        info.vendor = String::from("NONOS UEFI");
        info.version = String::from("2.8");
        info.revision = 0x00020008;
        info.firmware_revision = 0x00010000;

        *self.firmware_info.write() = info;
    }

    pub(crate) fn cache_security_variables(&self) {
        let vars = [
            ("SecureBoot", Guid::GLOBAL_VARIABLE),
            ("SetupMode", Guid::GLOBAL_VARIABLE),
            ("PK", Guid::GLOBAL_VARIABLE),
            ("KEK", Guid::GLOBAL_VARIABLE),
            ("db", Guid::IMAGE_SECURITY_DATABASE),
            ("dbx", Guid::IMAGE_SECURITY_DATABASE),
        ];

        for (name, guid) in &vars {
            if let Ok(data) = self.read_variable_raw(name, guid) {
                let var = UefiVariable::new(
                    String::from(*name),
                    *guid,
                    VariableAttributes::DEFAULT_NV_BS_RT,
                    data,
                );
                self.variables_cache
                    .write()
                    .insert((String::from(*name), *guid), var);
            }
        }
    }
}
