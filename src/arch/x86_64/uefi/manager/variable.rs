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
use alloc::vec;
use alloc::vec::Vec;
use core::ptr;

use crate::arch::x86_64::uefi::constants::status;
use crate::arch::x86_64::uefi::error::UefiError;
use crate::arch::x86_64::uefi::types::{Guid, VariableAttributes};
use crate::arch::x86_64::uefi::variable::{name_to_ucs2, UefiVariable};
use super::core::UefiManager;

impl UefiManager {
    pub(crate) fn read_variable_raw(&self, name: &str, guid: &Guid) -> Result<Vec<u8>, UefiError> {
        let rt_guard = self.runtime_services.read();
        let rt_ptr = (*rt_guard).ok_or(UefiError::RuntimeServicesNotAvailable)?;

        let name_buf = name_to_ucs2(name)?;
        let mut data_size: u64 = 0;
        let mut attributes: u32 = 0;

        // SAFETY: rt_ptr validated during init, name_buf is properly null-terminated
        let get_status = unsafe {
            let get_variable = (*rt_ptr).get_variable;
            get_variable(
                name_buf.as_ptr(),
                guid as *const Guid,
                &mut attributes,
                &mut data_size,
                ptr::null_mut(),
            )
        };

        if get_status != status::EFI_BUFFER_TOO_SMALL && get_status != status::EFI_SUCCESS {
            if get_status == status::EFI_NOT_FOUND {
                return Err(UefiError::VariableNotFound { name: "variable" });
            }
            return Err(UefiError::VariableReadFailed { status: get_status });
        }

        if data_size == 0 {
            return Ok(Vec::new());
        }

        let mut data = vec![0u8; data_size as usize];

        // SAFETY: rt_ptr validated, data buffer properly sized
        let read_status = unsafe {
            let get_variable = (*rt_ptr).get_variable;
            get_variable(
                name_buf.as_ptr(),
                guid as *const Guid,
                &mut attributes,
                &mut data_size,
                data.as_mut_ptr(),
            )
        };

        if read_status != status::EFI_SUCCESS {
            return Err(UefiError::VariableReadFailed { status: read_status });
        }

        data.truncate(data_size as usize);
        Ok(data)
    }

    pub fn get_variable(&self, name: &str, guid: &Guid) -> Result<UefiVariable, UefiError> {
        self.stats.inc_reads();

        {
            let cache = self.variables_cache.read();
            if let Some(var) = cache.get(&(String::from(name), *guid)) {
                self.stats.inc_cache_hits();
                return Ok(var.clone());
            }
        }

        self.stats.inc_cache_misses();

        match self.read_variable_raw(name, guid) {
            Ok(data) => {
                let var = UefiVariable::new(
                    String::from(name),
                    *guid,
                    VariableAttributes::DEFAULT_NV_BS_RT,
                    data,
                );

                self.variables_cache
                    .write()
                    .insert((String::from(name), *guid), var.clone());
                Ok(var)
            }
            Err(e) => {
                self.stats.inc_read_errors();
                Err(e)
            }
        }
    }

    pub fn set_variable(
        &self,
        name: &str,
        guid: &Guid,
        attributes: VariableAttributes,
        data: &[u8],
    ) -> Result<(), UefiError> {
        self.stats.inc_writes();

        let rt_guard = self.runtime_services.read();
        let rt_ptr = (*rt_guard).ok_or(UefiError::RuntimeServicesNotAvailable)?;

        let name_buf = name_to_ucs2(name)?;

        // SAFETY: rt_ptr validated during init
        let write_status = unsafe {
            let set_variable = (*rt_ptr).set_variable;
            set_variable(
                name_buf.as_ptr(),
                guid as *const Guid,
                attributes.bits(),
                data.len() as u64,
                data.as_ptr(),
            )
        };

        if write_status != status::EFI_SUCCESS {
            self.stats.inc_write_errors();
            return Err(UefiError::VariableWriteFailed { status: write_status });
        }

        let var = UefiVariable::new(String::from(name), *guid, attributes, data.to_vec());
        self.variables_cache
            .write()
            .insert((String::from(name), *guid), var);

        Ok(())
    }

    pub fn append_variable(&self, name: &str, guid: &Guid, data: &[u8]) -> Result<(), UefiError> {
        self.stats.inc_writes();

        let rt_guard = self.runtime_services.read();
        let rt_ptr = (*rt_guard).ok_or(UefiError::RuntimeServicesNotAvailable)?;

        let name_buf = name_to_ucs2(name)?;

        let attrs = VariableAttributes::NON_VOLATILE
            | VariableAttributes::BOOTSERVICE_ACCESS
            | VariableAttributes::RUNTIME_ACCESS
            | VariableAttributes::APPEND_WRITE;

        // SAFETY: rt_ptr validated during init
        let append_status = unsafe {
            let set_variable = (*rt_ptr).set_variable;
            set_variable(
                name_buf.as_ptr(),
                guid as *const Guid,
                attrs.bits(),
                data.len() as u64,
                data.as_ptr(),
            )
        };

        if append_status != status::EFI_SUCCESS {
            self.stats.inc_write_errors();
            return Err(UefiError::VariableWriteFailed { status: append_status });
        }

        self.variables_cache
            .write()
            .remove(&(String::from(name), *guid));

        Ok(())
    }

    pub fn delete_variable(&self, name: &str, guid: &Guid) -> Result<(), UefiError> {
        self.set_variable(name, guid, VariableAttributes::NONE, &[])?;
        self.variables_cache
            .write()
            .remove(&(String::from(name), *guid));
        Ok(())
    }
}
