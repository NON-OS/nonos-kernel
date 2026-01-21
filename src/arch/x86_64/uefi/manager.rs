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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::RwLock;

use super::constants::status;
use super::error::UefiError;
use super::signature::{build_signature_list, hash_in_signature_lists, parse_signature_lists, SignatureList};
use super::stats::{InternalStats, UefiStats};
use super::tables::{EfiTime, EfiTimeCapabilities, RuntimeServices};
use super::types::{Guid, ResetType, VariableAttributes};
use super::variable::{name_to_ucs2, FirmwareInfo, UefiVariable};

static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub struct UefiManager {
    runtime_services: RwLock<Option<*const RuntimeServices>>,
    firmware_info: RwLock<FirmwareInfo>,
    variables_cache: RwLock<BTreeMap<(String, Guid), UefiVariable>>,
    stats: InternalStats,
}

// SAFETY: RuntimeServices pointer is only accessed through synchronized methods
unsafe impl Send for UefiManager {}
unsafe impl Sync for UefiManager {}

impl UefiManager {
    pub const fn new() -> Self {
        Self {
            runtime_services: RwLock::new(None),
            firmware_info: RwLock::new(FirmwareInfo {
                vendor: String::new(),
                version: String::new(),
                revision: 0,
                firmware_revision: 0,
                secure_boot_enabled: false,
                setup_mode: true,
                variable_support: false,
                runtime_services_supported: false,
            }),
            variables_cache: RwLock::new(BTreeMap::new()),
            stats: InternalStats::new(),
        }
    }

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

    fn detect_firmware_info(&self) {
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

    fn cache_security_variables(&self) {
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

    fn read_variable_raw(&self, name: &str, guid: &Guid) -> Result<Vec<u8>, UefiError> {
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

    pub fn get_signature_database(&self) -> Result<Vec<SignatureList>, UefiError> {
        let var = self.get_variable("db", &Guid::IMAGE_SECURITY_DATABASE)?;
        parse_signature_lists(&var.data)
    }

    pub fn get_revoked_database(&self) -> Result<Vec<SignatureList>, UefiError> {
        let var = self.get_variable("dbx", &Guid::IMAGE_SECURITY_DATABASE)?;
        parse_signature_lists(&var.data)
    }

    pub fn verify_hash(&self, hash: &[u8]) -> Result<(), UefiError> {
        if !self.is_secure_boot_enabled() {
            return Ok(());
        }

        if let Ok(dbx_lists) = self.get_revoked_database() {
            if hash_in_signature_lists(hash, &dbx_lists) {
                return Err(UefiError::HashRevoked);
            }
        }

        if let Ok(db_lists) = self.get_signature_database() {
            if hash_in_signature_lists(hash, &db_lists) {
                return Ok(());
            }
        }

        Err(UefiError::HashNotInDatabase)
    }

    pub fn authorize_hash(&self, hash: &[u8]) -> Result<(), UefiError> {
        if !self.is_setup_mode() {
            return Err(UefiError::NotInSetupMode);
        }

        let sig_type = match hash.len() {
            32 => Guid::CERT_SHA256,
            48 => Guid::CERT_SHA384,
            64 => Guid::CERT_SHA512,
            _ => return Err(UefiError::InvalidParameter { param: "hash length" }),
        };

        let sig_list = build_signature_list(&sig_type, &Guid::NONOS_OWNER, hash);
        self.append_variable("db", &Guid::IMAGE_SECURITY_DATABASE, &sig_list)
    }

    pub fn revoke_hash(&self, hash: &[u8]) -> Result<(), UefiError> {
        if !self.is_setup_mode() {
            return Err(UefiError::NotInSetupMode);
        }

        let sig_type = match hash.len() {
            32 => Guid::CERT_SHA256,
            48 => Guid::CERT_SHA384,
            64 => Guid::CERT_SHA512,
            _ => return Err(UefiError::InvalidParameter { param: "hash length" }),
        };

        let sig_list = build_signature_list(&sig_type, &Guid::NONOS_OWNER, hash);
        self.append_variable("dbx", &Guid::IMAGE_SECURITY_DATABASE, &sig_list)
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

impl Default for UefiManager {
    fn default() -> Self {
        Self::new()
    }
}

pub static UEFI_MANAGER: UefiManager = UefiManager::new();

pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_creation() {
        let manager = UefiManager::new();
        let stats = manager.get_stats();
        assert_eq!(stats.variable_reads, 0);
        assert_eq!(stats.variable_writes, 0);
    }
}
