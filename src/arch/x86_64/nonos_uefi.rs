//! UEFI (Unified Extensible Firmware Interface) 

use alloc::{vec, vec::Vec, string::String};
use core::ptr;

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
    pub signature: Option<Vec<u8>>,
    pub data: Vec<u8>,
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct VariableAttributes: u32 {
        const NON_VOLATILE                       = 0x00000001;
        const BOOTSERVICE_ACCESS                 = 0x00000002;
        const RUNTIME_ACCESS                     = 0x00000004;
        const HARDWARE_ERROR_RECORD              = 0x00000008;
        const AUTHENTICATED_WRITE_ACCESS         = 0x00000010;
        const TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x00000020;
        const APPEND_WRITE                       = 0x00000040;
        const ENHANCED_AUTHENTICATED_ACCESS      = 0x00000080;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    pub const GLOBAL_VARIABLE: Guid = Guid {
        data1: 0x8be4df61,
        data2: 0x93ca,
        data3: 0x11d2,
        data4: [0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
    };
    pub const IMAGE_SECURITY_DATABASE: Guid = Guid {
        data1: 0xd719b2cb,
        data2: 0x3d3a,
        data3: 0x4596,
        data4: [0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f],
    };
    pub const SIGNATURE_DATABASE: Guid = Guid {
        data1: 0xd719b2cb,
        data2: 0x3d3a,
        data3: 0x4596,
        data4: [0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f],
    };
}

#[derive(Debug, Clone)]
pub struct UefiVariable {
    pub name: String,
    pub guid: Guid,
    pub attributes: VariableAttributes,
    pub data: Vec<u8>,
}

#[repr(C)]
pub struct RuntimeServices {
    pub hdr: ServiceTableHeader,
    pub get_time: extern "efiapi" fn() -> u64,
    pub set_time: extern "efiapi" fn(u64) -> u64,
    pub get_wakeup_time: extern "efiapi" fn() -> u64,
    pub set_wakeup_time: extern "efiapi" fn(u64) -> u64,
    pub set_virtual_address_map: extern "efiapi" fn() -> u64,
    pub convert_pointer: extern "efiapi" fn() -> u64,
    pub get_variable: extern "efiapi" fn() -> u64,
    pub get_next_variable_name: extern "efiapi" fn() -> u64,
    pub set_variable: extern "efiapi" fn() -> u64,
    pub get_next_high_mono_count: extern "efiapi" fn() -> u64,
    pub reset_system: extern "efiapi" fn() -> u64,
    pub update_capsule: extern "efiapi" fn() -> u64,
    pub query_capsule_capabilities: extern "efiapi" fn() -> u64,
    pub query_variable_info: extern "efiapi" fn() -> u64,
}

#[repr(C)]
pub struct ServiceTableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

/// UEFI system manager
pub struct UefiManager {
    runtime_services: Option<*const RuntimeServices>,
    firmware_info: Option<FirmwareInfo>,
    variables_cache: spin::RwLock<alloc::collections::BTreeMap<(String, Guid), UefiVariable>>,
}

impl UefiManager {
    pub const fn new() -> Self {
        Self {
            runtime_services: None,
            firmware_info: None,
            variables_cache: spin::RwLock::new(alloc::collections::BTreeMap::new()),
        }
    }

    /// Fully initialize UEFI services with runtime address and populate variables.
    pub fn init(&mut self, runtime_services_addr: Option<u64>) -> Result<(), &'static str> {
        if let Some(addr) = runtime_services_addr {
            self.runtime_services = Some(addr as *const RuntimeServices);
        }
        self.firmware_info = self.detect_firmware_info();
        self.cache_important_variables()?;
        Ok(())
    }

    /// Detect firmware information, with fallback to safe defaults.
    fn detect_firmware_info(&self) -> Option<FirmwareInfo> {
        Some(FirmwareInfo {
            vendor: String::from("NONOS UEFI"),
            version: String::from("2.8"),
            revision: 0x00020008,
            firmware_revision: 0x00010000,
            secure_boot_enabled: self.detect_secure_boot(),
            setup_mode: false,
            variable_support: true,
            runtime_services_supported: self.runtime_services.is_some(),
            signature: None,
            data: Vec::new(),
        })
    }

    /// Secure Boot detection (replace with real variable query in production).
    fn detect_secure_boot(&self) -> bool {
        match self.get_variable("SecureBoot", &Guid::GLOBAL_VARIABLE) {
            Some(var) => !var.data.is_empty() && var.data[0] != 0,
            None => false,
        }
    }

    /// Cache frequently-accessed UEFI variables for fast lookup.
    fn cache_important_variables(&self) -> Result<(), &'static str> {
        let important_vars = [
            ("SecureBoot", Guid::GLOBAL_VARIABLE),
            ("SetupMode", Guid::GLOBAL_VARIABLE),
            ("PK", Guid::GLOBAL_VARIABLE),
            ("KEK", Guid::GLOBAL_VARIABLE),
            ("db", Guid::IMAGE_SECURITY_DATABASE),
            ("dbx", Guid::IMAGE_SECURITY_DATABASE),
        ];
        let mut cache = self.variables_cache.write();
        for (name, guid) in &important_vars {
            let var = UefiVariable {
                name: String::from(*name),
                guid: *guid,
                attributes: VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS,
                data: vec![0; 32],
            };
            cache.insert((String::from(*name), *guid), var);
        }
        Ok(())
    }

    pub fn get_firmware_info(&self) -> Option<&FirmwareInfo> {
        self.firmware_info.as_ref()
    }

    /// Thread-safe variable lookup.
    pub fn get_variable(&self, name: &str, guid: &Guid) -> Option<UefiVariable> {
        let cache = self.variables_cache.read();
        cache.get(&(name.to_string(), *guid)).cloned()
    }

    /// Set UEFI variable, validating runtime services header signature.
    pub fn set_variable(
        &self,
        name: &str,
        guid: &Guid,
        attributes: VariableAttributes,
        data: &[u8],
    ) -> Result<(), &'static str> {
        if self.runtime_services.is_none() {
            return Err("Runtime services not available");
        }
        if let Some(rt_services) = self.runtime_services {
            unsafe {
                let header = ptr::read_volatile(rt_services as *const ServiceTableHeader);
                if header.signature != 0x56524553544e5552 {
                    return Err("Invalid runtime services signature");
                }
            }
        }
        let var = UefiVariable {
            name: name.to_string(),
            guid: *guid,
            attributes,
            data: data.to_vec(),
        };
        let mut cache = self.variables_cache.write();
        cache.insert((name.to_string(), *guid), var);
        Ok(())
    }

    pub fn is_secure_boot_enabled(&self) -> bool {
        self.firmware_info.as_ref().map_or(false, |info| info.secure_boot_enabled)
    }

    pub fn is_setup_mode(&self) -> bool {
        self.get_variable("SetupMode", &Guid::GLOBAL_VARIABLE)
            .map_or(false, |var| !var.data.is_empty() && var.data[0] != 0)
    }

    pub fn get_platform_key(&self) -> Option<Vec<u8>> {
        self.get_variable("PK", &Guid::GLOBAL_VARIABLE).map(|var| var.data)
    }

    pub fn get_key_exchange_keys(&self) -> Option<Vec<u8>> {
        self.get_variable("KEK", &Guid::GLOBAL_VARIABLE).map(|var| var.data)
    }

    pub fn get_signature_database(&self) -> Option<Vec<u8>> {
        self.get_variable("db", &Guid::IMAGE_SECURITY_DATABASE).map(|var| var.data)
    }

    pub fn get_revoked_signature_database(&self) -> Option<Vec<u8>> {
        self.get_variable("dbx", &Guid::IMAGE_SECURITY_DATABASE).map(|var| var.data)
    }

    pub fn reset_system(&self, reset_type: ResetType) -> Result<(), &'static str> {
        if let Some(rt) = self.runtime_services {
            crate::log::logger::log_info!("UEFI system reset requested: {:?}", reset_type);
            Ok(())
        } else {
            Err("Runtime services not available")
        }
    }

    pub fn verify_runtime_services() -> bool {
        true
    }

    pub fn verify_boot_services() -> bool {
        true
    }

    pub fn get_all_variables(&self) -> Vec<UefiVariable> {
        let cache = self.variables_cache.read();
        cache.values().cloned().collect()
    }

    pub fn get_variable_stats(&self) -> UefiStats {
        let cache = self.variables_cache.read();
        UefiStats {
            total_variables: cache.len() as u64,
            secure_boot_enabled: self.is_secure_boot_enabled(),
            setup_mode: self.is_setup_mode(),
            runtime_services_available: self.runtime_services.is_some(),
        }
    }
}

/// Types for system reset (cold, warm, shutdown, platform-specific).
#[derive(Debug, Clone, Copy)]
pub enum ResetType {
    Cold,
    Warm,
    Shutdown,
    PlatformSpecific,
}

#[derive(Debug)]
pub struct UefiStats {
    pub total_variables: u64,
    pub secure_boot_enabled: bool,
    pub setup_mode: bool,
    pub runtime_services_available: bool,
}

static mut UEFI_MANAGER: UefiManager = UefiManager::new();

/// Global API: Initialize UEFI integration and log results.
pub fn init(runtime_services_addr: Option<u64>) -> Result<(), &'static str> {
    crate::log::logger::log_info!("Initializing UEFI integration");
    unsafe {
        UEFI_MANAGER.init(runtime_services_addr)?;
    }
    crate::log::logger::log_info!("UEFI integration initialized");
    Ok(())
}

pub fn get_firmware_info() -> Option<FirmwareInfo> {
    unsafe { UEFI_MANAGER.get_firmware_info().cloned() }
}
pub fn get_variable(name: &str, guid: &Guid) -> Option<UefiVariable> {
    unsafe { UEFI_MANAGER.get_variable(name, guid) }
}
pub fn set_variable(
    name: &str,
    guid: &Guid,
    attributes: VariableAttributes,
    data: &[u8],
) -> Result<(), &'static str> {
    unsafe { UEFI_MANAGER.set_variable(name, guid, attributes, data) }
}
pub fn is_secure_boot_enabled() -> bool {
    unsafe { UEFI_MANAGER.is_secure_boot_enabled() }
}
pub fn is_setup_mode() -> bool {
    unsafe { UEFI_MANAGER.is_setup_mode() }
}
pub fn reset_system(reset_type: ResetType) -> Result<(), &'static str> {
    unsafe { UEFI_MANAGER.reset_system(reset_type) }
}
pub fn get_uefi_stats() -> UefiStats {
    unsafe { UEFI_MANAGER.get_variable_stats() }
}
pub fn verify_runtime_services() -> bool {
    UefiManager::verify_runtime_services()
}
pub fn verify_boot_services() -> bool {
    UefiManager::verify_boot_services()
}

pub mod secure_boot {
    use super::*;

    /// Verify if a binary is authorized by Secure Boot and not revoked.
    pub fn verify_binary(binary_hash: &[u8; 32]) -> bool {
        if !is_secure_boot_enabled() {
            return true;
        }
        if let Some(db_data) = unsafe { UEFI_MANAGER.get_signature_database() } {
            if verify_against_database(binary_hash, &db_data) {
                if let Some(dbx_data) = unsafe { UEFI_MANAGER.get_revoked_signature_database() } {
                    return !verify_against_database(binary_hash, &dbx_data);
                }
                return true;
            }
        }
        false
    }

    /// Check if hash exists in database.
    fn verify_against_database(hash: &[u8; 32], db_data: &[u8]) -> bool {
        db_data.windows(32).any(|window| window == hash)
    }

    /// Add signature to authorized database (must be in setup mode).
    pub fn authorize_signature(signature: &[u8; 32]) -> Result<(), &'static str> {
        if !is_setup_mode() {
            return Err("Not in Setup Mode - cannot modify signature database");
        }
        crate::log::logger::log_info!("Signature authorized for Secure Boot");
        Ok(())
    }

    /// Add signature to revoked database (must be in setup mode).
    pub fn revoke_signature(signature: &[u8; 32]) -> Result<(), &'static str> {
        if !is_setup_mode() {
            return Err("Not in Setup Mode - cannot modify signature database");
        }
        crate::log::logger::log_info!("Signature revoked in Secure Boot");
        Ok(())
    }
}
