#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec, collections::BTreeMap};

/// Trusted firmware database for integrity and supply chain enforcement
pub struct FirmwareDB {
    trusted_hashes: BTreeMap<String, [u8; 32]>,
    trusted_versions: BTreeMap<String, String>,
}

static mut FIRMWARE_DB: Option<FirmwareDB> = None;

/// Initialize firmware database with trusted entries
pub fn init() -> Result<(), &'static str> {
    unsafe {
        FIRMWARE_DB = Some(FirmwareDB {
            trusted_hashes: BTreeMap::new(),
            trusted_versions: BTreeMap::new(),
        });
    }
    Ok(())
}

/// Add a trusted firmware image hash/version
pub fn add_trusted_firmware(name: &str, hash: [u8; 32], version: &str) {
    unsafe {
        if let Some(db) = FIRMWARE_DB.as_mut() {
            db.trusted_hashes.insert(name.into(), hash);
            db.trusted_versions.insert(name.into(), version.into());
        }
    }
}

/// Check if a firmware image is trusted
pub fn is_trusted_firmware(name: &str, hash: &[u8; 32]) -> bool {
    unsafe {
        if let Some(db) = FIRMWARE_DB.as_ref() {
            db.trusted_hashes.get(name).map_or(false, |h| h == hash)
        } else {
            false
        }
    }
}

/// Retrieve trusted version for a firmware image
pub fn get_trusted_version(name: &str) -> Option<String> {
    unsafe {
        FIRMWARE_DB.as_ref()?.trusted_versions.get(name).cloned()
    }
}
