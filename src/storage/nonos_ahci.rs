//! AHCI storage subsystem for RAM-only builds.

#![no_std]

pub fn init() -> Result<(), &'static str> {
    Ok(())
}

pub fn scan_and_register_ahci_devices(_manager: &crate::storage::StorageManager) -> Result<(), &'static str> {
    Ok(())
}
