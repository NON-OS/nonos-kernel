//! NVMe storage subsystem shim for RAM-only builds.

#![no_std]

extern crate alloc;

use alloc::sync::Arc;

use crate::storage::{StorageManager};
use crate::storage::nonos_block_device::RamDisk;

pub fn init() -> Result<(), &'static str> {
    // Nothing to init in RAM-only mode.
    Ok(())
}

pub fn scan_and_register_nvme_devices(manager: &StorageManager) -> Result<(), &'static str> {
    // RAM-only: ensure there is at least one device so upper layers can rely on storage.
    RamDisk::ensure_default_registered(manager);
    Ok(())
}
