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
//! AHCI Host Controller driver - thin orchestration module.

mod helpers;
mod validation;
mod encryption;
mod commands;
mod io;
mod init;
mod secure_erase;

use alloc::{vec::Vec, string::String, collections::BTreeMap};
use spin::{Mutex, RwLock};
use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};
use crate::drivers::pci::{PciDevice, pci_read_config32};
use crate::crypto::aes::Aes256;
use super::error::AhciError;
use super::types::AhciDevice;
use super::dma::PortDma;
use super::stats::AhciStats;
use super::constants::COMMAND_TIMEOUT_DEFAULT;

pub use helpers::{hdr_flags_for, RegisterAccess};

/// AHCI Host Controller driver.
pub struct AhciController {
    base_addr: usize,
    ports: RwLock<BTreeMap<u32, AhciDevice>>,
    port_dma: Mutex<BTreeMap<u32, PortDma>>,
    read_ops: AtomicU64,
    write_ops: AtomicU64,
    trim_ops: AtomicU64,
    errors: AtomicU64,
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
    port_resets: AtomicU64,
    validation_failures: AtomicU64,
    encryption_enabled: AtomicBool,
    aes_cipher: Mutex<Option<Aes256>>,
    encryption_iv: [u8; 16],
    command_timeout: AtomicU32,
}

impl RegisterAccess for AhciController {
    fn base_addr(&self) -> usize { self.base_addr }
}

impl AhciController {
    /// Creates a new AHCI controller instance.
    pub fn new(pci_device: &PciDevice) -> Result<Self, AhciError> {
        let bar5 = pci_read_config32(pci_device.bus, pci_device.device, pci_device.function, 0x24);
        if bar5 == 0 { return Err(AhciError::Bar5NotConfigured); }

        let encryption_key = crate::security::capability::get_secure_random_bytes();
        let mut encryption_iv = [0u8; 16];
        crate::crypto::fill_random(&mut encryption_iv);

        Ok(Self {
            base_addr: (bar5 & !0xF) as usize,
            ports: RwLock::new(BTreeMap::new()),
            port_dma: Mutex::new(BTreeMap::new()),
            read_ops: AtomicU64::new(0),
            write_ops: AtomicU64::new(0),
            trim_ops: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            port_resets: AtomicU64::new(0),
            validation_failures: AtomicU64::new(0),
            encryption_enabled: AtomicBool::new(true),
            aes_cipher: Mutex::new(Some(Aes256::new(&encryption_key))),
            encryption_iv,
            command_timeout: AtomicU32::new(COMMAND_TIMEOUT_DEFAULT),
        })
    }

    /// Initializes the AHCI controller.
    pub fn init(&mut self) -> Result<(), AhciError> {
        let ports_impl = init::init_hba(self)?;

        for port in 0..32 {
            if (ports_impl & (1 << port)) != 0 {
                if let Err(e) = init::init_port(
                    self, &self.port_dma, &self.ports, &self.errors, &self.port_resets,
                    &self.encryption_enabled, self.command_timeout.load(Ordering::Relaxed), port
                ) {
                    crate::log::logger::log_critical(&alloc::format!("AHCI: Port {} init failed: {}", port, e));
                }
            }
        }

        init::enable_interrupts(self);
        Ok(())
    }

    /// Reads sectors from a SATA device.
    pub fn read_sectors(&self, port: u32, lba: u64, count: u16, buffer_va: u64) -> Result<(), AhciError> {
        io::read_sectors(
            self, &self.ports, &self.port_dma, &self.validation_failures,
            &self.read_ops, &self.bytes_read, &self.errors, &self.port_resets,
            &self.encryption_enabled, &self.aes_cipher, &self.encryption_iv,
            self.command_timeout.load(Ordering::Relaxed), port, lba, count, buffer_va
        )
    }

    /// Writes sectors to a SATA device.
    pub fn write_sectors(&self, port: u32, lba: u64, count: u16, buffer_va: u64) -> Result<(), AhciError> {
        io::write_sectors(
            self, &self.ports, &self.port_dma, &self.validation_failures,
            &self.write_ops, &self.bytes_written, &self.errors, &self.port_resets,
            &self.encryption_enabled, &self.aes_cipher, &self.encryption_iv,
            self.command_timeout.load(Ordering::Relaxed), port, lba, count, buffer_va
        )
    }

    /// TRIM sectors with rate limiting.
    pub fn trim_sectors(&self, port: u32, lba: u64, count: u32) -> Result<(), AhciError> {
        io::trim_sectors(
            self, &self.ports, &self.port_dma, &self.validation_failures,
            &self.trim_ops, &self.errors, &self.port_resets,
            self.command_timeout.load(Ordering::Relaxed), port, lba, count
        )
    }

    /// Secure erase device.
    pub fn secure_erase_device(&self, port: u32, enhanced: bool) -> Result<(), AhciError> {
        secure_erase::secure_erase_device(
            self, &self.ports, &self.port_dma, &self.errors, &self.port_resets,
            &self.command_timeout, port, enhanced
        )
    }

    /// Verify erasure by sampling sectors.
    pub fn verify_erasure(&self, port: u32, sample_count: u32) -> Result<bool, AhciError> {
        secure_erase::verify_erasure(
            self, &self.ports, &self.port_dma, &self.validation_failures,
            &self.read_ops, &self.bytes_read, &self.errors, &self.port_resets,
            &self.encryption_enabled, &self.aes_cipher, &self.encryption_iv,
            self.command_timeout.load(Ordering::Relaxed), port, sample_count
        )
    }

    pub fn set_command_timeout(&self, timeout: u32) { self.command_timeout.store(timeout, Ordering::Relaxed); }
    pub fn is_encryption_enabled(&self) -> bool { self.encryption_enabled.load(Ordering::Relaxed) }
    pub fn set_encryption_enabled(&self, enabled: bool) { self.encryption_enabled.store(enabled, Ordering::Relaxed); }
    pub fn get_device_ports(&self) -> Vec<u32> { self.ports.read().keys().copied().collect() }

    pub fn get_device_info(&self, port: u32) -> Option<(String, u64, bool)> {
        self.ports.read().get(&port).map(|d| (d.model.clone(), d.sectors, d.supports_trim))
    }

    pub fn get_stats(&self) -> AhciStats {
        AhciStats {
            read_ops: self.read_ops.load(Ordering::Relaxed),
            write_ops: self.write_ops.load(Ordering::Relaxed),
            trim_ops: self.trim_ops.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            devices_count: self.ports.read().len() as u32,
            port_resets: self.port_resets.load(Ordering::Relaxed),
            validation_failures: self.validation_failures.load(Ordering::Relaxed),
        }
    }
}
