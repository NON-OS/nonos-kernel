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

use super::super::constants::COMMAND_TIMEOUT_DEFAULT;
use super::super::error::AhciError;
use super::structure::AhciController;
use crate::crypto::aes::Aes256;
use crate::drivers::pci::{pci_read_config32, PciDevice};
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};
use spin::{Mutex, RwLock};

impl AhciController {
    pub fn new(pci_device: &PciDevice) -> Result<Self, AhciError> {
        let bar5 = pci_read_config32(pci_device.bus, pci_device.device, pci_device.function, 0x24);
        if bar5 == 0 {
            return Err(AhciError::Bar5NotConfigured);
        }
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
}
